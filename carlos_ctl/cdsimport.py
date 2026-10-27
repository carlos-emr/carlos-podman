# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""One-shot container adapter for the shared CARLOS CDS import engine."""

from __future__ import annotations

import json
import os
import re
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

from .cdsprotocol import (
    OPERATIONS,
    CdsCommandError,
    _operator,
    arguments_digest,
    engine_arguments,
    parse_args,
)
from .runner import Runner
from .util import CtlError

PROTOCOL = 1
CAPTURE_BYTES = 64 * 1024
DEADLINE = 30.0
CONTAINER_SOURCE = "/var/lib/carlos-emr/cds-import/source"
CONTAINER_STATE = "/var/lib/carlos-emr/cds-import/state"
CONTAINER_PROPERTIES = "/run/carlos-config"
LAUNCHER = "/usr/local/bin/carlos-cds-import"


def _unique_object(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate protocol field")
        result[key] = value
    return result


def _json(text: str) -> Any:
    if len(text.encode("utf-8")) > CAPTURE_BYTES:
        raise CdsCommandError("CDS_PROTOCOL: response exceeded its limit", 2)
    try:
        return json.loads(text, object_pairs_hook=_unique_object)
    except (ValueError, RecursionError):
        raise CdsCommandError("CDS_PROTOCOL: invalid runtime response", 2) from None


def _control(runner: Runner, arguments: Sequence[str]) -> str:
    cp = runner.run(runner.podman_user_argv(arguments), capture=True,
                    capture_limit=CAPTURE_BYTES, timeout=DEADLINE)
    if cp.returncode != 0:
        raise CdsCommandError("CDS_RUNTIME: required container/runtime operation failed", 2)
    return cp.stdout or ""


def _mounts_safe(runner: Runner, name: str) -> None:
    mounts = _json(_control(runner, ["inspect", "--format", "{{json .Mounts}}", name]))
    if not isinstance(mounts, list):
        raise CdsCommandError("CDS_MOUNTS: invalid import mount contract", 2)
    required = {CONTAINER_SOURCE: False, CONTAINER_STATE: True,
                CONTAINER_PROPERTIES: False, "/var/lib/CarlosDocument": True}
    seen: Dict[str, bool] = {}
    for mount in mounts:
        if not isinstance(mount, dict):
            raise CdsCommandError("CDS_MOUNTS: invalid import mount contract", 2)
        destination, writable = mount.get("Destination"), mount.get("RW")
        if not isinstance(destination, str):
            raise CdsCommandError("CDS_MOUNTS: invalid import mount contract", 2)
        if destination in required:
            if destination in seen or type(writable) is not bool:
                raise CdsCommandError("CDS_MOUNTS: conflicting import mount contract", 2)
            seen[destination] = writable
    if seen != required:
        raise CdsCommandError(
            "CDS_MOUNTS: re-provision the supported source/state/config/document mounts", 2)


def _deployed_image(runner: Runner, app: str) -> str:
    image = _control(runner, ["inspect", "--format", "{{.Image}}", app]).strip()
    if not re.fullmatch(r"(?:sha256:)?[a-f0-9]{64}", image):
        raise CdsCommandError("CDS_IMAGE: cannot resolve the exact deployed CARLOS image", 2)
    return image


def _create(
    runner: Runner, name: str, image: str, app: str, arguments: Sequence[str], *, probe: bool,
    heap: int,
) -> None:
    options = ["create", "--name", name, "--pull=never", "--pod", runner.settings.app_pod,
               "--volumes-from", app, "--read-only", "--security-opt", "no-new-privileges",
               "--cap-drop=ALL", "--memory", str((128 if probe else heap) + 256) + "m",
               "--cpus", "1", "--user", "10001:10001" if probe else "0:0",
               "--tmpfs", "/run/carlos-cds-delegations:rw,nosuid,nodev,noexec,"
               "size=1m,mode=0750,uid=0,gid=10001",
               "--env", "CARLOS_CDS_HEAP_MIB=" + str(heap),
               "--entrypoint", "/usr/bin/tini"]
    if not probe:
        options += ["--interactive", "--cap-add=CHOWN", "--cap-add=SETUID",
                    "--cap-add=SETGID", "--cap-add=SETPCAP"]
    options += [image, "--", LAUNCHER, *arguments]
    _control(runner, options)
    # Inspect before start: inherited read-only source/config modes must remain
    # true in the one-shot container, not merely in its producer's spec.
    _mounts_safe(runner, name)


def _remove(runner: Runner, name: str) -> bool:
    try:
        _control(runner, ["rm", "--force", "--ignore", name])
        return True
    except (CdsCommandError, CtlError, OSError):
        # Only this invocation's unpredictable name is eligible. Never scan or
        # stop other imports from a heartbeat guess; the Java owner fences them.
        return False


def _probe(runner: Runner, image: str, app: str, *, submission_lookup: bool = False) -> int:
    name = runner.settings.instance + "-cds-probe-" + uuid.uuid4().hex
    primary_error = False
    try:
        _create(runner, name, image, app, ["--capabilities"], probe=True, heap=128)
        caps = _json(_control(runner, ["start", "--attach", name]))
        operations = caps.get("operations") if isinstance(caps, dict) else None
        if not isinstance(caps, dict) or type(caps.get("protocol")) is not int \
                or caps["protocol"] != PROTOCOL or type(caps.get("java")) is not int \
                or caps["java"] != 25 or not isinstance(operations, list) \
                or not all(isinstance(item, str) for item in operations) \
                or not OPERATIONS.issubset(operations) \
                or type(caps.get("cliHeapMiB")) is not int \
                or not 128 <= caps["cliHeapMiB"] <= 16384:
            raise CdsCommandError(
                "CDS_HANDSHAKE: deploy matching Java25 CARLOS and CLI versions", 2)
        if submission_lookup and caps.get("submissionLookup") is not True:
            raise CdsCommandError(
                "CDS_HANDSHAKE: deploy a matching CARLOS release with submission lookup", 2)
        return int(caps["cliHeapMiB"])
    except BaseException:
        primary_error = True
        raise
    finally:
        if not _remove(runner, name):
            if primary_error:
                print("CDS_CLEANUP: probe-container retirement could not be confirmed",
                      file=sys.stderr)
            else:
                raise CdsCommandError(
                    "CDS_CLEANUP: probe-container retirement could not be confirmed", 2)


def _translated_input(runner: Runner, value: str) -> str:
    source = runner.settings.data_dir / "cds-import" / "source"
    try:
        root = source.resolve(strict=True)
        if source.is_symlink() or not root.is_dir():
            raise ValueError("unsafe source root")
        selected = Path(value)
        cursor = selected
        while cursor != source:
            if cursor.is_symlink() or cursor.parent == cursor:
                raise ValueError("linked or outside source")
            cursor = cursor.parent
        candidate = selected.resolve(strict=True)
        relative = candidate.relative_to(root)
        return str(Path(CONTAINER_SOURCE) / relative)
    except (OSError, ValueError):
        raise CdsCommandError(
            "CDS_SOURCE: input must exist within the instance CDS source root", 2) from None


def cmd_cds_import(runner: Runner, argv: Sequence[str]) -> int:
    name = None
    result = 2
    try:
        args = parse_args(argv)
        if os.geteuid() != 0:
            raise CdsCommandError(
                "CDS_AUTHORIZATION: invoke the administration command with sudo", 3)
        operator, uid = _operator()
        if args.operation == "import":
            args.input = _translated_input(runner, args.input)
        arguments = engine_arguments(args)
        app = runner.settings.app_pod + "-carlos"
        image = _deployed_image(runner, app)
        _mounts_safe(runner, app)
        # The bounded probe uses Java's actual production Properties loader;
        # never duplicate effective config semantics in the Python wrapper.
        heap = _probe(runner, image, app, submission_lookup=bool(args.status_submission))
        nonce = str(uuid.uuid4())
        issued = int(time.time())
        attestation = json.dumps({
            "protocol": PROTOCOL, "operator": operator, "operatorUid": uid,
            "provider": args.provider, "operation": args.operation,
            "argvSha256": arguments_digest(arguments), "nonce": nonce,
            "issuedEpochSeconds": issued, "expiresEpochSeconds": issued + 300,
        }, ensure_ascii=False, separators=(",", ":"))
        name = runner.settings.instance + "-cds-import-" + nonce
        _create(runner, name, image, app, [nonce, *arguments], probe=False, heap=heap)
        # Only the bounded attestation rides stdin. Clinical source payloads
        # remain mounted read-only; engine progress streams without capture.
        outcome = runner.run(runner.podman_user_argv(["start", "--attach", "--interactive", name]),
                             input_text=attestation, supervise=True)
        result = 2 if outcome.returncode in (125, 126, 127) else outcome.returncode
    except CdsCommandError as exc:
        print(str(exc), file=sys.stderr)
        result = exc.code
    except (CtlError, OSError):
        print("CDS_RUNTIME: import runtime failed; inspect durable run state before retrying",
              file=sys.stderr)
        result = 2
    except KeyboardInterrupt:
        result = 130
    except Exception:  # noqa: BLE001 — fail-closed entry boundary, no raw path/PHI detail
        print("CDS_RUNTIME: invalid import runtime state; inspect the durable run before retrying",
              file=sys.stderr)
        result = 2
    finally:
        if name is not None and not _remove(runner, name):
            print("CDS_CLEANUP: import-container retirement failed; "
                  "clinical commits remain in durable run state",
                  file=sys.stderr)
            if result == 0:
                result = 2
    return result
