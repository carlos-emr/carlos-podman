# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Protocol-1 command contract for the shared CARLOS CDS engine.

Mirrors the host adapter contract in carlos-emr/carlos-ctl. Clinical meaning,
authorization, source identity, completion and recovery belong to Java.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import pwd
import re
import struct
from typing import List, NoReturn, Optional, Sequence, Set

OPERATIONS = frozenset({"import", "status", "resume", "cancel", "report"})


class CdsCommandError(Exception):
    """An operator-safe message and process outcome; never raw source detail."""

    def __init__(self, message: str, code: int = 1) -> None:
        super().__init__(message)
        self.code = code


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        # argparse's default message echoes values, including PHI-bearing source
        # paths and unknown arguments. The engine's protected diagnostics carry
        # source context; the console only names the safe argument contract.
        raise CdsCommandError("CDS_ARGUMENTS: invalid, duplicate or conflicting arguments; "
                              "run 'carlos-ctl cds-import --help'")


class _Once(argparse.Action):
    def __call__(self, parser: argparse.ArgumentParser, namespace: argparse.Namespace,
                 values: object, option_string: Optional[str] = None) -> None:
        provided: Set[str] = getattr(namespace, "_provided", set())
        if self.dest in provided:
            parser.error("duplicate option")
        provided.add(self.dest)
        namespace._provided = provided
        setattr(namespace, self.dest, self.const if self.nargs == 0 else values)


def _identifier(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value, flags=re.ASCII):
        raise argparse.ArgumentTypeError("invalid identifier")
    return value


def _number(value: str) -> str:
    if not re.fullmatch(r"[0-9]{1,20}", value, flags=re.ASCII):
        raise argparse.ArgumentTypeError("invalid number")
    return value


def _provider(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,16}", value, flags=re.ASCII):
        raise argparse.ArgumentTypeError("invalid provider key")
    return value


def _shift(value: str) -> int:
    if not re.fullmatch(r"-?[0-9]{1,10}", value, flags=re.ASCII):
        raise argparse.ArgumentTypeError("invalid shift")
    result = int(value)
    if not -(2**31) <= result < 2**31:
        raise argparse.ArgumentTypeError("shift outside supported integer range")
    return result


def parser() -> argparse.ArgumentParser:
    ap = _Parser(
        prog="carlos-ctl cds-import",
        description=("Import OntarioMD CDS data through the same durable CARLOS engine "
                     "as the browser. Merge is off by default. Existing job operations "
                     "use their recorded source/options; they never resubmit the input."),
        allow_abbrev=False,
        epilog=("Exit: 0 clean import/no-op/dry-run (or successful status/report command); "
                "1 arguments; 2 configuration/runtime; 3 denied; 4 refused/busy/failed/"
                "partial/uncertain; 130 interrupted. Status/report success does not mean "
                "the recorded import is complete. A nonzero result can coexist with "
                "committed clinical data; resume/reconcile by run ID."),
    )
    ap.add_argument("--input", action=_Once, metavar="PATH",
                    help="source XML, ZIP or directory within the configured allowed root")
    ap.add_argument("--provider", action=_Once, type=_provider, required=True, metavar="ID",
                    help="active CARLOS provider approved for this operator's delegation")
    ap.add_argument("--program", action=_Once, type=_number, metavar="ID")
    ap.add_argument("--facility", action=_Once, type=_number, metavar="ID")
    ap.add_argument("--source-namespace", action=_Once, type=_identifier, metavar="KEY",
                    help="registered source instance; required for a new import")
    ap.add_argument("--source-profile", action=_Once, type=_identifier, metavar="KEY",
                    help="approved source contract profile; required for a new import")
    for flag, help_text in (
        ("--merge-existing", "opt in to a unique eligible HIN + exact DOB chart merge"),
        ("--dry-run", "preflight without clinical writes"),
        ("--no-match-providers", "retain source provider identities without name matching"),
        ("--synthetic", "authorized synthetic/anonymized mode, never real-chart merge"),
    ):
        ap.add_argument(flag, action=_Once, nargs=0, const=True, default=False, help=help_text)
    ap.add_argument("--timeshift", action=_Once, type=_shift, default=0, metavar="DAYS",
                    help="synthetic-mode date shift; default zero")
    ap.add_argument("--course", action=_Once, type=_number, metavar="ID",
                    help="authorized synthetic student/program replication")
    modes = ap.add_mutually_exclusive_group()
    for operation in ("status", "resume", "cancel", "report"):
        modes.add_argument("--" + operation, action=_Once, type=_identifier,
                           metavar="RUN_ID", help=operation + " an existing durable run")
    return ap


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    ap = parser()
    args = ap.parse_args(list(argv))
    selected = [name for name in OPERATIONS - {"import"} if getattr(args, name)]
    args.operation = selected[0] if selected else "import"
    args.run_id = getattr(args, args.operation) if selected else None
    provided: Set[str] = getattr(args, "_provided", set())
    if args.operation != "import":
        if provided - {"provider", args.operation}:
            ap.error("existing jobs cannot change input or options")
        return args
    if not args.input or not args.source_namespace or not args.source_profile:
        ap.error("input, namespace and profile are required")
    if any(ord(char) < 32 or ord(char) == 127 for char in args.input):
        ap.error("invalid source path")
    # Make the caller's relative path explicit before runuser changes identity.
    # This does not dereference symlinks or replace Java's allowed-root checks.
    args.input = os.path.abspath(args.input)
    if (args.course is not None or args.timeshift != 0) and not args.synthetic:
        ap.error("course and nonzero shift require synthetic mode")
    if args.merge_existing and args.synthetic:
        ap.error("synthetic import cannot merge real charts")
    return args


def engine_arguments(args: argparse.Namespace) -> List[str]:
    result = ["--operation", args.operation, "--provider", args.provider]
    if args.operation != "import":
        return result + ["--run", args.run_id]
    result += ["--input", args.input, "--source-namespace", args.source_namespace,
               "--source-profile", args.source_profile]
    for name in ("program", "facility", "course"):
        value = getattr(args, name)
        if value is not None:
            result += ["--" + name, value]
    for name in ("merge_existing", "dry_run", "no_match_providers", "synthetic"):
        if getattr(args, name):
            result.append("--" + name.replace("_", "-"))
    if args.timeshift != 0:
        result += ["--timeshift", str(args.timeshift)]
    return result


def _operator() -> tuple[str, int]:
    """Resolve the invoking OS identity; Java still requires explicit delegation."""
    try:
        sudo_uid = os.environ.get("SUDO_UID")
        if sudo_uid is not None:
            if not re.fullmatch(r"[0-9]{1,10}", sudo_uid, flags=re.ASCII):
                raise ValueError("invalid sudo identity")
            uid = int(sudo_uid)
        else:
            uid = os.getuid()
        name = pwd.getpwuid(uid).pw_name
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}\$?", name, flags=re.ASCII):
            raise ValueError("unsupported operator name")
        if sudo_uid is not None and os.environ.get("SUDO_USER") not in (None, name):
            raise ValueError("inconsistent sudo identity")
        return name, uid
    except (KeyError, ValueError, OverflowError):
        raise CdsCommandError("CDS_OPERATOR: cannot verify the invoking OS identity", 3) from None


def arguments_digest(arguments: Sequence[str]) -> str:
    """Wire protocol: SHA-256 of four-byte BE length + UTF-8 bytes per argument."""
    digest = hashlib.sha256()
    for argument in arguments:
        encoded = argument.encode("utf-8")
        digest.update(struct.pack(">I", len(encoded)))
        digest.update(encoded)
    return digest.hexdigest()
