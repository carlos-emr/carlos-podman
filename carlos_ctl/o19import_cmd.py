# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""The `import-o19` and `o19-preflight` verbs.

Thin on purpose. Everything an OSCAR 19 migration does — the phase order, the
ledger, the workspace lock, the resume rules, the refusals, the verification
report — is the engine's, taken from the CARLOS tree this instance deploys
(`o19source`). This module does three things: it decides whether the verb may
run on THIS host at all, it hands the engine podman's `Host`
(`o19runtime.PodmanHost`), and it calls the engine's entrypoint.

Anything that looks like migration logic belongs upstream in
carlos-emr/carlos, not here — two implementations of the same safety
properties is exactly what the port was designed to avoid.
"""

from __future__ import annotations

from typing import List, Sequence

from . import o19runtime, o19source
from .runner import Runner
from .util import CtlError, log

#: The engine's own experimental banner, repeated at the verb boundary so it
#: is seen even by an operator who never reads the CARLOS documentation.
_EXPERIMENTAL = (
    "The OSCAR 19 importer is EXPERIMENTAL. Its output must receive a "
    "technical review before clinical use, and the pre-import snapshot is "
    "the rollback point — do not start it without one you have verified.")


def _dev_seam(argv: Sequence[str]) -> bool:
    """Whether the operator pointed the verb at a development database.
    Read before argparse so the host gates below can key on it; the engine
    parses the same flag properly and is what actually uses the value."""
    return any(a == "--mariadb-arg" or a.startswith("--mariadb-arg=")
               for a in argv)


def _refuse_unless_reachable(runner: Runner, argv: Sequence[str]) -> None:
    """Refuse before ANY phase starts when this host cannot reach its own
    database non-interactively.

    The client authenticates with `CARLOS_DB_ROOT_PASSWORD` forwarded as
    MYSQL_PWD. Without it every statement the import makes fails with
    access-denied — after the workspace lock is taken, a staging schema is
    created and, for a resume, a ledger already exists. Naming the cause here
    costs one file read; discovering it three phases in costs a rollback."""
    if _dev_seam(argv):
        return
    s = runner.settings
    if not s.env_file.is_file():
        return  # not a provisioned instance; the engine refuses on its own
    if not s.get("CARLOS_DB_ROOT_PASSWORD"):
        raise CtlError(
            f"no CARLOS_DB_ROOT_PASSWORD in {s.env_file} — the OSCAR 19 import runs "
            "hundreds of statements as database root and cannot prompt. Put "
            "the root password in the (mode-600) env file, or run against a "
            "development database with --mariadb-arg.")


def _prepared(runner: Runner, argv: Sequence[str]) -> o19source.Engine:
    """The engine, fetched if needed and wired to podman's deployment."""
    _refuse_unless_reachable(runner, argv)
    engine = o19source.load_engine(runner)
    log(f"OSCAR 19 import engine: CARLOS {engine.commit[:12]} ({engine.described})")
    engine.o19import.HOST = o19runtime.make_host(runner, engine)
    return engine


def cmd_import_o19(runner: Runner, args: List[str]) -> int:
    """`carlos-ctl import-o19` — run the migration phases, or `--cleanup`."""
    log(_EXPERIMENTAL)
    engine = _prepared(runner, args)
    return int(engine.o19import.cmd_import_o19(list(args)))


def cmd_o19_preflight(runner: Runner, args: List[str]) -> int:
    """`carlos-ctl o19-preflight` — assess a bundle and report a verdict.

    Exit 0/1/2 are the VERDICT (go, go with acknowledgements, no-go); any
    other code is a tool error. The engine owns that mapping."""
    engine = _prepared(runner, args)
    return int(engine.o19import.cmd_o19_preflight(list(args)))
