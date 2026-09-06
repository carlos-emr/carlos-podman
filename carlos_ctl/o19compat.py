# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""The OSCAR 19 import engine's `util` / `dbops` / `config` surface, on podman.

The engine (`o19import`, `o19etl`, `o19docs`, `o19props`, `o19roles`,
`o19bundle`, `o19digest`, `o19report`, `o19_preflight`, `o19host` and the two
generated manifests) is taken VERBATIM from the CARLOS source tree this
deployment already pins — see `o19source`. It is not forked here, because the
ledger, the workspace lock, the resume rules, the phase order, the refusals
and the validation report are the parts a clinic's data depends on and they
must not drift between the two supported deployments.

What the engine needs from its package siblings is small and fixed: three
modules' worth of names, enumerated in `REQUIRED_*` below and verified against
the fetched sources by `o19source.verify_engine`. This module builds those
three as real module objects bound to one `Runner`, so the engine's relative
imports (`from .util import ...`) resolve to podman's answers.

The DEPLOYMENT questions — where the workspace lives, how a client is spawned,
who takes the snapshot — are NOT here: they belong to `o19host.Host`, and
`o19runtime.PodmanHost` overrides them. This module answers only "what does
`util.log` mean on this host", never "where do documents live".
"""

from __future__ import annotations

import os
import secrets as pysecrets
import string
import subprocess
import sys
import types
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .runner import Runner
from .util import log as _podman_log
from .util import warn as _podman_warn

#: Names the engine imports from its `util` sibling. Every one is checked
#: against the FETCHED engine sources at load time (o19source.verify_engine):
#: a CARLOS release that reaches for a name this shim does not provide is
#: refused with the missing name, not with an ImportError three phases in.
REQUIRED_UTIL_NAMES: Tuple[str, ...] = (
    "BACKUP_ENV", "CONF_DIR", "DRUGREF_PROPERTIES", "ENV_FILE", "LIB",
    "PROPERTIES", "SHARE", "STATE", "WEBAPP",
    "die", "env_get", "genpw", "genrandom", "log", "need_root", "out",
    "prop_escape", "prop_get", "prop_unescape", "run", "sql_escape",
    "warn", "which",
)

#: Names the engine imports from `dbops` (only `o19host.Host` does, and
#: `PodmanHost` overrides both call sites — but the base class imports the
#: module at module scope, so it has to exist and has to be correct).
REQUIRED_DBOPS_NAMES: Tuple[str, ...] = ("run_flyway", "sql_escape")

#: Names the engine imports from `config` (again only through `Host`, whose
#: podman subclass answers province and db name itself).
REQUIRED_CONFIG_NAMES: Tuple[str, ...] = ("load",)


def _make_run(runner: Runner) -> Callable[..., subprocess.CompletedProcess]:
    """`util.run` for the engine: the deb's kwargs, podman's chokepoint.

    Two contracts have to survive the translation.

    * DECODING. The deb pins utf-8/replace because the bytes crossing this
      seam are clinic data — mariadb batch output, tar member listings,
      document names. `Runner.run` defaults to the locale, which under the
      `LANG=C` that systemd units run in would decode a patient's name as
      mojibake (silently, into the migrated database) or raise
      UnicodeDecodeError mid-phase. Pinned here, for every engine call.
    * ENVIRONMENT. `subprocess` REPLACES the environment when given one;
      `Runner.run` MERGES into `os.environ`. The engine only ever passes a
      dict it built as `dict(os.environ, **extra)`, so merge and replace
      agree — and merging additionally guarantees PATH survives, which is
      the failure the deb's `_client_env` returns None to avoid.
    """

    def run(cmd: Sequence[str], **kw: Any) -> subprocess.CompletedProcess:
        # The deb's signature is subprocess.run's; podman's Runner renames
        # two of its keywords and takes no **kw, so translate explicitly and
        # refuse anything unmapped rather than silently dropping it (a
        # dropped `capture_output` turns a checked result into an empty one).
        unknown = set(kw) - {"capture_output", "input", "env", "errors",
                             "encoding", "text", "check", "stdin", "stdout",
                             "timeout"}
        if unknown:
            raise TypeError(
                f"o19compat.run does not translate {', '.join(sorted(unknown))}"
                f" — map it onto Runner.run before the engine can use it")
        return runner.run(
            list(cmd),
            check=bool(kw.get("check", False)),
            capture=bool(kw.get("capture_output", False)),
            input_text=kw.get("input"),
            stdin=kw.get("stdin"),
            stdout=kw.get("stdout"),
            env=kw.get("env"),
            timeout=kw.get("timeout"),
            encoding=kw.get("encoding", "utf-8"),
            errors=kw.get("errors", "replace"),
        )

    return run


def _die(msg: str, code: int = 1) -> SystemExit:
    """The engine's fatal exit. SystemExit, not CtlError: the engine raises
    this from deep inside a phase and the exit CODE is meaningful (the
    preflight verb's verdict is 0/1/2), which `CtlError` — always exit 1 —
    cannot carry. `cli.main` lets SystemExit through untouched."""
    print(f"carlos-ctl: ERROR: {msg}", file=sys.stderr)
    raise SystemExit(code)


def _need_root(verb: str) -> None:
    if os.geteuid() != 0:
        _die(f"this command needs root (try: sudo carlos-ctl {verb})")


def _genrandom(length: int, alphabet: str) -> str:
    return "".join(pysecrets.choice(alphabet) for _ in range(length))


def _genpw() -> str:
    # Alphanumeric only, exactly as the deb: these values land in a Java
    # properties file, a systemd EnvironmentFile and SQL DDL, and a quoting
    # bug in one of the three costs more than the few bits of entropy.
    return _genrandom(32, string.ascii_letters + string.digits)


#: java.util.Properties.load(InputStream) decodes ISO-8859-1, so that is what
#: reads of carlos.properties use here. latin-1 also maps every byte 1:1, so a
#: value this never touches cannot be corrupted by having been read.
PROPERTIES_ENCODING = "latin-1"


def _prop_get(path: str, key: str) -> Optional[str]:
    """Last active occurrence wins, mirroring java.util.Properties."""
    import re

    found = None
    try:
        with open(path, encoding=PROPERTIES_ENCODING) as fh:
            for line in fh:
                m = re.match(rf"^\s*{re.escape(key)}\s*=\s*(.*)$",
                             line.rstrip("\n"))
                if m:
                    found = m.group(1)
    except OSError:
        return None
    return found


def _prop_escape(value: str) -> str:
    """Backslashes double on the way into a properties value."""
    return value.replace("\\", "\\\\")


def _prop_unescape(value: str) -> str:
    return value.replace("\\\\", "\\")


def _env_get(path: str, key: str) -> Optional[str]:
    """One KEY=value line from a shell-style env file, %q-decoded — podman's
    env files are written by the same bash-era convention the deb's are."""
    from .util import first_match, shell_unquote_value

    try:
        raw = first_match(open(path, encoding="utf-8",
                               errors="replace").read().splitlines(), key)
    except OSError:
        return None
    return None if raw is None else shell_unquote_value(raw)


def _module(name: str, doc: str, members: Dict[str, Any]) -> types.ModuleType:
    """A shim module built from a mapping, so its whole surface is one
    readable literal and nothing is contributed by a stray assignment."""
    mod = types.ModuleType(name)
    mod.__doc__ = doc
    for key, value in members.items():
        setattr(mod, key, value)
    return mod


def build_shims(runner: Runner, engine_sql_escape: Callable[[str], str]
                ) -> Dict[str, types.ModuleType]:
    """The three sibling modules the engine imports, bound to `runner`.

    `engine_sql_escape` is the engine's OWN escape, handed in by
    `o19source` (`o19_preflight._sql_literal`, the deliberate standalone copy
    the deb pins against `util.sql_escape` in
    `tests/test_sql_escape_contract.py`). Re-implementing it here would make a
    third copy of a function that has already drifted once — and the copy that
    drifted was the one no test compared. Taking it from the fetched engine
    means the escape a podman import applies to clinic values is, by
    construction, the escape that release was tested with.
    """
    s = runner.settings
    run = _make_run(runner)

    def out(cmd: Sequence[str]) -> str:
        cp = run(list(cmd), capture_output=True)
        return cp.stdout.strip() if cp.returncode == 0 else ""

    def which(name: str) -> Optional[str]:
        from shutil import which as _which

        return _which(name)

    util = _module("util", (
        "podman's answers for the engine's `util` sibling — see "
        "carlos_ctl.o19compat"), {
        # --- paths ---------------------------------------------------------
        "CONF_DIR": str(s.conf_dir),
        "ENV_FILE": str(s.env_file),
        "PROPERTIES": str(s.properties_file),
        "DRUGREF_PROPERTIES": str(s.drugref_properties_file),
        # The deb's backup.env has no podman counterpart: restic's repository
        # and password live in carlos-app.env (or, on a sealed install, in the
        # SOPS bundle). Only `Host.backup_configured` /
        # `backup_configuration_hint` read this, and `PodmanHost` overrides
        # both with the real answer; pointing it at the env file keeps a
        # leaked default naming a file that exists.
        "BACKUP_ENV": str(s.env_file),
        "SHARE": str(s.emr_home / "container"),
        "LIB": str(s.emr_home / "build"),
        # There is no exploded webapp on the host: the WAR lives inside the
        # app image. Nothing in the engine reads WEBAPP (the deb uses it only
        # for its own Flyway runner); it is defined so a future engine that
        # does gets a path that plainly is not a webapp rather than a deb
        # path that plainly is not on this host.
        "WEBAPP": str(s.emr_home / "container" / "no-exploded-webapp"),
        # STATE is the engine's base for two DEFAULTS — `o19host.STATE_DIR`
        # (STATE/o19-import) and the `DOCUMENTS_ROOT` fallbacks in o19docs
        # and o19props (STATE/OscarDocument). Only the first is ever reached
        # on podman: `PodmanHost.state_dir` returns the same path, and every
        # documents caller reads `ctx["documents_root"]`, which `_make_ctx`
        # fills from `HOST.documents_root` (pinned by the CARLOS suite's
        # test_host and by test_o19runtime here). $EMR_HOME makes the
        # reachable one correct.
        "STATE": str(s.emr_home),
        # --- behaviour -----------------------------------------------------
        "log": _podman_log,
        "warn": _podman_warn,
        "die": _die,
        "need_root": _need_root,
        "run": run,
        "out": out,
        "sql_escape": engine_sql_escape,
        "genrandom": _genrandom,
        "genpw": _genpw,
        "prop_get": _prop_get,
        "prop_escape": _prop_escape,
        "prop_unescape": _prop_unescape,
        "env_get": _env_get,
        "which": which,
        "PROPERTIES_ENCODING": PROPERTIES_ENCODING,
    })

    def run_flyway(command: str) -> int:
        # Unreachable: PodmanHost.flyway_validate answers the only caller.
        # Fail CLOSED rather than return 0 — a stub that reported success
        # would silently retire P0's schema gate on this deployment.
        raise RuntimeError(
            "carlos-podman has no host-side Flyway runner; "
            "PodmanHost.flyway_validate answers the schema gate "
            f"(dbops.run_flyway({command!r}) must not be reached)")

    dbops = _module("dbops", (
        "podman's answers for the engine's `dbops` sibling — reached only "
        "through o19host.Host, whose podman subclass overrides both call "
        "sites"), {
        "sql_escape": engine_sql_escape,
        "run_flyway": run_flyway,
    })

    def load() -> Any:
        raise RuntimeError(
            "carlos-podman resolves the province from billregion in "
            "carlos.properties and the schema from CARLOS_DB_NAME "
            "(PodmanHost.configured_province / configured_db_name); "
            "config.load() must not be reached")

    config = _module("config", (
        "podman's answers for the engine's `config` sibling — reached only "
        "through o19host.Host, whose podman subclass answers province and "
        "db name itself"), {"load": load})

    return {"util": util, "dbops": dbops, "config": config}


def missing_names(shims: Dict[str, types.ModuleType],
                  module: str, names: Sequence[str]) -> List[str]:
    """Names `module` should provide but does not — the check `o19source`
    runs against what the FETCHED engine actually imports."""
    mod = shims.get(module)
    if mod is None:
        return list(names)
    return [n for n in names if not hasattr(mod, n)]
