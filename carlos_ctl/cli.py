# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Verb dispatch. Grouped by lifecycle; each verb states its scope (HOST-wide
vs THIS instance) and whether it can touch data. NO verb writes to
$EMR_HOME/data except the explicit db import paths (`db <file`), and
`uninstall` always preserves data.

Provisioning (host prep, instance bootstrap, config rendering, drift) is the
Ansible role's job — see ansible/site.yml and README "Migration from the bash
carlos-ctl"."""

from __future__ import annotations

import contextlib
import fcntl
import os
import sys
from typing import Callable, Dict, List, Optional, Tuple

from . import lifecycle
from .config import Settings, registry_entry, resolve_instance_home
from .runner import Runner
from .util import CtlError

USAGE = """\
carlos-ctl — CARLOS EMR pod runtime (app, obs, waf) under rootless podman

APP LIFECYCLE (images + pod processes only — never db/documents/backups):
  build [--use-cache]   build the CARLOS and DrugRef images. The default
                        (CARLOS_REF=auto / DRUGREF_REF=auto) resolves each app's
                        newest GitHub release (published WAR preferred, else
                        source compile) on the FIRST build and PINS it — later
                        builds stay on the pins until 'source update'
  source [show|update|set [--drugref] <ref> [--artifact war|source|image]|clear]
                        show/refresh/pin which CARLOS + DrugRef versions and
                        artifacts builds use
  rebuild [--ref <ref>] [--drugref-ref <ref>] [--pull]   build fresh images and
                        redeploy (both ref flags are ONE-SHOT overrides; the
                        pins are untouched)
  play [--pull]         validate the rendered pod YAMLs and (re)start the pods
  rollback [--accept-schema-mismatch]   point the app images back at the previous
                        build and re-play (images only — does NOT reverse SQL
                        schema migrations; refuses on a schema mismatch)
  down [--disable]      stop the pods (waf -> app -> obs); --disable also masks
  enable                undo `down --disable` without starting the pods now
  cert-renew            acme-mode TLS issuance/renewal (certbot one-shot; the
                        daily <instance>-cert-renew.timer runs this)

OPERATIONS:
  status                show pod/container/timer status
  logs [carlos|db|drugref|waf|<ctr>] [-f]   tail a container's logs
  check                 live post-deploy validation (read-only)
  backup [full|binlogs|docs|verify|status|restore ...]  backups & point-in-time restore
  monitor               run the health checks now (a timer runs this)
  alert-test            send a test alert through the real dispatch path
  guard                 boot-time blank-datadir guard (run by its unit)
  secrets render        render sealed secrets into /run tmpfs (run by its unit)
  alert <unit> <msg>    dispatch one alert (used by OnFailure= units)

DATA & BREAK-GLASS:
  db [args]             mariadb shell in the db container (root)
  db-dump [database...] consistent mariadb-dump to stdout
  db-backup [name]      mariadb-backup physical snapshot (--prepare'd)
  pma [--ttl <minutes>] on-demand phpMyAdmin on 127.0.0.1:<PMA_PORT> (default 120m ttl)

SECURITY:
  db-users              switch app/drugref/backup to least-privilege DB users
  seal                  consolidate secrets into the SOPS+age bundle (TPM-sealed)
  rotate <db|db-root|log-view|obs|age-key|restic>   rotate a stored credential

MULTI-INSTANCE & DECOMMISSION:
  --instance <name> <verb>   target a registered instance by name
  instances [--prune [--yes]]  list registered instances (--prune drops stale)
  uninstall             decommission host wiring; PRESERVES all data
  setup                 guided wizard: writes an Ansible host_vars file
  help | version        show this help / the carlos-ctl version

Provisioning: sudo ansible-playbook -i <inventory> ansible/site.yml
Configuration comes from $EMR_HOME/container/carlos-app.env (rendered by the
playbook); environment variables provide defaults for anything unset there.
"""

# Verbs that mutate instance state: they take the per-instance lock (so a
# manual verb racing a timer-driven rotate cannot interleave read-modify-write
# cycles on the secrets bundle / env file) and print the resolved target
# first — the #1 footgun on a multi-instance host is mutating the wrong one.
_MUTATING = {
    "build", "rebuild", "play", "rollback", "down", "enable", "cert-renew",
    "db-backup", "db-users", "seal", "rotate", "uninstall",
}


def _gating(verb: str, rest: List[str]) -> Tuple[bool, bool]:
    """(take_lock, show_banner) for a verb.

    LOCK (non-blocking cross-verb lock, serializes against rotate/seal/play):
    the _MUTATING set and `backup restore` only. `backup restore` OVERWRITES
    the live DB, so it must not race a rotate. The scheduled backup verbs
    (`full`/`binlogs`/`docs`) deliberately do NOT take this lock — they fire
    on 15-min timers and the nightly full runs for many minutes, so a
    non-blocking cross-verb lock would make them fail EACH OTHER (and the
    full would block every binlog/docs ship in its window, tripping the
    freshness monitor). They already serialize among themselves via
    BackupContext's own BLOCKING repo lock; a rare rotate-vs-backup overlap
    just fails that one run, which retries.

    BANNER (wrong-instance target echo): every state-touching verb — the
    _MUTATING set, all `backup` sub-verbs, and `db` (imports) — so a
    multi-instance operator always sees which instance they hit."""
    if verb in _MUTATING:
        return True, True
    if verb == "backup":
        return rest[:1] == ["restore"], True
    # `source` splits like `backup`: the writing sub-verbs rewrite the pin the
    # NEXT build consumes (lock: an update racing a running build's resolve
    # would interleave read-modify-write on the pin; banner: which instance's
    # pin moved matters on a multi-instance host); bare `source`/`source show`
    # is a read-only report.
    if verb == "source":
        writing = rest[:1] in (["update"], ["set"], ["clear"])
        return writing, writing
    if verb == "db":
        return False, True
    return False, False

_lock_fd: Optional[int] = None  # module-held so the lock lives for the process


def _acquire_ctl_lock(settings: Settings) -> None:
    """Serialize MUTATING verbs for one instance. Non-blocking: a second
    concurrent mutating verb fails fast rather than silently queueing.
    Best-effort: if the lock file cannot be opened (EMR_HOME unwritable/
    read-only-remounted) the operation still proceeds — but LOUDLY, so the
    'mutating verbs take a per-instance lock' guarantee is never silently
    void exactly when a degraded FS makes a rotate-vs-manual race plausible."""
    global _lock_fd
    # Do NOT mkdir EMR_HOME here: a mistyped EMR_HOME would otherwise be
    # CREATED as a side effect of any mutating verb. The playbook creates the
    # home; a missing one is an operator error to surface, not to paper over.
    if not settings.emr_home.is_dir():
        from .util import warn

        warn(f"{settings.emr_home} does not exist — the per-instance mutating lock "
             f"cannot be taken; is EMR_HOME correct / has the playbook run?")
        return
    lock_path = settings.emr_home / ".carlos-ctl.lock"
    try:
        _lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    except OSError as e:
        from .util import warn

        warn(f"could not open the mutating-verb lock {lock_path} ({e}) — proceeding "
             f"WITHOUT serialization; a concurrent rotate/play could interleave")
        return
    try:
        fcntl.flock(_lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        raise CtlError(
            f"another carlos-ctl mutating operation is already running for this instance "
            f"(lock {lock_path}) — wait for it to finish and retry"
        ) from None


def _target_banner(settings: Settings) -> None:
    # Write operator context to stderr so stdout remains safe for SQL pipelines
    # and captured query results. ``db-dump`` omits the banner for the same
    # reason.
    print(
        f"==> target: instance={settings.instance}  EMR_HOME={settings.emr_home}  "
        f"env={settings.env_file}",
        file=sys.stderr,
    )


def _dispatch(verb: str, args: List[str], runner: Runner) -> int:
    # Verbs that take NO arguments must say so instead of silently dropping
    # them: `seal --no-tpm` would otherwise run a TPM seal with the flag
    # ignored (the real knob is the CARLOS_SEAL_NO_TPM env var), and
    # `uninstall --dry-run` would head straight into the real confirmation
    # flow — silently-ignored flags on destructive verbs are how operators
    # get the opposite of what they asked for.
    no_arg_verbs = ("status", "cert-renew", "enable", "check", "seal",
                    "alert-test", "db-users", "monitor", "guard",
                    "uninstall", "setup")
    if verb in no_arg_verbs and args:
        raise CtlError(
            f"'carlos-ctl {verb}' takes no arguments (got: {' '.join(args)}) — "
            f"behavior knobs for it are environment variables; see the README"
        )
    if verb == "status":
        return lifecycle.cmd_status(runner)
    if verb == "logs":
        return lifecycle.cmd_logs(runner, args)
    if verb == "instances":
        return lifecycle.cmd_instances(runner, args)
    if verb == "cert-renew":
        from . import tlsops

        return tlsops.cmd_cert_renew(runner)
    if verb == "source":
        from . import source as source_mod

        return source_mod.cmd_source(runner, args)
    if verb in ("build", "rebuild", "rollback", "play", "down", "enable", "check"):
        from . import build as build_mod
        from . import lifecycle2
        table: Dict[str, Callable[..., int]] = {
            "build": lambda: build_mod.cmd_build(runner, args),
            "rebuild": lambda: build_mod.cmd_rebuild(runner, args),
            "rollback": lambda: build_mod.cmd_rollback(runner, args),
            "play": lambda: lifecycle2.cmd_play(runner, args),
            "down": lambda: lifecycle2.cmd_down(runner, args),
            "enable": lambda: lifecycle2.cmd_enable(runner),
            "check": lambda: lifecycle2.cmd_check(runner),
        }
        return table[verb]()
    if verb in ("seal", "rotate", "secrets"):
        from . import secrets as secrets_mod
        if verb == "seal":
            return secrets_mod.cmd_seal(runner)
        if verb == "rotate":
            return secrets_mod.cmd_rotate(runner, args)
        # Exact match, not a prefix test: `secrets render --dry-run` used to
        # drop the flag and perform the REAL render (decrypting the sealed
        # bundle into the /run tmpfs). Same no-silently-dropped-arguments
        # contract as the no_arg_verbs guard above and `rotate`.
        if args != ["render"]:
            raise CtlError("usage: carlos-ctl secrets render")
        return secrets_mod.cmd_secrets_render(runner)
    if verb == "alert-test":
        from . import alert
        return alert.cmd_alert_test(runner)
    if verb in ("db", "db-dump", "db-backup", "pma", "db-users"):
        from . import dbops
        table = {
            "db": lambda: dbops.cmd_db(runner, args),
            "db-dump": lambda: dbops.cmd_db_dump(runner, args),
            "db-backup": lambda: dbops.cmd_db_backup(runner, args),
            "pma": lambda: dbops.cmd_pma(runner, args),
            "db-users": lambda: dbops.cmd_db_users(runner),
        }
        return table[verb]()
    if verb == "backup":
        from . import backup
        return backup.cmd_backup(runner, args)
    if verb == "monitor":
        from . import monitor
        return monitor.cmd_monitor(runner)
    if verb == "alert":
        from . import alert
        return alert.cmd_alert(runner, args)
    if verb == "guard":
        from . import guard
        return guard.cmd_guard(runner)
    if verb == "uninstall":
        from . import uninstall
        return uninstall.cmd_uninstall(runner)
    if verb == "setup":
        from . import setup as setup_mod
        return setup_mod.cmd_setup(runner)
    # Name the unknown verb on stderr (usage alone left the operator guessing
    # whether the verb was rejected or the args were).
    print(f"carlos-ctl: unknown command '{verb}'\n", file=sys.stderr)
    print(USAGE, end="", file=sys.stderr)
    return 1


def main(argv: Optional[List[str]] = None) -> int:
    # SIGTERM -> SystemExit so `finally` blocks RUN: Python's default SIGTERM
    # action terminates without unwinding, which left staged plaintext PHI
    # dumps behind whenever systemd's TimeoutStartSec (or an operator kill)
    # stopped a backup/restore mid-flight. 143 = 128+SIGTERM convention.
    # SIGKILL remains uncatchable — the backup verbs' orphan reaper covers it.
    import signal

    with contextlib.suppress(ValueError):  # non-main thread (embedded use)
        signal.signal(signal.SIGTERM, lambda _s, _f: sys.exit(143))
    args = list(sys.argv[1:] if argv is None else argv)
    # Global `--instance <name>` selector, resolved BEFORE the env file is
    # read (fail-closed on an unregistered name).
    if args[:1] == ["--instance"]:
        if len(args) < 2 or not args[1]:
            print("ERROR: --instance needs an instance name", file=sys.stderr)
            return 1
        try:
            os.environ["EMR_HOME"] = resolve_instance_home(args[1], os.environ)
            # Pin the instance IDENTITY too, not just the home: every pod,
            # unit, network, secret, and nft-table name derives from INSTANCE,
            # which is otherwise read from the selected home's env file — and
            # when that file is missing (the unmounted-volume incident
            # --instance exists to handle) identity silently defaulted to
            # 'carlos', so `--instance clinicb down` stopped the FIRST
            # instance's production pods. The registry entry carries the
            # authoritative name.
            reg_inst = registry_entry(args[1], os.environ).get("INSTANCE", "") or args[1]
            os.environ["CARLOS_INSTANCE_PINNED"] = reg_inst
        except CtlError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        # Pin the registry-resolved home: an exported ENV_FILE (or an env
        # file that re-points EMR_HOME) would otherwise override the explicit
        # selector, so `sudo -E carlos-ctl --instance clinicb <verb>` could
        # mutate a DIFFERENT instance whose ENV_FILE was still in the shell.
        # An explicit --instance is authoritative — drop the stale ENV_FILE,
        # and mark EMR_HOME as PINNED so Settings does not let the selected
        # instance's own env-file EMR_HOME line win over the registry value.
        os.environ.pop("ENV_FILE", None)
        os.environ["CARLOS_EMR_HOME_PINNED"] = os.environ["EMR_HOME"]
        args = args[2:]
    if not args:
        print(USAGE, end="")
        return 1
    verb, rest = args[0], args[1:]
    # help/--help/-h print usage on STDOUT and exit 0 (a help request is not
    # an error); version prints the package version.
    if verb in ("help", "--help", "-h"):
        print(USAGE, end="")
        return 0
    if verb in ("version", "--version"):
        from . import __version__

        print(f"carlos-ctl {__version__}")
        return 0
    try:
        settings = Settings()
        runner = Runner(settings)
        take_lock, show_banner = _gating(verb, rest)
        if show_banner:
            _target_banner(settings)
        if take_lock:
            _acquire_ctl_lock(settings)
        return _dispatch(verb, rest, runner)
    except CtlError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    except Exception as e:  # noqa: BLE001 — top-level guard, not silent
        # An unexpected exception (OSError, KeyError, …) should reach the
        # operator as a clean one-liner with the type, not a raw traceback
        # (which can also leak paths/state). The full traceback is still
        # available with CARLOS_CTL_TRACEBACK=1 for debugging.
        if os.environ.get("CARLOS_CTL_TRACEBACK") == "1":
            raise
        print(f"ERROR: unexpected {type(e).__name__}: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
