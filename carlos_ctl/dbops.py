# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Database verbs: db / db-dump / db-backup / pma (break-glass) and the
least-privilege account provisioning shared by db-users, rotate db, and
play's auto-provisioning.

Credential discipline everywhere here: MYSQL_PWD is forwarded by NAME (a
bare `-e MYSQL_PWD`) so the root password is never a podman argv token in
the host process list; SQL travels over stdin (already off-argv)."""

from __future__ import annotations

import contextlib
import os
import re
import secrets as pysecrets
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Tuple

from .runner import Runner
from .util import (
    CtlError,
    chown_to_service_user,
    first_match,
    log,
    properties_escape_value,
    properties_unescape_value,
    set_kv,
    sql_escape,
    warn,
)

_PROVISION_SQL = """\
-- Account DDL must NOT ride the binary log. The dump/replay legs deliberately
-- exclude mysql/sys and run under sql_log_bin=0, so a point-in-time RESTORE
-- never re-applies account passwords — but that contract only holds if the
-- provisioning itself stays out of the binlog too. Without this, a `rotate db`
-- / `db-users` ALTER USER lands in the chain; a windowed restore (or the
-- Sunday drill) then REPLAYS it onto the live (or scratch) server, rewinding
-- the app/root credentials to a stale generation — app-down at reboot, or a
-- root lockout requiring skip-grant-tables to recover (ninth-pass finding).
SET SESSION sql_log_bin = 0;
CREATE USER IF NOT EXISTS 'carlos'@'localhost' IDENTIFIED BY '{app}';
CREATE USER IF NOT EXISTS 'carlos'@'127.0.0.1' IDENTIFIED BY '{app}';
ALTER USER 'carlos'@'localhost' IDENTIFIED BY '{app}';
ALTER USER 'carlos'@'127.0.0.1' IDENTIFIED BY '{app}';
GRANT ALL PRIVILEGES ON `oscar`.* TO 'carlos'@'localhost';
GRANT ALL PRIVILEGES ON `oscar`.* TO 'carlos'@'127.0.0.1';
CREATE USER IF NOT EXISTS 'drugref'@'localhost' IDENTIFIED BY '{drugref}';
CREATE USER IF NOT EXISTS 'drugref'@'127.0.0.1' IDENTIFIED BY '{drugref}';
ALTER USER 'drugref'@'localhost' IDENTIFIED BY '{drugref}';
ALTER USER 'drugref'@'127.0.0.1' IDENTIFIED BY '{drugref}';
GRANT ALL PRIVILEGES ON `drugref2`.* TO 'drugref'@'localhost';
GRANT ALL PRIVILEGES ON `drugref2`.* TO 'drugref'@'127.0.0.1';
CREATE USER IF NOT EXISTS 'backup'@'localhost' IDENTIFIED BY '{backup}';
ALTER USER 'backup'@'localhost' IDENTIFIED BY '{backup}';
-- mariadb-dump --single-transaction --master-data=2 needs SELECT/SHOW VIEW/
-- TRIGGER/EVENT (dump contents), RELOAD (FLUSH BINARY LOGS / --flush-logs)
-- and REPLICATION CLIENT (binlog coordinates). NOT PROCESS: mariadb-dump
-- does not use it, and a leak of backup-db.env would then let an attacker
-- watch every clinician's live SQL (SHOW PROCESSLIST exposes bound PHI).
GRANT SELECT, SHOW VIEW, TRIGGER, EVENT, RELOAD, REPLICATION CLIENT ON *.* TO 'backup'@'localhost';
CREATE USER IF NOT EXISTS 'exporter'@'localhost' IDENTIFIED BY '{exporter}';
CREATE USER IF NOT EXISTS 'exporter'@'127.0.0.1' IDENTIFIED BY '{exporter}';
ALTER USER 'exporter'@'localhost' IDENTIFIED BY '{exporter}';
ALTER USER 'exporter'@'127.0.0.1' IDENTIFIED BY '{exporter}';
GRANT PROCESS, REPLICATION CLIENT ON *.* TO 'exporter'@'localhost';
GRANT PROCESS, REPLICATION CLIENT ON *.* TO 'exporter'@'127.0.0.1';
GRANT SELECT ON `performance_schema`.* TO 'exporter'@'localhost';
GRANT SELECT ON `performance_schema`.* TO 'exporter'@'127.0.0.1';
-- mysql_secure_installation-equivalent hygiene (finding C24): the official
-- mariadb image ships no anonymous users TODAY, but a PHI database must not
-- rest on an unverified image default — drop them explicitly so the
-- invariant holds across image bumps and restored dumps. Deliberately no
-- dropping of the `test` database (review finding): provisioning must stay
-- ADDITIVE — a legacy OSCAR/OpenO migration can arrive with a POPULATED
-- `test` schema, and destroying data inside a routine deploy violates the
-- data-safety contract; without anonymous users a leftover test db carries
-- no access anyway. Remove it by hand if present and unwanted.
DROP USER IF EXISTS ''@'localhost';
DROP USER IF EXISTS ''@'%';
FLUSH PRIVILEGES;
"""


def _legacy_helper_current(legacy: Path) -> bool:
    """True when a leftover carlos-backup.sh carries the current secrets-
    backend marker. Byte search with an unreadable-file fallback to FALSE
    (stale): a helper we cannot read (or that holds non-UTF-8 bytes) must be
    treated as stale — the callers then warn/refuse, never traceback."""
    try:
        return b"secrets-backend: sops-age" in legacy.read_bytes()
    except OSError:
        return False


def require_provisioning_prereqs(runner: Runner) -> None:
    """Preflight shared by db-users (first provisioning) and rotate db
    (rotation). A leftover pre-migration carlos-backup.sh means the Ansible
    cleanup has not run on this host — its timers would still call the old
    script with the old credential layout, so refuse until provisioning is
    current."""
    s = runner.settings
    if not s.properties_file.is_file():
        raise CtlError(f"no {s.properties_file} — run the provisioning playbook first")
    runner.require_db_running()
    legacy = s.emr_home / "container" / "carlos-backup.sh"
    if legacy.is_file() and not _legacy_helper_current(legacy):
        raise CtlError(
            f"installed {legacy} predates the single-master secrets backend — re-run the "
            f"provisioning playbook (its cleanup task removes superseded helpers) first"
        )


def provision_db_accounts(runner: Runner) -> bool:
    """Create-or-update the carlos/drugref/backup/exporter accounts with
    fresh random passwords and rewrite every credential store that holds
    them. The SQL is idempotent, so re-running it IS the rotation. Returns
    False (files untouched) on any failure — callers decide whether that is
    fatal (rotate) or a warning (play's auto-provisioning)."""
    from . import secrets as secrets_mod

    s = runner.settings
    # On a sealed install the rotation ends in cmd_seal — prove that re-seal
    # can succeed BEFORE any password changes (a no-TPM refusal after the
    # mutation strands a stale bundle that re-materializes old credentials).
    secrets_mod.preflight_reseal(runner)
    root_pw = secrets_mod.need_db_password(runner)

    # Both credential files must exist BEFORE the destructive rotation. set_kv
    # raises if drugref2.properties is missing — and it is written AFTER the
    # SQL has already rotated the DB passwords and carlos.properties, so a
    # missing drugref file would strand a half-rotated state (drugref left with
    # a rotated DB password but a stale file → auth failure). Fail up front.
    for pf in (s.properties_file, s.drugref_properties_file):
        if not pf.is_file():
            raise CtlError(
                f"{pf} does not exist — cannot rotate DB credentials atomically; re-run "
                f"the provisioning playbook to render it first"
            )

    # Generated hex by default; the CARLOS_DB_{APP,DRUGREF,BACKUP,EXPORTER}_
    # PASSWORD variables supply specific (therefore known) values instead.
    pws = {}
    for name, var in (
        ("app", "CARLOS_DB_APP_PASSWORD"),
        ("drugref", "CARLOS_DB_DRUGREF_PASSWORD"),
        ("backup", "CARLOS_DB_BACKUP_PASSWORD"),
        ("exporter", "CARLOS_DB_EXPORTER_PASSWORD"),
    ):
        pws[name] = s.get(var) or pysecrets.token_hex(16)
        secrets_mod.validate_db_password(pws[name], var)

    log("Creating least-privilege accounts (carlos, drugref, backup, exporter)")
    sql = _PROVISION_SQL.format(
        app=sql_escape(pws["app"]), drugref=sql_escape(pws["drugref"]),
        backup=sql_escape(pws["backup"]), exporter=sql_escape(pws["exporter"]),
    )
    # Abort before any store is touched on SQL failure: a failed step must not
    # fall through to the credential-file rewrites and install passwords
    # MariaDB never accepted (the app then bounces into auth failure).
    # quiet: a client-side parse error echoes the failing statement's
    # `near '...'` context, which for CREATE/ALTER USER could carry the new
    # plaintext password into journald — capture instead of streaming stderr.
    cp = runner.podman_user(
        ["exec", "-i", "-e", "MYSQL_PWD", f"{s.app_pod}-db", "mariadb", "-uroot"],
        input_text=sql, env={"MYSQL_PWD": root_pw}, quiet=True,
    )
    if cp.returncode != 0:
        # The SQL executes statement-by-statement, so the DATABASE may hold
        # partially-applied new passwords even though no credential FILE was
        # touched. The SQL is idempotent — re-running converges both sides.
        warn(
            "account provisioning SQL failed — no credential FILE was touched, but the "
            "DATABASE may hold partially-applied new passwords (db down mid-run? wrong root "
            "password?). Re-run 'carlos-ctl db-users' / 'carlos-ctl rotate db' to converge."
        )
        return False

    # Re-auth gate: prove each new credential actually authenticates BEFORE
    # any file is rewritten. A password set in the DB but failing auth (SQL
    # mode quirk, truncation, plugin mismatch) would otherwise be written
    # into the credential files and take the app down at its next reconnect.
    probe_fail = False
    for user, pw, extra in (
        ("carlos", pws["app"], ["-h127.0.0.1"]),
        ("drugref", pws["drugref"], ["-h127.0.0.1"]),
        ("backup", pws["backup"], []),
        ("exporter", pws["exporter"], ["-h127.0.0.1"]),
    ):
        cp = runner.podman_user(
            ["exec", "-i", "-e", "MYSQL_PWD", f"{s.app_pod}-db",
             "mariadb", f"-u{user}", *extra, "-e", "SELECT 1"],
            env={"MYSQL_PWD": pw}, quiet=True,
        )
        if cp.returncode != 0:
            probe_fail = True
            warn(f"re-auth as '{user}' with its NEW password FAILED")
    if probe_fail:
        warn(
            "the DATABASE passwords WERE already changed but the new credentials do not "
            "authenticate — NO credential file was rewritten, so the files still hold the "
            "PREVIOUS passwords. Recovery: re-run 'carlos-ctl db-users' / 'carlos-ctl "
            "rotate db' (idempotent, mints fresh passwords); root access via "
            "CARLOS_DB_ROOT_PASSWORD is unaffected."
        )
        return False

    # Record incomplete provisioning across the separate atomic credential
    # rewrites. A later run uses this marker to converge files that were not
    # updated before an interruption.
    incomplete = s.conf_dir / ".db-provision-incomplete"
    with contextlib.suppress(OSError):
        incomplete.parent.mkdir(parents=True, exist_ok=True)
        incomplete.write_text("credential-store rewrite in progress\n")
    # Rewrite the rendered credential files (literal-safe, not sed). Password
    # values are .properties-escaped so a backslash in an operator-supplied
    # password can't corrupt the Java Properties parse.
    set_kv(s.properties_file, "db_username", "carlos")
    set_kv(s.properties_file, "db_password", properties_escape_value(pws["app"]))
    set_kv(s.drugref_properties_file, "db_user", "drugref")
    set_kv(s.drugref_properties_file, "db_password", properties_escape_value(pws["drugref"]))
    # Atomic write-then-rename for both secret-bearing files, 0600 from birth.
    restic_dir = s.conf_dir / "restic"
    restic_dir.mkdir(parents=True, exist_ok=True)
    backup_env_new = restic_dir / "backup-db.env.new"
    # O_EXCL+O_NOFOLLOW after an unlink: the staging names live in service-
    # user-writable dirs — never follow or reuse a pre-existing (possibly
    # symlinked) file there when writing as root.
    backup_env_new.unlink(missing_ok=True)
    fd = os.open(backup_env_new, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        # %q: legacy of the shell-sourced era (kept so existing files and the
        # sealed-bundle copies stay one format); the backup verb PARSES the
        # file and %q-decodes the value.
        f.write("BACKUP_DB_USER=backup\n")
        f.write(f"BACKUP_DB_PASSWORD={secrets_mod.percent_q(pws['backup'])}\n")
    os.replace(backup_env_new, restic_dir / "backup-db.env")
    # mysqld-exporter .my.cnf (metrics account; PROCESS/REPLICATION CLIENT +
    # SELECT on performance_schema only — no PHI table access).
    exporter_new = s.exporter_mycnf_file.with_name(s.exporter_mycnf_file.name + ".new")
    exporter_new.parent.mkdir(parents=True, exist_ok=True)
    exporter_new.unlink(missing_ok=True)
    fd = os.open(exporter_new, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("[client]\nuser = exporter\n")
        f.write(f"password = {properties_escape_value(pws['exporter'])}\n")
        f.write("host = 127.0.0.1\nport = 3306\n")
    os.replace(exporter_new, s.exporter_mycnf_file)
    # Readable by the non-root mysqld-exporter uid (chown inside the userns).
    # The file was just written root-owned; re-hand it to the service user —
    # BOTH uid and gid — so the unshare chown can touch it, then map it to
    # 65534. Handing over the uid ALONE leaves the file group-root, and host
    # gid 0 is not in the service user's userns id_map, so the unshare chown
    # then fails with EPERM on every run: mysqld metrics vanished from the
    # first `play` (which auto-provisions these accounts by default) and never
    # came back, because `play` — the remedy this warning names — re-ran the
    # same failing chown. Only a full playbook re-run (whose subuid-aware
    # sweep sets uid AND gid) recovered it.
    if not chown_to_service_user(s.exporter_mycnf_file, s.service_user):
        warn(f"could not hand {s.exporter_mycnf_file} to '{s.service_user}' — the userns "
             f"chown below cannot succeed on a file owned by an unmapped uid/gid")
    if not runner.ok(runner.podman_user_argv(
        ["unshare", "chown", "65534:65534", str(s.exporter_mycnf_file)]
    )):
        warn(
            f"could not chown {s.exporter_mycnf_file} to the exporter uid inside the userns "
            f"— mysqld metrics may be missing until 'carlos-ctl play'"
        )
    # All four stores rewritten — the set is consistent again.
    with contextlib.suppress(OSError):
        incomplete.unlink()
    log("Rewrote carlos.properties, drugref2.properties, backup-db.env, and exporter.my.cnf")

    # If this install is sealed (uses the SOPS+age bundle), fold the freshly
    # rotated credentials into it and re-render /run — seal is idempotent and
    # re-ingests the new plaintext, restoring the __SEALED__ placeholders.
    if secrets_mod.bundle_available(runner):
        log("Folding the rotated credentials into the secrets bundle")
        secrets_mod.cmd_seal(runner)
    return True


_SCHEMA_FP_SQL = (
    "SELECT table_name, column_name, ordinal_position, column_type "
    "FROM information_schema.columns WHERE table_schema='oscar' "
    "ORDER BY table_name, column_name, ordinal_position"
)


def schema_fingerprint(runner: Runner) -> str:
    """sha256 (hex) over the oscar schema's deterministic column inventory —
    the compatibility signature the rollback guard compares. CARLOS schema
    migrations are hand-applied SQL, so rolling the CODE back never reverses
    them; this fingerprint is how rollback notices the mismatch.

    Runs as the app account from carlos.properties (GRANT ALL ON oscar.*
    sees every oscar column) with a root fallback when the env still carries
    CARLOS_DB_ROOT_PASSWORD. Hashed in-process from captured stdout (a few
    MB at most — no GROUP_CONCAT length trap). Returns "" when it cannot
    fingerprint (db down, no credentials, empty schema): callers must treat
    that as UNKNOWN, never as a match."""
    import hashlib

    s = runner.settings
    attempts: List[Tuple[str, str]] = []
    if s.properties_file.is_file():
        lines = s.properties_file.read_text().splitlines()
        user = first_match(lines, "db_username")
        pw = first_match(lines, "db_password")
        if pw:
            # .properties stores backslashes doubled (provision_db_accounts
            # writes properties_escape_value); the raw value would fail auth
            # for any password containing one — same decode as
            # backup._resolve_db_creds.
            pw = properties_unescape_value(pw)
        if user and user != "root":
            attempts.append((user, pw or ""))
    if s.get("CARLOS_DB_ROOT_PASSWORD"):
        attempts.append(("root", s.get("CARLOS_DB_ROOT_PASSWORD")))
    for user, pw in attempts:
        # SQL on argv (-e) like the other non-secret probes (@@log_bin, the
        # engine audit) — only the password is off-argv.
        cp = runner.podman_user(
            ["exec", "-i", "-e", "MYSQL_PWD", f"{s.app_pod}-db",
             "mariadb", f"-u{user}", "-N", "-B", "-e", _SCHEMA_FP_SQL],
            env={"MYSQL_PWD": pw}, quiet=True, capture=True,
        )
        out = (cp.stdout or "").strip()
        if cp.returncode == 0 and out:
            return hashlib.sha256(out.encode()).hexdigest()
    return ""


def record_schema_fingerprint(runner: Runner) -> None:
    """Record the schema the CURRENT :latest images last ran healthily
    against ($EMR_HOME/build/.schema-fingerprint, non-secret 0644). Called
    after play's readiness gate and after db-users. Best-effort: an unknown
    fingerprint leaves the previous marker in place (stale-but-honest beats
    overwritten-with-nothing) and warns once."""
    s = runner.settings
    fp = schema_fingerprint(runner)
    if not fp:
        warn(
            "could not fingerprint the oscar schema (db unreachable or no "
            "credentials) — rollback's schema-compatibility guard keeps the "
            "previous baseline"
        )
        return
    marker = s.emr_home / "build" / ".schema-fingerprint"
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(fp + "\n")
    except OSError:
        warn(f"could not write {marker} — rollback's schema guard will lack a baseline")


def restart_app_and_waf(runner: Runner) -> None:
    """Bounce the app pod so it reconnects with the credentials just written,
    then the WAF: the app pod gets a new IP, and nginx resolves the static
    proxy_pass BACKEND hostname once at startup and caches it — without the
    second restart every proxied request 502s. Best-effort: warns, never dies
    (callers run with the pod already up)."""
    s = runner.settings
    log(f"Restarting {s.app_pod} so it reconnects on the current DB credentials")
    if (s.quadlet_dir() / f"{s.instance}.kube").is_file() and runner.systemd_running():
        if not runner.ok(runner.systemctl_user_argv(["restart", f"{s.instance}.service"])):
            warn("app restart failed — run 'carlos-ctl play' to apply the new credentials")
        if not runner.ok(runner.systemctl_user_argv(["restart", f"{s.waf_pod}.service"])):
            warn("waf restart failed — run 'carlos-ctl play' to re-point the WAF at the app pod")
    else:
        if runner.podman_user([
            "kube", "play", "--replace", "--network", s.net_name,
            "--network", s.edge_net_name, "--log-driver", "journald", str(s.rendered_yaml),
        ]).returncode != 0:
            warn("app restart failed — run 'carlos-ctl play' to apply the new credentials")
        if runner.podman_user([
            "kube", "play", "--replace", "--network", s.edge_net_name,
            "--log-driver", "journald", str(s.rendered_waf_yaml),
        ]).returncode != 0:
            warn("waf restart failed — run 'carlos-ctl play' to re-point the WAF at the app pod")


def wait_db_accepting(
    runner: Runner, password: str, timeout: float
) -> Tuple[bool, str]:
    """Poll the db container until MariaDB actually ANSWERS as root, or the
    timeout expires. Returns (ready, last_stderr).

    `Runner.require_db_running` only proves the container NAME is in
    `podman ps` — a container that is Up-but-still-starting passes it while
    mysqld is not yet accepting connections. Anything that runs SQL right
    after a pod restart (the rotations; play's auto-provisioning) therefore
    needs this second gate, or it reports a connection-timing failure as
    something else entirely. ONE implementation so the two call sites cannot
    drift: the probe statement carries no credential, so its stderr is safe
    to hand back for diagnosis ("Access denied" vs "Can't connect")."""
    s = runner.settings
    deadline = time.time() + timeout
    last_err = ""
    while True:
        cp = runner.podman_user(
            ["exec", "-i", "-e", "MYSQL_PWD", f"{s.app_pod}-db",
             "mariadb", "-uroot", "-e", "SELECT 1"],
            env={"MYSQL_PWD": password}, capture=True, quiet=True,
        )
        if cp.returncode == 0:
            return True, ""
        # BOTH streams: the client writes its diagnostics to stderr, but a
        # wrapper (podman exec's own message, a shim) can surface them on
        # stdout — keying only on stderr would turn a terminal auth failure
        # into a full-timeout wait.
        last_err = ((cp.stderr or "") + (cp.stdout or "")).strip()
        # A wrong password is terminal — retrying it until the deadline just
        # delays the (correct) diagnosis and hammers the server's failed-login
        # counters. Only a not-yet-accepting server is worth waiting out.
        if "access denied" in last_err.lower():
            return False, last_err
        if time.time() >= deadline:
            return False, last_err
        time.sleep(2)


def maybe_provision_db_users(runner: Runner) -> bool:
    """Called at the end of `play` to make least-privilege DB accounts the
    DEFAULT rather than a manual post-install step.

    Returns True when the app's steady-state DB connection is ACCEPTABLE —
    already on a least-privilege account, just provisioned onto one, or the
    operator consciously accepted root (CARLOS_SKIP_AUTO_DB_USERS=1 to defer to
    a manual `db-users`, or CARLOS_ALLOW_DB_ROOT=1 to keep root). Returns False
    when the app is left connected as ROOT by a FAILURE or environmental
    problem the operator did NOT opt into (db not ready, provisioning error,
    stale pre-migration helper). `play` treats False as a deploy failure: an
    internet-facing EMR silently steady-stating on the MariaDB root account —
    where an app-tier compromise owns the entire PHI database — must never read
    as a green deploy. The pod is already up, so this cannot un-start it; it
    makes the un-downgraded root state a LOUD nonzero exit instead of a warning
    buried in play output (the monitor's app-db-root check pages on it too)."""
    s = runner.settings
    if not s.properties_file.is_file():
        return True
    # A surviving marker means a prior provisioning was killed BETWEEN the
    # four credential-store rewrites — the DB may be on new passwords with
    # some files stale. Re-run the idempotent provisioning to converge before
    # trusting the application state.
    if (s.conf_dir / ".db-provision-incomplete").is_file():
        warn(
            "a prior credential provisioning was interrupted mid-rewrite "
            "(.db-provision-incomplete present) — re-running to converge the credential "
            "stores with the database"
        )
        if not provision_db_accounts(runner):
            return False
        # Convergence mints FRESH passwords and ALTERs the database, but the
        # already-running app assembled its config from the pre-convergence
        # files — without a bounce it keeps authenticating with a password the
        # DB no longer accepts and degrades as its connection pool recycles.
        restart_app_and_waf(runner)
        return True
    username = first_match(s.properties_file.read_text().splitlines(), "db_username")
    if username != "root":
        return True  # already on a least-privilege account
    if s.get("CARLOS_SKIP_AUTO_DB_USERS", "0") == "1":
        warn(
            "app is configured as DB ROOT and CARLOS_SKIP_AUTO_DB_USERS=1 — run "
            "'carlos-ctl db-users' to switch to least-privilege accounts"
        )
        return True  # conscious opt-out: deferred to a manual db-users
    if not s.get("CARLOS_DB_ROOT_PASSWORD"):
        # Reachable only via CARLOS_ALLOW_DB_ROOT=1 (preflight_db_root_guard
        # refuses to start a root app with no root password otherwise), so the
        # operator has consciously accepted root — acceptable, not a failure.
        warn(
            f"app is running as DB ROOT and CARLOS_DB_ROOT_PASSWORD is unset "
            f"(CARLOS_ALLOW_DB_ROOT accepted) — set the password in {s.env_file} and run "
            f"'carlos-ctl db-users' to switch to least-privilege accounts"
        )
        return True
    # Same stale-helper guard as require_provisioning_prereqs: a leftover
    # pre-migration carlos-backup.sh means the Ansible cleanup has not run, so
    # its root timers would keep calling the OLD script against the credential
    # layout a silent auto-rotation here would have just rewritten. This is an
    # environmental fault the operator did NOT opt into, so it fails the deploy
    # (return False) rather than silently leaving the app on root.
    legacy = s.emr_home / "container" / "carlos-backup.sh"
    if legacy.is_file() and not _legacy_helper_current(legacy):
        warn(
            f"installed {legacy} predates the single-master secrets backend — cannot "
            f"auto-provision (the app stays on DB root); re-run the provisioning "
            f"playbook (its cleanup task removes superseded helpers), then "
            f"'carlos-ctl db-users'"
        )
        return False
    log("Least-privilege DB accounts are the default; provisioning "
        "(set CARLOS_SKIP_AUTO_DB_USERS=1 to skip)")
    # Wait (bounded) for the db to accept root connections. A fresh datadir
    # plus MARIADB_AUTO_UPGRADE can be slow; if it isn't ready in time we
    # warn and leave the app on root rather than blocking the deploy. Budget
    # aligned with play's readiness gate for the DB container (see
    # lifecycle2.ready_budgets: 1320 s, sized to the 80x15 s first-boot
    # startupProbe) — an explicit READY_WAIT_SECONDS still overrides both.
    # A smaller default here than the db budget would abort provisioning at
    # 900 s while wait_app_ready then legitimately passes at 1320 s: a false
    # deploy failure that also leaves the app on the DB root account.
    ready, _probe_err = wait_db_accepting(
        runner, s.get("CARLOS_DB_ROOT_PASSWORD"),
        s.get_int_or("READY_WAIT_SECONDS", 1320),
    )
    if not ready:
        warn("db not ready in time — app remains on DB root; run 'carlos-ctl db-users' "
             "once the pod is up")
        return False
    # A provisioning or restart error leaves the app on root: return False so
    # `play` fails loudly (the pod is already up, so we cannot un-start it).
    try:
        if not provision_db_accounts(runner):
            warn("least-privilege provisioning failed — app remains on DB root; run "
                 "'carlos-ctl db-users' to retry")
            return False
    except CtlError as e:
        warn(f"least-privilege provisioning failed ({e}) — app remains on DB root; run "
             f"'carlos-ctl db-users' to retry")
        return False
    restart_app_and_waf(runner)
    return True


def cmd_db_users(runner: Runner) -> int:
    s = runner.settings
    require_provisioning_prereqs(runner)
    current = first_match(s.properties_file.read_text().splitlines(), "db_username")
    if current != "root":
        raise CtlError(
            f"carlos.properties already uses db_username={current} — use "
            f"'carlos-ctl rotate db' to rotate the passwords"
        )
    if not provision_db_accounts(runner):
        return 1
    # The db is provably up here — refresh rollback's schema baseline too.
    record_schema_fingerprint(runner)
    return 0


def cmd_db(runner: Runner, args: List[str]) -> int:
    """mariadb shell in the db container (root): interactive with no args, or
    pass client args/redirects through. Auth: CARLOS_DB_ROOT_PASSWORD is
    forwarded off-argv; without it the client prompts, which needs a
    terminal, so piped runs die with guidance instead of hanging on a prompt
    nobody sees."""
    s = runner.settings
    runner.require_db_running()
    # -t only when BOTH stdin and stdout are terminals: `db < dump.sql` must
    # not allocate a tty (podman -t breaks piped stdin), and a tty on piped
    # stdout would CRLF-mangle query output.
    interactive = sys.stdin.isatty() and sys.stdout.isatty()
    flags = ["-it"] if interactive else ["-i"]
    root_pw = s.get("CARLOS_DB_ROOT_PASSWORD")
    if root_pw:
        cp = runner.podman_user(
            ["exec", *flags, "-e", "MYSQL_PWD", f"{s.app_pod}-db", "mariadb", "-uroot", *args],
            env={"MYSQL_PWD": root_pw}, stdin=None if interactive else sys.stdin,
        )
        return cp.returncode
    if interactive:
        # Fully interactive only: the -p prompt needs a tty.
        cp = runner.podman_user(
            ["exec", "-it", f"{s.app_pod}-db", "mariadb", "-uroot", "-p", *args]
        )
        return cp.returncode
    raise CtlError(
        f"no CARLOS_DB_ROOT_PASSWORD in {s.env_file} and this is not a fully interactive "
        f"run (piped/redirected) — the password prompt needs a terminal; set "
        f"CARLOS_DB_ROOT_PASSWORD (mode-600 env file) or run without redirections"
    )


# db-migrate pins the client session because CARLOS' schema is
# utf8mb4_general_ci while MariaDB 11.4+ images ship
# character_set_collations = utf8mb4=uca1400_ai_ci: under that session
# default a bare CAST(... AS CHAR) takes the uca1400 collation, and
# collation-sensitive migrations (V1.0.7's dxphcpgroup backfill join) abort
# with ERROR 1267 (illegal mix of collations). The pin must be established
# in the SAME client session that executes the migration — a separate
# `carlos-ctl db -e 'SET NAMES ...'` runs in its own client process, so its
# session settings never reach the next one. --init-command also re-fires
# on client reconnects, unlike a first-line SET NAMES prepended to stdin.
MIGRATION_SESSION_PIN = "SET NAMES utf8mb4 COLLATE utf8mb4_general_ci"


def cmd_db_migrate(runner: Runner, args: List[str]) -> int:
    """Apply schema migration files in argv order through a root mariadb
    session pinned to the schema's utf8mb4_general_ci collation family
    (see MIGRATION_SESSION_PIN). Fail-fast on the first failing file — NO
    --force: continuing past an arbitrary SQL error would leave the schema
    in an unknown partial state. Earlier files are fully applied and later
    ones untouched, so recovery is: fix the cause, then rerun starting at
    the failed file (CARLOS migrations are written re-runnable — CREATE/ADD
    ... IF NOT EXISTS DDL and existence-guarded backfills)."""
    usage = "usage: carlos-ctl db-migrate [--db <database>] <file.sql> [more.sql ...]"
    s = runner.settings
    db = "oscar"
    files = list(args)
    if files[:1] == ["--db"]:
        if len(files) < 2:
            raise CtlError(usage)
        db = files[1]
        files = files[2:]
    # Refuse flag-shaped leftovers instead of piping them to the client as
    # filenames (same no-silently-dropped-arguments contract as db-backup).
    if not files or any(f.startswith("-") for f in files):
        raise CtlError(usage)
    paths = [Path(f) for f in files]
    # Validate the WHOLE list before touching the database: a typo'd later
    # filename must fail the run up front, not strand the sequence half-way.
    missing = [str(p) for p in paths if not p.is_file()]
    if missing:
        raise CtlError(
            f"migration file(s) not found: {', '.join(missing)} — nothing was applied"
        )
    runner.require_db_running()
    root_pw = s.get("CARLOS_DB_ROOT_PASSWORD")
    if not root_pw:
        raise CtlError(
            f"no CARLOS_DB_ROOT_PASSWORD in {s.env_file} — db-migrate streams SQL on "
            f"stdin, so the client's interactive -p prompt cannot be used; set the "
            f"password in the mode-600 env file"
        )
    for i, path in enumerate(paths):
        log(f"Applying {path.name} to database '{db}' (collation-pinned session)")
        with path.open("rb") as fh:
            cp = runner.podman_user(
                ["exec", "-i", "-e", "MYSQL_PWD", f"{s.app_pod}-db", "mariadb",
                 "-uroot", f"--init-command={MIGRATION_SESSION_PIN}", db],
                env={"MYSQL_PWD": root_pw}, stdin=fh,
            )
        if cp.returncode != 0:
            remaining = ", ".join(p.name for p in paths[i + 1:]) or "(none)"
            raise CtlError(
                f"{path.name} failed (mariadb exit {cp.returncode}) — stopping "
                f"fail-fast. Earlier files are fully applied; {path.name} may be "
                f"partially applied (CARLOS migrations are re-runnable — rerun it "
                f"once the cause is fixed), then continue with: {remaining}"
            )
    log(f"Applied {len(paths)} migration file(s) to database '{db}'")
    return 0


def cmd_db_dump(runner: Runner, args: List[str]) -> int:
    """Consistent one-off export to stdout (the same flag set the nightly
    backup uses: single InnoDB snapshot, safe on a running database)."""
    s = runner.settings
    runner.require_db_running()
    if sys.stdout.isatty():
        raise CtlError(
            "refusing to write a dump to the terminal — redirect it: "
            "carlos-ctl db-dump > oscar-$(date +%F).sql"
        )
    # A password prompt cannot work on a piped stream, and podman -t would
    # CRLF-mangle the dump, so this path needs the non-interactive credential.
    root_pw = s.get("CARLOS_DB_ROOT_PASSWORD")
    if not root_pw:
        raise CtlError(
            f"db-dump needs CARLOS_DB_ROOT_PASSWORD in {s.env_file} (a redirected dump "
            f"cannot prompt for the password)"
        )
    warn("the dump is PLAINTEXT PHI — write it to an encrypted volume and delete it after use")
    dbs = args or ["oscar"]
    # --hex-blob matches the nightly tier: BLOB/BINARY columns (encrypted
    # casemgmt notes, eform attachments) are emitted as hex literals, immune
    # to charset/binary mangling between dump and reload.
    cp = runner.podman_user(
        ["exec", "-i", "-e", "MYSQL_PWD", f"{s.app_pod}-db",
         "mariadb-dump", "--single-transaction", "--quick", "--routines", "--events",
         "--hex-blob", "-uroot", "--databases", *dbs],
        env={"MYSQL_PWD": root_pw},
    )
    return cp.returncode


def cmd_db_backup(runner: Runner, args: List[str]) -> int:
    """Native PHYSICAL (hot) backup via mariadb-backup — the manual
    alternative to the restic tier, --prepare'd immediately so the snapshot
    is restore-ready. Deliberately NOT scheduled/encrypted/offsite/monitored:
    restic remains the primary tier (this does not touch the monitor's
    .last-full-ok marker), and retention here is manual."""
    from . import secrets as secrets_mod

    s = runner.settings
    runner.require_db_running()
    # Validate arguments before reading credentials or creating a snapshot.
    # The optional name becomes a directory below the backup root, so reject
    # extra arguments and flag-like names.
    if len(args) > 1:
        raise CtlError(
            f"usage: carlos-ctl db-backup [name]  — one optional name, got {len(args)} "
            f"arguments ({' '.join(args)}); this verb has no flags"
        )
    if args and args[0].startswith("-"):
        raise CtlError(
            f"usage: carlos-ctl db-backup [name]  — '{args[0]}' looks like a flag, and "
            f"this verb has none; a name may not start with '-' (it becomes a directory "
            f"under {s.emr_home}/backup/mariadb-hot)"
        )
    root_pw = secrets_mod.need_db_password(runner)
    name = args[0] if args else time.strftime("%Y-%m-%d-%H%M%S")
    # The name becomes a path segment on the host and in the container.
    if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        raise CtlError(f"backup name must match [A-Za-z0-9._-]+ (got: {name})")
    host_dir = s.emr_home / "backup" / "mariadb-hot" / name
    if host_dir.exists():
        raise CtlError(f"{host_dir} already exists — pick another name (no silent overwrite)")
    log(f"Physical backup (mariadb-backup) of the running db -> {host_dir}")
    warn(
        f"the snapshot is PLAINTEXT PHI (a file copy of the datadir) — it stays in the 0700 "
        f"{s.emr_home}/backup/mariadb-hot, delete it when done"
    )
    # MYSQL_PWD honored by mariadb-backup since MDEV-25321 (fixed 10.5.10).
    cp = runner.podman_user(
        ["exec", "-e", "MYSQL_PWD", f"{s.app_pod}-db", "mariadb-backup", "--backup",
         "-uroot", f"--target-dir=/backup/mariadb-hot/{name}"],
        env={"MYSQL_PWD": root_pw},
    )
    if cp.returncode != 0:
        import shutil

        shutil.rmtree(host_dir, ignore_errors=True)
        raise CtlError(
            "mariadb-backup --backup failed (partial target removed) — db down or "
            "credentials wrong?"
        )
    # Prepare now, not at restore time: applies the redo log so the directory
    # is immediately restore-ready (and a failed prepare surfaces today, not
    # during an emergency restore).
    cp = runner.podman_user(
        ["exec", f"{s.app_pod}-db", "mariadb-backup", "--prepare",
         f"--target-dir=/backup/mariadb-hot/{name}"],
    )
    if cp.returncode != 0:
        raise CtlError(
            f"mariadb-backup --prepare failed — the snapshot in {host_dir} is NOT restore-ready"
        )
    # mariadb_backup_binlog_info, NOT xtrabackup_binlog_info: MariaDB renamed
    # the metadata files with mariadb-backup, and the pinned DB_IMAGE
    # (mariadb:11.4) writes only the mariadb_backup_* names. The old string
    # pointed a recovering operator at a file that does not exist. (The
    # unrelated xtrabackup_binlog_pos_innodb IS still written — it carries
    # InnoDB LSN positions, not the binlog coordinates a PITR needs.)
    log(f"Snapshot ready: {host_dir} (binlog coordinates in mariadb_backup_binlog_info)")
    log(
        "Restore recipe: README, 'Native MariaDB physical backups'. NOTE: this manual "
        "snapshot does not update backup-freshness monitoring — the restic tier remains "
        "the primary backup."
    )
    return 0


def cmd_pma(runner: Runner, args: List[str]) -> int:
    """On-demand phpMyAdmin for break-glass DB admin — NOT a standing
    container. Publishes on the host loopback only; reach it through an SSH
    tunnel. MariaDB binds in-pod loopback (the WAF/DB isolation boundary), so
    there is NO network path to 3306 from anywhere — phpMyAdmin connects over
    the db's UNIX SOCKET.

    --ttl <minutes> (default 120) bounds the session: a dropped SSH tunnel or
    a killed attached client otherwise left a PHP/Apache panel onto the FULL
    PHI database serving indefinitely (the monitor's liveness sweep only
    alerts on EXPECTED containers being absent — never an unexpected pma
    container being PRESENT, which is now also alerted). --ttl 0 disables the
    bound (foreground until Ctrl-C, the historical behavior)."""
    s = runner.settings
    ttl_min = 120
    i = 0
    while i < len(args):
        if args[i] == "--ttl" and i + 1 < len(args) and args[i + 1].isdigit():
            ttl_min = int(args[i + 1])
            i += 2
        else:
            raise CtlError("usage: carlos-ctl pma [--ttl <minutes>]  (0 = no bound)")
    runner.require_db_running()
    sock = s.db_socket_dir / "mysqld.sock"
    # Warn (not die): the socket appears once the db container runs with the
    # socket mount — a pre-upgrade pod that hasn't been re-played won't have it.
    if not sock.is_socket():
        warn(
            f"no MariaDB socket at {sock} — run 'carlos-ctl play' so the db container "
            f"mounts the socket dir (added with the WAF/DB isolation split)"
        )
    pma_port = s.get("PMA_PORT")
    log(f"Launching on-demand phpMyAdmin on 127.0.0.1:{pma_port} — Ctrl-C to stop")
    log(f"  tunnel:  ssh -L {pma_port}:127.0.0.1:{pma_port} <this-host>   "
        f"then open  http://localhost:{pma_port}/")
    log("  auth:    a MariaDB account (e.g. root) — nothing is stored")
    # Socket connections authenticate as <user>@localhost. The container
    # needs no podman network at all; the socket dir is mounted rw on purpose
    # — connect(2) on a unix socket fails through a read-only mount.
    # Match the pod hardening posture with a minimal capability set, disabled
    # privilege escalation, and a memory limit. Podman applies its default
    # seccomp profile. The image needs a writable root filesystem for session
    # and php-fpm state; loopback publishing and the SSH tunnel provide network
    # isolation.
    if ttl_min > 0:
        log(f"  ttl:     auto-stops after {ttl_min} min (override with --ttl; 0 disables)")
    # --stop-timeout is a stop grace, not a lifetime — bound the lifetime with
    # `timeout` wrapping the run so a dropped tunnel / killed client cannot
    # leave the panel serving the PHI database forever (`--rm` removes it on
    # exit). Journald-tag the session start/stop for the break-glass trail.
    if runner.have("logger"):
        runner.run(["logger", "-t", "carlos-pma", "-p", "daemon.notice", "--",
                    f"break-glass phpMyAdmin STARTED on 127.0.0.1:{pma_port} "
                    f"(ttl {ttl_min}m)"], quiet=True)
    run_argv = [
        # Allocate an interactive terminal only when both standard input and
        # output are terminals. Otherwise Podman would tie the container to an
        # input stream that may already be closed.
        "run", "--rm",
        *(["-it"] if (sys.stdin.isatty() and sys.stdout.isatty()) else []),
        "--name", f"{s.instance}-pma-ondemand",
        # Apache needs these capabilities to prepare its configuration, bind
        # port 80, and change to the www-data account.
        "--cap-drop", "ALL",
        "--cap-add", "CHOWN,DAC_OVERRIDE,SETGID,SETUID,NET_BIND_SERVICE",
        "--security-opt", "no-new-privileges",
        "--memory", "512m",
        "-p", f"127.0.0.1:{pma_port}:80",
        "-v", f"{s.db_socket_dir}:/run/db-socket",
        "-e", "PMA_SOCKET=/run/db-socket/mysqld.sock",
        s.get("PHPMYADMIN_IMAGE"),
    ]
    cp: subprocess.CompletedProcess
    ttl_bounded = ttl_min > 0 and runner.have("timeout")
    if ttl_bounded:
        # SIGTERM at the deadline, SIGKILL 10s later if it ignores it; podman
        # forwards the signal to the container, which --rm then removes. The
        # `timeout` wraps the fully-resolved runuser+podman argv.
        cp = runner.run(
            ["timeout", "-k", "10", f"{ttl_min}m",
             *runner.podman_user_argv(run_argv)]
        )
    else:
        cp = runner.podman_user(run_argv)
    if runner.have("logger"):
        runner.run(["logger", "-t", "carlos-pma", "-p", "daemon.notice", "--",
                    "break-glass phpMyAdmin STOPPED"], quiet=True)
    # Reaching the --ttl deadline is the DESIGNED end of a pma session, not a
    # failure: `timeout` reports 124 (and 137 when the -k SIGKILL was needed),
    # which would otherwise make the documented happy path exit nonzero and
    # trip `set -e` / `carlos-ctl pma && ...` operator scripting. Ctrl-C (130)
    # is likewise a normal operator stop. Report those as success and say why;
    # every other rc still propagates.
    if ttl_bounded and cp.returncode in (124, 137):
        log(f"phpMyAdmin stopped at its {ttl_min}-minute ttl (override with --ttl; 0 disables)")
        return 0
    if cp.returncode == 130:
        log("phpMyAdmin stopped (interrupted)")
        return 0
    return cp.returncode
