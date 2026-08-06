# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Backups (`carlos-ctl backup <full|binlogs|docs|verify|restore>`): restic +
mariadb-dump orchestration with point-in-time recovery.

secrets-backend: sops-age

Strategy (unchanged from the bash):
  - full     nightly consistent logical dump (--single-transaction
             --master-data=2 --flush-logs) staged + footer-verified, then
             streamed into restic; documents + config; retention/prune/check
             delegated to restic
  - binlogs  FLUSH BINARY LOGS + ship every CLOSED binlog every 15 min —
             worst-case data loss (RPO) is one binlog interval, not one day
  - docs     15-minute document-store snapshots (db-free on purpose)
  - verify   weekly drill: listability gates, throwaway tmpfs MariaDB, dump
             load, binlog replay from the recorded anchor, core-table sanity
  - restore  guided point-in-time restore INTO THE LIVE DATABASE

Everything restic does well is DELEGATED to restic (retention, prune,
`check --read-data`, dedup, repo locks); this module owns only the gaps
restic cannot cover: dump completeness, the PITR anchor contract, the
lost-mount repo-init guard, and empty-source detection. Runs as ROOT from
host timers; every service-user-owned file is PARSED, never executed."""

from __future__ import annotations

import contextlib
import fcntl
import os
import re
import secrets as pysecrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import IO, List, Optional, Tuple

from . import pitr
from .config import Settings, parse_env_file
from .runner import Runner
from .util import (
    CtlError,
    first_match,
    log,
    properties_unescape_value,
    restic_local_path,
    size_to_mib,
    warn,
)


def stop_datetime_epoch(stop: str, container_tz: str) -> float:
    """Epoch of a `--stop-datetime` instant, interpreted in the DB CONTAINER's
    timezone — the zone mariadb-binlog evaluates it in at replay (the container
    runs with TZ=<carlos_tz>, default America/Toronto). The old
    time.mktime(strptime(...)) used the HOST's local zone, so on a UTC host
    with a Toronto container the past-chain-end guard compared an instant
    hours off: it silently passed targets it should refuse (silent
    under-restore) or refused targets it should pass. Returns 0.0 when the
    string or the zone is unusable — callers treat 0.0 as 'skip the guard'
    (and warn, so the degradation is visible)."""
    try:
        from datetime import datetime
        from zoneinfo import ZoneInfo

        return (
            datetime.strptime(stop, "%Y-%m-%d %H:%M:%S")
            .replace(tzinfo=ZoneInfo(container_tz))
            .timestamp()
        )
    except Exception:  # noqa: BLE001 — bad string OR unknown zone: guard degrades loudly
        return 0.0

# Tunables root parses from the (service-user-writable) restic env. These are
# non-secret EXCEPT RESTIC_PASSWORD, which is whitelisted solely so the
# non-empty guard in BackupContext can .strip()-check it — it is never logged,
# never forwarded on argv, and never reaches the tunable() Settings fallback;
# it (and any offsite-backend credentials) still reach the restic container
# only via --env-file.
_ROOT_TUNABLES = [
    "RESTIC_REPOSITORY", "RESTIC_PASSWORD", "RESTIC_IMAGE", "BACKUP_KEEP",
    "BACKUP_KEEP_BINLOG", "BACKUP_KEEP_DOCS", "CHECK_READ_DATA_DOW",
    "VERIFY_TMPFS_SIZE", "VERIFY_MEM_LIMIT",
]

# Tables that CANNOT be made InnoDB, so the engine audit must not refuse the
# dump over them — the operator has no remedy to apply.
#
# formRourke2009 (the Rourke Baby Record in the upstream ON/BC schema) has
# 1,227 columns, exceeding InnoDB's limit of 1,017 columns. Converting it fails
# with MariaDB error 185 under every supported row format, including with a
# 32 KiB InnoDB page size. Aria is therefore required for this table. CARLOS
# also does not offer the 2009 form in the encounter's form picker
# (`encounterForm` lists Rourke/2006/2017/2020), so it holds legacy rows
# only — though the save path is still allowlisted in the app's
# FrmRecordFactory, so it is retired by configuration, not enforced.
#
# Matched on BARE TABLE NAME, case-insensitively: the schema is `oscar` on a
# stock install but need not be, and MariaDB table names are case-sensitive
# on Linux while the DDL casing has drifted across upstream migrations.
# Keep this list SHORT and evidence-backed — every entry is a permanently
# accepted PITR gap. A non-InnoDB table that is narrow enough to convert must
# NOT be added here; convert it instead.
_PITR_UNCONVERTIBLE_TABLES = frozenset({"formrourke2009"})


def _is_pitr_unconvertible(audit_line: str) -> bool:
    """True for an engine-audit line naming a known-unconvertible table.
    The line format is `schema.table [engine]` (see the audit query)."""
    ident = audit_line.split(" [", 1)[0].strip()
    table = ident.rsplit(".", 1)[-1]
    return table.lower() in _PITR_UNCONVERTIBLE_TABLES


_KEEP_DEFAULT = "--keep-daily 7 --keep-weekly 5 --keep-monthly 12"
# PITR needs the binlog chain covering the reach of the retained DUMPS: daily
# dumps kept 7 days need ~7 days of binlogs + a day of margin -> 9d (below the
# 10d local binlog_expire_logs_seconds in zz-carlos.cnf, so nothing needed is
# pruned locally before it ships). NOTE: PITR reach is this window (~9d), NOT
# the 12-month dump horizon — older dumps restore to their exact instant only.
_KEEP_BINLOG_DEFAULT = "--keep-within 9d"
# The 15-minute docs snapshots only close the intra-day document RPO gap; the
# long horizon for documents is the nightly `files` tier.
_KEEP_DOCS_DEFAULT = "--keep-within 3d"




class BackupContext:
    """Resolved credentials, repo plumbing, and shared helpers for one run."""

    def __init__(self, runner: Runner) -> None:
        self.runner = runner
        self.s = runner.settings
        self.backup_dir = self.s.emr_home / "backup"
        self.binlog_dir = self.s.data_dir / "mariadb-binlog"
        self.cache_dir = self.backup_dir / "restic-cache"
        # The lost-mount sentinel must NOT share a volume with the repo it
        # guards: operators are told to put $EMR_HOME/backup on its own
        # (LUKS) volume, and a sentinel inside it vanishes together with the
        # repo when that volume fails to mount — ensure_repo would then
        # silently `restic init` a fresh empty repo over the bare mountpoint,
        # the exact outcome the sentinel exists to refuse. It lives with the
        # (root-volume) restic conf instead; the legacy in-backup location is
        # still read for pre-migration installs.
        self.repo_sentinel = self.s.conf_dir / "restic" / ".restic-repo-initialized"
        self.legacy_repo_sentinel = self.backup_dir / ".restic-repo-initialized"
        self.snapshot_host = f"{self.s.instance}-emr"
        self._tmp_env: Optional[str] = None
        self._lock_fd: Optional[int] = None
        self.extra_mount: List[str] = []
        self.binlog_shipped = False
        try:
            self._init_env_and_repo(runner)
        except BaseException:
            # Constructor refusals (no RESTIC_REPOSITORY, empty password,
            # out-of-tree repo path, failed db-cred resolution) fire before
            # cmd_backup's try/finally arms ctx.close() — without this, every
            # failed timer run would abandon another decrypted restic
            # credentials tempfile in /run until reboot.
            self.close()
            raise

    def _init_env_and_repo(self, runner: Runner) -> None:
        # Restic repo + password: the plaintext env file (unsealed), else the
        # whole restic env decrypted out of the single-master bundle (sealed).
        env_file = self.s.conf_dir / "restic" / "restic.env"
        env_text = ""
        if not env_file.is_file() and self.s.secrets_bundle.is_file():
            from . import secrets as secrets_mod

            env_text = secrets_mod.bundle_get(runner, "restic", "env")
            if not env_text:
                # Distinguish a decrypt FAILURE (corrupt bundle / lost or
                # wrong age key — a DR emergency) from a merely-absent restic
                # section, instead of blaming "no age key" for both.
                if secrets_mod.bundle_decrypts(runner):
                    raise CtlError(
                        f"backup: the secrets bundle {self.s.secrets_bundle} decrypts but "
                        f"carries no restic 'env' section — run 'carlos-ctl seal' after "
                        f"provisioning the restic credentials"
                    )
                raise CtlError(
                    f"backup: could NOT decrypt {self.s.secrets_bundle} — the age key is "
                    f"missing, wrong, or the bundle is corrupt (a DR-critical failure); "
                    f"restore the escrowed age key and re-run"
                )
            fd, self._tmp_env = tempfile.mkstemp(dir=self._tmp_dir(), prefix="restic-env.")
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(env_text if env_text.endswith("\n") else env_text + "\n")
            # podman reads this as --env-file AS the service user; ownership is
            # handed over only AFTER the content is fully written (root parses
            # the in-memory copy, never this file).
            with contextlib.suppress(OSError, KeyError):
                import pwd

                os.chown(self._tmp_env, pwd.getpwnam(self.s.service_user).pw_uid, -1)
            env_file = Path(self._tmp_env)
        if not env_file.is_file():
            raise CtlError("backup: no restic credentials — run the provisioning playbook "
                           "/ 'carlos-ctl seal' first")
        self.env_file = env_file
        tunables = parse_env_file(env_text or env_file.read_text(), whitelist=_ROOT_TUNABLES)
        # Tunable precedence (matches the bash, which sourced carlos-app.env
        # BEFORE reading restic.env): restic.env > carlos-app.env / process
        # env (Settings) > built-in default. Reading restic.env only would
        # silently revert site-set retention to the 7-day default — restic
        # forget would then PERMANENTLY expire dumps the operator believed
        # retained.
        def tunable(key: str, default: str = "") -> str:
            return tunables.get(key) or self.s.get(key) or default

        # RESTIC_REPOSITORY is deliberately NOT a tunable(): Settings injects
        # a local default for it, so the fallback would make this guard dead
        # and silently retarget a sealed install whose bundle lost the line to
        # a fresh LOCAL repo — nightly stamps green while the real offsite
        # repository rots. The repository must come from the restic credential
        # material itself, or the run must refuse.
        self.repository = tunables.get("RESTIC_REPOSITORY", "")
        if not self.repository:
            raise CtlError(
                f"backup: restic credentials carry no RESTIC_REPOSITORY — check "
                f"{env_file} / the sealed bundle"
            )
        # Refuse an EMPTY RESTIC_PASSWORD loudly: restic treats it as "not
        # supplied" and blocks on an interactive prompt that never comes in
        # the backup container, so every backup would fail with an obscure
        # error. A blank password is only reachable via a provisioning
        # misconfiguration (the template must render the derived password),
        # so name that cause.
        if not (tunables.get("RESTIC_PASSWORD") or "").strip():
            raise CtlError(
                f"backup: RESTIC_PASSWORD is empty in {env_file} — restic cannot open "
                f"or initialize a repository without it (a default install should have a "
                f"generated password). Re-run the provisioning playbook, or set "
                f"carlos_restic_password in host_vars, then re-run."
            )
        # Non-secret DR-posture marker (local vs offsite), refreshed on every
        # backup run: on a SEALED install restic.env is shredded, so the
        # monitor's local-only-repo alert cannot read the repository itself —
        # without this marker a sealed local-only install would never get the
        # recurring "your backups die with the host" page. Never the URL
        # (remote URLs may embed credentials) — just the posture word.
        with contextlib.suppress(OSError):
            self.backup_dir.mkdir(parents=True, exist_ok=True)
            posture_file = self.backup_dir / ".repo-posture"
            posture_file.write_text(
                ("local" if restic_local_path(self.repository) else "offsite") + "\n"
            )
            # Explicit 0644 (root writes under umask 077): the marker is
            # non-secret by construction and `backup status` advertises
            # non-root readability.
            posture_file.chmod(0o644)
        self.restic_image = tunable("RESTIC_IMAGE")
        self.keep = tunable("BACKUP_KEEP", _KEEP_DEFAULT).split()
        self.keep_binlog = tunable("BACKUP_KEEP_BINLOG", _KEEP_BINLOG_DEFAULT).split()
        self.keep_docs = tunable("BACKUP_KEEP_DOCS", _KEEP_DOCS_DEFAULT).split()
        self.check_read_data_dow = tunable("CHECK_READ_DATA_DOW", "7")
        # Restore-drill scratch datadir size: the dump loads into a RAM tmpfs,
        # so this MUST exceed the restored database size (a DB larger than
        # host RAM needs a disk-backed drill).
        self.verify_tmpfs_size = tunable("VERIFY_TMPFS_SIZE", "4g")
        # Drill container memory cap. Default: DERIVED from the tmpfs size
        # (+2 GiB of mariadbd overhead) so an oversized dump pressures the
        # DRILL into its own cgroup OOM instead of pressuring host RAM into
        # an OOM that can kill a LIVE pod. A BOUND, not a guarantee: on a
        # host with less RAM than the cap the global OOM killer can still
        # fire first. VERIFY_MEM_LIMIT overrides; VERIFY_MEM_LIMIT=0
        # disables the cap (disk-backed setups, or a rootless host without
        # cgroup-v2 memory delegation where podman rejects --memory).
        self.verify_mem_limit = tunable("VERIFY_MEM_LIMIT")
        if not self.verify_mem_limit:
            mib = size_to_mib(self.verify_tmpfs_size)
            if mib is not None:
                self.verify_mem_limit = f"{mib + 2048}m"
        elif self.verify_mem_limit == "0":
            self.verify_mem_limit = ""

        # Local path repositories are bind-mounted at /repo inside the
        # container; remote backends pass through via the env file. A remote
        # URL may embed credentials, so it is NEVER placed on the podman argv
        # — the -e override below exists only for the local-path case, whose
        # value ("/repo") holds no secret.
        self.repo_mount: List[str] = []
        self.repo_env: List[str] = []
        # restic_local_path, not startswith("/"): `local:<path>` and relative
        # spellings are the same host — they must get the mount AND count as
        # "local" for every posture gate.
        self.repo_local = restic_local_path(self.repository)
        if self.repo_local:
            # RESTIC_REPOSITORY came from a service-user-writable file — root
            # must not act on an arbitrary path from it. Only auto-create a
            # repo INSIDE this instance's EMR home; any other local path must
            # already exist (a hostile value like /etc must never be chown'd).
            repo_path = Path(self.repo_local)
            if self.repo_local.startswith(str(self.s.emr_home) + "/"):
                self._install_service_user_dir(repo_path)
            elif not repo_path.is_dir():
                raise CtlError(
                    f"local restic repository {self.repository} is outside "
                    f"{self.s.emr_home} and does not exist — refusing to create it as "
                    f"root; create it owned by {self.s.service_user} first"
                )
            self.repo_mount = ["-v", f"{self.repo_local}:/repo"]
            self.repo_env = ["-e", "RESTIC_REPOSITORY=/repo"]
        self._install_service_user_dir(self.cache_dir)

        # DB credentials: prefer the dedicated least-privilege backup account,
        # fall back to the app credentials on unprovisioned installs.
        self.db_user, self.db_pw = self._resolve_db_creds()

        # Binary-logging probe. CRITICAL: distinguish "the DB genuinely
        # reports log_bin off" from "the probe itself failed" (db not up yet,
        # wrong creds) — collapsing both silently degrades PITR while the run
        # exits 0 and no OnFailure alert fires.
        cp = self.db_exec(["mariadb", f"-u{self.db_user}", "-N", "-e", "SELECT @@log_bin"],
                          capture=True)
        if cp.returncode == 0:
            self.binlog_probe_ok = True
            digits = re.sub(r"[^0-9]", "", cp.stdout or "")
            self.binlog_on = (digits or "0") == "1"
        else:
            self.binlog_probe_ok = False
            self.binlog_on = False
        self._server_identity: Optional[str] = None
        self._binlog_runtime_open: Optional[bool] = None

    def binlog_runtime_open(self) -> Optional[bool]:
        """Is the binary log OPEN **right now**? True/False, or None when the
        probe itself could not answer (db down, no privilege) — callers must
        treat None as UNKNOWN and never as "closed".

        `@@log_bin` (the probe in the constructor) reports the STARTUP OPTION
        and NOTHING ELSE. MariaDB latches binary logging OFF for the rest of
        the server's life the first time it cannot open a new binlog file —
        a full binlog volume (ENOSPC) or a permissions change (EACCES) on the
        dedicated `mariadb-binlog` mount is enough:

            [ERROR] Could not use /var/lib/mysql-binlog/binlog.000006 for
            logging (error 13). Turning logging off for the whole duration of
            the MariaDB server process. To turn it on again: fix the cause,
            shutdown the MariaDB server and restart it.

        After that latch, ``@@log_bin`` may still report 1. A guard based only
        on that variable can therefore report healthy binary logging after the
        chain has stopped advancing. ``FLUSH BINARY LOGS`` may also return 0
        while logging is disabled, so successful command execution alone is
        not a sufficient health signal.

        `SHOW BINLOG STATUS` (MariaDB 11.4+, and its pre-11.4 spelling
        `SHOW MASTER STATUS`) is the runtime-authoritative answer: it returns
        one row while the binlog is open and ZERO rows once it is closed.
        Needs only BINLOG MONITOR — which `REPLICATION CLIENT`, already granted
        to the least-privilege `backup` account, is the MariaDB alias for."""
        if self._binlog_runtime_open is not None:
            return self._binlog_runtime_open
        for stmt in ("SHOW BINLOG STATUS", "SHOW MASTER STATUS"):
            cp = self.db_exec(
                ["mariadb", f"-u{self.db_user}", "-N", "-B", "-e", stmt],
                capture=True, quiet=True,
            )
            if cp.returncode != 0:
                # Unsupported spelling on this server version — try the other.
                continue
            self._binlog_runtime_open = bool((cp.stdout or "").strip())
            return self._binlog_runtime_open
        return None  # neither spelling answered: UNKNOWN, not "closed"

    def binlog_latched_off(self) -> bool:
        """The dangerous, silent state: the server was STARTED with binary
        logging on (so this deployment expects PITR) but has since latched it
        OFF. Only a positively-observed CLOSED binlog counts — an unknown
        probe leaves the existing guards in charge rather than inventing a
        refusal on a database we could not interrogate."""
        return self.binlog_on and self.binlog_runtime_open() is False

    _LATCHED_OFF_HINT = (
        "MariaDB has TURNED BINARY LOGGING OFF for the rest of this server "
        "process (it does that permanently the first time it cannot open a new "
        "binlog file — a FULL binlog volume or a permissions change on "
        "$EMR_HOME/data/mariadb-binlog). Point-in-time recovery is DEAD from "
        "that moment: no new transactions are being logged, so the shipped "
        "chain can never reach them. '@@log_bin' still reads 1, which is why "
        "this has to be probed separately. Look for 'Turning logging off for "
        "the whole duration' in the db container log ('carlos-ctl logs db'), "
        "FIX THE CAUSE (free space / ownership on the binlog volume), then "
        "RESTART the db container — nothing short of a restart re-opens it."
    )

    def server_identity(self) -> str:
        """This datadir's lineage id — the signal the binlog chain needs: a DR
        play that initializes a blank datadir gets a NEW id (mismatch fires),
        while a physical datadir restore keeps the old one (the chain
        legitimately continues). The binlog files themselves carry only the
        4-byte server_id (default 1 everywhere — useless), so it has to come
        from the datadir.

        `@@server_uuid` is tried first for MySQL-flavored servers, but it is a
        MySQL variable: MariaDB — including the pinned DB_IMAGE — answers
        `ERROR 1193 Unknown system variable 'server_uuid'`, so the probe alone
        returned '' on EVERY CARLOS deployment and silently disabled the whole
        chain-pollution defense (the ship-time gate, the sidecar, the drill's
        identity check, and the restore's mismatch refusal all key on a
        non-empty value). The fallback therefore MINTS a uuid4 into a dotfile
        AT THE DATADIR ROOT, which gives exactly the lineage semantics: it is
        copied by a physical datadir backup/restore, and it is absent from a
        freshly-initialized datadir. MariaDB only treats DIRECTORIES in the
        datadir as databases, so a dotfile is inert to the server.

        Minting is gated on the datadir actually being initialized: writing an
        id into an UNMOUNTED mountpoint would fabricate a lineage for a volume
        that is not there. '' = unknown (no datadir yet / unwritable) —
        callers treat unknown as legacy, never as a hard failure."""
        if self._server_identity is not None:
            return self._server_identity
        cp = self.db_exec(
            ["mariadb", f"-u{self.db_user}", "-N", "-e", "SELECT @@server_uuid"],
            capture=True, quiet=True,
        )
        out = (cp.stdout or "").strip().lower()
        if cp.returncode == 0 and re.fullmatch(r"[0-9a-f-]{36}", out):
            self._server_identity = out
            return self._server_identity
        self._server_identity = self._datadir_identity()
        return self._server_identity

    def _datadir_identity(self) -> str:
        """Read (or mint) the datadir-resident lineage id. Best-effort: any
        failure returns '' and the callers degrade to legacy semantics."""
        from .guard import datadir_initialized

        marker = self.s.data_dir / "mariadb-mnt" / pitr.IDENTITY_SIDECAR
        with contextlib.suppress(OSError):
            val = marker.read_text().strip().lower()
            if re.fullmatch(r"[0-9a-f-]{36}", val):
                return val
        if not datadir_initialized(self.s.data_dir):
            # No initialized datadir: an unmounted/blank volume must not be
            # handed an identity that would later look like a legitimate
            # continuation of this chain.
            return ""
        import uuid

        new = str(uuid.uuid4())
        try:
            marker.write_text(new + "\n")
            # 0644 for the same reason as the binlog sidecar: mariadb-backup
            # and the rootless restic container (host root is unmapped in its
            # userns) must be able to read it. It is a random opaque id, not
            # a secret.
            marker.chmod(0o644)
        except OSError as e:
            warn(
                f"could not persist the datadir lineage id ({marker}: {e}) — the binlog "
                f"chain-pollution guard stays UNVERIFIED for this run"
            )
            return ""
        log(f"minted this datadir's binlog-chain lineage id ({marker.name})")
        return new

    # -- plumbing ---------------------------------------------------------

    def _tmp_dir(self) -> str:
        if os.path.isdir("/run") and os.access("/run", os.W_OK):
            return "/run"
        return tempfile.gettempdir()

    def _install_service_user_dir(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError, KeyError):
            import pwd

            os.chown(path, pwd.getpwnam(self.s.service_user).pw_uid, -1)

    def close(self) -> None:
        if self._tmp_env:
            with contextlib.suppress(OSError):
                os.unlink(self._tmp_env)
        if self._lock_fd is not None:
            with contextlib.suppress(OSError):
                os.close(self._lock_fd)

    def lock(self) -> None:
        """Serialize full and binlog runs (restic repo locks would make an
        overlap fail noisily; this makes it wait instead)."""
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self._lock_fd = os.open(self.backup_dir / ".backup.lock",
                                os.O_WRONLY | os.O_CREAT, 0o600)
        fcntl.flock(self._lock_fd, fcntl.LOCK_EX)

    def unlock(self) -> None:
        """Release the host flock early for long read-only phases (prune,
        check --read-data, the drill): holding it would queue the 15-minute
        binlog/docs timers behind them, degrading the advertised RPO. Safe:
        restic's own repo locks still serialize any repo mutation."""
        if self._lock_fd is not None:
            with contextlib.suppress(OSError):
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)

    def within_boot_grace(self) -> bool:
        """Liveness probes that fire while the stack is still starting after
        a reboot must not page for a self-healing condition."""
        grace = int(self.s.get("BOOT_GRACE_SECONDS", "900") or "900")
        try:
            with open("/proc/uptime") as f:
                uptime = float(f.read().split()[0])
        except (OSError, ValueError, IndexError):
            return False
        return uptime < grace

    def run_restic(
        self, args: List[str], *, stdin: Optional[IO[bytes]] = None,
        stdout: Optional[IO[bytes]] = None,
        capture: bool = False, quiet: bool = False,
    ) -> subprocess.CompletedProcess:
        return self.runner.podman_user(
            [
                "run", "--rm", "-i", "--pull=missing", "--hostname", self.snapshot_host,
                "--env-file", str(self.env_file),
                *self.repo_env,
                "-v", f"{self.cache_dir}:/root/.cache/restic",
                "-v", f"{self.s.data_dir}/OscarDocument:/backup/OscarDocument:ro",
                "-v", f"{self.s.emr_home}/container:/backup/container:ro",
                "-v", f"{self.binlog_dir}:/backup/binlog:ro",
                *self.repo_mount,
                *self.extra_mount,
                self.restic_image, *args,
            ],
            stdin=stdin, stdout=stdout, capture=capture, quiet=quiet,
        )

    def db_exec(
        self, args: List[str], *, input_text: Optional[str] = None,
        stdin: Optional[IO[bytes]] = None,
        capture: bool = False, quiet: bool = False, password: Optional[str] = None,
    ) -> subprocess.CompletedProcess:
        """mariadb client in the db container. MYSQL_PWD is forwarded by NAME
        so the plaintext password is never a podman argv token. `stdin` feeds
        a FILE into the client (streamed — dump loads must not buffer)."""
        return self.runner.podman_user(
            ["exec", "-i", "-e", "MYSQL_PWD", f"{self.s.app_pod}-db", *args],
            env={"MYSQL_PWD": password if password is not None else self.db_pw},
            input_text=input_text, stdin=stdin, capture=capture, quiet=quiet,
        )

    def _resolve_db_creds(self) -> Tuple[str, str]:
        s = self.s
        creds_file = s.conf_dir / "restic" / "backup-db.env"
        if creds_file.is_file():
            # Unsealed install: plaintext dedicated backup account, %q-encoded
            # on disk (legacy of the shell-sourced era). Parsed, never sourced.
            vals = parse_env_file(creds_file.read_text(),
                                  whitelist=["BACKUP_DB_USER", "BACKUP_DB_PASSWORD"])
            if vals.get("BACKUP_DB_PASSWORD"):
                return vals.get("BACKUP_DB_USER", ""), vals["BACKUP_DB_PASSWORD"]
        if s.secrets_bundle.is_file():
            from . import secrets as secrets_mod

            with contextlib.suppress(CtlError):
                bdb = secrets_mod.bundle_get(self.runner, "backup_db", "env")
                if bdb:
                    vals = parse_env_file(
                        bdb, whitelist=["BACKUP_DB_USER", "BACKUP_DB_PASSWORD"]
                    )
                    if vals.get("BACKUP_DB_PASSWORD"):
                        return vals.get("BACKUP_DB_USER", ""), vals["BACKUP_DB_PASSWORD"]
        # Fall back to the app credentials on unprovisioned installs.
        user = pw = ""
        escaped = True
        if s.properties_file.is_file():
            lines = s.properties_file.read_text().splitlines()
            user = first_match(lines, "db_username") or ""
            pw = first_match(lines, "db_password") or ""
        if pw == "__SEALED__":
            # App credentials were sealed before db-users provisioning: prefer
            # the fragment carlos-secrets.service rendered into /run tmpfs
            # (escaped), else decrypt from the bundle (raw).
            frag = s.run_secrets_dir / "carlos-db.properties"
            if frag.is_file():
                lines = frag.read_text().splitlines()
                user = first_match(lines, "db_username") or ""
                pw = first_match(lines, "db_password") or ""
            elif s.secrets_bundle.is_file():
                from . import secrets as secrets_mod

                with contextlib.suppress(CtlError):
                    user = secrets_mod.bundle_get(self.runner, "carlos", "db_username")
                    pw = secrets_mod.bundle_get(self.runner, "carlos", "db_password")
                    escaped = False  # bundle stores the RAW value
        # .properties values store each backslash doubled; MYSQL_PWD needs the
        # RAW value — reverse the doubling for file-derived reads (NOT the
        # bundle, which is already raw). Otherwise a backslash-bearing password
        # would fail auth here though the app connects fine.
        if escaped:
            pw = properties_unescape_value(pw)
        return user, pw

    # -- repo init guard ----------------------------------------------------

    def ensure_repo(self) -> None:
        """One-time repository initialization — but ONLY when the repo is
        genuinely uninitialized. `cat config` also fails on an unreachable
        backend or a wrong RESTIC_PASSWORD, and blindly running `restic init`
        there would silently create a FRESH EMPTY repo that every later
        backup fills while the real repository rots unreferenced. Initialize
        only on restic's explicit "repository does not exist" exit code (10,
        restic >= 0.17) or an empty local-path directory; refuse loudly
        otherwise. The sentinel (recording the repo path, OUTSIDE the repo
        volume) additionally tells a lost mount apart from a first run."""
        cat = self.run_restic(["cat", "config"], quiet=True)
        if cat.returncode == 0:
            # Repo healthy: backfill/refresh the sentinel so a LATER lost
            # mount can be told apart from a genuine first run.
            if not self._sentinel_matches():
                self._write_sentinel()
            # Drop stale locks from a previously KILLED run (systemd timeout /
            # SIGKILL leaves a lock inside the repo that wedges every later
            # backup). `restic unlock` only removes locks whose owning process
            # is gone, and the host flock already serializes our own runs.
            self.run_restic(["unlock"], quiet=True)
            return
        rc = cat.returncode
        try:
            local_empty = (
                bool(self.repo_local)
                and Path(self.repo_local).is_dir()
                and not any(Path(self.repo_local).iterdir())
            )
        except OSError:
            # A stale mount / EIO on the repo dir is exactly the lost-mount
            # scenario this guard exists for — route it into the refuse
            # branch's diagnostic, never a raw traceback.
            local_empty = False
        local_missing = bool(self.repo_local) and not Path(self.repo_local).exists()
        if rc == 10 or local_empty or local_missing:
            if self._sentinel_matches() and self.s.get("CARLOS_INIT_REPO") != "1":
                mp = ""
                if self.runner.have("mountpoint") and self.repo_local \
                        and self.runner.ok(["mountpoint", "-q", self.repo_local]):
                    mp = " (the path is a mountpoint)"
                raise CtlError(
                    f"restic repository at {self.repository} reads uninitialized/empty, "
                    f"but this instance already initialized THIS repository (sentinel "
                    f"{self.repo_sentinel} records it){mp} — the repo volume is almost "
                    f"certainly unmounted or wiped. REFUSING to 'restic init' a fresh "
                    f"empty repo over it (that would orphan real backup history while "
                    f"the freshness monitor stays green). Mount the repo volume and "
                    f"re-run, or set CARLOS_INIT_REPO=1 to intentionally re-provision an "
                    f"empty repo here."
                )
            log(f"Initializing restic repository at {self.repository}")
            if self.run_restic(["init"]).returncode != 0:
                raise CtlError("restic init failed")
            self._write_sentinel()
            self.run_restic(["unlock"], quiet=True)
            return
        raise CtlError(
            f"restic repository check failed (exit {rc}) but the repository does not look "
            f"uninitialized — unreachable backend, or wrong RESTIC_PASSWORD? REFUSING to "
            f"run 'restic init' over it; fix the backend/credentials and re-run"
        )

    def _sentinel_matches(self) -> bool:
        for path in (self.repo_sentinel, self.legacy_repo_sentinel):
            try:
                if path.read_text().strip() == self.repository:
                    return True
            except OSError:
                continue
        return False

    def _write_sentinel(self) -> None:
        # Best-effort; a missing sentinel only weakens the guard.
        with contextlib.suppress(OSError):
            self.repo_sentinel.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.repo_sentinel, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(self.repository + "\n")

    # -- shared policies -----------------------------------------------------

    def docs_store_populated(self) -> bool:
        """Empty-source guard: restic happily snapshots an empty tree and
        exits 0, so an unmounted/mis-pathed OscarDocument would stamp success
        forever while backing up nothing. Bounded count — cheap on huge
        stores. 0 disables (a genuinely fresh pre-go-live install)."""
        threshold = int(self.s.get("CARLOS_DOCS_MIN_FILES", "1") or "1")
        if threshold <= 0:
            return True
        count = 0
        docs = self.s.data_dir / "OscarDocument"
        if docs.is_dir():
            for p in docs.rglob("*"):
                if p.is_file():
                    count += 1
                    if count >= threshold:
                        return True
        return False

    def stamp_docs_ok(self) -> None:
        """ONE owner of the "may a docs snapshot claim success?" policy,
        shared by the docs and full modes — two hand-synced copies would let
        the nightly and 15-minute paths drift and silently re-green an empty
        store on one of them."""
        if self.docs_store_populated():
            (self.backup_dir / ".last-docs-ok").touch()
        else:
            warn(
                f"document store {self.s.data_dir}/OscarDocument holds fewer than "
                f"{self.s.get('CARLOS_DOCS_MIN_FILES', '1')} file(s) — snapshot taken but "
                f"success NOT stamped (unmounted/mis-pathed document dir? a pre-go-live "
                f"install can set CARLOS_DOCS_MIN_FILES=0 in carlos-app.env)"
            )

    def ship_binlogs(self) -> bool:
        """FLUSH BINARY LOGS, then ship every CLOSED binlog (the new active
        one is excluded and picked up next run; restic dedups unchanged
        files). Returns False when shipping failed in an alertable way — a
        PITR deployment MUST have binary logging on, so a silent green run
        would hide a degraded (24h, not 15m) RPO. Sole exception: a
        db-unreachable probe within the boot grace window is a quiet skip
        (True, without setting binlog_shipped, so the stamp stays honest)."""
        self.binlog_shipped = False
        if not self.binlog_probe_ok:
            if self.within_boot_grace():
                log(
                    f"db probe failed within boot grace "
                    f"({self.s.get('BOOT_GRACE_SECONDS', '900')}s after boot) — stack "
                    f"likely still starting; skipping this ship without an alert"
                )
                return True
            warn("could not determine binary-logging state (db unreachable / bad creds?) "
                 "— cannot ship binlogs")
            return False
        if not self.binlog_on:
            warn(
                "binary logging is OFF but this deployment expects it ON for point-in-time "
                "recovery (check log_bin in zz-carlos.cnf) — not shipping"
            )
            return False
        # Runtime latch check, BEFORE the FLUSH: once MariaDB has turned
        # logging off mid-process, FLUSH BINARY LOGS becomes a no-op that
        # RETURNS 0 and the already-closed binlogs are all still on disk — so
        # this ship would run clean, re-store an identical (dedup'd) snapshot,
        # and stamp .last-binlog-ok every 15 minutes FOREVER while the chain
        # stopped advancing. Failing here is what makes the stamp honest, so
        # the monitor's BINLOG_MAX_AGE_MIN check pages within ~35 minutes
        # instead of never.
        if self.binlog_runtime_open() is False:
            warn(f"not shipping binlogs: {self._LATCHED_OFF_HINT}")
            return False
        # Chain-identity gate, BEFORE the FLUSH mutates anything: shipping a
        # rebuilt/DR-fresh server's unrelated binlog.000001+ would mask the
        # real chain as the newest 'latest' snapshots — replay would then
        # misreport the true anchor as pruned (refusal/data-loss) or, on a
        # sequence collision, apply another server's events as corruption.
        ident = self.server_identity()
        ident_marker = self.backup_dir / ".binlog-identity"
        if ident:
            prev_ident = ""
            with contextlib.suppress(OSError):
                prev_ident = ident_marker.read_text().strip()
            if prev_ident and prev_ident != ident:
                if self.s.flag("CARLOS_ACCEPT_NEW_BINLOG_IDENTITY"):
                    warn(
                        f"binlog chain identity change ACCEPTED "
                        f"({prev_ident} -> {ident}) — this server's chain replaces "
                        f"the old one in the repository from here on"
                    )
                else:
                    warn(
                        f"this server's identity ({ident}) differs from the identity "
                        f"that last shipped into this repository ({prev_ident}) — a "
                        f"rebuilt/DR server's unrelated binlogs must not pollute the "
                        f"existing PITR chain. If the rebuild is intentional (the new "
                        f"chain replaces the old), re-run once with "
                        f"CARLOS_ACCEPT_NEW_BINLOG_IDENTITY=1; a completed "
                        f"'backup restore' re-anchors this automatically."
                    )
                    return False
        if self.db_exec(["mariadb", f"-u{self.db_user}", "-e",
                         "FLUSH BINARY LOGS"]).returncode != 0:
            warn("FLUSH BINARY LOGS failed — cannot ship binlogs")
            return False
        # Identify the active binlog explicitly. A failed read would otherwise
        # let the exclude match nothing, shipping the live, still-written
        # active binlog (a torn copy) — bail loudly instead.
        index = self.binlog_dir / "binlog.index"
        try:
            index_lines = index.read_text().splitlines()
        except OSError:
            warn(
                f"no readable {index} — cannot exclude the active binlog; skipping this "
                f"ship rather than copy a live file"
            )
            return False
        active = os.path.basename(index_lines[-1]) if index_lines else ""
        if not active or active == ".":
            warn("could not determine the active binlog from binlog.index — skipping ship")
            return False
        # The identity rides INSIDE the snapshot as a sidecar file, so replay
        # learns who shipped the chain from the restored files themselves
        # (legacy snapshots simply lack the file — warn-don't-fail there).
        # MariaDB ignores foreign dotfiles in the binlog dir (it consults
        # only binlog.index).
        if ident:
            try:
                sidecar = self.binlog_dir / pitr.IDENTITY_SIDECAR
                sidecar.write_text(ident + "\n")
                # Explicit 0644 (root writes under umask 077): the sidecar is
                # non-secret by construction, and the rootless restic container
                # (real root is unmapped in its userns) must be able to read it
                # into the snapshot — a 0600 sidecar fails every subsequent
                # ship with an unreadable-source error. Mirrors .repo-posture.
                sidecar.chmod(0o644)
            except OSError:
                warn(
                    f"could not write the chain-identity sidecar in {self.binlog_dir} — "
                    f"this snapshot ships with LEGACY (unverifiable) identity"
                )
        # Exclude the active binlog AND anything at/after its sequence: a
        # server-side rotation (max_binlog_size under write load) landing
        # between the index read and restic's walk creates a NEWER live file
        # the single-name exclude would not match — restic would capture a
        # torn copy of it. Numeric compare, not lexical (the 6->7 digit
        # rollover breaks lexical ordering).
        excludes = ["--exclude", f"/backup/binlog/{active}"]
        m_active = re.match(r"^(.*)\.(\d+)$", active)
        if m_active:
            stem, active_seq = m_active.group(1), int(m_active.group(2))
            with contextlib.suppress(OSError):
                for f in sorted(os.listdir(self.binlog_dir)):
                    m = re.match(r"^(.*)\.(\d+)$", f)
                    if (m and m.group(1) == stem and f != active
                            and int(m.group(2)) >= active_seq):
                        excludes += ["--exclude", f"/backup/binlog/{f}"]
        log(f"Shipping closed binlogs (active: {active}, excluded)")
        if self.run_restic([
            "backup", "/backup/binlog", *excludes,
            "--tag", "binlog",
        ]).returncode != 0:
            warn("restic backup of the binlogs failed")
            return False
        if ident:
            try:
                ident_marker.write_text(ident + "\n")
            except OSError:
                warn(f"could not record the shipped chain identity in {ident_marker}")
        self.binlog_shipped = True
        return True


def _backup_status(runner: Runner) -> int:
    """Credential-free at-a-glance state: stamp ages vs their alert
    thresholds, the DR posture, and where the override knobs are documented —
    'did last night's backup run?' should not need restic or root secrets."""
    s = runner.settings
    backup_dir = s.emr_home / "backup"
    now = time.time()
    rows = (
        (".last-full-ok", s.get_int_or("BACKUP_MAX_AGE_HOURS", 26) * 3600, "full db"),
        (".last-binlog-ok", s.get_int_or("BINLOG_MAX_AGE_MIN", 35) * 60, "binlog ship"),
        (".last-docs-ok", s.get_int_or("DOCS_MAX_AGE_MIN", 35) * 60, "documents"),
        (".last-verify-ok", s.get_int_or("VERIFY_MAX_AGE_HOURS", 192) * 3600,
         "restore drill"),
    )
    stale = False
    for stamp, max_age, label in rows:
        f = backup_dir / stamp
        # try/except, not is_file()-then-stat(): a stamp unlinked mid-run (or
        # a permissions surprise) must degrade to a line, never a traceback.
        try:
            age = int(now - f.stat().st_mtime)
        except OSError:
            print(f"{label:<14} MISSING — never ran (or stamps were wiped)")
            stale = True
            continue
        state = "OK" if age <= max_age else "STALE"
        stale = stale or age > max_age
        print(f"{label:<14} {state:<6} last success {age // 60} min ago "
              f"(threshold {max_age // 60} min)")
    posture = backup_dir / ".repo-posture"
    try:
        word = posture.read_text().strip()
    except OSError:
        word = ""
    if word:
        print(f"{'repository':<14} {word.upper()}"
              + (" — not DR; see README 'Backups'" if word == "local" else ""))
    print("overrides: CARLOS_INIT_REPO / CARLOS_DRILL_ALLOW_NO_PITR / "
          "CARLOS_ACCEPT_LOCAL_REPO — see README 'Backups (restic)'")
    return 1 if stale else 0


def _reap_orphaned_stagings(ctx: BackupContext) -> None:
    """Remove plaintext PHI stagings orphaned by a hard-killed run. The
    SIGTERM->SystemExit handler in cli.main makes finally-cleanup run for
    ordinary kills, but SIGKILL (OOM, TimeoutStartSec) still can't be caught
    — without this sweep a killed nightly left a complete plaintext DB dump
    in $EMR_HOME/backup FOREVER, one file per killed run. PID-precise for
    the .<pid>-suffixed dump files (a live producer is skipped regardless of
    age; a dead one is reaped immediately); age-gated 24h for the
    random-suffix .restore.* scratch dirs."""
    for f in list(ctx.backup_dir.glob(".carlos-databases.sql.*")) + \
            list(ctx.backup_dir.glob(".restore-databases.sql.*")) + \
            list(ctx.backup_dir.glob(".verify-doc.*")):
        pid = f.suffix.lstrip(".")
        if pid.isdigit() and Path(f"/proc/{pid}").is_dir():
            continue  # its producer is still running
        with contextlib.suppress(OSError):
            f.unlink()
            warn(f"reaped an orphaned plaintext staging: {f.name} "
                 f"(a prior run was hard-killed)")
    # A SIGKILLed drill also orphans its throwaway MariaDB container — a full
    # plaintext PHI database serving in tmpfs until someone notices. Same
    # PID-precision as the file reap: the name embeds the producer's pid.
    verify_ctrs = ctx.runner.output(ctx.runner.podman_user_argv(
        ["ps", "-a", "--filter", f"name=^{ctx.s.instance}-verify-", "--format", "{{.Names}}"]
    )).splitlines()
    for ctr in verify_ctrs:
        pid = ctr.rsplit("-", 1)[-1]
        if pid.isdigit() and Path(f"/proc/{pid}").is_dir():
            continue  # its drill is still running
        if ctx.runner.ok(ctx.runner.podman_user_argv(["rm", "-f", ctr])):
            warn(f"reaped an orphaned restore-drill DB container: {ctr} "
                 f"(a prior drill was hard-killed; it held a plaintext PHI copy)")
    now = time.time()
    # Both the restore (.restore.*) and the drill (.verify.*) use mkdtemp with
    # a RANDOM suffix (no pid to key on), and both hold a full plaintext PHI
    # dump + restored binlog chain. The drill's scratch dir was previously
    # swept ONLY at the start of the next drill (weekly), so a SIGKILLed drill
    # leaked PHI for up to ~7 days — the reaper runs on every 15-minute backup
    # verb, so age-gate both here to close that gap.
    for stale in list(ctx.backup_dir.glob(".restore.*")) + \
            list(ctx.backup_dir.glob(".verify.*")):
        with contextlib.suppress(OSError):
            if stale.is_dir() and now - stale.stat().st_mtime > 24 * 3600:
                shutil.rmtree(stale, ignore_errors=True)
                warn(f"reaped an orphaned restore scratch dir: {stale.name}")


def cmd_backup(runner: Runner, args: List[str]) -> int:
    mode = args[0] if args else "full"
    if mode not in ("full", "binlogs", "docs", "verify", "restore", "status"):
        raise CtlError(
            "usage: carlos-ctl backup [full|binlogs|docs|verify|status|restore "
            "[--snapshot=ID] [--stop-datetime='YYYY-MM-DD HH:MM:SS'] [--dry-run]]"
        )
    # ONLY `restore` takes arguments; every other mode used to DROP whatever
    # followed it. The usage line advertises `--dry-run` two words after
    # `full|binlogs|docs|verify|status`, so `carlos-ctl backup full --dry-run`
    # reads as a preview and silently ran the REAL nightly tier instead —
    # staging a multi-GB plaintext-PHI dump, committing a restic snapshot and
    # advancing retention. Same class as the db-backup argument contract and
    # the CLI's no-argument-verb guard: a silently-dropped flag on a verb that
    # moves PHI. Refuse here, before the repo lock and the credential lookup.
    if mode != "restore" and args[1:]:
        raise CtlError(
            f"'carlos-ctl backup {mode}' takes no arguments (got: {' '.join(args[1:])}) — "
            f"only 'backup restore' accepts flags (--snapshot=, --stop-datetime=, "
            f"--dry-run); behavior knobs for the scheduled tiers are environment "
            f"variables, see the README"
        )
    # status is credential-free and lock-free by design — usable while a
    # backup runs, on a sealed install, and by a non-root operator shell.
    if mode == "status":
        return _backup_status(runner)
    ctx = BackupContext(runner)
    try:
        ctx.lock()
        _reap_orphaned_stagings(ctx)
        ctx.ensure_repo()
        if mode == "binlogs":
            if not ctx.ship_binlogs():
                return 1
            # Success stamp for the freshness monitor — must not advance for
            # a boot-grace run that shipped nothing.
            if ctx.binlog_shipped:
                (ctx.backup_dir / ".last-binlog-ok").touch()
                # Expire binlog snapshots ONLY while nightly fulls are FRESH
                # : the replay chain rolls forward from the
                # newest dump's anchor, so age-expiring binlogs while fulls
                # fail would erode the only chain that can recover a stale
                # dump — retention silently pre-deciding data loss. While
                # fulls are stale the snapshots accumulate instead: disk
                # growth is the alerted, recoverable direction for PHI.
                full_stamp = ctx.backup_dir / ".last-full-ok"
                max_age = ctx.s.get_int_or("BACKUP_MAX_AGE_HOURS", 26) * 3600
                full_fresh = False
                with contextlib.suppress(OSError):
                    full_fresh = time.time() - full_stamp.stat().st_mtime < max_age
                if full_fresh:
                    _forget_own_tag(ctx, "binlog", ctx.keep_binlog)
                else:
                    log("binlog retention deferred — the last full backup is stale or "
                        "missing, so the replay chain is preserved until fulls recover")
        elif mode == "docs":
            # Deliberately db-free — documents keep shipping even while the
            # db (or the whole pod) is down.
            log("Snapshotting the document store")
            if ctx.run_restic(["backup", "/backup/OscarDocument",
                               "--tag", "docs"]).returncode != 0:
                return 1
            # Stamp success only for a NON-EMPTY store; exit 0 either way — a
            # persistent empty store should surface as ONE hourly stale-stamp
            # alert from the monitor, not a 15-minute OnFailure page storm.
            ctx.stamp_docs_ok()
            _forget_own_tag(ctx, "docs", ctx.keep_docs)
        elif mode == "verify":
            # Release the host flock for the drill's duration: it can run
            # long, and holding the lock would queue the 15-minute timers
            # behind it, degrading the advertised RPO.
            ctx.unlock()
            if not _verify_restore(ctx):
                return 1
            # Success stamp for the freshness monitor: OnFailure only covers
            # drills that RUN and fail — a drill whose timer silently stops
            # firing must surface as a stale/missing stamp, or operators
            # believe backups are verified-restorable when nothing has
            # checked in months.
            (ctx.backup_dir / ".last-verify-ok").touch()
        elif mode == "restore":
            if not _restore_pitr(ctx, args[1:]):
                return 1
        else:
            if not _full_backup(ctx):
                return 1
        log(f"Backup ({mode}) complete")
        return 0
    finally:
        ctx.close()


def _stage_dr_env(s: Settings) -> None:
    """DISASTER RECOVERY: carlos-app.env is excluded from the backup (MariaDB
    root password), but a full restore NEEDS its non-secret site identity —
    SERVER_NAME, BIND_IP, ports, image pins — so stage a SECRETS-STRIPPED
    copy that DOES ride in the backup as carlos-app.env.dr. ALLOWLIST, not a
    name-pattern denylist: a key is kept only when it is a
    KNOWN carlos-ctl key that is not in config.SECRET_ENV_KEYS. The old
    regex strip was fail-OPEN — an operator's custom secret whose name
    matched none of the credential tokens (SMTP_AUTH=..., S3_ACCESS=...)
    was copied verbatim into the backup. Unknown keys are now dropped AND
    warned by name: fail-safe stays, silence goes."""
    dr_env = s.emr_home / "container" / "carlos-app.env.dr"
    if not s.env_file.is_file():
        return
    from .config import SECRET_ENV_KEYS, known_keys

    keep_keys = known_keys() - SECRET_ENV_KEYS
    key_re = re.compile(r"^\s*(?:export\s+)?([A-Za-z0-9_]+)=")
    dropped_unknown: List[str] = []
    try:
        fd = os.open(dr_env, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        # Explicit 0644 via the fd (root writes under umask 077, and O_CREAT
        # never resets the mode of an existing file): the copy is non-secret
        # BY CONSTRUCTION (allowlist above), and the rootless restic `files`
        # snapshot MUST be able to read it — host-root ownership is unmapped
        # in the service user's userns, so the `other` bits govern. A
        # root-0600 .dr file makes restic exit 3 and fails every nightly
        # full — the exact DR contract this staging exists to serve.
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "w") as f:
            f.write("# CARLOS site identity — SECRETS-STRIPPED disaster-recovery copy.\n")
            f.write("# Restore per the README DR runbook, then re-add "
                    "CARLOS_DB_ROOT_PASSWORD\n")
            f.write('# from the sealed bundle (sops -d --extract '
                    "'[\"carlos\"][\"db_root_password\"]').\n")
            for line in s.env_file.read_text().splitlines():
                m = key_re.match(line)
                if m is None:
                    # comments/blank lines carry no values — keep as-is
                    if not line.strip() or line.lstrip().startswith("#"):
                        f.write(line + "\n")
                    continue
                key = m.group(1)
                if key in keep_keys:
                    f.write(line + "\n")
                elif key not in SECRET_ENV_KEYS:
                    dropped_unknown.append(key)
    except OSError:
        with contextlib.suppress(OSError):
            dr_env.unlink()
        warn("could not stage carlos-app.env.dr — DR restore will need the site env "
             "reconstructed by hand")
    if dropped_unknown:
        warn(
            f"carlos-app.env.dr: dropped key(s) carlos-ctl does not know "
            f"({', '.join(sorted(set(dropped_unknown)))}) — unknown keys never ride "
            f"in the DR copy (they may be operator secrets); if one is genuinely "
            f"non-secret site identity, re-add it to the restored env by hand"
        )


def _full_backup(ctx: BackupContext) -> bool:
    s = ctx.s
    # If we couldn't even determine the binlog state, do NOT take a dump
    # without a verified anchor and call it a success — fail so the alert
    # fires and PITR isn't silently broken for the night. Exception: a
    # catch-up fire just after a reboot skips quietly (no stamp advances).
    if not ctx.binlog_probe_ok:
        if ctx.within_boot_grace():
            log(
                f"db probe failed within boot grace "
                f"({s.get('BOOT_GRACE_SECONDS', '900')}s after boot) — stack likely still "
                f"starting; skipping this full backup without an alert"
            )
            return True
        warn("could not determine binary-logging state (db unreachable?) — refusing to "
             "take a dump with no verified binlog anchor")
        return False
    # Engine audit: --single-transaction only snapshots transactional tables,
    # and the --master-data anchor won't correspond to MyISAM/Aria tables —
    # replay would mis-apply them. Fail CLOSED on a failed probe too: an
    # empty result from a FAILED query would read as "all InnoDB" — a
    # fail-open dump of a repo whose consistency we never verified.
    # Audit EVERY user schema, not just oscar/drugref2: the dump is
    # --all-databases and the restore replays every non-system schema
    # (pitr.filter_system_schemas), so a MyISAM/Aria table in any other
    # schema (e.g. a populated legacy `test` schema carried over from an
    # OSCAR/OpenO migration) breaks the same consistency contract. The
    # system schemas are excluded by name — they are Aria/MyISAM by design
    # in MariaDB and the restore never replays them.
    cp = ctx.db_exec(
        ["mariadb", f"-u{ctx.db_user}", "-N", "-e",
         "SELECT CONCAT(table_schema,'.',table_name,' [',engine,']') "
         "FROM information_schema.tables WHERE table_schema NOT IN "
         "('mysql','sys','performance_schema','information_schema') "
         "AND engine IS NOT NULL AND engine <> 'InnoDB'"],
        capture=True,
    )
    allow_non_innodb = s.get("CARLOS_ALLOW_NON_INNODB", "0") == "1"
    if cp.returncode != 0:
        if not allow_non_innodb:
            warn(
                "refusing the nightly dump: could not audit table storage engines (the "
                "information_schema probe failed) — cannot confirm the PITR consistency "
                "contract holds. Fix DB access, or set CARLOS_ALLOW_NON_INNODB=1 to "
                "accept dump-time-only consistency."
            )
            return False
        noninnodb = ""
    else:
        noninnodb = (cp.stdout or "").strip()
    if noninnodb:
        found = [t for t in noninnodb.splitlines() if t.strip()]
        # Partition: tables that CANNOT be converted (see
        # _PITR_UNCONVERTIBLE_TABLES) must not refuse the dump — the operator
        # has no action to take, and a guard that fires on every fresh ON/BC
        # install just trains people to set the blanket override, which then
        # also masks a future table that COULD have been converted. Anything
        # else still refuses.
        blocking = [t for t in found if not _is_pitr_unconvertible(t)]
        unconvertible = [t for t in found if _is_pitr_unconvertible(t)]
        warn(
            "non-InnoDB tables detected — --single-transaction dumps them WITHOUT "
            "transactional consistency, and the --master-data anchor won't line up with "
            "them, so any change to these tables since the dump can be SILENTLY LOST on a "
            "point-in-time restore:"
        )
        for t in blocking:
            print(f"WARNING:   {t}  (convert to InnoDB)", file=sys.stderr)
        for t in unconvertible:
            print(
                f"WARNING:   {t}  (KNOWN-unconvertible: more than InnoDB's 1017-column "
                f"limit — accepted, dump-time-only consistency)",
                file=sys.stderr,
            )
        if blocking and not allow_non_innodb:
            warn(
                "refusing the nightly dump: non-InnoDB tables break the point-in-time-"
                "recovery consistency contract — convert them to InnoDB, or set "
                "CARLOS_ALLOW_NON_INNODB=1 to accept dump-time-only consistency for "
                "those tables"
            )
            return False
        if unconvertible and not blocking:
            # Proceed, but never silently: the accepted loss window is real,
            # it is just not one the operator can close.
            warn(
                "proceeding: the only non-InnoDB tables are known-unconvertible ones. A "
                "point-in-time restore can silently lose writes made to them after the "
                "dump; every other table stays PITR-consistent. See the README "
                "'Backups (restic)' fresh-install note."
            )

    # Refuse BEFORE the dump when binary logging has been latched off at
    # runtime. mariadb-dump would run the whole (multi-GB, minutes-long) dump
    # and only then die resolving the --master-data anchor:
    #   Couldn't execute 'SELECT BINLOG_GTID_POS(...)': You are not using
    #   binary logging (1381)
    # — after which the generic handler below blamed "db down or credentials
    # wrong?", sending the operator to check two things that are both fine.
    # Name the real cause, and do it without burning the dump first.
    if ctx.binlog_latched_off():
        warn(f"refusing the full backup: {ctx._LATCHED_OFF_HINT}")  # noqa: SLF001
        warn(
            "the dump itself would also fail — mariadb-dump cannot resolve the "
            "--master-data binlog anchor with logging closed (error 1381)"
        )
        return False

    dump_args = ["--all-databases", "--single-transaction", "--quick", "--routines",
                 "--events", "--hex-blob"]
    if ctx.binlog_on:
        # --master-data=2 is correct for mariadb:11.4. NOTE: the flag is being
        # phased out in favor of --source-data — verify it is still accepted
        # when bumping DB_IMAGE past 11.4 (the dump runs the client from
        # inside the db container, so the client version tracks the server).
        dump_args += ["--master-data=2", "--flush-logs"]
    else:
        warn("binary logging is off — dump has no binlog coordinates (no point-in-time "
             "recovery)")

    # Stage the dump and verify it is COMPLETE before handing it to restic:
    # streaming straight into `restic backup --stdin` would commit whatever
    # bytes arrived before a mid-dump failure as a "successful" snapshot — a
    # truncated, silently unrestorable backup. The staged file is a plaintext
    # PHI dump: 0600, lives only for this run, removed on every exit path
    # (needs free space >= dump size on the backup filesystem — keep it on a
    # LUKS volume).
    dump_file = ctx.backup_dir / f".carlos-databases.sql.{os.getpid()}"
    log("Backing up MariaDB (mariadb-dump --single-transaction, staged + verified)")
    try:
        fd = os.open(dump_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            # First line: the originating server's identity, as an inert SQL
            # comment — replay compares it against the binlog chain's sidecar
            # so another server's events are never applied to this dump.
            ident = ctx.server_identity()
            if ident:
                f.write(f"-- carlos-server-uuid: {ident}\n".encode())
                f.flush()
            cp = ctx.runner.podman_user(
                ["exec", "-i", "-e", "MYSQL_PWD", f"{s.app_pod}-db",
                 "mariadb-dump", *dump_args, f"-u{ctx.db_user}"],
                env={"MYSQL_PWD": ctx.db_pw}, stdout=f,
            )
            if cp.returncode != 0:
                warn("mariadb-dump failed — no snapshot taken (db down or credentials "
                     "wrong?)")
                return False
        if not pitr.dump_footer_complete(dump_file):
            warn("mariadb-dump output is missing its '-- Dump completed' footer "
                 "(truncated?) — refusing to commit an incomplete dump")
            return False
        # Content floor: a footer-complete dump can still be semantically
        # EMPTY (wrong --databases list, everything filtered) — committing it
        # would stamp .last-full-ok on a backup that restores nothing.
        if not pitr.dump_has_content(dump_file):
            warn("mariadb-dump output contains no CREATE TABLE/INSERT INTO — the dump "
                 "is empty; refusing to commit it as the nightly full")
            return False
        with open(dump_file, "rb") as df:
            if ctx.run_restic(
                ["backup", "--stdin", "--stdin-filename", "carlos-databases.sql",
                 "--tag", "db"],
                stdin=df,
            ).returncode != 0:
                warn("restic backup of the db dump failed")
                return False
    finally:
        with contextlib.suppress(OSError):
            dump_file.unlink()

    _stage_dr_env(s)

    # Documents and configuration (repository is encrypted). The SOPS+age
    # secrets bundle IS included — encrypted to the instance's age key, safe
    # at rest inside the repo; a full restore needs the TWO escrowed off-host
    # secrets (the age key, and the restic.env content that reaches/opens
    # the repo). The age PRIVATE key needs NO exclude: it lives in
    # secrets-private (root-only), OUTSIDE /backup/container — it must never
    # ride in the repo it unlocks. carlos-app.env (root password), the
    # superseded plaintext conf/restic, and rolling *.bak are excluded.
    log("Backing up documents and configuration")
    if ctx.run_restic([
        "backup", "/backup/OscarDocument", "/backup/container", "--tag", "files",
        "--exclude", "/backup/container/conf/restic",
        "--exclude", "/backup/container/carlos-app.env",
        "--exclude", "/backup/container/*.sh",
        "--exclude", "*.bak",
    ]).returncode != 0:
        warn("restic backup of documents/configuration failed")
        return False

    # Catch the binlogs closed by --flush-logs right away.
    if not ctx.ship_binlogs():
        return False

    # Retention per snapshot class, prune once, then integrity check — all
    # delegated to restic. --host scopes retention to THIS instance's
    # snapshots so a shared repository can never expire (or count) another
    # instance's backups.
    log("Applying retention and checking repository")
    host_args = ["--host", ctx.snapshot_host]
    # A failed forget/prune must FAIL the run before any stamp advances (the
    # bash aborted under set -e): an append-only/WORM bucket or a persistent
    # prune error would otherwise stamp green every night while retention is
    # never applied and the repository grows unbounded, unpaged.
    for tag, keep in (("db", ctx.keep), ("files", ctx.keep), ("docs", ctx.keep_docs)):
        if ctx.run_restic(["forget", *host_args, "--tag", tag, *keep]).returncode != 0:
            warn(f"restic forget --tag {tag} failed — retention was NOT applied")
            return False
    # Release the host flock BEFORE prune + check: --prune can run for
    # MINUTES (and --read-data for hours); restic's own repo lock serializes
    # any concurrent repo mutation, so a binlog backup starting now cannot
    # corrupt the prune. It CAN however wait on (or lose to) the prune's
    # exclusive lock — that 15-minute binlog run then fails, pages via
    # OnFailure, and self-heals on the next cycle: transient noise, never
    # corruption.
    ctx.unlock()
    if ctx.run_restic(["forget", *host_args, "--tag", "binlog", *ctx.keep_binlog,
                       "--prune"]).returncode != 0:
        warn("restic forget --tag binlog --prune failed — retention/prune was NOT applied")
        return False
    # Structural check nightly; FULL pack-data read once a week (bit-rot
    # detection — `restic check` alone never reads pack data).
    if time.strftime("%u") == ctx.check_read_data_dow:
        check = ctx.run_restic(["check", "--read-data"])
    else:
        check = ctx.run_restic(["check"])
    if check.returncode != 0:
        warn("restic repository check failed")
        return False
    (ctx.backup_dir / ".last-full-ok").touch()
    if ctx.binlog_shipped:
        (ctx.backup_dir / ".last-binlog-ok").touch()
    ctx.stamp_docs_ok()
    return True


def _pipe_filtered_dump(runner: Runner, dump_path: Path, podman_args: List[str],
                        env: dict, *, drop_user_schemas: bool = False) -> bool:
    """Stream the system-schema-filtered dump into a mariadb client's stdin
    (constant memory, no second on-disk copy). The credential travels via the
    ENVIRONMENT of the pipe (off-argv, as everywhere else).

    drop_user_schemas=True makes the load DROP + recreate each dumped user
    schema (see pitr.filter_system_schemas) so the subsequent binlog replay
    applies onto exactly the dump state — the restore/drill loads set it."""
    full_env = dict(os.environ)
    full_env.update(env)
    # surrogateescape BOTH ways: a 19-year OSCAR-lineage dump can carry
    # non-UTF-8 bytes (mixed-charset history), and strict decoding raised an
    # uncaught UnicodeDecodeError AFTER the destructive load had begun. The
    # escape round-trips every byte exactly (never errors, never corrupts —
    # unlike errors="replace", which would silently rewrite restored data);
    # the schema markers the filter keys on are plain ASCII either way.
    proc = subprocess.Popen(  # noqa: S603
        runner.podman_user_argv(podman_args),
        stdin=subprocess.PIPE, text=True, encoding="utf-8",
        errors="surrogateescape", env=full_env,
    )
    assert proc.stdin is not None  # noqa: S101 — Popen(stdin=PIPE) guarantees it
    stats: dict = {}
    try:
        with open(dump_path, encoding="utf-8", errors="surrogateescape") as fin:
            for line in pitr.filter_system_schemas(
                fin, drop_user_schemas=drop_user_schemas, stats=stats
            ):
                proc.stdin.write(line)
        proc.stdin.close()
    except (OSError, BrokenPipeError):
        with contextlib.suppress(OSError):
            proc.stdin.close()
        proc.wait()
        return False
    if drop_user_schemas and not stats.get("dropped"):
        # No `-- Current Database:` sections recognized — the load silently
        # degraded to the old merge semantics (post-dump tables persist and
        # can abort the binlog replay). Loud, not fatal: the load itself
        # still applied everything the dump carried.
        warn(
            f"dump {dump_path.name} carried no recognizable schema sections — the load "
            f"MERGED over the existing schemas instead of drop-and-recreating them; a "
            f"binlog replay may collide with tables created after this dump"
        )
    return proc.wait() == 0


def _verify_docs_content(ctx: BackupContext) -> bool:
    """BYTE-verify one document from the docs snapshot: the listability gate
    above only proves paths exist — a torn/truncated capture (the store is
    snapshotted live, without quiesce) still listed fine and the weekly
    check --read-data verifies REPOSITORY integrity, not source fidelity.
    The OLDEST regular file in the live store is the sentinel (most
    certainly captured, least likely to have changed since): its restored
    bytes must match the live bytes. A size mismatch means the file changed
    after the snapshot (legitimate — skipped with a note); same-size
    different-bytes is corruption and FAILS the drill. Empty store: skip."""
    import hashlib

    store = ctx.s.data_dir / "OscarDocument"
    oldest: Optional[Path] = None
    oldest_mtime = 0.0
    for p in store.rglob("*"):
        try:
            if not p.is_file():
                continue
            mt = p.stat().st_mtime
        except OSError:
            continue
        if oldest is None or mt < oldest_mtime:
            oldest, oldest_mtime = p, mt
    if oldest is None:
        return True
    rel = oldest.relative_to(store)
    sentinel = ctx.backup_dir / f".verify-doc.{os.getpid()}"
    try:
        fd = os.open(sentinel, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            cp = ctx.run_restic(
                ["dump", "latest", "--host", ctx.snapshot_host, "--tag", "docs",
                 f"/backup/OscarDocument/{rel}"],
                stdout=f,
            )
        if cp.returncode != 0:
            warn(
                f"restore drill FAILED — the docs snapshot cannot restore the store's "
                f"oldest document ({rel}): the snapshot is missing content the live "
                f"store has carried the longest"
            )
            return False
        live_bytes = oldest.read_bytes()
        restored_bytes = sentinel.read_bytes()
        if len(live_bytes) != len(restored_bytes):
            log(
                f"restore drill: sentinel document {rel} changed size since the last "
                f"docs snapshot — byte comparison skipped for this run"
            )
            return True
        if hashlib.sha256(live_bytes).digest() != hashlib.sha256(restored_bytes).digest():
            warn(
                f"restore drill FAILED — the docs snapshot's copy of {rel} DIFFERS from "
                f"the live file at identical size: the captured document is corrupt "
                f"(torn live-store capture?)"
            )
            return False
        log(f"Restore drill: document content byte-verified ({rel})")
        return True
    except OSError as e:
        warn(f"restore drill: could not byte-verify a sentinel document ({e}) — "
             f"listability was the only docs check this run")
        return True
    finally:
        with contextlib.suppress(OSError):
            sentinel.unlink()


def _snapshot_listing_count(ctx: BackupContext, tag: str, needle: str) -> int:
    """Count matching ENTRY paths in the latest snapshot listing. STREAMED,
    never captured: `restic ls` prints header lines (an EMPTY snapshot
    already has some), and a mature document store lists 10^5+ paths —
    holding that in the root process on a memory-capped EMR host is the
    exact regression the bash's streamed `grep -c` engineered against."""
    proc = subprocess.Popen(  # noqa: S603
        ctx.runner.podman_user_argv([
            "run", "--rm", "-i", "--pull=missing", "--hostname", ctx.snapshot_host,
            "--env-file", str(ctx.env_file),
            *ctx.repo_env,
            "-v", f"{ctx.cache_dir}:/root/.cache/restic",
            "-v", f"{ctx.s.data_dir}/OscarDocument:/backup/OscarDocument:ro",
            "-v", f"{ctx.s.emr_home}/container:/backup/container:ro",
            "-v", f"{ctx.binlog_dir}:/backup/binlog:ro",
            *ctx.repo_mount,
            ctx.restic_image,
            "ls", "latest", "--host", ctx.snapshot_host, "--tag", tag,
        ]),
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
    )
    count = 0
    assert proc.stdout is not None  # noqa: S101 — Popen(stdout=PIPE) guarantees it
    for line in proc.stdout:
        if needle in line:
            count += 1
    if proc.wait() != 0:
        return 0
    return count


def _forget_own_tag(ctx: BackupContext, tag: str, keep: List[str]) -> None:
    """Per-mode retention: the nightly full used to be the ONLY
    place binlog/docs snapshots were forgotten — while fulls fail for days
    (dump error, engine-audit refusal), the 15-minute binlog/docs modes kept
    accumulating ~192 snapshots/day with NO pruning, and a local repo could
    fill the disk (breaking the very shipping that still worked). Each mode
    now applies its own --host-scoped forget (no --prune — that stays in the
    nightly full; forget alone is cheap metadata). WARN-only on failure: a
    15-minute cadence must not page-storm; the nightly full still hard-fails
    retention errors."""
    if ctx.run_restic(
        ["forget", "--host", ctx.snapshot_host, "--tag", tag, *keep]
    ).returncode != 0:
        warn(f"restic forget --tag {tag} failed in the {tag} run — retention for this "
             f"tier rides on the nightly full (which hard-fails if it stays broken)")


def _verify_restore(ctx: BackupContext) -> bool:
    """Weekly restore drill: prove the latest db dump AND the binlog chain
    actually restore. `restic check` only validates repository integrity, not
    that the data loads. All restic reads are --host-scoped to THIS
    instance's snapshot hostname so a shared repository can never restore or
    validate another clinic's PHI.

    NOTE: the binlog-replay leg touches podman/mariadb-binlog and cannot be
    exercised in the hermetic test suite; validate with a live
    `carlos-ctl backup verify` on a real host after changes here."""
    s = ctx.s
    runner = ctx.runner
    # Reap any scratch dir orphaned by a prior hard-killed drill — a stale
    # .verify.* holds a plaintext whole-DB dump. 3h cutoff clears the
    # abandoned, spares a run somehow still going.
    now = time.time()
    for stale in ctx.backup_dir.glob(".verify.*"):
        with contextlib.suppress(OSError):
            if stale.is_dir() and now - stale.stat().st_mtime > 3 * 3600:
                shutil.rmtree(stale, ignore_errors=True)

    # Cheap listability gates FIRST (no throwaway DB needed): broken/empty
    # document and config backups must fail the drill, not just the db leg.
    docs_min = int(s.get("CARLOS_DOCS_MIN_FILES", "1") or "1")
    if docs_min > 0 and _snapshot_listing_count(ctx, "docs", "/backup/OscarDocument/") == 0:
        warn(
            "restore drill FAILED — no listable 'docs' snapshot, or it lists no document "
            "entries (document backups never ran, or an unmounted/mis-pathed OscarDocument "
            "is being snapshotted empty; set CARLOS_DOCS_MIN_FILES=0 only for a "
            "pre-go-live install)"
        )
        return False
    if docs_min > 0 and not _verify_docs_content(ctx):
        return False
    # DR contract: the encrypted secrets bundle rides INSIDE the backup, so a
    # restore needs only the two escrowed off-host secrets (the age key and
    # the restic.env content) — nothing else. Only asserted when sealed.
    if s.secrets_bundle.is_file() and \
            _snapshot_listing_count(ctx, "files", "conf/secrets/secrets.enc.yaml") == 0:
        warn(
            "restore drill FAILED — no listable 'files' snapshot, or it does not contain "
            "conf/secrets/secrets.enc.yaml (the DR contract: the encrypted bundle must "
            "ride in the backup)"
        )
        return False

    # Tmpfs preflight: the drill restores the whole DB into a
    # RAM tmpfs (VERIFY_TMPFS_SIZE, default 4g). Once the live DB outgrows
    # it, the weekly drill — the only end-to-end restorability proof — fails
    # every week until resized. Warn ahead of time from restic's own stats
    # (restore size x1.2 headroom for InnoDB overhead); best-effort — the
    # load failure below remains the backstop.
    cp_stats = ctx.run_restic(
        ["stats", "latest", "--host", ctx.snapshot_host, "--tag", "db",
         "--mode", "restore-size", "--json"],
        capture=True, quiet=True,
    )
    if cp_stats.returncode == 0:
        with contextlib.suppress(ValueError, KeyError, TypeError):
            import json as _json

            total = int(_json.loads(cp_stats.stdout or "{}").get("total_size", 0))
            tmpfs_mib = size_to_mib(ctx.verify_tmpfs_size)
            if total and tmpfs_mib and (total * 1.2) / (1024 * 1024) > tmpfs_mib:
                warn(
                    f"restore drill: the latest db snapshot restores to "
                    f"~{total // (1024 * 1024)} MiB but VERIFY_TMPFS_SIZE is "
                    f"{ctx.verify_tmpfs_size} (~{tmpfs_mib} MiB) — the drill will start "
                    f"failing once the load outgrows the tmpfs. Raise VERIFY_TMPFS_SIZE "
                    f"in restic.env (VERIFY_MEM_LIMIT auto-follows at tmpfs+2G)."
                )

    rootpw = pysecrets.token_hex(16)
    name = f"{s.instance}-verify-{os.getpid()}"
    ctx.backup_dir.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix=".verify.", dir=str(ctx.backup_dir)))
    # The rootless restic container restores the binlog snapshot into the
    # scratch dir, so it must be writable by the service user.
    with contextlib.suppress(OSError, KeyError):
        import pwd

        os.chown(scratch, pwd.getpwnam(s.service_user).pw_uid, -1)
    sqlfile = scratch / "db.sql"

    def vexec(args: List[str], *, input_text: Optional[str] = None,
              stdin: Optional[IO[bytes]] = None,
              capture: bool = False, quiet: bool = False) -> subprocess.CompletedProcess:
        # Root password forwarded by NAME (never an argv token).
        return runner.podman_user(
            ["exec", "-i", "-e", "MYSQL_PWD", name, *args],
            env={"MYSQL_PWD": rootpw}, input_text=input_text, stdin=stdin,
            capture=capture, quiet=quiet,
        )

    try:
        log(f"Restore drill: starting throwaway MariaDB ({s.get('DB_IMAGE')})")
        # Container memory cap so the drill can't pressure host RAM into an
        # OOM that kills a LIVE pod. Defaults to VERIFY_TMPFS_SIZE + 2 GiB
        # (derived in BackupContext — the tmpfs pages count against the
        # container's cgroup, so the cap must exceed tmpfs + mariadbd
        # overhead); VERIFY_MEM_LIMIT overrides, =0 disables.
        mem_args = ["--memory", ctx.verify_mem_limit] if ctx.verify_mem_limit else []
        cp = runner.podman_user(
            ["run", "-d", "--rm", "--name", name, *mem_args,
             "--tmpfs", f"/var/lib/mysql:rw,size={ctx.verify_tmpfs_size}",
             "-e", "MARIADB_ROOT_PASSWORD", s.get("DB_IMAGE"),
             # The drill server mounts no zz-carlos.cnf — mirror its packet
             # ceiling (1G, sized for --hex-blob doubling) or a large INSERT
             # the LIVE server accepts would fail only here (false drill
             # failure).
             "--max-allowed-packet=1G"],
            env={"MARIADB_ROOT_PASSWORD": rootpw}, quiet=True,
        )
        if cp.returncode != 0:
            warn(
                "restore drill FAILED — could not start the throwaway MariaDB. If podman "
                "rejected the --memory cap (rootless host without cgroup-v2 memory "
                "delegation), set VERIFY_MEM_LIMIT=0 in restic.env to disable it."
            )
            return False
        for _ in range(60):
            # NOT a bare socket `mariadb-admin ping`: the mariadb image's
            # entrypoint initializes an empty datadir by starting a TEMPORARY
            # server on the SAME unix socket, then shutting it down before
            # exec'ing the real one. A socket ping is satisfied by that temp
            # server (measured: OK at 3.6 s, socket gone 4.5-6.4 s, real
            # server at 6.5 s), so the drill broke out of this loop, walked
            # into the shutdown gap, and failed the load with a raw
            # "ERROR 2002 ... (2)" under the VERIFY_TMPFS_SIZE message below —
            # every run, on a normal host, not just under load. The temp
            # server runs --skip-networking, so the image's own healthcheck
            # and a TCP ping are only satisfiable by the REAL server; this is
            # the same gate the pod specs' db readinessProbe uses.
            if vexec(["sh", "-c",
                      "healthcheck.sh --connect --innodb_initialized 2>/dev/null"
                      " || mariadb-admin --protocol=tcp --host=127.0.0.1 --user=root"
                      " ping --silent 2>/dev/null"], quiet=True).returncode == 0:
                break
            time.sleep(2)
        else:
            # Exhaustion must be TERMINAL: falling through to the
            # load made a never-ready scratch server fail with the dump-load
            # message below, whose "raise VERIFY_TMPFS_SIZE" guidance sent
            # the operator at a tmpfs-sizing fix for what was a container
            # startup failure (seen live under image-pull contention).
            warn(
                "restore drill FAILED — the throwaway MariaDB never became ready "
                "within 120 s (container startup/image contention, or the DB_IMAGE "
                "entrypoint failing; check `podman logs` for it while it runs). This "
                "is NOT a VERIFY_TMPFS_SIZE problem — re-run the drill; if it "
                "persists, start the scratch container by hand to see why."
            )
            return False
        # Restore the dump to a FILE, STREAMED (a multi-GB PHI dump must
        # never be buffered in RAM); 0600 from birth.
        fd = os.open(sqlfile, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            cp = ctx.run_restic(
                ["dump", "latest", "--host", ctx.snapshot_host, "--tag", "db",
                 "carlos-databases.sql"],
                stdout=f,
            )
        if cp.returncode != 0:
            warn("restore drill FAILED — could not restore carlos-databases.sql from the "
                 "repository")
            return False
        # Load into the scratch server, EXCLUDING the system schemas (shared
        # stream filter — reloading production account rows over the scratch
        # server's own root would break the drill's subsequent auth). PIPED
        # straight into the client: one on-disk dump copy, constant memory —
        # a second staged copy would double the free-space requirement and
        # risk leaking a partial plaintext PHI file on an error path.
        # The scratch server can DIE between the ping loop and here — an
        # `--rm` container that mariadbd exits (OOM under the memory cap, or
        # a crash under host I/O/image-pull contention) is gone by load time,
        # and the load then fails with a raw "Can't connect to socket 2002".
        # Diagnose that as a startup/liveness failure, NOT as a tmpfs-sizing
        # problem — the VERIFY_TMPFS_SIZE guidance below misdirects the
        # operator when the container simply isn't there.
        if not runner.ok(runner.podman_user_argv(
            ["container", "exists", name]
        )) or "running" not in runner.output(runner.podman_user_argv(
            ["inspect", "-f", "{{.State.Status}}", name]
        )).strip().lower():
            warn(
                "restore drill FAILED — the throwaway MariaDB EXITED before the dump "
                "load (it passed the readiness ping, then died: an OOM under the drill "
                "memory cap, or a crash under host I/O/image-pull contention). This is "
                "NOT a VERIFY_TMPFS_SIZE problem — check `podman logs` for a scratch "
                "container while a drill runs, and re-run; raise VERIFY_MEM_LIMIT if it "
                "was OOM-killed."
            )
            return False
        if not _pipe_filtered_dump(
            runner, sqlfile,
            # --init-command WITHOUT embedded quotes: this is an argv list (no
            # shell) — quotes would ride into the SQL and fail the connect.
            # sql_log_bin=0 keeps the drill identical to the live load (the
            # scratch server has no binlog, so it is a no-op here).
            ["exec", "-i", "-e", "MYSQL_PWD", name, "mariadb", "--user=root",
             "--max-allowed-packet=1G", "--init-command=SET SESSION sql_log_bin=0"],
            {"MYSQL_PWD": rootpw},
            drop_user_schemas=True,
        ):
            warn(
                f"restore drill FAILED — could not load carlos-databases.sql into the "
                f"scratch DB. If the database has outgrown the drill's RAM scratch "
                f"space (currently VERIFY_TMPFS_SIZE={ctx.verify_tmpfs_size}), raise "
                f"VERIFY_TMPFS_SIZE in restic.env — it must exceed the restored "
                f"database size."
            )
            return False
        # Replay the binlog chain from the dump's recorded anchor so the
        # actual point-in-time-recovery path is proven, not just the base dump.
        anchor = pitr.dump_anchor(sqlfile)
        if anchor:
            log(f"Restore drill: replaying binlogs from {anchor.log_file}:{anchor.log_pos}")
            ctx.extra_mount = ["-v", f"{scratch}:/restore-scratch"]
            cp = ctx.run_restic(
                ["restore", "latest", "--host", ctx.snapshot_host, "--tag", "binlog",
                 "--target", "/restore-scratch/binlog"],
                quiet=True,
            )
            ctx.extra_mount = []
            if cp.returncode != 0:
                warn("restore drill FAILED — could not restore the binlog snapshot for "
                     "replay")
                return False
            bdir = scratch / "binlog" / "backup" / "binlog"
            # Chain identity: a mismatch between the dump's originating server
            # and the chain's shipping server means the repo chain got
            # polluted (a rebuilt server shipped over it) — the drill is the
            # honest signal for exactly that, so it FAILS. Either side
            # unknown = pre-identity dump/snapshots: warn, sequence
            # contiguity stays the only check (legacy semantics).
            dump_ident = pitr.dump_server_identity(sqlfile)
            chain_ident = pitr.read_identity_sidecar(bdir)
            if dump_ident and chain_ident and dump_ident != chain_ident:
                warn(
                    f"restore drill FAILED — the binlog chain was shipped by server "
                    f"{chain_ident} but this dump was taken on {dump_ident}: the "
                    f"repository chain has been polluted by another server's binlogs "
                    f"(rebuilt host shipping without a completed restore?)"
                )
                return False
            if not (dump_ident and chain_ident):
                # Name WHICH side is unidentified. The old single message said
                # "pre-identity dump/snapshots" for every case, which read as
                # "your old data predates the feature" even when the CURRENT
                # run could not determine an identity at all — the shape this
                # deployment was permanently in while the id probe was a
                # MySQL-only variable.
                missing = " and ".join(
                    part for part, have in (("dump", dump_ident), ("binlog chain", chain_ident))
                    if not have
                )
                warn(
                    f"restore drill: binlog chain identity UNVERIFIED — the {missing} "
                    f"carries no lineage id (snapshots taken before the id existed, or a "
                    f"datadir whose id could not be read/minted). Sequence contiguity is "
                    f"the only chain check for this drill; it re-verifies once a full "
                    f"backup and a binlog ship have both run with an identified datadir."
                )
            # Validated chain (anchor present + contiguous): the drill is the
            # weekly proof PITR works, so a broken chain must FAIL it — an
            # unvalidated selection would replay a wrong slice and pass green.
            replay, problem = pitr.select_replay_chain(bdir, anchor.log_file)
            if problem:
                warn(f"restore drill FAILED — {problem}")
                return False
            if replay:
                cpv = runner.podman_user(["cp", str(bdir), f"{name}:/tmp/binlog-replay"],
                                         quiet=True)
                if cpv.returncode != 0:
                    # A failed copy would leave /tmp/binlog-replay absent or
                    # partial, and the replay below would then either error
                    # opaquely or (worse) replay a TRUNCATED chain and call it
                    # a passing drill. Fail the drill loudly instead.
                    warn(f"restore drill FAILED — could not copy binlogs into {name} "
                         f"for replay (podman cp rc={cpv.returncode})")
                    return False
                files = " ".join(f"/tmp/binlog-replay/{b}" for b in replay)  # noqa: S108 — in-container path
                # set -o pipefail INSIDE the container shell: without it the
                # pipeline's status is the trailing client's — a mid-stream
                # mariadb-binlog failure (corrupt/truncated binlog) would exit
                # 0 and green-light a broken PITR chain. bash (not sh): the
                # mariadb image always ships bash.
                cp = vexec([
                    "bash", "-c",
                    # --no-defaults (must be first): mariadb-binlog reads the
                    # [client] group, and the operator cnf's
                    # default-character-set there is an "unknown variable"
                    # that aborts it. The drill's scratch container has no
                    # such cnf, but the LIVE restore's does — keep both replay
                    # invocations identical so the drill rehearses the real one.
                    # --init-command single-quoted: this rides inside a remote
                    # bash -c string — unquoted, bash word-splits the SQL.
                    # sql_log_bin=0 mirrors the live replay (no-op here: the
                    # scratch server has no binlog).
                    f"set -o pipefail; mariadb-binlog --no-defaults "
                    f"--start-position={anchor.log_pos} {files} | "
                    f"mariadb --user=root --max-allowed-packet=1G "
                    f"--init-command='SET SESSION sql_log_bin=0'",
                ])
                if cp.returncode != 0:
                    warn("restore drill FAILED — binlog replay onto the scratch DB errored")
                    return False
                log(f"Restore drill: replayed {len(replay)} binlog(s)")
        else:
            # No PITR anchor means the point-in-time-recovery chain — the
            # whole reason for the binlog stream — was NOT exercised.
            # Warn-then-OK would let a broken chain pass green.
            if s.get("CARLOS_DRILL_ALLOW_NO_PITR", "0") != "1":
                warn(
                    "restore drill FAILED — the dump carries NO binlog anchor "
                    "(--master-data), so point-in-time recovery was NOT exercised (is "
                    "binary logging on?). Set CARLOS_DRILL_ALLOW_NO_PITR=1 to accept a "
                    "base-dump-only drill."
                )
                return False
            warn("restore drill: dump carries no binlog anchor — PITR replay NOT "
                 "exercised (CARLOS_DRILL_ALLOW_NO_PITR=1 set, accepting a base-dump-only "
                 "drill)")
        # Sanity check core CARLOS tables across the clinical, security, and
        # document domains. A missing table (truncated dump) errors the COUNT;
        # `provider` must additionally be NON-EMPTY (a working CARLOS always
        # has providers) so an empty-but-present table can't pass as a good
        # restore. The others are presence-only: a fresh-ish install may
        # legitimately have no drugs/prescriptions/notes/documents yet.
        for table in ("provider", "demographic", "appointment", "security", "drugs",
                      "prescription", "casemgmt_note", "document"):
            cp = vexec(
                ["mariadb", "--user=root", "-N", "-e",
                 f"SELECT COUNT(*) FROM oscar.{table}"],  # noqa: S608 — table from the literal tuple above
                capture=True,
            )
            count = (cp.stdout or "").strip()
            if not count.isdigit():
                warn(
                    f"restore drill FAILED — sanity query on oscar.{table} returned no row "
                    f"count (dump truncated or missing tables?)"
                )
                return False
            if table == "provider" and int(count) == 0:
                warn("restore drill FAILED — oscar.provider is EMPTY in the restored dump "
                     "(a valid CARLOS DB always has providers)")
                return False
            log(f"  oscar.{table} rows in the restored dump: {count}")
        log("Restore drill OK — docs/files snapshots listable, dump loaded, binlogs "
            "replayed, core tables present")
        return True
    finally:
        # Reap the scratch container AND the restored plaintext PHI on every
        # exit path.
        runner.podman_user(["rm", "-f", name], quiet=True)
        shutil.rmtree(scratch, ignore_errors=True)


def _restore_pitr(ctx: BackupContext, argv: List[str]) -> bool:
    """Guided point-in-time restore INTO THE LIVE DATABASE — the incident-
    recovery path the README runbook used to require operators to hand-type
    (easy to mis-read the anchor or stop-datetime under pressure). Safe-by-
    default: refuses without an explicit confirmation, and --dry-run shows
    exactly what it would do.

    Load semantics: every schema carried by the dump is DROPPED and re-created
    from it (DROP DATABASE injected by the stream filter), so the binlog
    replay applies onto exactly the dump's state — a merge-load left post-dump
    tables in place and the replayed CREATE TABLE aborted the restore (1050).
    The mysql/sys system schemas and any user database ABSENT from the dump
    are untouched; the one residual is a DATABASE created after the dump,
    whose replayed CREATE DATABASE can still collide (1007). Load and replay
    both run with sql_log_bin=0, so a failed attempt can be re-run as-is: the
    reload resets to dump state and the chain never accumulates re-logged
    copies of replayed events (retry double-apply, 1062).

    Caveats: --stop-datetime granularity is 1 second and interpreted in the db
    container's TZ (America/Toronto, which observes DST) — a time in the
    fall-back hour is ambiguous; use binlog coordinates for a precise cut.
    A user-supplied --snapshot=<id> selects the DB-dump snapshot only; the
    binlog chain is still resolved from 'latest --tag binlog', so --snapshot is
    effectively base-dump-only unless that snapshot's chain is still present.

    Data-safety override knobs (each accepts a loss the restore otherwise
    refuses): CARLOS_RESTORE_BASE_DUMP_ONLY (unusable chain -> load the dump
    only), CARLOS_STOP_BEFORE_DUMP_OK (--stop-datetime predates the dump),
    CARLOS_ACCEPT_BINLOG_IDENTITY_MISMATCH (replay a foreign server's chain),
    CARLOS_RESTORE_ACCEPT_UNSHIPPED (restore-to-latest when the final binlog
    ship failed), and CARLOS_STOP_PAST_CHAIN_END_OK (--stop-datetime postdates
    the newest shipped binlog, so replay stops short at the chain end)."""
    s = ctx.s
    runner = ctx.runner
    snap, stop, dry = "latest", "", False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--dry-run":
            dry = True
            i += 1
        elif a.startswith("--snapshot="):
            snap = a.split("=", 1)[1]
            i += 1
        elif a == "--snapshot" and i + 1 < len(argv):
            snap = argv[i + 1]
            i += 2
        elif a.startswith("--stop-datetime="):
            stop = a.split("=", 1)[1]
            i += 1
        elif a == "--stop-datetime" and i + 1 < len(argv):
            stop = argv[i + 1]
            i += 2
        else:
            warn(f"restore: unknown argument '{a}'")
            return False
    # Strict shape BEFORE anything runs: the value is interpolated (quoted)
    # into the in-container replay shell, so only a plain timestamp may pass
    # — a quote/metacharacter must die here, not in the container.
    if stop and not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}(:\d{2})?)?", stop
    ):
        warn(
            f"restore: --stop-datetime '{stop}' is not a plain timestamp "
            f"(YYYY-MM-DD [HH:MM[:SS]]) — refusing"
        )
        return False
    # Normalize ONCE, here, so every downstream consumer (the dump-instant
    # guard AND the mariadb-binlog replay clause) sees the same canonical
    # 'YYYY-MM-DD HH:MM:SS'. mariadb-binlog does not parse the ISO-8601 'T'
    # separator — a raw 'T' form passed to --stop-datetime would error out
    # (or worse, be misparsed) AFTER the destructive load already ran.
    if stop:
        stop = pitr.normalize_stop_datetime(stop)
    if not ctx.db_user:
        warn("restore: no db credentials resolved")
        return False
    # The live overwrite needs ROOT (drops/recreates schemas + accounts). In
    # a DISASTER RECOVERY rebuild carlos-app.env is reconstructed from the
    # secrets-stripped .dr copy and does NOT carry the root password yet —
    # fall back to the sealed bundle (seal ingests carlos.db_root_password)
    # so the restore works before the operator hand-re-adds it.
    root_pw = s.get("CARLOS_DB_ROOT_PASSWORD")
    if not root_pw and s.secrets_bundle.is_file():
        from . import secrets as secrets_mod

        with contextlib.suppress(CtlError):
            root_pw = secrets_mod.bundle_get(runner, "carlos", "db_root_password")
    if not root_pw:
        warn(
            f"restore: set CARLOS_DB_ROOT_PASSWORD (the live overwrite runs as MariaDB "
            f"root) — it is in {s.env_file}, or seal a bundle so it can be recovered from "
            f"carlos.db_root_password"
        )
        return False
    names = runner.output(runner.podman_user_argv(["ps", "--format", "{{.Names}}"]))
    if f"{s.app_pod}-db" not in names.splitlines():
        warn(f"restore: the {s.app_pod}-db container is not running — start the stack "
             f"first ('carlos-ctl play')")
        return False

    # Stage the dump to a 0600 file and verify its footer before touching the
    # live DB.
    dump_file = ctx.backup_dir / f".restore-databases.sql.{os.getpid()}"
    scratch: Optional[Path] = None  # binlog-snapshot staging; cleaned in finally
    try:
        log(f"restore: fetching db dump (snapshot {snap})")
        fd = os.open(dump_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            cp = ctx.run_restic(
                ["dump", snap, "--host", ctx.snapshot_host, "--tag", "db",
                 "carlos-databases.sql"],
                stdout=f,
            )
        if cp.returncode != 0:
            warn(f"restore: could not fetch carlos-databases.sql from snapshot {snap}")
            return False
        if not pitr.dump_footer_complete(dump_file):
            warn("restore: fetched dump is missing its '-- Dump completed' footer "
                 "(truncated?) — refusing to load it")
            return False
        anchor = pitr.dump_anchor(dump_file)
        # EVERY refusal below runs BEFORE the destructive load — discovering
        # "your requested instant is unreachable" after the live database was
        # already overwritten destroys the pre-restore state for a restore
        # that was going to be refused anyway.
        #
        # (a) --stop-datetime needs an anchor at all.
        if stop and not anchor:
            warn(
                f"restore: --stop-datetime '{stop}' was requested but this dump carries "
                f"NO binlog anchor (--master-data; was binary logging on?) — the "
                f"requested instant cannot be reached. Re-run without --stop-datetime "
                f"to accept a base-dump-only restore."
            )
            return False
        # (b) a stop-datetime earlier than the dump's instant is unreachable:
        # mariadb-binlog would emit zero events, exit 0, and the run would
        # report success while the database sits at the dump's LATER state.
        # The comparable instant we HAVE is the dump-completion footer, which
        # postdates the true --single-transaction snapshot (dump START) by
        # the dump's duration — a stop inside that window is actually
        # reachable, so the refusal is deliberately overridable.
        if stop:
            # `stop` was canonicalized at arg parse ('YYYY-MM-DD HH:MM:SS'),
            # so it compares lexicographically against the footer instant.
            completed = pitr.dump_completed_at(dump_file)
            if completed and stop < completed \
                    and s.get("CARLOS_STOP_BEFORE_DUMP_OK", "0") != "1":
                warn(
                    f"restore: --stop-datetime '{stop}' is EARLIER than this dump's "
                    f"completion instant ({completed}) — replay cannot rewind; the result "
                    f"would silently be the dump's later state. Restore an OLDER snapshot "
                    f"(--snapshot=<ID>; list with restic snapshots) or drop "
                    f"--stop-datetime. If the instant lies between this dump's START and "
                    f"its completion (the dump ran across it), it IS reachable — re-run "
                    f"with CARLOS_STOP_BEFORE_DUMP_OK=1."
                )
                return False
        # Restore-to-latest on a LIVE host: the freshest local binlogs are
        # shipped AFTER the confirmation gate and AFTER the carlos/drugref
        # containers are stopped. With the writers quiesced,
        # FLUSH BINARY LOGS closes a binlog holding every committed write, so
        # nothing a clinician saved during the (possibly minutes-long)
        # confirmation prompt can be stranded in the still-active binlog.
        # The old order shipped BEFORE the prompt: any write landing between
        # the ship and the app-stop went into the new active binlog, was
        # excluded from the shipped chain, and silently vanished from a
        # "restore complete". A --stop-datetime restore ships TOO: the repo
        # chain ends at the last 15-minute timer fire, so a stop instant
        # PAST that end would replay to the chain's end, exit 0
        # (mariadb-binlog does not error when --stop-datetime is never
        # reached), and report a successful point-in-time restore while
        # silently missing up to one ship interval of committed writes that
        # sit in the LOCAL binlogs. Shipping extends the chain to now; the
        # replay's --stop-datetime clause still cuts at the requested
        # instant. Skipped only for --dry-run (must touch NOTHING — the ship
        # FLUSHes the live DB and writes to the repo).
        #
        # CRITICAL — only ship when the LOCAL binlogs genuinely continue
        # THIS dump's chain, i.e. the newest local sequence is STRICTLY GREATER
        # than the dump anchor's sequence. In a disaster-recovery rebuild the
        # runbook's `carlos-ctl play` starts a FRESH MariaDB that creates an
        # unrelated binlog.000001 before restore runs. Shipping that as the new
        # 'latest' binlog snapshot would MASK the real chain (the fetch below
        # pulls 'latest'), so select_replay_chain would see the true anchor as
        # "pruned" and fall back to base-dump-only — up to a full day of
        # committed clinical writes silently lost, or (if the anchor sequence
        # were low enough to collide) unrelated events replayed as corruption.
        # `>` not `>=`: a fresh server sits at binlog.000001, and 1 > anchor_seq
        # is false for every real anchor, so DR never ships; the only
        # same-host case it skips is a dump taken so recently no binlog rotation
        # has happened yet (newest == anchor), where deferring to the repo chain
        # costs at most the sub-rotation tail — the safe direction for PHI.
        local_newest = pitr.newest_local_binlog_seq(ctx.binlog_dir)
        anchor_seq = pitr.binlog_seq(anchor.log_file) if anchor else None
        local_continues_chain = (
            local_newest is not None and anchor_seq is not None
            and local_newest > anchor_seq
        )
        # Identity belt on top of the sequence arithmetic: when the live
        # server and the dump's originating server are BOTH known and differ,
        # the local binlogs are another server's regardless of how their
        # sequence numbers happen to compare — never pre-ship them.
        dump_ident = pitr.dump_server_identity(dump_file)
        live_ident = ctx.server_identity()
        if local_continues_chain and dump_ident and live_ident \
                and dump_ident != live_ident:
            warn(
                "restore: the live server's identity differs from the dump's "
                "originating server — local binlogs are NOT this dump's chain; "
                "not pre-shipping"
            )
            local_continues_chain = False
        # Chain fetch + validation, factored so --dry-run (exact plan, no
        # mutation) and the live path (which runs it AFTER the confirm gate
        # and app-stop share one implementation. Read-only
        # against the repository: with the anchor pruned (any dump older than
        # the ~9-day binlog window) or a mid-chain gap, replay would apply
        # --start-position to the WRONG file / silently skip lost
        # transactions and corrupt the freshly loaded database — every
        # refusal here still runs BEFORE the destructive load. Returns the
        # replay list ([] = base-dump-only), or None to refuse the restore.
        def fetch_chain(app_stopped: bool = False) -> Optional[List[str]]:
            nonlocal scratch
            # Refusals after the app-stop must say so and name the recovery
            # command; pre-confirm/pre-stop refusals (dry-run, and live
            # restores with no final ship — edge case) leave the app
            # serving and need no hint.
            down_hint = (
                " The carlos/drugref containers are STOPPED (the EMR front door "
                "is DOWN) — run 'carlos-ctl play' to bring the app back up."
                if app_stopped else ""
            )
            if not anchor:
                return []
            scratch = Path(tempfile.mkdtemp(prefix=".restore.", dir=str(ctx.backup_dir)))
            with contextlib.suppress(OSError, KeyError):
                import pwd

                os.chown(scratch, pwd.getpwnam(s.service_user).pw_uid, -1)
            ctx.extra_mount = ["-v", f"{scratch}:/restore-scratch"]
            # ALWAYS "latest" here, never the user's --snapshot value: restic
            # applies --host/--tag filters only when resolving 'latest'. An
            # explicit DB-dump snapshot ID would restore THAT snapshot (the
            # dump) into the binlog scratch — the chain dir would never exist
            # and select_replay_chain would misreport the anchor as pruned,
            # steering a --snapshot restore into base-dump-only data loss.
            # The docstring contract ("the binlog chain is still resolved from
            # 'latest --tag binlog'") and the drill both depend on this.
            cp = ctx.run_restic(
                ["restore", "latest", "--host", ctx.snapshot_host, "--tag", "binlog",
                 "--target", "/restore-scratch/binlog"],
                quiet=True,
            )
            ctx.extra_mount = []
            if cp.returncode != 0:
                warn("restore: could not fetch the binlog snapshot for replay — "
                     "REFUSING before the live database is touched; fix the repo "
                     "access and re-run." + down_hint)
                return None
            bdir = scratch / "binlog" / "backup" / "binlog"
            # Chain identity — BEFORE the destructive load: replaying a chain
            # shipped by a different server than the one this dump came from
            # would apply unrelated events over the freshly loaded database.
            chain_ident = pitr.read_identity_sidecar(bdir)
            if dump_ident and chain_ident and dump_ident != chain_ident \
                    and not s.flag("CARLOS_ACCEPT_BINLOG_IDENTITY_MISMATCH"):
                warn(
                    f"restore: the fetched binlog chain was shipped by server "
                    f"{chain_ident} but this dump was taken on {dump_ident} — "
                    f"replaying it would apply an UNRELATED server's events over the "
                    f"restored database. REFUSING before the live database is "
                    f"touched. If you are certain the chain is right, re-run with "
                    f"CARLOS_ACCEPT_BINLOG_IDENTITY_MISMATCH=1." + down_hint
                )
                return None
            if not (dump_ident and chain_ident):
                missing = " and ".join(
                    part for part, have in (("dump", dump_ident), ("binlog chain", chain_ident))
                    if not have
                )
                warn(
                    f"restore: binlog chain identity UNVERIFIED — the {missing} carries no "
                    f"lineage id (snapshots taken before the id existed, or a datadir whose "
                    f"id could not be read/minted). Sequence contiguity is the only chain "
                    f"check for this restore — confirm by hand that this repository's "
                    f"binlogs came from the same server as this dump."
                )
            selected, problem = pitr.select_replay_chain(bdir, anchor.log_file)
            if problem:
                if stop:
                    warn(
                        f"restore: {problem}. The requested --stop-datetime CANNOT be "
                        f"reached — REFUSING before the live database is touched. "
                        f"Restore a newer dump, or re-run without --stop-datetime to "
                        f"accept base-dump-only." + down_hint
                    )
                    return None
                # Restore-to-latest with an unusable chain would load the base
                # dump ONLY — the DB ends at the dump's instant and every write
                # after it is LOST. That is exactly the DR data-loss this path
                # must not do SILENTLY: refuse before touching the live database
                # and make the operator either restore a newer snapshot or
                # explicitly accept the loss (mirrors CARLOS_STOP_BEFORE_DUMP_OK).
                # --dry-run only PRINTS the plan, so it never refuses here;
                # the guard applies to the real, destructive restore.
                if not dry and s.get("CARLOS_RESTORE_BASE_DUMP_ONLY", "0") != "1":
                    warn(
                        f"restore: {problem}. Point-in-time roll-forward is NOT possible "
                        f"for this dump, so restoring would load the base dump ONLY — the "
                        f"database would sit at the dump's instant and every committed "
                        f"write after it would be LOST. REFUSING before the live database "
                        f"is touched. Restore a NEWER snapshot (restic snapshots --tag "
                        f"db; pass --snapshot=<ID>), or re-run with "
                        f"CARLOS_RESTORE_BASE_DUMP_ONLY=1 to accept the base-dump-only "
                        f"restore." + down_hint
                    )
                    return None
                warn(
                    f"restore: {problem}. Proceeding BASE-DUMP-ONLY "
                    f"(CARLOS_RESTORE_BASE_DUMP_ONLY=1) — the database will be at the "
                    f"dump's instant; no binlog replay."
                )
                return []
            # M3: a --stop-datetime that postdates the newest binlog we can
            # replay cannot be honored — mariadb-binlog --stop-datetime would
            # replay to the shipped chain's end and exit 0, silently landing
            # the DB SHORT of the requested target. A stop restore whose LOCAL
            # binlogs continue the dump's chain ships them first (will_ship
            # below), so this fetch sees a chain fresh to the app-stop and the
            # guard passes for any past target; the guard bites on the NO-SHIP
            # paths (DR rebuild, foreign/pruned local binlogs — pre-confirm,
            # app still serving, so the refusal costs nothing) and on a stop
            # instant that is simply in the future. Compare against the newest
            # shipped binlog's mtime (restic restores it = the file's close
            # time), with 60s slack for clock skew. The stop instant is
            # interpreted in the DB CONTAINER's timezone (stop_datetime_epoch)
            # — mariadb-binlog evaluates --stop-datetime in that zone, and the
            # old host-local mktime() made this guard fail open (silent
            # under-restore) or fail closed by the full host↔container offset.
            # A DRY-RUN that WILL ship (local binlogs continue the dump's
            # chain) must not refuse here: the real run ships the active binlog
            # after the app-stop and reaches any past target, so refusing on
            # the still-stale repo chain contradicts the dry-run contract ("shows
            # exactly what it would do") and coaches CARLOS_STOP_PAST_CHAIN_END_OK
            # — a data-loss knob — for a refusal the live run would never make
            #
            if stop and selected and dry and will_ship:
                warn(
                    f"restore(plan): --stop-datetime '{stop}' is past the currently "
                    f"shipped chain end; the live run ships the active binlog after the "
                    f"app-stop, so it is expected to cover this target"
                )
            elif stop and selected and not s.flag("CARLOS_STOP_PAST_CHAIN_END_OK"):
                stop_epoch = stop_datetime_epoch(stop, s.get("TZ") or "UTC")
                if not stop_epoch:
                    warn(
                        f"restore: could not interpret --stop-datetime '{stop}' in the "
                        f"container zone TZ={s.get('TZ')!r} — the past-chain-end guard is "
                        f"SKIPPED for this run; verify the replay end yourself"
                    )
                try:
                    newest_mtime = (bdir / selected[-1]).stat().st_mtime
                except OSError:
                    stop_epoch = newest_mtime = 0.0  # missing file: skip the guard
                if stop_epoch and stop_epoch > newest_mtime + 60:
                    newest_desc = time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime(newest_mtime))
                    warn(
                        f"restore: --stop-datetime '{stop}' POSTDATES the newest shipped "
                        f"binlog (closed ~{newest_desc}) — the target lands in the "
                        f"still-active, UNSHIPPED binlog that a --stop-datetime restore "
                        f"cannot reach, so replay would stop SHORT at the chain end. "
                        f"REFUSING before the live database is touched. Restore to "
                        f"latest (which ships the active binlog first) to reach a target "
                        f"inside that window, or re-run with "
                        f"CARLOS_STOP_PAST_CHAIN_END_OK=1 to accept the chain end."
                        + down_hint
                    )
                    return None
            return selected

        will_ship = bool(local_continues_chain)
        anchor_desc = (f"{anchor.log_file if anchor else '<none>'}:"
                       f"{anchor.log_pos if anchor else '<none>'}")
        replay: Optional[List[str]] = None
        if dry or not will_ship:
            # No final ship can alter the chain here (dry-run, or a rebuild
            # whose local binlogs don't continue this dump), so fetch +
            # validate NOW, before the confirmation gate: every refusal
            # happens with the app still serving, and the plan shows exact
            # counts. Only a restore that will ship must defer the fetch
            # until after the app-stop.
            replay = fetch_chain(app_stopped=False)
            if replay is None:
                return False
        if dry:
            log("restore: plan")
            log(f"  snapshot:      {snap}")
            log(f"  anchor:        {anchor_desc}")
            replay_desc = (
                f"{len(replay)} binlog(s) from {anchor.log_file}:{anchor.log_pos}"
                + (f" up to '{stop}'" if stop else "")
                if anchor and replay else "none"
            )
            log(f"  binlog replay: {replay_desc}")
            if stop:
                log(f"  stop-datetime: '{stop}' — interpreted in the db container's "
                    f"LOCAL time zone (TZ={s.get('TZ')}); DST fall-back times are "
                    f"ambiguous, prefer binlog coordinates for a precise cut")
            ship_desc = (
                "yes — a live run ships the local binlogs after the confirm + "
                "app-stop (captures every committed write)" if will_ship else "no"
            )
            log(f"  final ship:    {ship_desc}")
            log(f"  target:        the LIVE {s.app_pod}-db (every schema in the dump is "
                f"DROPPED and re-created from it, then rolled forward; other "
                f"user schemas and mysql/sys preserved)")
            log("restore: --dry-run — no changes made")
            return True

        # Live plan: when a final ship will run, it happens AFTER the
        # confirmation (so the chain captures writes made during the prompt)
        # and the exact replay count is only known post-confirm — the plan
        # then names the anchor and defers the count. No-ship restores
        # already validated the chain above and show exact counts.
        log("restore: plan")
        log(f"  snapshot:      {snap}")
        log(f"  anchor:        {anchor_desc}")
        if replay is not None:
            replay_desc = (
                f"{len(replay)} binlog(s) from {anchor.log_file}:{anchor.log_pos}"
                + (f" up to '{stop}'" if stop else "")
                if anchor and replay else "none"
            )
        elif anchor:
            replay_desc = (
                f"resolved after confirmation (from {anchor.log_file}:{anchor.log_pos}"
                + (f" up to '{stop}'" if stop else "") + ")"
            )
        else:
            replay_desc = "none (dump carries no binlog anchor)"
        log(f"  binlog replay: {replay_desc}")
        if stop:
            log(f"  stop-datetime: '{stop}' — interpreted in the db container's "
                f"LOCAL time zone (TZ={s.get('TZ')}); DST fall-back times are "
                f"ambiguous, prefer binlog coordinates for a precise cut")
        ship_desc = (
            "yes — after the app stops, so the chain holds every committed write"
            if will_ship else "no"
        )
        log(f"  final ship:    {ship_desc}")
        log(f"  target:        the LIVE {s.app_pod}-db (every schema in the dump is "
            f"DROPPED and re-created from it, then rolled forward; other "
            f"user schemas and mysql/sys preserved)")

        # Confirmation gate — INSTANCE-NAMED in both modes: this overwrites
        # live PHI, so it must be at least as strict as the (data-preserving)
        # uninstall, which requires the instance name. Interactive types
        # 'RESTORE <instance>'; non-interactive sets
        # CARLOS_RESTORE_CONFIRMED=<instance>. A bare '1' is accepted for one
        # release with a deprecation warning (it was the old contract).
        # A confirmation persisted in carlos-app.env pre-confirms EVERY future
        # restore on this instance — the instance-named form fixed the
        # wrong-instance staleness but not this one; warn value-agnostically.
        from .config import parse_env_file

        ef = s.env_file
        if ef.is_file() and parse_env_file(
            ef.read_text(errors="replace")
        ).get("CARLOS_RESTORE_CONFIRMED"):
            warn(
                f"CARLOS_RESTORE_CONFIRMED is PERSISTED in {ef} — this override is "
                f"meant to be a one-shot shell prefix; while that line survives, every "
                f"future 'backup restore' on this instance skips its confirmation gate"
            )
        confirmed = s.get("CARLOS_RESTORE_CONFIRMED")
        if confirmed != s.instance:
            if confirmed == "1":
                warn(
                    f"CARLOS_RESTORE_CONFIRMED=1 is DEPRECATED — set it to the instance "
                    f"name ('{s.instance}') so a wrong-instance restore can't be "
                    f"triggered by a stale env; proceeding this time"
                )
            elif sys.stdin.isatty():
                ans = input(
                    f"This OVERWRITES the live {s.instance} databases with the restore "
                    f"above. Type 'RESTORE {s.instance}' to proceed: "
                )
                if ans != f"RESTORE {s.instance}":
                    warn("restore: not confirmed — aborting")
                    return False
            else:
                warn(
                    f"restore: refusing to overwrite the live database non-interactively "
                    f"— set CARLOS_RESTORE_CONFIRMED={s.instance} to proceed"
                )
                return False

        # Quiesce the app BEFORE the final binlog ship AND the overwrite
        # the DROP/CREATE load must not race Tomcat's pooled
        # connections still writing PHI, and stopping the writers FIRST means
        # the FLUSH below closes a binlog holding every committed write —
        # nothing can land in the active binlog during the confirmation
        # prompt or between the ship and the load. Stop only the carlos +
        # drugref containers — NOT the pod (the db is in the same pod and the
        # restore needs it up). `carlos-ctl play` (the post-restore step
        # below) brings them back.
        for app_ctr in (f"{s.app_pod}-carlos", f"{s.app_pod}-drugref"):
            if app_ctr in names.splitlines():
                log(f"restore: stopping {app_ctr} so it cannot write during the overwrite")
                if not runner.ok(runner.podman_user_argv(["stop", "-t", "20", app_ctr])):
                    warn(f"restore: could not stop {app_ctr} — it may write during the "
                         f"restore; proceeding")

        # Final ship with the writers stopped: FLUSH BINARY LOGS + ship the
        # closed binlogs so the chain fetched next contains everything ever
        # committed, including writes made while the operator sat at the
        # confirmation prompt. Only then can the chain be fetched — no-ship
        # restores fetched and validated it before the confirmation gate.
        if will_ship:
            log("restore: shipping the final local binlogs (writers stopped — the chain "
                "now holds every committed write)")
            if not ctx.ship_binlogs():
                # M2: the whole point of restore-to-latest is "every committed
                # write". If the final ship FAILS, the fetched chain is stale
                # and every write since the last 15-min ship would be LOST —
                # and nothing has been dropped yet, so refusing here is free.
                if not s.flag("CARLOS_RESTORE_ACCEPT_UNSHIPPED"):
                    warn(
                        "restore: the final binlog ship FAILED — every write committed "
                        "since the last successful 15-minute ship would be MISSING from "
                        "the restored database (they exist only in the local, unshipped "
                        "binlogs). REFUSING before the live database is touched. The "
                        "carlos/drugref containers are STOPPED (the EMR front door is "
                        "DOWN) — run 'carlos-ctl play' to bring the app back up, fix the "
                        "repository access, and re-run; or re-run with "
                        "CARLOS_RESTORE_ACCEPT_UNSHIPPED=1 to accept the loss."
                    )
                    return False
                warn("restore: final ship FAILED — proceeding WITHOUT it "
                     "(CARLOS_RESTORE_ACCEPT_UNSHIPPED=1); writes since the last "
                     "successful ship are NOT in the replay chain")
            replay = fetch_chain(app_stopped=True)
            if replay is None:
                return False
            if anchor and replay:
                log(f"restore: replay chain resolved: {len(replay)} binlog(s) from "
                    f"{anchor.log_file}:{anchor.log_pos}"
                    + (f" up to '{stop}'" if stop else ""))
        assert replay is not None  # noqa: S101 — both branches above assign or return

        # Load the dump, EXCLUDING the system schemas (shared stream filter)
        # so the live server's own accounts are never clobbered. PIPED
        # straight into the client: one on-disk copy (the bash's awk|mariadb
        # shape) — the live restore runs in anger on a possibly degraded
        # host, so it must not need 2x the dump in free space nor risk
        # leaking a second plaintext PHI file.
        log("restore: loading the dump into the live database")
        if not _pipe_filtered_dump(
            runner, dump_file,
            # --init-command WITHOUT embedded quotes (argv list, no shell).
            # sql_log_bin=0: the load must not re-enter the binlog chain — a
            # re-logged load bloats every ship with a full DB copy, and a
            # later restore replaying across it would double-apply events.
            ["exec", "-i", "-e", "MYSQL_PWD", f"{s.app_pod}-db", "mariadb", "-uroot",
             "--max-allowed-packet=1G", "--init-command=SET SESSION sql_log_bin=0"],
            {"MYSQL_PWD": root_pw},
            drop_user_schemas=True,
        ):
            warn("restore: dump load FAILED — the dumped schemas were DROPPED and only "
                 "partially reloaded, and the carlos/drugref containers are STOPPED (the "
                 "EMR front door is DOWN). Fix the cause and re-run 'backup restore' — the "
                 "load is idempotent (each schema is re-created from the dump); then "
                 "'carlos-ctl play' brings the app back up.")
            return False

        # Replay the PRE-VALIDATED chain (fetched and checked before the load).
        if replay and anchor and scratch is not None:
            log(f"restore: replaying binlogs from {anchor.log_file}:{anchor.log_pos}"
                + (f" up to '{stop}'" if stop else ""))
            bdir = scratch / "binlog" / "backup" / "binlog"
            # Clear any staging dir left by a previous (failed) restore FIRST:
            # `podman cp <dir> ctr:/existing-dir` copies the source INTO the
            # existing dir (docker cp semantics) instead of replacing it, so a
            # retry would replay the PREVIOUS attempt's stale chain — the new
            # files land one level down where mariadb-binlog never looks.
            runner.podman_user(
                ["exec", f"{s.app_pod}-db", "rm", "-rf",
                 "/tmp/binlog-replay"],  # noqa: S108 — in-container path
                quiet=True,
            )
            cpv = runner.podman_user(
                ["cp", str(bdir), f"{s.app_pod}-db:/tmp/binlog-replay"], quiet=True
            )
            if cpv.returncode != 0:
                # The dump has already been loaded; the binlog replay is what
                # rolls forward to the requested point. A silently-skipped copy
                # would leave the DB at the dump's timestamp while REPORTING a
                # point-in-time restore — data loss disguised as success. Abort
                # loudly so the operator knows the roll-forward did not happen.
                raise CtlError(
                    f"restore: dump loaded but could NOT copy binlogs into "
                    f"{s.app_pod}-db for replay (podman cp rc={cpv.returncode}) — the "
                    f"database is at the dump's point-in-time, NOT the requested one; "
                    f"investigate before treating this as a completed restore"
                )
            files = " ".join(f"/tmp/binlog-replay/{b}" for b in replay)  # noqa: S108 — in-container path
            # --stop-datetime carries a SPACE; it is interpolated into
            # the remote `bash -c` STRING, so it must be single-quoted
            # THERE or the remote shell word-splits the time into a
            # stray argument mariadb-binlog treats as a filename. (The value
            # was validated against a strict timestamp shape AND normalized
            # to 'YYYY-MM-DD HH:MM:SS' at arg parse — mariadb-binlog does
            # not accept the ISO 'T' separator.)
            stop_clause = f"--stop-datetime='{stop}' " if stop else ""
            cp = runner.podman_user(
                ["exec", "-i", "-e", "MYSQL_PWD", f"{s.app_pod}-db", "bash", "-c",
                 # --no-defaults (must be first): inside the LIVE db container
                 # the operator-owned zz-carlos.cnf is mounted, and its
                 # [client] default-character-set is an "unknown variable"
                 # that aborts mariadb-binlog outright — without this flag the
                 # replay leg of every live restore fails after the dump load,
                 # with the app containers already stopped.
                 # --init-command single-quoted (inside the remote bash -c
                 # string). sql_log_bin=0: replayed events must NOT be
                 # re-binlogged — a retry after a failed restore would replay
                 # original + re-logged copies and abort on duplicates (1062).
                 f"set -o pipefail; mariadb-binlog --no-defaults "
                 f"--start-position={anchor.log_pos} {stop_clause}{files} | "
                 f"mariadb --user=root --max-allowed-packet=1G "
                 f"--init-command='SET SESSION sql_log_bin=0'"],
                env={"MYSQL_PWD": root_pw},
            )
            if cp.returncode != 0:
                warn("restore: binlog replay FAILED — the base dump loaded but PITR is "
                     "incomplete, and the carlos/drugref containers are STOPPED (the EMR "
                     "front door is DOWN). Re-running 'backup restore' is safe (the load "
                     "re-creates each schema from the dump and the replay is never "
                     "re-binlogged); see README 'If the restore fails mid-flight' for the "
                     "manual-replay fallback, then 'carlos-ctl play' brings the app back up.")
                return False
            log(f"restore: replayed {len(replay)} binlog(s)")
            if stop and not will_ship:
                # Repo-only chain (DR rebuild / no local continuation): the
                # chain ends at the last timer ship, and mariadb-binlog exits
                # 0 even when --stop-datetime lies past that end — the
                # database would then sit at the chain's end, NOT the
                # requested instant, with no error anywhere. The M3 mtime
                # guard refused the clear-cut case pre-load, but it is
                # overridable (CARLOS_STOP_PAST_CHAIN_END_OK) and skipped
                # when the mtime is unreadable — so still surface the
                # possibility here instead of implying precision.
                warn(
                    f"restore: the replay chain came from the repository only (no "
                    f"local binlogs continue this dump). If '{stop}' postdates the "
                    f"chain's last shipped event, replay stopped at the chain's end "
                    f"WITHOUT error — verify the restored state actually reaches the "
                    f"intended instant before resuming service."
                )
        elif not anchor:
            warn("restore: dump carried no binlog anchor — loaded the base dump only "
                 "(no PITR replay)")
        # Re-anchor the chain-identity marker to THIS server: after a
        # completed restore the live server's binlogs legitimately continue
        # the recovered state, so the next 15-minute ship must not refuse
        # (the ship-time identity gate exists for rebuilds WITHOUT a restore).
        if live_ident:
            try:
                (ctx.backup_dir / ".binlog-identity").write_text(live_ident + "\n")
                log("restore: chain identity re-anchored to this server for future ships")
            except OSError:
                warn("restore: could not re-anchor the chain identity — the next binlog "
                     "ship may refuse until CARLOS_ACCEPT_NEW_BINLOG_IDENTITY=1 is set once")
        log("restore complete — restart the app so it reconnects: carlos-ctl play")
        if stop:
            # The local binlog chain still carries the DISCARDED timeline tail
            # (events past the stop instant, plus anything the abandoned
            # timeline wrote). A later restore-to-latest would replay that
            # tail over the rewound state — logical corruption the sequence/
            # identity checks cannot see. Only a fresh full dump (new anchor,
            # --flush-logs) fences it off.
            warn(
                "MANDATORY next step after a --stop-datetime restore: run "
                "'sudo carlos-ctl backup full' NOW. The existing binlog chain still "
                "contains the discarded timeline; until a new full dump re-anchors past "
                "it, a restore-to-latest would replay abandoned events over this state."
            )
        # The dump excludes the mysql system schema (accounts/grants) by
        # design, so the restored server keeps ITS current accounts — after a
        # true DR rebuild those are only root. Point the operator at the
        # idempotent re-provisioner rather than leaving login failures to be
        # diagnosed from Tomcat stack traces.
        log(
            "NOTE: database ACCOUNTS/GRANTS are not part of the dump (system schemas are "
            "excluded) — on a rebuilt host run 'carlos-ctl db-users' after play to "
            "re-provision the least-privilege app/drugref/backup/exporter accounts"
        )
        return True
    finally:
        with contextlib.suppress(OSError):
            dump_file.unlink()
        if scratch is not None:
            shutil.rmtree(scratch, ignore_errors=True)
