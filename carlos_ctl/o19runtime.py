# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""carlos-podman's answers to the OSCAR 19 importer's deployment questions.

The engine asks ONE object where the workspace lives, how a mariadb client is
spawned, who takes the pre-import snapshot, whether the application is running,
and who must own the restored document tree (`o19host.Host`, in the CARLOS
tree). The deb IS that object's default; this module is the podman
implementation of the same interface, so the phase order, the ledger, the
resume rules, the refusals and the validation report are literally the same
code on both deployments.

`PodmanHostBehaviour` carries every differing answer and is deliberately NOT
derived from `Host` at definition time — `Host` only exists once the engine is
fetched (`o19source`). `make_host()` composes the two. The split is also what
lets the unit tests exercise every answer against a stub base class without a
network fetch.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from . import dbops
from .runner import Runner
from .util import CtlError, log, warn

#: The uid the CARLOS container runs as, and therefore the uid that must own
#: the patient document tree on the host side of the volume mount. It is the
#: `runAsUser:` of the carlos container in
#: ansible/roles/carlos_podman/templates/carlos-app.yaml.j2, and the id its
#: `carlos-init` initContainer chowns /var/lib/CarlosDocument to. Change one
#: and this must change with it — a mismatch leaves a tree the application
#: cannot read, which a root-run reconciliation would not notice.
CARLOS_CONTAINER_UID = 10001

#: Where CARLOS's Flyway migration set sits on the WAR classpath inside the
#: deployed image (pom.xml copies database/mysql/migration/ to db/migration).
IMAGE_MIGRATION_DIR = (
    "/usr/local/tomcat/webapps/carlos/WEB-INF/classes/db/migration")

#: `V<version>__<description>.sql` — Flyway's versioned-migration filename.
_MIGRATION_FILE = re.compile(r"^V(?P<version>[0-9][0-9._]*)__.*\.sql$")

#: One `/proc/self/uid_map` (or gid_map) row: inside-id, outside-id, count.
_ID_MAP_ROW = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s*$")

#: Document tree posture: PHI at rest, same as the MariaDB datadir and the
#: playbook's own 0700 on $EMR_HOME/data/CarlosDocument. Only the container's
#: identity (and root) need in — there is no group to share with, so no
#: setgid bit and no group read, unlike the deb's 2750/0640.
DOCUMENT_DIR_MODE = "0700"
DOCUMENT_FILE_MODE = "0600"


class PodmanHostBehaviour:

    """Every deployment answer that differs from the deb package's.

    Mixed in AHEAD of `o19host.Host` so these win; anything not overridden
    here is the deb's answer, which for this interface means the shared
    engine logic (`staging_init_command`, the reserved-schema list, ...)
    rather than a deb-specific path."""

    label = "the carlos-podman deployment"

    def __init__(self, runner: Runner, engine: Any) -> None:
        self.runner = runner
        self.engine = engine
        self._document_owner: Optional[str] = None

    # -- where things live -------------------------------------------------

    @property
    def state_dir(self) -> str:
        """The import workspace: ledger, reports, staged bundle, archive CSV
        export. Under $EMR_HOME so `--instance` selects it like everything
        else, and beside the fetched engine (`o19-import/engine/<commit>`)."""
        return str(self.runner.settings.emr_home / "o19-import")

    @property
    def documents_root(self) -> str:
        """The patient document tree, host side of the pod's volume mount.
        `Settings.document_store` is authoritative: it follows the
        CarlosDocument rename and falls back to the legacy directory until
        the playbook's one-time move has run, so an import mid-transition
        writes where the application actually reads."""
        return str(self.runner.settings.document_store)

    # -- who this host is --------------------------------------------------

    def is_packaged_host(self) -> bool:
        """A provisioned instance, as opposed to a development database
        reached through `--mariadb-arg`. carlos-app.env is what the playbook
        renders and what `Settings` reads, so its presence is the fact."""
        return self.runner.settings.env_file.is_file()

    def configured_province(self) -> str:
        """The province this instance is deployed for.

        There is no province key in carlos-app.env: the playbook renders the
        application's own `billregion` into carlos.properties, and that single
        value drives the app's Flyway locations, its billing module and — here
        — which manifest profile the import binds. Reading anything else would
        let the two disagree.

        A development database (no env file) defaults to Ontario, matching the
        deb. `generic` is a valid CARLOS billregion and is NOT a migration
        profile: refuse it by name rather than letting `bind()` raise."""
        if not self.is_packaged_host():
            return "on"
        s = self.runner.settings
        raw = self._properties_value("billregion")
        if raw is None:
            raise CtlError(
                f"no billregion in {s.properties_file} — the OSCAR 19 import binds the manifest "
                "profile for the province this instance is deployed for, and "
                "that is the value the application itself bills under. Set "
                "carlos_billing_province in host_vars and re-run the "
                "provisioning playbook.")
        province = raw.strip().lower()
        if province not in ("on", "bc"):
            raise CtlError(
                f"billregion={raw.strip()!r} in {s.properties_file}: the OSCAR 19 importer carries "
                "curated manifest profiles for Ontario ('ON') and British "
                "Columbia ('BC') only. A 'generic' or other region has no "
                "profile, and importing a clinic under the wrong one would "
                "run another province's rulings against this schema.")
        return province

    def configured_db_name(self) -> Optional[str]:
        """The EMR schema this instance deploys — CARLOS_DB_NAME, validated
        as a plain identifier by the same function every other verb uses
        (it is interpolated into backtick-quoted DDL run as database root).
        None off a packaged host, so the caller falls back to a dev default."""
        if not self.is_packaged_host():
            return None
        return dbops.require_db_identifier(self.runner.settings)

    def identity_source(self) -> str:
        """What an operator should look at when the host's identity is what
        is being refused. carlos-app.env is what `is_packaged_host` tests and
        where the instance's identity is rendered; the province refusals name
        carlos.properties themselves, since billregion lives there."""
        return str(self.runner.settings.env_file)

    def _properties_value(self, key: str) -> Optional[str]:
        """One carlos.properties value, decoded the way the application reads
        the file (ISO-8859-1, last occurrence wins) — via the engine's own
        `util` shim, so the import and the app never disagree about it."""
        util = self.engine.package.util
        return util.prop_get(str(self.runner.settings.properties_file), key)

    # -- reaching the database ---------------------------------------------

    def client_base_argv(self,
                         mariadb_args: Optional[Sequence[str]]) -> List[str]:
        """argv that starts a mariadb client against THIS instance's database
        as root, with the statement still to be appended.

        MariaDB publishes no TCP port in this deployment (the WAF/DB isolation
        boundary), so the client runs INSIDE the db container, reached across
        the root -> rootless-engine boundary exactly like every `dbops` call.
        `-e MYSQL_PWD` forwards the password BY NAME: /proc/<pid>/cmdline is
        world-readable and these statements carry PHI.

        `--mariadb-arg` replaces the whole thing with a host client for a
        development database (and implies `--dev-target`), matching the deb."""
        if mariadb_args:
            return ["mariadb"] + list(mariadb_args)
        s = self.runner.settings
        return self.runner.podman_user_argv([
            "exec", "-i", "-e", "MYSQL_PWD", f"{s.app_pod}-db",
            "mariadb", "-uroot",
        ])

    def client_env(self) -> Dict[str, str]:
        """The database root password, by name, for every client invocation.

        Empty when there is none configured: that is the development-database
        case, and on a provisioned instance the verb's own entry gate
        (`o19import_cmd`) refuses before any phase starts rather than letting
        every statement fail with access-denied."""
        pw = self.runner.settings.get("CARLOS_DB_ROOT_PASSWORD")
        return {"MYSQL_PWD": pw} if pw else {}

    def stage_credential(self, password: str,
                         client_cnf: str) -> Dict[str, str]:
        """Make the throwaway staging account's password reachable by the
        restore client — through the environment, not a file.

        The deb writes a 0600 defaults file because its client is another
        process on the same filesystem. Here the client is a process inside a
        container: a host file would not be visible to it without mounting a
        credential into the pod, and the deployment already has an off-argv
        channel that works — `-e MYSQL_PWD`, forwarded by name across
        runuser and podman exec. Nothing is written to disk, so nothing has
        to be shredded afterwards."""
        return {"MYSQL_PWD": password}

    def clear_stage_credential(self, client_cnf: str) -> None:
        """Nothing was written, so there is nothing to remove — but a
        workspace that once ran under a file-based host may still hold one,
        and this is called from a `finally` whose whole job is that the
        staging password does not outlive the restore."""
        if client_cnf and os.path.exists(client_cnf):
            os.unlink(client_cnf)

    def staging_client_argv(self, base_argv: Sequence[str],
                            client_cnf: str,
                            statement_timeout: int = 0) -> List[str]:
        """The restore client's argv: the same container (or the same dev
        seam), with root's identity replaced by the throwaway staging account
        whose password rides `MYSQL_PWD`.

        Built explicitly rather than by stripping the root argv: on this
        deployment that argv begins `runuser -u <service user> --`, and the
        engine's `strip_client_identity` — correct for a bare client tail —
        would remove that `-u <user>` pair and silently run the clinic's
        restore as ROOT's podman engine.

        `--one-database` keeps a statement addressed at another schema from
        running, `--local-infile=0` closes the client-side file read a system
        defaults file could otherwise enable, and `--user=` on the argv
        outranks every option file the client still reads."""
        o19import = self.engine.o19import
        flags = [
            "--user=" + self.engine.o19host.STAGING_USER,
            "--local-infile=0", "--max-allowed-packet=1G",
            "--one-database",
            "--init-command=" + o19import.staging_init_command(
                statement_timeout),
            o19import.STAGING_SCHEMA,
        ]
        base = list(base_argv)
        if base[:1] == ["mariadb"]:
            # development seam: a host client, identity stripped from its
            # own tail exactly as the deb does
            return (["mariadb"]
                    + o19import.strip_client_identity(base[1:]) + flags)
        s = self.runner.settings
        return self.runner.podman_user_argv([
            "exec", "-i", "-e", "MYSQL_PWD", f"{s.app_pod}-db",
            "mariadb",
        ] + flags)

    # -- the document tree -------------------------------------------------

    def _id_map(self, which: str) -> List[Tuple[int, int, int]]:
        """The service user's rootless id map, as podman itself sees it."""
        out = self.runner.output(self.runner.podman_user_argv(
            ["unshare", "cat", f"/proc/self/{which}"]))
        rows = []
        for line in out.splitlines():
            m = _ID_MAP_ROW.match(line)
            if m:
                rows.append((int(m.group(1)), int(m.group(2)),
                             int(m.group(3))))
        return rows

    def _map_to_host(self, rows: Sequence[Tuple[int, int, int]],
                     container_id: int) -> Optional[int]:
        for inside, outside, count in rows:
            if inside <= container_id < inside + count:
                return outside + (container_id - inside)
        return None

    def document_ownership(self) -> Tuple[str, str, str]:
        """(owner, directory mode, file mode) for the restored document tree.

        The engine chowns the tree as HOST root. The application reads it as
        container uid 10001, which on a rootless host is one of the service
        user's SUBUIDs — so the host-side owner is that mapped id, resolved
        from podman's own `/proc/self/uid_map` rather than guessed from
        /etc/subuid. Handing the tree to the service user instead would leave
        every chart unopenable until the pod's init container noticed and
        swept the whole tree; handing it to host uid 10001 would give it to
        an unrelated local account.

        Fails CLOSED. A tree chowned to the wrong id passes the root-run
        reconciliation and then fails every chart that opens a scan, which is
        exactly the failure this method exists to prevent."""
        if self._document_owner is not None:
            return (self._document_owner, DOCUMENT_DIR_MODE,
                    DOCUMENT_FILE_MODE)
        uid = self._map_to_host(self._id_map("uid_map"), CARLOS_CONTAINER_UID)
        gid = self._map_to_host(self._id_map("gid_map"), CARLOS_CONTAINER_UID)
        if uid is None or gid is None:
            user = self.runner.settings.service_user
            raise CtlError(
                f"could not resolve container uid {CARLOS_CONTAINER_UID} to a "
                f"host id through the {user} user's rootless id map — the "
                "restored document tree would be chowned to an identity the "
                "application cannot use. Check /etc/subuid and /etc/subgid "
                f"for {user} (re-run the provisioning playbook if they are "
                "missing) and that 'podman unshare' works for that user.")
        if uid != gid:
            user = self.runner.settings.service_user
            raise CtlError(
                f"container uid {CARLOS_CONTAINER_UID} maps to host uid "
                f"{uid} but host gid {gid}; the importer chowns the document "
                f"tree with one id for both. Reconcile the {user} user's "
                "subuid and subgid ranges (they are normally identical) and "
                "re-run.")
        self._document_owner = str(uid)
        return (self._document_owner, DOCUMENT_DIR_MODE, DOCUMENT_FILE_MODE)

    # -- what the deployment can be asked to do ----------------------------

    def _escape(self, value: str) -> str:
        """The ENGINE's SQL escape, taken from the loaded engine rather than
        from the base class's MRO: this mixin is also exercised standalone by
        the unit suite, and one escape for both paths is the whole point of
        `o19compat` taking it from `o19_preflight`."""
        return str(self.engine.package.dbops.sql_escape(value))

    def _client_rows(self, sql: str) -> Tuple[int, List[List[str]]]:
        """(returncode, rows) for one read-only statement, through the same
        client the import uses. Local to this module: `Host` is handed a
        query callable for the phases, but these gates run before one
        exists."""
        argv = self.client_base_argv(None) + [
            "--default-character-set=utf8mb4", "-N", "-B"]
        cp = self.runner.run(argv, input_text=sql, capture=True,
                             env=self.client_env() or None,
                             encoding="utf-8", errors="replace")
        rows = [line.split("\t")
                for line in (cp.stdout or "").splitlines() if line]
        return cp.returncode, rows

    def _flyway_history(self) -> Optional[List[Tuple[str, bool]]]:
        """[(version, succeeded)] from the target's flyway_schema_history, or
        None when the table does not exist — which is the NORMAL state on
        this deployment, where the migration set is applied with
        `carlos-ctl db-migrate` (raw SQL, no Flyway bookkeeping)."""
        db = self.configured_db_name() or ""
        rc, rows = self._client_rows(
            "SELECT COUNT(*) FROM information_schema.TABLES WHERE "  # noqa: S608 — db is identifier-validated by require_db_identifier and escaped
            f"TABLE_SCHEMA = '{self._escape(db)}' AND TABLE_NAME = "
            "'flyway_schema_history'")
        if rc != 0 or not rows or rows[0][0] in ("0", ""):
            return None
        rc, rows = self._client_rows(
            f"SELECT version, success FROM `{db}`.flyway_schema_history "  # noqa: S608 — db is identifier-validated by require_db_identifier
            "WHERE version IS NOT NULL")
        if rc != 0:
            return None
        return [(r[0], r[1] == "1") for r in rows if len(r) >= 2]

    def _image_migration_versions(self) -> Optional[Set[str]]:
        """Migration versions the DEPLOYED image ships for this province, or
        None when the image cannot be read (it is the artifact that will read
        the migrated data, so this is the authoritative list)."""
        s = self.runner.settings
        province = self.configured_province()
        cp = self.runner.podman_user([
            "run", "--rm", "--network=none", "--entrypoint", "",
            s.get("CARLOS_IMAGE"), "sh", "-c",
            f"ls -1 {IMAGE_MIGRATION_DIR}/common {IMAGE_MIGRATION_DIR}/{province}",
        ], capture=True, quiet=True)
        if cp.returncode != 0:
            return None
        found = set()
        for line in (cp.stdout or "").splitlines():
            m = _MIGRATION_FILE.match(line.strip())
            if m:
                found.add(m.group("version"))
        return found or None

    def flyway_validate(self) -> int:
        """P0's schema gate: 0 when the target's schema matches the CARLOS
        this instance deploys, nonzero when it demonstrably does not.

        The deb runs Flyway's own `validate` out of its exploded webapp.
        There is no host-side Flyway runner here (the WAR lives in the image,
        and the deployment's documented path applies the migration set as raw
        SQL through `carlos-ctl db-migrate`), so this checks what evidence the
        deployment actually has:

        * a `flyway_schema_history` with a FAILED row is a half-applied
          migration — refuse, whatever else is true;
        * a clean history that is MISSING a version the deployed image ships
          is a target behind its application — refuse;
        * no history table at all is the raw-SQL path, which records nothing.
          That is not evidence of a mismatch, and refusing would block the
          documented deployment. It warns, and P0's own pristine-seed floors
          — which count stock rows this CARLOS version seeds — are what catch
          an unmigrated or wrong-version target before anything is written.
        """
        applied = self._flyway_history()
        if applied is None:
            warn(
                "no flyway_schema_history in the target schema — this "
                "instance's migrations were applied as raw SQL "
                "('carlos-ctl db-migrate'), which records nothing, so the "
                "importer cannot compare versions. Confirm the schema was "
                "loaded from the CARLOS checkout at the pinned release "
                "('carlos-ctl source show'); P0's pristine-seed check "
                "follows and will refuse a target that is not a stock "
                "deploy of it.")
            return 0
        failed = sorted(v for v, ok in applied if not ok)
        if failed:
            warn("the target's flyway_schema_history records FAILED "
                 f"migration(s): {', '.join(failed)}. Repair the schema "
                 "before importing a clinic into it.")
            return 1
        shipped = self._image_migration_versions()
        if shipped is None:
            image = self.runner.settings.get("CARLOS_IMAGE")
            warn(
                f"could not list the migration set inside {image} — the "
                "schema's recorded history is clean but could not be "
                "compared with what the deployed image expects.")
            return 0
        pending = sorted(shipped - {v for v, ok in applied if ok})
        if pending:
            warn(
                "the deployed CARLOS image ships migration(s) the target has "
                f"not applied: {', '.join(pending)}. Run them ('carlos-ctl "
                "db-migrate') before importing — the manifest is generated "
                "for the schema the application expects.")
            return 1
        return 0

    def backup_configured(self) -> bool:
        """Whether a pre-import snapshot can be taken. restic's password
        lives in carlos-app.env on a plaintext install and inside the SOPS
        bundle on a sealed one; either is enough for `backup full` to run."""
        s = self.runner.settings
        if (s.get("RESTIC_PASSWORD") or "").strip():
            return True
        return s.secrets_bundle.is_file()

    def backup_configuration_hint(self) -> str:
        s = self.runner.settings
        return (f"{s.env_file} (RESTIC_REPOSITORY / RESTIC_PASSWORD), or the sealed "
                f"bundle {s.secrets_bundle}")

    def pre_import_backup(self) -> Tuple[bool, str]:
        """Take the pre-import snapshot — the rollback point everything after
        P3 assumes exists. The nightly tier, run now: one restic snapshot of
        the dump plus the document store, through the same code path and into
        the same repository the clinic's scheduled backups use, so what is
        taken here is something `carlos-ctl backup restore` can restore."""
        from . import backup as backup_mod

        log("taking the pre-import backup ('backup full'; this is the "
            "rollback point) ...")
        try:
            rc = backup_mod.cmd_backup(self.runner, ["full"])
        except CtlError as exc:
            return False, str(exc)
        if rc != 0:
            return False, ("carlos-ctl backup status, and "
                           f"journalctl -u {self.runner.settings.instance}-backup")
        return True, ""

    def app_running_refusal(self) -> Optional[str]:
        """Why the import may not run right now, or None.

        Two conditions, and they pull in opposite directions: the CARLOS
        container must be STOPPED (its startup listener creates rows that
        would fail row parity, and a live session could read a half-copied
        chart) while the DATABASE container must be RUNNING (every statement
        the import makes goes through it).

        Fails CLOSED on an unreadable engine: a `podman ps` that did not
        answer has not established that the application is stopped, and the
        whole point of the gate is that a running CARLOS writes into the
        target while the import copies into it."""
        if not self.is_packaged_host():
            return None  # a development database, no pod
        s = self.runner.settings
        cp = self.runner.run(self.runner.podman_user_argv(
            ["ps", "--format", "{{.Names}}"]), capture=True)
        if cp.returncode != 0:
            return ("could not determine whether CARLOS is running "
                    f"(podman ps exited {cp.returncode} for the "
                    f"{s.service_user} user). The import must not run "
                    "against a live application: confirm with 'carlos-ctl "
                    "status' and re-run.")
        running = set((cp.stdout or "").split())
        app = f"{s.app_pod}-carlos"
        db = f"{s.app_pod}-db"
        if app in running:
            return (
                f"{app} is running — stop the APPLICATION for the duration of "
                "the import while leaving the database up:\n"
                f"    runuser -u {s.service_user} -- podman stop {app}\n"
                "and start it again with 'carlos-ctl play' only after the "
                "verified import and the properties fragment have been "
                "applied. ('carlos-ctl down' stops the database too, which "
                "the import needs.)")
        if db not in running:
            return (
                f"{db} is not running — the import talks to the clinic's "
                "database through it. Start the pod ('carlos-ctl play'), "
                "then stop only the application container "
                f"('runuser -u {s.service_user} -- podman stop {s.app_pod}-carlos') and "
                "re-run.")
        return None


def make_host(runner: Runner, engine: Any) -> Any:
    """Compose podman's answers onto the engine's `Host` and instantiate.

    The class is built here rather than declared because `Host` arrives with
    the engine, at run time. Method resolution puts the podman behaviour
    first, so anything not overridden falls through to the engine's own
    implementation — which for this interface is shared logic, not deb
    paths."""
    cls = type("PodmanHost", (PodmanHostBehaviour, engine.o19host.Host), {})
    return cls(runner, engine)
