# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Unit tests for carlos_ctl.dbops.maybe_provision_db_users — the #6 contract.

The app must never SILENTLY steady-state on the MariaDB root account. This pins
which end states are acceptable (return True → play stays green) vs a failure
that left the app on root without a conscious opt-out (return False → play
fails loudly)."""

from __future__ import annotations

from pathlib import Path

from carlos_ctl import dbops


def _write_properties(runner, db_username: str) -> None:
    p: Path = runner.settings.properties_file
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(f"db_username={db_username}\ndb_password=x\n")


class TestSchemaFingerprint:
    """The rollback guard's compatibility signature: deterministic hash of
    the oscar column inventory; '' = cannot-fingerprint (never a match)."""

    def test_same_inventory_hashes_identically(self, mk_runner) -> None:
        r1, r2 = mk_runner(), mk_runner()
        for r in (r1, r2):
            _write_properties(r, "carlos")
            r.script("mariadb", "-ucarlos", out="demographic\tdemographic_no\t1\tint\n")
        assert dbops.schema_fingerprint(r1) == dbops.schema_fingerprint(r2) != ""

    def test_changed_inventory_changes_the_fingerprint(self, mk_runner) -> None:
        r1, r2 = mk_runner(), mk_runner()
        _write_properties(r1, "carlos")
        _write_properties(r2, "carlos")
        r1.script("mariadb", "-ucarlos", out="demographic\tdemographic_no\t1\tint\n")
        r2.script("mariadb", "-ucarlos", out="demographic\tnew_col\t2\ttext\n")
        assert dbops.schema_fingerprint(r1) != dbops.schema_fingerprint(r2)

    def test_failed_probe_is_unknown_not_a_match(self, mk_runner) -> None:
        r = mk_runner()
        _write_properties(r, "carlos")
        r.script("mariadb", "-ucarlos", rc=1)
        assert dbops.schema_fingerprint(r) == ""

    def test_empty_inventory_is_unknown(self, mk_runner) -> None:
        r = mk_runner()
        _write_properties(r, "carlos")
        r.script("mariadb", "-ucarlos", out="")
        assert dbops.schema_fingerprint(r) == ""

    def test_root_fallback_when_app_account_fails(self, mk_runner) -> None:
        r = mk_runner(extra_env={"CARLOS_DB_ROOT_PASSWORD": "rootpw"})
        _write_properties(r, "carlos")
        r.script("mariadb", "-ucarlos", rc=1)
        r.script("mariadb", "-uroot", out="demographic\tdemographic_no\t1\tint\n")
        assert dbops.schema_fingerprint(r) != ""


class TestMaybeProvisionDbUsers:
    def test_already_least_privilege_is_acceptable(self, mk_runner) -> None:
        r = mk_runner()
        _write_properties(r, "carlos")
        assert dbops.maybe_provision_db_users(r) is True

    def test_conscious_skip_is_acceptable(self, mk_runner) -> None:
        r = mk_runner(extra_env={"CARLOS_SKIP_AUTO_DB_USERS": "1"})
        _write_properties(r, "root")
        assert dbops.maybe_provision_db_users(r) is True

    def test_root_without_password_is_accepted_optout(self, mk_runner) -> None:
        # Reachable only via CARLOS_ALLOW_DB_ROOT=1 (preflight refuses otherwise),
        # so it is a conscious acceptance, not a silent failure.
        r = mk_runner()
        _write_properties(r, "root")
        assert dbops.maybe_provision_db_users(r) is True

    def test_stale_legacy_helper_fails_the_deploy(self, mk_runner) -> None:
        r = mk_runner(extra_env={"CARLOS_DB_ROOT_PASSWORD": "rootpw"})
        _write_properties(r, "root")
        legacy = r.settings.emr_home / "container" / "carlos-backup.sh"
        legacy.parent.mkdir(parents=True, exist_ok=True)
        legacy.write_text("#!/bin/sh\n# pre-migration helper, no backend marker\n")
        assert dbops.maybe_provision_db_users(r) is False

    def test_db_never_ready_fails_the_deploy(self, mk_runner) -> None:
        # root, password present, no stale helper, but the DB never accepts the
        # root probe → provisioning cannot run → app left on root → False.
        r = mk_runner(extra_env={
            "CARLOS_DB_ROOT_PASSWORD": "rootpw",
            "READY_WAIT_SECONDS": "0",
        })
        _write_properties(r, "root")
        r.script("mariadb", "-uroot", "-e", "SELECT 1", rc=1)
        assert dbops.maybe_provision_db_users(r) is False


class TestWaitDbAccepting:
    """`require_db_running` only proves the container NAME is listed; the
    server can still be starting. The shared probe distinguishes the two
    causes so a rotation right after a pod restart is not reported as a
    credential problem."""

    def test_ready_when_the_server_answers(self, mk_runner) -> None:
        r = mk_runner("CARLOS_DB_ROOT_PASSWORD=pw\n")
        r.script("podman", "exec", rc=0, out="1\n")
        ready, err = dbops.wait_db_accepting(r, "pw", 5)
        assert ready is True
        assert err == ""

    def test_access_denied_returns_immediately(self, mk_runner) -> None:
        # A wrong password is terminal — waiting it out only delays the
        # correct diagnosis and hammers the failed-login counters. The
        # generous timeout here would make a retry loop hang the test.
        r = mk_runner("CARLOS_DB_ROOT_PASSWORD=pw\n")
        r.script("podman", "exec", rc=1,
                 out="ERROR 1045 (28000): Access denied for user 'root'@'localhost'")
        ready, err = dbops.wait_db_accepting(r, "pw", 600)
        assert ready is False
        assert "Access denied" in err

    def test_not_ready_within_the_timeout(self, mk_runner) -> None:
        r = mk_runner("CARLOS_DB_ROOT_PASSWORD=pw\n")
        r.script("podman", "exec", rc=1, out="ERROR 2002: Can't connect")
        ready, _err = dbops.wait_db_accepting(r, "pw", 0)
        assert ready is False

    def test_the_password_never_reaches_argv(self, mk_runner) -> None:
        r = mk_runner("CARLOS_DB_ROOT_PASSWORD=pw\n")
        r.script("podman", "exec", rc=0, out="1\n")
        dbops.wait_db_accepting(r, "s3cr3t-probe-pw", 5)
        assert not any("s3cr3t-probe-pw" in tok for call in r.calls for tok in call)


class TestProvisionSqlHygiene:
    def test_provision_sql_drops_anonymous_users_and_test_db(self) -> None:
        # Finding C24: mysql_secure_installation-equivalent hygiene must ride
        # in the same provisioning statement batch — the official image's
        # clean defaults are an unverified assumption for a PHI database.
        from carlos_ctl.dbops import _PROVISION_SQL

        assert "DROP USER IF EXISTS ''@'localhost';" in _PROVISION_SQL
        assert "DROP USER IF EXISTS ''@'%';" in _PROVISION_SQL
        # Provisioning must stay ADDITIVE (data-safety contract): no DROP
        # DATABASE — a legacy migration can arrive with a populated `test`
        # schema, and a routine deploy must never destroy data.
        assert "DROP DATABASE" not in _PROVISION_SQL
        # The hygiene must land before the final FLUSH PRIVILEGES.
        assert _PROVISION_SQL.index("DROP USER") < _PROVISION_SQL.rindex("FLUSH PRIVILEGES")


class TestPmaRunFlags:
    """cmd_pma launches a real `podman run` — the flag set must be valid
    podman-run vocabulary (not kube-spec vocabulary) and must leave the
    apache-based phpmyadmin image runnable. Pins the two live-found breaks:
    `seccomp=RuntimeDefault` (kube-only value; podman run rejects it) and a
    bare --cap-drop ALL (httpd cannot bind :80 / setuid www-data)."""

    def _pma_argv(self, r) -> list:
        dbops.cmd_pma(r, ["--ttl", "0"])
        runs = [c for c in r.calls if "run" in c and "--rm" in c]
        assert runs, "cmd_pma never issued a podman run"
        return runs[-1]

    def test_no_kube_vocabulary_in_security_opts(self, mk_runner) -> None:
        r = mk_runner()
        r.script("podman", "ps", out="carlos-app-db\n")
        argv = self._pma_argv(r)
        assert "seccomp=RuntimeDefault" not in argv

    def test_cap_drop_all_grants_the_minimal_apache_set(self, mk_runner) -> None:
        r = mk_runner()
        r.script("podman", "ps", out="carlos-app-db\n")
        argv = self._pma_argv(r)
        assert "ALL" in argv and "--cap-drop" in argv
        i = argv.index("--cap-add")
        assert argv[i + 1] == "CHOWN,DAC_OVERRIDE,SETGID,SETUID,NET_BIND_SERVICE"


class TestPmaTtlExitCode:
    """Reaching --ttl is the DESIGNED end of a pma session, so it must exit 0.
    `timeout` reports 124 (137 when its -k SIGKILL was needed), which made the
    documented happy path — `carlos-ctl pma --ttl 120`, the default — report
    FAILURE and break `set -e` / `carlos-ctl pma && ...` operator scripting
    (verified live: --ttl 1 returned 124 after 62s). A real failure must still
    propagate."""

    def _run(self, mk_runner, rc: int, args: list) -> int:
        r = mk_runner()
        # `timeout` must be on PATH or cmd_pma takes the UNBOUNDED branch and
        # these cases would never exercise the ttl path at all.
        r.tools.add("timeout")
        r.script("podman", "ps", out="carlos-app-db\n")
        r.script("timeout", rc=rc)
        return dbops.cmd_pma(r, args)

    def test_the_ttl_branch_is_actually_taken(self, mk_runner) -> None:
        # Guards the fixture itself: without `timeout` on PATH the cases below
        # would pass on the unbounded branch's default rc 0.
        r = mk_runner()
        r.tools.add("timeout")
        r.script("podman", "ps", out="carlos-app-db\n")
        dbops.cmd_pma(r, ["--ttl", "5"])
        assert any(c[:1] == ["timeout"] for c in r.calls), "ttl did not wrap the run"

    def test_ttl_expiry_reports_success(self, mk_runner) -> None:
        assert self._run(mk_runner, 124, ["--ttl", "5"]) == 0

    def test_ttl_sigkill_escalation_reports_success(self, mk_runner) -> None:
        assert self._run(mk_runner, 137, ["--ttl", "5"]) == 0

    def test_a_real_failure_still_propagates(self, mk_runner) -> None:
        # e.g. podman could not start the container — must NOT read as success.
        assert self._run(mk_runner, 125, ["--ttl", "5"]) == 125

    def test_interrupt_reports_success(self, mk_runner) -> None:
        # Ctrl-C is the documented way to stop an unbounded session.
        r = mk_runner()
        r.script("podman", "ps", out="carlos-app-db\n")
        r.script("podman", "run", rc=130)
        assert dbops.cmd_pma(r, ["--ttl", "0"]) == 0

    def test_unbounded_session_still_propagates_failure(self, mk_runner) -> None:
        r = mk_runner()
        r.script("podman", "ps", out="carlos-app-db\n")
        r.script("podman", "run", rc=125)
        assert dbops.cmd_pma(r, ["--ttl", "0"]) == 125


class TestProvisioningSqlNotBinlogged:
    """Account DDL must NOT ride the binary log — otherwise a windowed PITR
    restore (or the Sunday drill) replays the ALTER USER onto the live/scratch
    server and rewinds the app/root credentials to a stale generation
    (ninth-pass finding: app-down at reboot, worst case a root lockout)."""

    def test_provision_sql_opens_with_sql_log_bin_off(self) -> None:
        first = next(
            ln.strip() for ln in dbops._PROVISION_SQL.splitlines()
            if ln.strip() and not ln.strip().startswith("--")
        )
        assert first.replace(" ", "").lower() == "setsessionsql_log_bin=0;"


class TestDbBackupArgumentContract:
    """`db-backup` writes a PLAINTEXT-PHI physical copy of the datadir to a
    directory named from argv. Pass 14 found it read args[0] and dropped the
    rest, and the name regex accepts a leading dash — so `carlos-ctl db-backup
    --help` took a real snapshot into a directory called `--help` (verified
    live) instead of printing usage, and `db-backup nightly --flag` silently
    ignored the flag. Same class as the CLI's no-argument-verb guard."""

    def _ctx(self, mk_runner):
        r = mk_runner()
        r.script("podman", "ps", out="carlos-app-db\n")
        s = r.settings
        (s.conf_dir / "carlos").mkdir(parents=True, exist_ok=True)
        s.properties_file.write_text("db_username=carlos\ndb_password=x\n")
        return r

    def _refuses(self, r, args) -> str:
        from carlos_ctl.util import CtlError

        try:
            dbops.cmd_db_backup(r, args)
        except CtlError as e:
            return str(e)
        raise AssertionError(f"db-backup accepted {args!r}")

    def test_extra_arguments_are_refused_not_dropped(self, mk_runner) -> None:
        r = self._ctx(mk_runner)
        assert "one optional name" in self._refuses(r, ["nightly", "--compress"])

    def test_flag_shaped_name_is_refused(self, mk_runner) -> None:
        r = self._ctx(mk_runner)
        assert "looks like a flag" in self._refuses(r, ["--help"])

    def test_short_flag_shaped_name_is_refused(self, mk_runner) -> None:
        r = self._ctx(mk_runner)
        assert "looks like a flag" in self._refuses(r, ["-h"])

    def test_refusal_happens_before_any_snapshot_is_taken(self, mk_runner) -> None:
        # The point of the guard: no mariadb-backup, no directory, no PHI on
        # disk. (`podman ps` from require_db_running may run; nothing else.)
        r = self._ctx(mk_runner)
        self._refuses(r, ["--help"])
        assert not r.called_with("mariadb-backup")
        hot = r.settings.emr_home / "backup" / "mariadb-hot"
        assert not hot.exists() or not any(hot.iterdir())

    def test_a_plain_name_is_still_accepted(self, mk_runner) -> None:
        from carlos_ctl.util import CtlError

        r = self._ctx(mk_runner)
        try:
            dbops.cmd_db_backup(r, ["pre-upgrade.1"])
        except CtlError as e:  # may fail later (no real db) — but NOT on args
            assert "usage: carlos-ctl db-backup" not in str(e)


class TestExporterCnfOwnershipHandover:
    """The exporter cnf is handed to container uid 65534 by a rootless
    `podman unshare chown`. chown(2) refuses a file whose current owner OR
    group is outside the userns id_map, and host uid/gid 0 are never mapped —
    so the hand-over to the service user must set BOTH ids. Setting only the
    uid left the file group-root and made every later userns chown EPERM
    (pass 14, reproduced live: mysqld metrics gone from the first `play`,
    which auto-provisions these accounts by default)."""

    def test_helper_sets_uid_and_gid(self, tmp_path, monkeypatch) -> None:
        import pwd as pwd_mod

        from carlos_ctl import util

        seen = {}

        class _PW:
            pw_uid, pw_gid = 4242, 4343

        monkeypatch.setattr(pwd_mod, "getpwnam", lambda _n: _PW())
        monkeypatch.setattr(
            util.os, "chown", lambda p, u, g: seen.update(path=p, uid=u, gid=g)
        )
        f = tmp_path / "exporter.my.cnf"
        f.write_text("[client]\n")
        assert util.chown_to_service_user(f, "carlos") is True
        assert (seen["uid"], seen["gid"]) == (4242, 4343), "gid must not be left as -1"

    def test_helper_reports_failure_instead_of_raising(self, tmp_path) -> None:
        from carlos_ctl import util

        f = tmp_path / "gone.cnf"
        assert util.chown_to_service_user(f, "no-such-user-for-carlos-tests") is False

    def test_provisioning_hands_over_before_the_userns_chown(self, monkeypatch) -> None:
        # Ordering is the contract: the unshare chown can only succeed on a
        # file whose ids are already inside the service user's map.
        import inspect

        src = inspect.getsource(dbops.provision_db_accounts)
        handover = src.index("chown_to_service_user(s.exporter_mycnf_file")
        userns = src.index('"unshare", "chown", "65534:65534"')
        assert handover < userns

    def test_play_repairs_ownership_before_its_userns_chown(self) -> None:
        # `play` is the remedy both warnings name, so it must repair a
        # root-written file, not merely re-observe the EPERM.
        import inspect

        from carlos_ctl import lifecycle2

        src = inspect.getsource(lifecycle2.cmd_play)
        assert "chown_to_service_user(target, s.service_user)" in src
        assert src.index("chown_to_service_user(target") < src.index('"unshare", "chown"')


class TestDbMigrate:
    """`db-migrate` (issue #17): CARLOS migrations must run in a client
    session pinned to the schema's utf8mb4_general_ci family — on MariaDB
    11.4+ the session default is uca1400_ai_ci and V1.0.7's bare
    CAST(... AS CHAR) comparison dies with ERROR 1267. The pin has to ride
    the SAME session as the SQL (a prior `db -e 'SET NAMES ...'` process
    doesn't carry over), so the client is started with --init-command."""

    @staticmethod
    def _sql(tmp_path: Path, *names: str) -> list:
        files = []
        for n in names:
            p = tmp_path / n
            p.write_text("SELECT 1;\n")
            files.append(str(p))
        return files

    def _runner(self, mk_runner):
        r = mk_runner("CARLOS_DB_ROOT_PASSWORD=root-pw\n")
        r.script("podman", "ps", out=f"{r.settings.app_pod}-db\n")
        return r

    def test_pins_the_session_collation_in_the_same_client(self, mk_runner, tmp_path) -> None:
        r = self._runner(mk_runner)
        assert dbops.cmd_db_migrate(r, self._sql(tmp_path, "V1.0.7.sql")) == 0
        execs = [c for c in r.calls if "exec" in c and "mariadb" in c]
        assert len(execs) == 1
        assert f"--init-command={dbops.MIGRATION_SESSION_PIN}" in execs[0]
        assert execs[0][-1] == "oscar"

    def test_applies_files_in_argv_order(self, mk_runner, tmp_path) -> None:
        r = self._runner(mk_runner)
        files = self._sql(tmp_path, "V1.0.7.sql", "V1.0.13.sql")
        assert dbops.cmd_db_migrate(r, files) == 0
        execs = [c for c in r.calls if "exec" in c and "mariadb" in c]
        assert len(execs) == 2

    def test_db_flag_overrides_the_target_database(self, mk_runner, tmp_path) -> None:
        r = self._runner(mk_runner)
        assert dbops.cmd_db_migrate(r, ["--db", "drugref2", *self._sql(tmp_path, "a.sql")]) == 0
        execs = [c for c in r.calls if "exec" in c and "mariadb" in c]
        assert execs[0][-1] == "drugref2"

    def test_fail_fast_stops_before_the_next_file(self, mk_runner, tmp_path) -> None:
        # NO --force semantics: the first SQL error ends the run; the
        # remaining files are named in the error, not silently attempted.
        import pytest

        from carlos_ctl.util import CtlError

        r = self._runner(mk_runner)
        r.script("podman", "exec", rc=1)
        files = self._sql(tmp_path, "V1.0.7.sql", "V1.0.13.sql")
        with pytest.raises(CtlError, match=r"V1\.0\.7\.sql failed.*V1\.0\.13\.sql"):
            dbops.cmd_db_migrate(r, files)
        execs = [c for c in r.calls if "exec" in c and "mariadb" in c]
        assert len(execs) == 1

    def test_a_missing_file_refuses_before_any_sql_runs(self, mk_runner, tmp_path) -> None:
        # A typo in the MIDDLE of the list must not half-apply the sequence.
        import pytest

        from carlos_ctl.util import CtlError

        r = self._runner(mk_runner)
        first = self._sql(tmp_path, "V1.0.7.sql")
        with pytest.raises(CtlError, match="not found"):
            dbops.cmd_db_migrate(r, [*first, str(tmp_path / "nope.sql")])
        assert not any("exec" in c and "mariadb" in c for c in r.calls)

    def test_requires_the_root_password_in_the_env_file(self, mk_runner, tmp_path) -> None:
        # Stdin carries the SQL, so the interactive -p prompt is unusable —
        # refuse with guidance instead of hanging on a prompt nobody sees.
        import pytest

        from carlos_ctl.util import CtlError

        r = mk_runner("")
        r.script("podman", "ps", out=f"{r.settings.app_pod}-db\n")
        with pytest.raises(CtlError, match="CARLOS_DB_ROOT_PASSWORD"):
            dbops.cmd_db_migrate(r, self._sql(tmp_path, "a.sql"))

    def test_requires_the_db_container_running(self, mk_runner, tmp_path) -> None:
        import pytest

        from carlos_ctl.util import CtlError

        r = mk_runner("CARLOS_DB_ROOT_PASSWORD=pw\n")
        r.script("podman", "ps", out="")
        with pytest.raises(CtlError, match="db container not running"):
            dbops.cmd_db_migrate(r, self._sql(tmp_path, "a.sql"))

    def test_the_password_never_reaches_argv(self, mk_runner, tmp_path) -> None:
        r = self._runner(mk_runner)
        dbops.cmd_db_migrate(r, self._sql(tmp_path, "a.sql"))
        assert not any("root-pw" in tok for call in r.calls for tok in call)

    def test_flag_shaped_or_empty_file_lists_are_refused(self, mk_runner, tmp_path) -> None:
        import pytest

        from carlos_ctl.util import CtlError

        r = self._runner(mk_runner)
        with pytest.raises(CtlError, match="usage"):
            dbops.cmd_db_migrate(r, [])
        with pytest.raises(CtlError, match="usage"):
            dbops.cmd_db_migrate(r, ["--force", *self._sql(tmp_path, "a.sql")])

    def test_flag_shaped_db_value_is_refused(self, mk_runner, tmp_path) -> None:
        # The db name lands on the client's argv: `--db --force` would turn
        # ON mariadb's continue-past-SQL-errors mode (defeating fail-fast)
        # and `--db --help` exits 0 without reading the SQL at all.
        import pytest

        from carlos_ctl.util import CtlError

        r = self._runner(mk_runner)
        for bad in ("--force", "--help", "-f", ""):
            with pytest.raises(CtlError, match="invalid database name"):
                dbops.cmd_db_migrate(r, ["--db", bad, *self._sql(tmp_path, "a.sql")])
        assert not any("exec" in c and "mariadb" in c for c in r.calls)
