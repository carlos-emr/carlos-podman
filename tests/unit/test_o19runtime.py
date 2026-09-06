# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Unit tests for carlos_ctl.o19runtime: podman's answers to the OSCAR 19
importer's deployment questions.

Every one of these is a place where answering the deb's way would break a
clinic's migration on this deployment — a workspace written where this host
has no such directory, a client that cannot reach a database with no
published port, a document tree chowned to an identity the container cannot
use, a gate that lets the import run while CARLOS is writing to the target."""

from __future__ import annotations

import subprocess

import pytest

from carlos_ctl import o19runtime
from carlos_ctl.util import CtlError

_PROPS = "billregion=ON\ndb_username=carlos\n"


class FakeBase:
    """Stands in for the engine's `o19host.Host`. Only what the podman
    behaviour composes onto: everything the mixin overrides is overridden,
    so the base contributes nothing to these answers."""

    label = "the carlos-emr deb package"

    def sql_escape(self, value):  # pragma: no cover - overridden path
        return value


class FakeEngineModule:
    STAGING_USER = "o19_import"
    STAGING_SCHEMA = "o19_import"

    @staticmethod
    def staging_init_command(statement_timeout=0):
        return "SET SESSION sql_log_bin=0"

    @staticmethod
    def strip_client_identity(args):
        out, skip = [], False
        for a in args:
            if skip:
                skip = False
                continue
            if a in ("-u", "--user"):
                skip = True
                continue
            if a.startswith(("-u", "--user", "-p", "--password")):
                continue
            out.append(a)
        return out


class FakeEnginePackage:
    dbops = type("dbops", (), {
        "sql_escape": staticmethod(
            lambda v: v.replace("\\", "\\\\").replace("'", "\\'"))})
    util = type("util", (), {
        "prop_get": staticmethod(
            lambda path, key: _prop_get(path, key))})


def _prop_get(path, key):
    found = None
    try:
        with open(path, encoding="latin-1") as fh:
            for line in fh:
                if line.split("=", 1)[0].strip() == key:
                    found = line.split("=", 1)[1].rstrip("\n")
    except OSError:
        return None
    return found


class FakeEngine:
    o19host = FakeEngineModule
    o19import = FakeEngineModule
    package = FakeEnginePackage


def make(runner):
    cls = type("PodmanHost", (o19runtime.PodmanHostBehaviour, FakeBase), {})
    return cls(runner, FakeEngine())


@pytest.fixture
def host(mk_runner):
    """A provisioned instance: env file present, root password set."""
    runner = mk_runner("CARLOS_DB_ROOT_PASSWORD=rootpw\n")
    runner.settings.properties_file.parent.mkdir(parents=True, exist_ok=True)
    runner.settings.properties_file.write_text(_PROPS)
    return runner, make(runner)


class TestWhereThingsLive:

    def test_the_workspace_is_under_emr_home(self, host):
        runner, h = host
        assert h.state_dir == str(runner.settings.emr_home / "o19-import")

    def test_the_documents_root_follows_the_document_store(self, host):
        runner, h = host
        (runner.settings.data_dir / "CarlosDocument").mkdir(parents=True)
        assert h.documents_root == str(
            runner.settings.data_dir / "CarlosDocument")

    def test_the_documents_root_follows_the_legacy_store_mid_rename(
            self, host):
        # the playbook's one-time rename may not have run; a migration must
        # write where the application actually reads
        runner, h = host
        (runner.settings.data_dir / "OscarDocument").mkdir(parents=True)
        assert h.documents_root == str(
            runner.settings.data_dir / "OscarDocument")


class TestIdentity:

    def test_a_provisioned_instance_is_a_packaged_host(self, host):
        _, h = host
        assert h.is_packaged_host()

    def test_no_env_file_is_a_development_database(self, mk_runner,
                                                   tmp_path):
        runner = mk_runner()
        runner.settings.env_file.unlink()
        h = make(runner)
        assert not h.is_packaged_host()
        assert h.configured_province() == "on"
        assert h.configured_db_name() is None

    def test_the_province_comes_from_billregion(self, host):
        _, h = host
        assert h.configured_province() == "on"

    def test_billregion_bc_selects_the_bc_profile(self, host):
        runner, h = host
        runner.settings.properties_file.write_text("billregion=BC\n")
        assert h.configured_province() == "bc"

    def test_a_generic_billregion_is_refused_by_name(self, host):
        # 'generic' is a valid CARLOS billregion and NOT a migration profile;
        # importing under another province's rulings must not be possible
        runner, h = host
        runner.settings.properties_file.write_text("billregion=generic\n")
        with pytest.raises(CtlError) as exc:
            h.configured_province()
        assert "generic" in str(exc.value)

    def test_a_missing_billregion_is_refused(self, host):
        runner, h = host
        runner.settings.properties_file.write_text("db_username=carlos\n")
        with pytest.raises(CtlError) as exc:
            h.configured_province()
        assert "billregion" in str(exc.value)

    def test_the_schema_name_is_identifier_validated(self, mk_runner):
        runner = mk_runner("CARLOS_DB_NAME=clinic_a\n")
        runner.settings.properties_file.parent.mkdir(parents=True,
                                                     exist_ok=True)
        runner.settings.properties_file.write_text(_PROPS)
        assert make(runner).configured_db_name() == "clinic_a"

    def test_a_schema_name_that_is_not_an_identifier_is_refused(self,
                                                                mk_runner):
        runner = mk_runner("CARLOS_DB_NAME=bad;name\n")
        with pytest.raises(CtlError):
            make(runner).configured_db_name()


class TestReachingTheDatabase:

    def test_the_client_runs_inside_the_db_container(self, host):
        runner, h = host
        argv = h.client_base_argv(None)
        assert argv[:1] == ["podman"]  # FakeRunner drops the runuser wrapper
        assert argv[-2:] == ["mariadb", "-uroot"]
        assert f"{runner.settings.app_pod}-db" in argv

    def test_the_password_rides_the_environment_never_the_argv(self, host):
        _, h = host
        assert h.client_env() == {"MYSQL_PWD": "rootpw"}
        assert "rootpw" not in " ".join(h.client_base_argv(None))
        # forwarded BY NAME across the boundary
        assert h.client_base_argv(None).count("MYSQL_PWD") == 1
        assert "-e" in h.client_base_argv(None)

    def test_no_root_password_yields_no_credential(self, mk_runner):
        runner = mk_runner()
        assert make(runner).client_env() == {}

    def test_the_development_seam_replaces_the_whole_client(self, host):
        _, h = host
        assert (h.client_base_argv(["--socket=/tmp/s", "-uroot"])
                == ["mariadb", "--socket=/tmp/s", "-uroot"])


class TestTheStagingCredential:

    def test_the_password_is_returned_for_the_environment_not_written(
            self, host, tmp_path):
        _, h = host
        cnf = tmp_path / "client.cnf"
        assert h.stage_credential("stagingpw", str(cnf)) == {
            "MYSQL_PWD": "stagingpw"}
        assert not cnf.exists()

    def test_clearing_removes_a_file_that_somehow_exists(self, host,
                                                         tmp_path):
        _, h = host
        cnf = tmp_path / "client.cnf"
        cnf.write_text("[client]\n")
        h.clear_stage_credential(str(cnf))
        assert not cnf.exists()

    def test_clearing_a_missing_file_is_not_an_error(self, host):
        _, h = host
        h.clear_stage_credential("/nonexistent/client.cnf")

    def test_the_restore_client_keeps_the_runuser_boundary(self, host):
        # the engine's strip_client_identity is correct for a bare client
        # tail; applied to THIS argv it would eat `runuser -u <service user>`
        # and run the clinic's restore through root's podman engine
        runner, h = host
        base = h.client_base_argv(None)
        argv = h.staging_client_argv(base, "/unused", 0)
        assert argv[:1] == ["podman"]
        assert f"{runner.settings.app_pod}-db" in argv
        assert "-uroot" not in argv
        assert "--user=o19_import" in argv

    def test_the_restore_client_is_scoped_and_cannot_read_local_files(
            self, host):
        _, h = host
        argv = h.staging_client_argv(h.client_base_argv(None), "/unused", 0)
        assert "--one-database" in argv
        assert "--local-infile=0" in argv
        assert argv[-1] == "o19_import"

    def test_the_statement_timeout_reaches_the_restore_session(self, host):
        _, h = host
        argv = h.staging_client_argv(h.client_base_argv(None), "/unused", 30)
        assert any(a.startswith("--init-command=") for a in argv)

    def test_the_development_seam_strips_its_own_identity(self, host):
        _, h = host
        base = h.client_base_argv(["--socket=/tmp/s", "-uroot", "-psecret"])
        argv = h.staging_client_argv(base, "/unused", 0)
        assert argv[0] == "mariadb"
        assert "--socket=/tmp/s" in argv
        assert "-uroot" not in argv
        assert "-psecret" not in argv
        assert "--user=o19_import" in argv


class TestAcrossTheRealBoundary:

    """The same argv questions, against the REAL `Runner.podman_user_argv`.

    The unit FakeRunner deliberately returns a bare `podman ...` (so tests
    need no local service user), which HIDES the `runuser -u <user> --`
    prefix every pod-facing call actually carries. That prefix is exactly
    what a naive identity-strip destroys, so it has to be asserted against
    the production shape or the assertion is vacuous."""

    @staticmethod
    def _real_boundary(runner):
        from carlos_ctl.runner import Runner

        runner.settings.service_uid = lambda: 1000
        runner.podman_user_argv = Runner.podman_user_argv.__get__(runner)

    def test_the_root_client_crosses_to_the_service_user(self, host):
        runner, h = host
        self._real_boundary(runner)
        argv = h.client_base_argv(None)
        assert argv[:4] == ["runuser", "-u", runner.settings.service_user,
                            "--"]
        assert argv[-2:] == ["mariadb", "-uroot"]

    def test_the_restore_client_keeps_the_crossing_intact(self, host):
        # `strip_client_identity` is correct for a bare client tail; applied
        # to THIS argv it eats the `-u <service user>` pair and the clinic's
        # restore runs through ROOT's podman engine instead
        runner, h = host
        self._real_boundary(runner)
        base = h.client_base_argv(None)
        argv = h.staging_client_argv(base, "/unused", 0)
        assert argv[:4] == ["runuser", "-u", runner.settings.service_user,
                            "--"]
        assert "podman" in argv
        assert f"{runner.settings.app_pod}-db" in argv
        assert "--user=o19_import" in argv
        assert "-uroot" not in argv

    def test_the_credential_never_becomes_an_argv_token(self, host):
        runner, h = host
        self._real_boundary(runner)
        for argv in (h.client_base_argv(None),
                     h.staging_client_argv(h.client_base_argv(None),
                                           "/unused", 0)):
            assert "rootpw" not in " ".join(argv)
            assert "MYSQL_PWD" in argv  # forwarded by NAME
            assert argv[argv.index("MYSQL_PWD") - 1] == "-e"


class TestDocumentOwnership:

    @staticmethod
    def _maps(runner, uid_rows, gid_rows):
        def fake(argv, **kw):
            joined = " ".join(argv)
            if "uid_map" in joined:
                return subprocess.CompletedProcess(argv, 0, uid_rows, "")
            if "gid_map" in joined:
                return subprocess.CompletedProcess(argv, 0, gid_rows, "")
            return subprocess.CompletedProcess(argv, 0, "", "")

        runner.run = fake

    def test_the_owner_is_the_containers_uid_mapped_to_the_host(self, host):
        # container uid 10001 is a SUBUID on the host; handing the tree to
        # the service user leaves every chart unopenable until the pod's
        # init container sweeps it, and to host uid 10001 gives it away
        runner, h = host
        self._maps(runner, "         0       1000          1\n"
                           "         1     100000      65536\n",
                   "         0       1000          1\n"
                   "         1     100000      65536\n")
        owner, dmode, fmode = h.document_ownership()
        assert owner == str(100000 + o19runtime.CARLOS_CONTAINER_UID - 1)
        assert (dmode, fmode) == ("0700", "0600")

    def test_the_answer_is_resolved_once(self, host):
        runner, h = host
        self._maps(runner, "         1     100000      65536\n",
                   "         1     100000      65536\n")
        first = h.document_ownership()
        runner.run = lambda argv, **kw: (_ for _ in ()).throw(
            AssertionError("re-resolved"))
        assert h.document_ownership() == first

    def test_an_unmappable_uid_fails_closed(self, host):
        # a tree chowned to the wrong id passes the root-run reconciliation
        # and then fails every chart that opens a scan
        runner, h = host
        self._maps(runner, "         0       1000          1\n",
                   "         0       1000          1\n")
        with pytest.raises(CtlError) as exc:
            h.document_ownership()
        assert "subuid" in str(exc.value)

    def test_an_unreadable_id_map_fails_closed(self, host):
        runner, h = host
        runner.run = lambda argv, **kw: subprocess.CompletedProcess(
            argv, 1, "", "podman unshare: no subuid ranges")
        with pytest.raises(CtlError):
            h.document_ownership()

    def test_diverging_uid_and_gid_maps_are_refused(self, host):
        # the importer chowns with ONE id for both
        runner, h = host
        self._maps(runner, "         1     100000      65536\n",
                   "         1     200000      65536\n")
        with pytest.raises(CtlError) as exc:
            h.document_ownership()
        assert "gid" in str(exc.value)


class TestTheBackupGate:

    def test_a_plaintext_restic_password_counts_as_configured(self,
                                                              mk_runner):
        runner = mk_runner("RESTIC_PASSWORD=x\n")
        assert make(runner).backup_configured()

    def test_a_sealed_bundle_counts_as_configured(self, mk_runner):
        runner = mk_runner()
        runner.settings.secrets_bundle.parent.mkdir(parents=True,
                                                    exist_ok=True)
        runner.settings.secrets_bundle.write_text("sops")
        assert make(runner).backup_configured()

    def test_neither_is_not_configured(self, mk_runner):
        runner = mk_runner()
        h = make(runner)
        assert not h.backup_configured()
        assert "RESTIC_PASSWORD" in h.backup_configuration_hint()

    def test_the_snapshot_is_the_real_backup_path(self, host, monkeypatch):
        from carlos_ctl import backup as backup_mod

        runner, h = host
        seen = {}

        def fake(r, args):
            seen["args"] = args
            return 0

        monkeypatch.setattr(backup_mod, "cmd_backup", fake)
        assert h.pre_import_backup() == (True, "")
        assert seen["args"] == ["full"]

    def test_a_failed_snapshot_reports_where_to_look(self, host,
                                                     monkeypatch):
        from carlos_ctl import backup as backup_mod

        runner, h = host
        monkeypatch.setattr(backup_mod, "cmd_backup", lambda r, a: 1)
        ok, hint = h.pre_import_backup()
        assert not ok
        assert "journalctl" in hint

    def test_a_refusing_snapshot_surfaces_its_own_reason(self, host,
                                                         monkeypatch):
        from carlos_ctl import backup as backup_mod

        runner, h = host

        def boom(r, a):
            raise CtlError("restic repository is uninitialized")

        monkeypatch.setattr(backup_mod, "cmd_backup", boom)
        ok, hint = h.pre_import_backup()
        assert not ok
        assert "uninitialized" in hint


class TestTheAppRunningGate:

    @staticmethod
    def _ps(runner, names, rc=0):
        runner.run = lambda argv, **kw: subprocess.CompletedProcess(
            argv, rc, "\n".join(names) + "\n", "")

    def test_a_running_application_is_refused(self, host):
        runner, h = host
        pod = runner.settings.app_pod
        self._ps(runner, [f"{pod}-carlos", f"{pod}-db"])
        message = h.app_running_refusal()
        assert message is not None
        assert "podman stop" in message

    def test_the_refusal_does_not_tell_the_operator_to_stop_the_database(
            self, host):
        # 'carlos-ctl down' stops the db too, and the import needs it
        runner, h = host
        pod = runner.settings.app_pod
        self._ps(runner, [f"{pod}-carlos", f"{pod}-db"])
        message = h.app_running_refusal()
        assert f"podman stop {pod}-carlos" in message
        assert "'carlos-ctl down' stops the database too" in message

    def test_a_stopped_application_with_the_database_up_passes(self, host):
        runner, h = host
        self._ps(runner, [f"{runner.settings.app_pod}-db"])
        assert h.app_running_refusal() is None

    def test_a_stopped_database_is_refused_too(self, host):
        runner, h = host
        self._ps(runner, [])
        message = h.app_running_refusal()
        assert message is not None
        assert "not running" in message

    def test_an_unreadable_engine_fails_closed(self, host):
        # a podman ps that did not answer has NOT established that the
        # application is stopped
        runner, h = host
        self._ps(runner, [], rc=125)
        message = h.app_running_refusal()
        assert message is not None
        assert "could not determine" in message

    def test_a_development_database_has_no_pod_to_check(self, mk_runner):
        runner = mk_runner()
        runner.settings.env_file.unlink()
        assert make(runner).app_running_refusal() is None


class TestTheSchemaGate:

    @staticmethod
    def _answers(runner, *, history=None, images=None, table=True):
        """history: [(version, success)]; images: ['1', '1.0.1'];
        table=False models the raw-SQL deployment with no bookkeeping."""

        def fake_run(argv, **kw):
            sql = str(kw.get("input_text") or "")
            if "information_schema.TABLES" in sql:
                return subprocess.CompletedProcess(
                    argv, 0, "1\n" if table else "0\n", "")
            if "flyway_schema_history" in sql:
                body = "".join(f"{v}\t{'1' if ok else '0'}\n"
                               for v, ok in (history or []))
                return subprocess.CompletedProcess(argv, 0, body, "")
            return subprocess.CompletedProcess(argv, 0, "", "")

        def fake_podman(args, **kw):
            if images is None:
                return subprocess.CompletedProcess(list(args), 1, "", "")
            body = "".join(f"V{v}__thing.sql\n" for v in images)
            return subprocess.CompletedProcess(list(args), 0, body, "")

        runner.run = fake_run
        runner.podman_user = fake_podman

    def test_the_raw_sql_deployment_warns_and_defers_to_the_seed_floors(
            self, host, capsys):
        runner, h = host
        self._answers(runner, table=False)
        assert h.flyway_validate() == 0
        assert "db-migrate" in capsys.readouterr().err

    def test_a_failed_migration_is_refused(self, host):
        runner, h = host
        self._answers(runner, history=[("1", True), ("1.0.1", False)])
        assert h.flyway_validate() == 1

    def test_a_target_behind_the_deployed_image_is_refused(self, host):
        runner, h = host
        self._answers(runner, history=[("1", True)],
                      images=["1", "1.0.1"])
        assert h.flyway_validate() == 1

    def test_a_matching_schema_passes(self, host):
        runner, h = host
        self._answers(runner, history=[("1", True), ("1.0.1", True)],
                      images=["1", "1.0.1"])
        assert h.flyway_validate() == 0

    def test_an_unreadable_image_does_not_veto_a_clean_history(self, host,
                                                               capsys):
        runner, h = host
        self._answers(runner, history=[("1", True)], images=None)
        assert h.flyway_validate() == 0
        assert "could not list the migration set" in capsys.readouterr().err

    def test_the_image_listing_asks_for_this_instances_province(self, host):
        runner, h = host
        seen = {}

        def fake_podman(args, **kw):
            seen["args"] = list(args)
            return subprocess.CompletedProcess(list(args), 0,
                                               "V1__x.sql\n", "")

        self._answers(runner, history=[("1", True)], images=["1"])
        runner.podman_user = fake_podman
        h.flyway_validate()
        joined = " ".join(seen["args"])
        assert f"{o19runtime.IMAGE_MIGRATION_DIR}/common" in joined
        assert f"{o19runtime.IMAGE_MIGRATION_DIR}/on" in joined
        assert "--network=none" in seen["args"]


class TestComposition:

    def test_the_podman_answers_win_over_the_engines(self, mk_runner):
        runner = mk_runner()
        engine = FakeEngine()
        engine.o19host = type("m", (), {"Host": FakeBase,
                                        "STAGING_USER": "o19_import"})
        host = o19runtime.make_host(runner, engine)
        assert host.label == "the carlos-podman deployment"
        assert host.state_dir == str(runner.settings.emr_home / "o19-import")

    def test_the_class_is_named_for_what_it_is(self, mk_runner):
        runner = mk_runner()
        engine = FakeEngine()
        engine.o19host = type("m", (), {"Host": FakeBase,
                                        "STAGING_USER": "o19_import"})
        assert type(o19runtime.make_host(runner, engine)).__name__ \
            == "PodmanHost"
