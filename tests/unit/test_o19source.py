# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Unit tests for carlos_ctl.o19source: taking the OSCAR 19 import engine
from the CARLOS tree this instance deploys.

The stakes: the engine's two manifests are GENERATED per CARLOS version —
every ruling in them ("this column merges there", "this table is
archive-only") is correct for exactly one schema. Loading the engine from a
different version than the deployed WAR would migrate a clinic under rulings
its own application does not implement, and nothing downstream would notice.
So: no pin, no import; a moving ref, no import; a module or a name missing,
no import."""

from __future__ import annotations

import subprocess
import textwrap

import pytest

from carlos_ctl import o19compat, o19source, source
from carlos_ctl.source import SourcePin
from carlos_ctl.util import CtlError

_SHA = "a" * 40


def subprocess_result(argv, rc, out=""):
    return subprocess.CompletedProcess(argv, rc, out, "")


def _escape(value: str) -> str:
    return "<escaped:" + value + ">"


def write_fake_engine(root, extra=None, omit=(), sibling_imports=()):
    """A minimal but STRUCTURALLY REAL engine tree: every required module,
    o19_preflight carrying the escape the shims are built from, and o19host
    carrying a Host the podman behaviour can be composed onto."""
    root.mkdir(parents=True, exist_ok=True)
    bodies = {
        "o19_preflight": textwrap.dedent("""
            def _sql_literal(value):
                return (value.replace("\\\\", "\\\\\\\\")
                        .replace("'", "\\\\'").replace("\\0", "\\\\0")
                        .replace("\\r", "\\\\r"))
        """),
        "o19host": textwrap.dedent("""
            from . import dbops
            from .util import STATE, log, run

            STAGING_USER = "o19_import"
            STATE_DIR = STATE + "/o19-import"


            class Host(object):
                label = "the carlos-emr deb package"

                @property
                def state_dir(self):
                    return STATE_DIR

                @property
                def documents_root(self):
                    return STATE + "/OscarDocument"

                def is_packaged_host(self):
                    return False

                def configured_province(self):
                    return "on"

                def configured_db_name(self):
                    return None

                def identity_source(self):
                    return "deb"

                def client_base_argv(self, mariadb_args):
                    return ["mariadb"]

                def client_env(self):
                    return {}

                def stage_credential(self, password, client_cnf):
                    return {}

                def clear_stage_credential(self, client_cnf):
                    return None

                def staging_client_argv(self, base, cnf, timeout=0):
                    return ["mariadb"]

                def document_ownership(self):
                    return ("carlos", "2750", "0640")

                def sql_escape(self, value):
                    return dbops.sql_escape(value)

                def flyway_validate(self):
                    return 0

                def backup_configured(self):
                    return False

                def backup_configuration_hint(self):
                    return "deb"

                def pre_import_backup(self):
                    log("backup")
                    run(["true"])
                    return (True, "")

                def app_running_refusal(self):
                    return None
        """),
        "o19import": textwrap.dedent("""
            from . import o19host

            HOST = o19host.Host()
            STAGING_SCHEMA = "o19_import"
            CALLS = []


            def staging_init_command(statement_timeout=0):
                return "SET SESSION sql_log_bin=0"


            def strip_client_identity(args):
                return [a for a in args if not a.startswith("-u")]


            def cmd_import_o19(argv):
                CALLS.append(("import", list(argv)))
                return 0


            def cmd_o19_preflight(argv):
                CALLS.append(("preflight", list(argv)))
                return 2
        """),
    }
    for name in o19source.REQUIRED_MODULES:
        if name in omit:
            continue
        body = bodies.get(name, f"VALUE = {name!r}\n")
        if name in dict(sibling_imports or {}):
            body = dict(sibling_imports)[name] + body
        (root / (name + ".py")).write_text(body)
    for name, body in (extra or {}).items():
        (root / (name + ".py")).write_text(body)
    return root


@pytest.fixture(autouse=True)
def _clean_engine():
    o19source.unload_engine()
    yield
    o19source.unload_engine()


class TestWhichCarlos:
    """The importer comes from the pinned tree or it does not run."""

    def test_no_pin_at_all_is_refused(self, mk_runner):
        runner = mk_runner()
        with pytest.raises(CtlError) as exc:
            o19source.pinned_commit(runner)
        assert "no pinned CARLOS version" in str(exc.value)

    def test_a_corrupt_pin_reads_as_no_pin(self, mk_runner):
        # read_pin's own structural check rejects an implausible pin and
        # warns; the importer must not fall through to "some version"
        runner = mk_runner()
        path = source.pin_path(runner, source.CARLOS)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{"ref": "develop", "kind": "branch"}')
        with pytest.raises(CtlError) as exc:
            o19source.pinned_commit(runner)
        assert "no pinned CARLOS version" in str(exc.value)

    def test_a_commitless_pin_is_refused_even_if_read_pin_lets_it_by(
            self, mk_runner, monkeypatch):
        # defence in depth: read_pin guarantees a 40-hex ref today, and a
        # moving ref reaching the loader means a clinic migrated under
        # another CARLOS version's manifest
        runner = mk_runner()
        monkeypatch.setattr(
            source, "read_pin",
            lambda r, app: SourcePin(ref="develop", kind="branch",
                                     branch="develop"))
        with pytest.raises(CtlError) as exc:
            o19source.pinned_commit(runner)
        assert "names no commit" in str(exc.value)

    def test_a_release_pin_yields_its_commit(self, mk_runner):
        runner = mk_runner()
        source.write_pin(runner, source.CARLOS,
                         SourcePin(ref=_SHA, kind="release", tag="2026.9.0",
                                   commit=_SHA), implicit=True)
        commit, described = o19source.pinned_commit(runner)
        assert commit == _SHA
        assert "2026.9.0" in described

    def test_a_bare_sha_ref_counts_as_a_commit(self, mk_runner):
        runner = mk_runner()
        source.write_pin(runner, source.CARLOS,
                         SourcePin(ref=_SHA, kind="manual"), implicit=True)
        assert o19source.pinned_commit(runner)[0] == _SHA

    def test_the_engine_is_keyed_by_commit(self, mk_runner):
        # an upgrade fetches BESIDE the old tree, so a resume started under
        # the previous manifest still finds the modules it began with
        runner = mk_runner()
        root = o19source.engine_root(runner, _SHA)
        assert root.name == _SHA
        assert root.parent == runner.settings.emr_home / "o19-import" / "engine"


class TestFetching:

    @staticmethod
    def _transport(runner, monkeypatch, *, curl_rc=0, tar_rc=0,
                   unpack=None):
        """Model curl+tar the way the real ones behave: curl WRITES the file
        it was given with -o, tar WRITES the members it extracted. Scripting
        them by return code alone would let a test pass against code that
        never produced either."""
        import pathlib

        real = runner.run

        def fake(argv, **kw):
            argv = list(argv)
            runner.calls.append(argv)
            if argv[:1] == ["curl"]:
                if curl_rc == 0:
                    out = pathlib.Path(argv[argv.index("-o") + 1])
                    out.write_bytes(b"tarball")
                return subprocess_result(argv, curl_rc)
            if argv[:1] == ["tar"]:
                if tar_rc == 0:
                    dest = pathlib.Path(argv[argv.index("-C") + 1])
                    write_fake_engine(dest, omit=(unpack or ()))
                return subprocess_result(argv, tar_rc)
            return real(argv, **kw)

        monkeypatch.setattr(runner, "run", fake)

    def test_a_complete_tree_is_reused_without_fetching(self, mk_runner):
        runner = mk_runner()
        write_fake_engine(o19source.engine_root(runner, _SHA))
        assert o19source.ensure_engine(runner, _SHA)
        assert runner.calls == []  # no curl, no tar

    def test_a_fetch_lands_every_required_module(self, mk_runner,
                                                 monkeypatch):
        runner = mk_runner()
        self._transport(runner, monkeypatch)
        root = o19source.fetch_engine(runner, _SHA)
        assert (sorted(o19source.engine_modules_present(root))
                == sorted(o19source.REQUIRED_MODULES))

    def test_an_incomplete_tree_is_refetched_not_trusted(self, mk_runner,
                                                         monkeypatch):
        runner = mk_runner()
        write_fake_engine(o19source.engine_root(runner, _SHA),
                          omit=("o19etl",))
        self._transport(runner, monkeypatch)
        root = o19source.ensure_engine(runner, _SHA)
        assert (root / "o19etl.py").is_file()

    def test_a_failed_download_names_the_url(self, mk_runner, monkeypatch):
        runner = mk_runner()
        self._transport(runner, monkeypatch, curl_rc=7)
        with pytest.raises(CtlError) as exc:
            o19source.fetch_engine(runner, _SHA)
        assert "codeload.github.com" in str(exc.value)

    def test_a_download_that_wrote_nothing_is_refused(self, mk_runner,
                                                      monkeypatch):
        # curl exiting 0 without producing the file (a proxy 204, a full
        # disk) must not read as a successful fetch
        runner = mk_runner()
        monkeypatch.setattr(
            runner, "run",
            lambda argv, **kw: subprocess_result(list(argv), 0))
        with pytest.raises(CtlError) as exc:
            o19source.fetch_engine(runner, _SHA)
        assert "could not download" in str(exc.value)

    def test_the_extract_is_scoped_to_the_engine_modules(self, mk_runner,
                                                         monkeypatch):
        # a tampered archive must not be able to drop a file anywhere else
        # under $EMR_HOME
        runner = mk_runner()
        self._transport(runner, monkeypatch)
        o19source.fetch_engine(runner, _SHA)
        tar = [c for c in runner.calls if c[:1] == ["tar"]][0]
        assert "*/debian/assets/carlos_ctl/o19*.py" in tar
        assert "--strip-components" in tar
        assert "--no-same-owner" in tar

    def test_a_release_without_the_importer_says_so(self, mk_runner,
                                                    monkeypatch):
        runner = mk_runner()
        self._transport(runner, monkeypatch, tar_rc=2)
        with pytest.raises(CtlError) as exc:
            o19source.fetch_engine(runner, _SHA)
        assert "predates the OSCAR 19 importer" in str(exc.value)

    def test_a_tree_missing_a_module_names_it(self, mk_runner, monkeypatch):
        runner = mk_runner()
        self._transport(runner, monkeypatch, unpack=("o19roles",))
        with pytest.raises(CtlError) as exc:
            o19source.fetch_engine(runner, _SHA)
        assert "o19roles" in str(exc.value)

    def test_a_half_fetched_engine_is_never_left_under_its_commit(
            self, mk_runner, monkeypatch):
        runner = mk_runner()
        self._transport(runner, monkeypatch, unpack=("o19roles",))
        with pytest.raises(CtlError):
            o19source.fetch_engine(runner, _SHA)
        assert not o19source.engine_root(runner, _SHA).exists()

    def test_the_staging_directory_is_removed_on_failure(self, mk_runner,
                                                         monkeypatch):
        runner = mk_runner()
        self._transport(runner, monkeypatch, curl_rc=7)
        with pytest.raises(CtlError):
            o19source.fetch_engine(runner, _SHA)
        parent = o19source.engine_root(runner, _SHA).parent
        assert list(parent.iterdir()) == []


class TestVerification:
    """Both directions of the shim contract, checked from the SOURCE before
    anything is imported."""

    def test_the_imports_are_read_from_the_fetched_source(self, tmp_path):
        root = write_fake_engine(tmp_path / "engine")
        found = o19source.imported_sibling_names(root)
        assert "util" in found
        assert "dbops" in found
        # o19* siblings are the engine's own and are not shim surface
        assert not any(m.startswith("o19") for m in found)

    def test_a_complete_shim_passes(self, mk_runner, tmp_path):
        runner = mk_runner()
        root = write_fake_engine(tmp_path / "engine")
        o19source.verify_engine(root, o19compat.build_shims(runner, _escape))

    def test_a_name_the_shim_lacks_is_refused_by_name(self, mk_runner,
                                                      tmp_path):
        runner = mk_runner()
        root = write_fake_engine(tmp_path / "engine")
        (root / "o19etl.py").write_text(
            "from .util import invented_helper\n")
        shims = o19compat.build_shims(runner, _escape)
        with pytest.raises(CtlError) as exc:
            o19source.verify_engine(root, shims)
        assert "invented_helper" in str(exc.value)

    def test_an_unknown_sibling_module_is_refused(self, mk_runner, tmp_path):
        runner = mk_runner()
        root = write_fake_engine(tmp_path / "engine")
        (root / "o19etl.py").write_text("from .waf import something\n")
        shims = o19compat.build_shims(runner, _escape)
        with pytest.raises(CtlError) as exc:
            o19source.verify_engine(root, shims)
        assert "'waf'" in str(exc.value)

    def test_a_shim_that_lost_a_declared_name_is_refused(self, mk_runner,
                                                         tmp_path):
        runner = mk_runner()
        root = write_fake_engine(tmp_path / "engine")
        shims = o19compat.build_shims(runner, _escape)
        delattr(shims["util"], "sql_escape")
        with pytest.raises(CtlError) as exc:
            o19source.verify_engine(root, shims)
        assert "sql_escape" in str(exc.value)


class TestLoading:
    """The real loader, against a fabricated engine tree."""

    def _load(self, runner, monkeypatch, root):
        monkeypatch.setattr(o19source, "pinned_commit",
                            lambda r: (_SHA, "release 2026.9.0"))
        monkeypatch.setattr(o19source, "ensure_engine",
                            lambda r, c: root)
        return o19source.load_engine(runner)

    def test_the_engine_imports_with_podmans_siblings_underneath(
            self, mk_runner, monkeypatch, tmp_path):
        runner = mk_runner()
        root = write_fake_engine(tmp_path / "engine")
        engine = self._load(runner, monkeypatch, root)
        # the engine's own module, resolved through the synthetic package
        assert engine.o19import.STAGING_SCHEMA == "o19_import"
        # ...and its `from .util import STATE` resolved to THIS host
        assert engine.o19host.STATE_DIR == str(
            runner.settings.emr_home / "o19-import")

    def test_the_escape_comes_from_the_fetched_engine(self, mk_runner,
                                                      monkeypatch, tmp_path):
        runner = mk_runner()
        root = write_fake_engine(tmp_path / "engine")
        engine = self._load(runner, monkeypatch, root)
        assert engine.package.util.sql_escape("O'Brien") == "O\\'Brien"
        assert engine.package.dbops.sql_escape("a\\b") == "a\\\\b"

    def test_an_engine_without_the_escape_is_refused(self, mk_runner,
                                                     monkeypatch, tmp_path):
        runner = mk_runner()
        root = write_fake_engine(tmp_path / "engine")
        (root / "o19_preflight.py").write_text("VALUE = 1\n")
        with pytest.raises(CtlError) as exc:
            self._load(runner, monkeypatch, root)
        assert "_sql_literal" in str(exc.value)

    def test_a_refused_load_leaves_no_half_imported_package(
            self, mk_runner, monkeypatch, tmp_path):
        import sys

        runner = mk_runner()
        root = write_fake_engine(tmp_path / "engine")
        (root / "o19_preflight.py").write_text("VALUE = 1\n")
        with pytest.raises(CtlError):
            self._load(runner, monkeypatch, root)
        assert not [m for m in sys.modules
                    if m.startswith(o19source.PACKAGE)]
        assert o19source.loaded_engine() is None

    def test_the_engine_is_loaded_once_per_process(self, mk_runner,
                                                   monkeypatch, tmp_path):
        runner = mk_runner()
        root = write_fake_engine(tmp_path / "engine")
        first = self._load(runner, monkeypatch, root)
        assert o19source.load_engine(runner) is first

    def test_the_loaded_engine_names_which_carlos(self, mk_runner,
                                                  monkeypatch, tmp_path):
        runner = mk_runner()
        root = write_fake_engine(tmp_path / "engine")
        engine = self._load(runner, monkeypatch, root)
        assert engine.commit == _SHA
        assert "2026.9.0" in engine.described

    def test_an_unknown_engine_module_raises_a_named_error(
            self, mk_runner, monkeypatch, tmp_path):
        runner = mk_runner()
        root = write_fake_engine(tmp_path / "engine")
        engine = self._load(runner, monkeypatch, root)
        with pytest.raises(AttributeError) as exc:
            _ = engine.o19nonexistent
        assert "o19nonexistent" in str(exc.value)
