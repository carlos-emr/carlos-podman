# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Unit tests for the `import-o19` / `o19-preflight` verbs and their CLI
wiring.

The verb layer is deliberately thin — its whole job is to refuse a host that
cannot run the import, hand the engine podman's `Host`, and get out of the
way. These pin exactly that: the entry gate fires BEFORE anything is fetched
or locked, the host actually reaches the engine (a port whose answers are
never installed would silently write into the deb's paths), and the CLI
serializes the import against every other mutating verb."""

from __future__ import annotations

import pytest

from carlos_ctl import cli, o19import_cmd, o19source
from carlos_ctl.util import CtlError


class FakeEngineImport:
    def __init__(self):
        self.HOST = "the deb's host"
        self.calls = []

    def cmd_import_o19(self, argv):
        self.calls.append(("import", list(argv)))
        return 0

    def cmd_o19_preflight(self, argv):
        self.calls.append(("preflight", list(argv)))
        return 2


class FakeEngine:
    def __init__(self):
        self.o19import = FakeEngineImport()
        self.o19host = type("m", (), {"Host": object})
        self.commit = "b" * 40
        self.described = "release 2026.9.0"


@pytest.fixture
def wired(mk_runner, monkeypatch):
    runner = mk_runner("CARLOS_DB_ROOT_PASSWORD=rootpw\n")
    engine = FakeEngine()
    monkeypatch.setattr(o19source, "load_engine", lambda r: engine)
    monkeypatch.setattr(o19import_cmd.o19runtime, "make_host",
                        lambda r, e: "podman's host")
    return runner, engine


class TestTheEntryGate:
    """Refuse before the workspace lock, the fetch and the staging schema."""

    def test_no_root_password_is_refused_by_name(self, mk_runner,
                                                 monkeypatch):
        runner = mk_runner()
        called = {}
        monkeypatch.setattr(o19source, "load_engine",
                            lambda r: called.setdefault("loaded", True))
        with pytest.raises(CtlError) as exc:
            o19import_cmd.cmd_import_o19(runner, [])
        assert "CARLOS_DB_ROOT_PASSWORD" in str(exc.value)
        assert "loaded" not in called  # nothing fetched, nothing locked

    def test_the_development_seam_needs_no_root_password(self, mk_runner,
                                                         monkeypatch):
        runner = mk_runner()
        engine = FakeEngine()
        monkeypatch.setattr(o19source, "load_engine", lambda r: engine)
        monkeypatch.setattr(o19import_cmd.o19runtime, "make_host",
                            lambda r, e: "podman's host")
        assert o19import_cmd.cmd_import_o19(
            runner, ["--mariadb-arg=--socket=/tmp/s"]) == 0

    def test_the_paired_form_of_the_seam_is_recognised(self, mk_runner,
                                                       monkeypatch):
        runner = mk_runner()
        engine = FakeEngine()
        monkeypatch.setattr(o19source, "load_engine", lambda r: engine)
        monkeypatch.setattr(o19import_cmd.o19runtime, "make_host",
                            lambda r, e: "podman's host")
        assert o19import_cmd.cmd_import_o19(
            runner, ["--mariadb-arg", "--socket=/tmp/s"]) == 0

    def test_an_unprovisioned_host_is_left_to_the_engine(self, mk_runner,
                                                         monkeypatch):
        # no carlos-app.env: the engine has its own refusal, and duplicating
        # it here would give two different messages for one condition
        runner = mk_runner()
        runner.settings.env_file.unlink()
        engine = FakeEngine()
        monkeypatch.setattr(o19source, "load_engine", lambda r: engine)
        monkeypatch.setattr(o19import_cmd.o19runtime, "make_host",
                            lambda r, e: "podman's host")
        assert o19import_cmd.cmd_import_o19(runner, []) == 0


class TestWiring:

    def test_the_import_runs_on_podmans_host(self, wired):
        runner, engine = wired
        o19import_cmd.cmd_import_o19(runner, ["--dry-run"])
        assert engine.o19import.HOST == "podman's host"
        assert engine.o19import.calls == [("import", ["--dry-run"])]

    def test_the_preflight_runs_on_podmans_host_too(self, wired):
        runner, engine = wired
        assert o19import_cmd.cmd_o19_preflight(runner, ["--bundle", "b"]) == 2
        assert engine.o19import.HOST == "podman's host"
        assert engine.o19import.calls == [("preflight", ["--bundle", "b"])]

    def test_the_preflight_verdict_is_returned_verbatim(self, wired):
        # 0/1/2 are the VERDICT; a wrapper that normalised them would turn a
        # no-go into a success
        runner, engine = wired
        assert o19import_cmd.cmd_o19_preflight(runner, []) == 2

    def test_which_carlos_the_engine_came_from_is_logged(self, wired,
                                                         capsys):
        runner, engine = wired
        o19import_cmd.cmd_import_o19(runner, [])
        out = capsys.readouterr().out
        assert "bbbbbbbbbbbb" in out
        assert "2026.9.0" in out

    def test_the_experimental_banner_is_repeated_at_the_verb(self, wired,
                                                             capsys):
        runner, engine = wired
        o19import_cmd.cmd_import_o19(runner, [])
        assert "EXPERIMENTAL" in capsys.readouterr().out


class TestCliGating:

    def test_the_import_takes_the_mutating_lock_and_the_banner(self):
        # a rotate mid-import would change the app credentials the
        # properties fragment is written against
        assert cli._gating("import-o19", []) == (True, True)

    def test_the_preflight_shows_the_banner_without_the_lock(self):
        # it stages a plaintext dump, so WHICH instance matters; but it must
        # not block a rotate for the length of an assessment
        assert cli._gating("o19-preflight", []) == (False, True)

    def test_both_verbs_are_in_the_usage_text(self):
        assert "import-o19" in cli.USAGE
        assert "o19-preflight" in cli.USAGE

    def test_the_verbs_dispatch_to_the_port(self, mk_runner, monkeypatch):
        runner = mk_runner()
        seen = []
        monkeypatch.setattr(o19import_cmd, "cmd_import_o19",
                            lambda r, a: seen.append(("import", a)) or 0)
        monkeypatch.setattr(o19import_cmd, "cmd_o19_preflight",
                            lambda r, a: seen.append(("pre", a)) or 3)
        assert cli._dispatch("import-o19", ["--resume"], runner) == 0
        assert cli._dispatch("o19-preflight", ["--help"], runner) == 3
        assert seen == [("import", ["--resume"]), ("pre", ["--help"])]

    def test_neither_verb_is_treated_as_taking_no_arguments(self, mk_runner,
                                                            monkeypatch):
        # the no-arg guard would reject every flag the engine parses
        runner = mk_runner()
        monkeypatch.setattr(o19import_cmd, "cmd_import_o19", lambda r, a: 0)
        assert cli._dispatch("import-o19", ["--cleanup"], runner) == 0
