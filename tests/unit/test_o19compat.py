# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Unit tests for carlos_ctl.o19compat: the OSCAR 19 engine's package
siblings, on podman.

The stakes: this is the surface an UNMODIFIED engine imports. A path that
answers the deb's location writes a clinic's workspace where this host has
none; a decode that follows the locale turns a patient's name into mojibake
inside the migrated database; a stub that reports success where podman cannot
answer retires one of P0's gates without saying so."""

from __future__ import annotations

import subprocess

import pytest

from carlos_ctl import o19compat
from carlos_ctl.util import CtlError  # noqa: F401 — imported for symmetry


def _escape(value: str) -> str:
    """Stand-in for the engine's own escape (o19_preflight._sql_literal),
    which the real loader hands in. Identity-marked so a test can prove the
    shims use THIS and never a local reimplementation."""
    return "<escaped:" + value + ">"


@pytest.fixture
def shims(mk_runner):
    runner = mk_runner()
    return runner, o19compat.build_shims(runner, _escape)


class TestTheDeclaredSurface:
    """What the shim promises is what it provides. `o19source.verify_engine`
    checks the fetched engine against these tuples, so a name listed but not
    built would make that check vacuous."""

    def test_every_declared_util_name_exists(self, shims):
        _, s = shims
        assert o19compat.missing_names(
            s, "util", o19compat.REQUIRED_UTIL_NAMES) == []

    def test_every_declared_dbops_name_exists(self, shims):
        _, s = shims
        assert o19compat.missing_names(
            s, "dbops", o19compat.REQUIRED_DBOPS_NAMES) == []

    def test_every_declared_config_name_exists(self, shims):
        _, s = shims
        assert o19compat.missing_names(
            s, "config", o19compat.REQUIRED_CONFIG_NAMES) == []

    def test_a_missing_name_is_reported_by_name(self, shims):
        _, s = shims
        assert o19compat.missing_names(s, "util", ["log", "nope"]) == ["nope"]

    def test_an_absent_module_reports_every_name(self, shims):
        _, s = shims
        assert o19compat.missing_names(s, "waf", ["a", "b"]) == ["a", "b"]


class TestPaths:
    """Every path the engine defaults to has to be THIS host's."""

    def test_the_paths_are_this_instances(self, shims):
        runner, s = shims
        home = runner.settings.emr_home
        assert s["util"].STATE == str(home)
        assert s["util"].ENV_FILE == str(runner.settings.env_file)
        assert s["util"].PROPERTIES == str(runner.settings.properties_file)
        assert s["util"].CONF_DIR == str(runner.settings.conf_dir)

    def test_the_engines_workspace_default_matches_the_hosts(self, shims):
        # o19host computes STATE_DIR as STATE/o19-import and PodmanHost
        # returns $EMR_HOME/o19-import; if STATE were anything else the two
        # would disagree and a leaked default would write elsewhere
        runner, s = shims
        assert (s["util"].STATE + "/o19-import"
                == str(runner.settings.emr_home / "o19-import"))

    def test_no_path_points_into_the_debs_tree(self, shims):
        _, s = shims
        for name in ("STATE", "CONF_DIR", "ENV_FILE", "PROPERTIES",
                     "DRUGREF_PROPERTIES", "BACKUP_ENV", "SHARE", "LIB",
                     "WEBAPP"):
            value = getattr(s["util"], name)
            assert "/var/lib/carlos-emr" not in value, name
            assert "/etc/carlos-emr" not in value, name
            assert "/usr/share/carlos-emr" not in value, name


class TestRunTranslation:
    """`util.run` is subprocess.run's signature; Runner.run renames two of
    its keywords and takes no **kw."""

    def test_capture_and_stdin_reach_the_runner(self, mk_runner):
        runner = mk_runner()
        s = o19compat.build_shims(runner, _escape)
        s["util"].run(["mariadb"], input="SELECT 1", capture_output=True)
        assert runner.calls[-1] == ["mariadb"]
        assert runner.stdins[-1] == "SELECT 1"

    def test_the_decode_is_pinned_to_utf8_not_the_locale(self, mk_runner):
        # clinic data crosses this seam; under LANG=C a locale decode
        # silently mojibakes a patient name into the migrated database
        seen = {}

        class Recording(type(mk_runner())):
            def run(self, argv, **kw):
                seen.update(kw)
                return subprocess.CompletedProcess(list(argv), 0, "", "")

        runner = mk_runner()
        recording = Recording(runner.settings)
        s = o19compat.build_shims(recording, _escape)
        s["util"].run(["tar", "-tf", "x"])
        assert seen["encoding"] == "utf-8"
        assert seen["errors"] == "replace"

    def test_an_explicit_errors_argument_still_wins(self, mk_runner):
        seen = {}

        class Recording(type(mk_runner())):
            def run(self, argv, **kw):
                seen.update(kw)
                return subprocess.CompletedProcess(list(argv), 0, "", "")

        runner = mk_runner()
        s = o19compat.build_shims(Recording(runner.settings), _escape)
        s["util"].run(["x"], errors="strict")
        assert seen["errors"] == "strict"

    def test_an_untranslated_keyword_is_refused_not_dropped(self, shims):
        # a silently dropped capture_output turns a checked result into an
        # empty one; refuse instead
        _, s = shims
        with pytest.raises(TypeError) as exc:
            s["util"].run(["x"], preexec_fn=None)
        assert "preexec_fn" in str(exc.value)

    def test_out_returns_stdout_only_on_success(self, mk_runner):
        runner = mk_runner()
        runner.script("good", out="  value\n")
        runner.default = (1, "ignored")
        s = o19compat.build_shims(runner, _escape)
        assert s["util"].out(["good"]) == "value"
        assert s["util"].out(["bad"]) == ""


class TestBehaviour:

    def test_die_raises_system_exit_with_the_code(self, shims, capsys):
        _, s = shims
        with pytest.raises(SystemExit) as exc:
            s["util"].die("no", 2)
        assert exc.value.code == 2
        assert "no" in capsys.readouterr().err

    def test_the_escape_is_the_engines_own(self, shims):
        # NOT a local reimplementation: a third copy of this function is
        # exactly what the CARLOS suite's escape contract test exists to
        # prevent
        _, s = shims
        assert s["util"].sql_escape("x") == "<escaped:x>"
        assert s["dbops"].sql_escape("x") == "<escaped:x>"

    def test_prop_get_takes_the_last_occurrence(self, shims, tmp_path):
        _, s = shims
        f = tmp_path / "carlos.properties"
        f.write_text("billregion=ON\nother=1\nbillregion=BC\n")
        assert s["util"].prop_get(str(f), "billregion") == "BC"

    def test_prop_get_reads_latin1_like_the_application(self, shims,
                                                        tmp_path):
        # java.util.Properties.load(InputStream) decodes ISO-8859-1; a utf-8
        # read would raise or mangle a migrated Latin-1 value
        _, s = shims
        f = tmp_path / "carlos.properties"
        f.write_bytes("clinic=Sant\xe9\n".encode("latin-1"))
        assert s["util"].prop_get(str(f), "clinic") == "Santé"

    def test_prop_get_on_a_missing_file_is_none(self, shims):
        _, s = shims
        assert s["util"].prop_get("/nonexistent/x.properties", "k") is None

    def test_generated_passwords_are_alphanumeric(self, shims):
        _, s = shims
        pw = s["util"].genpw()
        assert len(pw) == 32
        assert pw.isalnum()

    def test_the_flyway_stub_fails_closed(self, shims):
        # returning 0 here would silently retire P0's schema gate
        _, s = shims
        with pytest.raises(RuntimeError) as exc:
            s["dbops"].run_flyway("validate")
        assert "flyway_validate" in str(exc.value)

    def test_the_config_stub_fails_closed(self, shims):
        _, s = shims
        with pytest.raises(RuntimeError) as exc:
            s["config"].load()
        assert "billregion" in str(exc.value)
