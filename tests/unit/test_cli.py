# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Unit tests for the CLI front door: help/version, the mutating-verb gating,
and the top-level exception guard."""

import pytest

from carlos_ctl import cli
from carlos_ctl.util import CtlError


class TestHelpVersion:
    def test_help_prints_usage_exit_zero(self, capsys) -> None:
        assert cli.main(["help"]) == 0
        assert "carlos-ctl" in capsys.readouterr().out

    def test_flag_help_exit_zero(self, capsys) -> None:
        assert cli.main(["--help"]) == 0
        capsys.readouterr()

    def test_version_prints_and_exits_zero(self, capsys) -> None:
        assert cli.main(["version"]) == 0
        assert "carlos-ctl" in capsys.readouterr().out

    def test_no_args_prints_usage_exit_one(self, capsys) -> None:
        assert cli.main([]) == 1
        capsys.readouterr()


class TestGating:
    def test_backup_restore_locks_and_banners(self) -> None:
        assert cli._gating("backup", ["restore"]) == (True, True)

    def test_backup_status_banners_but_no_lock(self) -> None:
        # status must stay lock-free (usable while a backup runs).
        assert cli._gating("backup", ["status"]) == (False, True)

    def test_backup_verify_no_lock(self) -> None:
        # verify runs long and manages its own repo lock.
        assert cli._gating("backup", ["verify"]) == (False, True)

    def test_db_banners_but_no_lock(self) -> None:
        # an interactive db shell must not hold the cross-verb lock.
        assert cli._gating("db", []) == (False, True)

    def test_rotate_locks_and_banners(self) -> None:
        assert cli._gating("rotate", ["db"]) == (True, True)

    def test_read_only_verb_neither(self) -> None:
        assert cli._gating("status", []) == (False, False)


class TestSecretsSubVerbArguments:
    """`secrets render` decrypts the sealed bundle into the /run tmpfs. The
    dispatch used a PREFIX test (args[:1] == ['render']), so
    `secrets render --dry-run` dropped the flag and did the real render."""

    def test_render_with_a_trailing_flag_is_refused(self, mk_runner, capsys) -> None:
        r = mk_runner("")
        with pytest.raises(CtlError) as e:
            cli._dispatch("secrets", ["render", "--dry-run"], r)
        assert "usage: carlos-ctl secrets render" in str(e.value)
        assert r.calls == []

    def test_bare_secrets_is_refused(self, mk_runner) -> None:
        r = mk_runner("")
        with pytest.raises(CtlError):
            cli._dispatch("secrets", [], r)


class TestExceptionGuard:
    def test_unexpected_exception_is_a_clean_line(self, capsys, monkeypatch) -> None:
        # An unexpected (non-CtlError) exception must surface as one line,
        # not a raw traceback.
        def boom(_verb, _rest, _runner):
            raise RuntimeError("kaboom")

        # Drive an unknown-ish path: monkeypatch _dispatch to raise.
        monkeypatch.setattr(cli, "_dispatch", boom)
        monkeypatch.setattr(cli, "_gating", lambda v, r: (False, False))
        monkeypatch.delenv("CARLOS_CTL_TRACEBACK", raising=False)
        rc = cli.main(["status"])
        assert rc == 1
        err = capsys.readouterr().err
        assert "unexpected RuntimeError" in err
        assert "kaboom" in err


class TestTargetBanner:
    """The banner is operator context, and `db` — which carries it because
    imports touch data — is also the documented scripting idiom. On stdout it
    became the first line of every piped result, so the README's own
    `carlos-ctl db -N -B -e ... | carlos-ctl db drugref2` remedy fed
    '==> target: ...' to mariadb (ERROR 1064) and left the drugref2 tables
    Aria — the exact state that makes `backup full` refuse."""

    def test_banner_goes_to_stderr_not_stdout(self, mk_settings, capsys) -> None:
        cli._target_banner(mk_settings())
        cap = capsys.readouterr()
        assert cap.out == ""
        assert "==> target: instance=" in cap.err

    def test_db_is_a_banner_verb(self) -> None:
        # If `db` ever stops carrying the banner this test is the reminder to
        # revisit the stream choice above, not to silently drop the
        # wrong-instance guard on the one verb that can import PHI.
        assert cli._gating("db", []) == (False, True)


class TestSourceVerbGating:
    """`source` splits like `backup`: the writing sub-verbs move the pin the
    next build consumes (lock + banner), the report forms stay read-only."""

    def test_writing_subverbs_lock_and_banner(self) -> None:
        for sub in ("update", "set", "clear"):
            assert cli._gating("source", [sub]) == (True, True)

    def test_show_forms_are_read_only(self) -> None:
        assert cli._gating("source", []) == (False, False)
        assert cli._gating("source", ["show"]) == (False, False)

    def test_source_dispatches_to_the_module(self, mk_settings, monkeypatch) -> None:
        from carlos_ctl.runner import Runner

        seen = {}
        import carlos_ctl.source as source_mod

        monkeypatch.setattr(
            source_mod, "cmd_source",
            lambda runner, args: seen.update(args=args) or 0,
        )
        assert cli._dispatch("source", ["show"], Runner(mk_settings())) == 0
        assert seen["args"] == ["show"]
