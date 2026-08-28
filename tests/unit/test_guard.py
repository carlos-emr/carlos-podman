# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Unit tests for the boot-time blank-datadir guard (`carlos-ctl guard`)."""

from carlos_ctl.guard import DATADIR_SIGNATURE, cmd_guard


def _deploy(runner) -> None:
    (runner.settings.emr_home / "container" / ".deployed").touch()


def _init_datadir(runner) -> None:
    (runner.settings.data_dir / DATADIR_SIGNATURE).mkdir(parents=True, exist_ok=True)


class TestGuard:
    def test_not_deployed_passes(self, mk_runner) -> None:
        # No go-live marker: an empty datadir is the expected first-install
        # state — nothing to guard.
        assert cmd_guard(mk_runner()) == 0

    def test_deployed_wiped_datadir_refused(self, mk_runner) -> None:
        r = mk_runner()
        _deploy(r)
        assert cmd_guard(r) == 1

    def test_deployed_initialized_passes(self, mk_runner) -> None:
        r = mk_runner()
        _deploy(r)
        _init_datadir(r)
        (r.settings.data_dir / "mariadb-binlog").mkdir(parents=True)
        (r.settings.data_dir / "mariadb-binlog" / "binlog.000001").touch()
        (r.settings.data_dir / "CarlosDocument").mkdir(parents=True)
        (r.settings.data_dir / "CarlosDocument" / "doc.pdf").touch()
        assert cmd_guard(r) == 0

    def test_legacy_store_name_passes_until_renamed(self, mk_runner) -> None:
        # Mid-transition (new carlos-ctl, playbook's one-time rename not run
        # yet) the store still sits at the legacy OscarDocument path; the
        # guard must keep protecting it, not fail it as unmounted.
        r = mk_runner()
        _deploy(r)
        _init_datadir(r)
        (r.settings.data_dir / "mariadb-binlog").mkdir(parents=True)
        (r.settings.data_dir / "mariadb-binlog" / "binlog.000001").touch()
        (r.settings.data_dir / "OscarDocument").mkdir(parents=True)
        (r.settings.data_dir / "OscarDocument" / "doc.pdf").touch()
        assert cmd_guard(r) == 0

    def test_env_flag_accepts_empty(self, mk_runner, capsys) -> None:
        r = mk_runner("", {"CARLOS_ACCEPT_EMPTY_DATADIR": "1"})
        _deploy(r)
        assert cmd_guard(r) == 0
        assert "CARLOS_ACCEPT_EMPTY_DATADIR=1" in capsys.readouterr().out

    def test_marker_from_play_accepts_empty(self, mk_runner, capsys) -> None:
        # The boot guard runs as root with none of play's shell env, so the
        # one-shot CARLOS_ACCEPT_EMPTY_DATADIR prefix is gone. play persists it
        # to guard/accept-empty-datadir; the boot guard must honor that marker.
        r = mk_runner()
        _deploy(r)
        guard_dir = r.settings.emr_home / "container" / "guard"
        guard_dir.mkdir(parents=True, exist_ok=True)
        (guard_dir / "accept-empty-datadir").touch()
        assert cmd_guard(r) == 0
        assert "marker set by play" in capsys.readouterr().out

    def test_persisted_env_flag_warns(self, mk_runner, capsys) -> None:
        r = mk_runner("CARLOS_ACCEPT_EMPTY_DATADIR=1\n")
        _deploy(r)
        cmd_guard(r)
        assert "PERSISTED" in capsys.readouterr().err


def _healthy_volumes(r) -> None:
    _init_datadir(r)
    (r.settings.data_dir / "mariadb-binlog").mkdir(parents=True, exist_ok=True)
    (r.settings.data_dir / "mariadb-binlog" / "binlog.000001").touch()
    (r.settings.data_dir / "CarlosDocument").mkdir(parents=True, exist_ok=True)
    (r.settings.data_dir / "CarlosDocument" / "doc.pdf").touch()


class TestGuardHostfw:
    # Finding S12: the nft apply unit is fail-open — the guard is the
    # boot-path detector that a hostfw-enabled instance actually has its
    # default-deny table loaded before the pods start.

    def test_missing_table_fails_the_guard(self, mk_runner, capsys) -> None:
        r = mk_runner(env_lines="HOSTFW_ENABLED=1\n")
        r.tools = r.tools | {"nft"}
        _deploy(r)
        _healthy_volumes(r)
        r.script("nft", "list", "table", rc=1)
        assert cmd_guard(r) == 1
        assert "FAIL-OPEN" in capsys.readouterr().err

    def test_loaded_default_deny_passes(self, mk_runner) -> None:
        r = mk_runner(env_lines="HOSTFW_ENABLED=1\n")
        r.tools = r.tools | {"nft"}
        _deploy(r)
        _healthy_volumes(r)
        r.script("nft", "list", "table", rc=0,
                 out="table inet carlos-hostfw { chain input { policy drop; } }\n")
        assert cmd_guard(r) == 0

    def test_missing_nft_binary_fails_when_hostfw_expected(
        self, mk_runner, capsys
    ) -> None:
        r = mk_runner(env_lines="HOSTFW_ENABLED=1\n")
        r.tools = r.tools - {"nft"}
        _deploy(r)
        _healthy_volumes(r)
        assert cmd_guard(r) == 1
        assert "nft binary is missing" in capsys.readouterr().err

    def test_acceptEmptyDatadir_stillFailsOnMissingHostfwTable(
        self, mk_runner, capsys
    ) -> None:
        # The accept-empty override covers DATA VOLUMES only: a reboot inside
        # the accept window with a failed nft apply must still refuse (the
        # host would otherwise come up FAIL-OPEN with nothing paging).
        r = mk_runner(env_lines="HOSTFW_ENABLED=1\nCARLOS_ACCEPT_EMPTY_DATADIR=1\n")
        r.tools = r.tools | {"nft"}
        _deploy(r)
        r.script("nft", "list", "table", rc=1)
        assert cmd_guard(r) == 1
        assert "FAIL-OPEN" in capsys.readouterr().err

    def test_acceptEmptyDatadir_passesWithHostfwLoaded(self, mk_runner) -> None:
        r = mk_runner(env_lines="HOSTFW_ENABLED=1\nCARLOS_ACCEPT_EMPTY_DATADIR=1\n")
        r.tools = r.tools | {"nft"}
        _deploy(r)
        r.script("nft", "list", "table", rc=0,
                 out="table inet carlos-hostfw { chain input { policy drop; } }\n")
        assert cmd_guard(r) == 0

    def test_disabled_expectation_never_probes(self, mk_runner) -> None:
        # Pre-existing env files lack HOSTFW_ENABLED (default 0): the guard
        # behaves exactly as before until the playbook re-renders the key.
        r = mk_runner()
        r.tools = r.tools | {"nft"}
        _deploy(r)
        _healthy_volumes(r)
        assert cmd_guard(r) == 0
        assert not any(c and c[0] == "nft" for c in r.calls)
