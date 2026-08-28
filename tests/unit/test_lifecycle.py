# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Unit tests for play's go-live gates, guard, and down/enable plumbing."""

from pathlib import Path

import pytest

from carlos_ctl.guard import DATADIR_SIGNATURE, cmd_guard, datadir_initialized
from carlos_ctl.lifecycle2 import (
    cmd_enable,
    datadir_guard,
    db_isolation_gate,
    preflight_db_root_guard,
    require_alert_channel,
    require_heartbeat,
    seed_backup_stamps,
    start_instance_timers,
    validate_rendered,
    wait_app_ready,
)
from carlos_ctl.util import CtlError


class TestAlertAndHeartbeatGates:
    def test_no_channel_refuses_go_live(self, mk_runner) -> None:
        with pytest.raises(CtlError, match="JOURNAL ONLY"):
            require_alert_channel(mk_runner())

    def test_webhook_satisfies(self, mk_runner) -> None:
        require_alert_channel(mk_runner("ALERT_WEBHOOK=https://x/hook\n"))

    def test_journal_only_ack_satisfies(self, mk_runner) -> None:
        require_alert_channel(mk_runner("", {"ALERT_JOURNAL_ONLY": "1"}))

    def test_no_heartbeat_refuses(self, mk_runner) -> None:
        with pytest.raises(CtlError, match="dead-man's switch"):
            require_heartbeat(mk_runner())

    def test_heartbeat_url_satisfies(self, mk_runner) -> None:
        require_heartbeat(mk_runner("HEARTBEAT_URL=https://hc/ping\n"))

    def test_no_heartbeat_ack_satisfies(self, mk_runner) -> None:
        require_heartbeat(mk_runner("", {"CARLOS_NO_HEARTBEAT": "1"}))


class TestDbRootGuard:
    def _props(self, runner, username: str) -> None:
        p = runner.settings.properties_file
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(f"db_username={username}\ndb_password=x\n")

    def test_root_without_password_refused(self, mk_runner) -> None:
        r = mk_runner()
        self._props(r, "root")
        with pytest.raises(CtlError, match="refusing to deploy on the root account"):
            preflight_db_root_guard(r)

    def test_root_with_password_allowed_for_autoprovision(self, mk_runner) -> None:
        r = mk_runner("CARLOS_DB_ROOT_PASSWORD=pw\n")
        self._props(r, "root")
        preflight_db_root_guard(r)

    def test_provisioned_user_never_blocked(self, mk_runner) -> None:
        # An emergency restart must not depend on the root password.
        r = mk_runner()
        self._props(r, "carlos")
        preflight_db_root_guard(r)

    def test_explicit_root_override(self, mk_runner, capsys) -> None:
        r = mk_runner("", {"CARLOS_ALLOW_DB_ROOT": "1"})
        self._props(r, "root")
        preflight_db_root_guard(r)
        assert "MariaDB ROOT" in capsys.readouterr().err

    def test_persisted_override_warns(self, mk_runner, capsys) -> None:
        # CARLOS_ALLOW_DB_ROOT=1 persisted in the env file must be called out:
        # the override is meant as a one-shot prefix, not standing config.
        r = mk_runner("CARLOS_ALLOW_DB_ROOT=1\n")
        self._props(r, "root")
        preflight_db_root_guard(r)
        assert "PERSISTED" in capsys.readouterr().err


class TestDatadirGuards:
    def test_first_install_empty_datadir_allowed(self, mk_runner) -> None:
        datadir_guard(mk_runner())  # no .deployed marker

    def test_deployed_with_wiped_datadir_refused(self, mk_runner) -> None:
        r = mk_runner()
        (r.settings.emr_home / "container" / ".deployed").touch()
        with pytest.raises(CtlError, match="BLANK database"):
            datadir_guard(r)

    def test_deployed_with_initialized_datadir_passes(self, mk_runner) -> None:
        r = mk_runner()
        (r.settings.emr_home / "container" / ".deployed").touch()
        (r.settings.data_dir / DATADIR_SIGNATURE).mkdir(parents=True)
        datadir_guard(r)

    def test_persisted_accept_empty_warns(self, mk_runner, capsys) -> None:
        # CARLOS_ACCEPT_EMPTY_DATADIR persisted in the env file is the same
        # standing-config footgun as CARLOS_ALLOW_DB_ROOT — call it out.
        r = mk_runner("CARLOS_ACCEPT_EMPTY_DATADIR=1\n")
        (r.settings.emr_home / "container" / ".deployed").touch()
        datadir_guard(r)
        assert "PERSISTED" in capsys.readouterr().err

    def test_accept_empty_override_and_marker_sync(self, mk_runner) -> None:
        r = mk_runner("", {"CARLOS_ACCEPT_EMPTY_DATADIR": "1"})
        (r.settings.emr_home / "container" / ".deployed").touch()
        datadir_guard(r)
        marker = r.settings.emr_home / "container" / "guard" / "accept-empty-datadir"
        assert marker.is_file()
        # Re-run without the override: the marker must be cleared so the boot
        # guard and in-pod refusal track THIS play's intent.
        r2 = mk_runner()
        (r2.settings.data_dir / DATADIR_SIGNATURE).mkdir(parents=True)
        (r2.settings.emr_home / "container" / ".deployed").touch()
        datadir_guard(r2)
        assert not marker.is_file() or r2.settings.emr_home != r.settings.emr_home


class TestWaitAppReady:
    def test_healthy_passes(self, mk_runner) -> None:
        r = mk_runner()
        r.script("podman", "inspect", rc=0, out="healthy\n")
        assert wait_app_ready(r) is True

    def test_gates_the_db_container_too(self, mk_runner) -> None:
        # The gate covers db AND carlos AND drugref AND waf — a db whose
        # server never answers its real-ping probe must fail play.
        r = mk_runner()
        r.script("podman", "inspect", rc=0, out="healthy\n")
        assert wait_app_ready(r) is True
        assert r.called_with("inspect", f"{r.settings.app_pod}-db")

    def test_no_health_info_warns_but_passes(self, mk_runner, capsys) -> None:
        # rc 0 with no health block AND no healthcheck configured = nothing
        # to gate on (stubbed engines / a podman that didn't wire the probe).
        # The empty status triggers a .Config.Healthcheck follow-up; empty
        # there too still PASSES (compatibility), but must WARN loudly rather
        # than silently false-green the readiness gate.
        r = mk_runner()
        r.script("podman", "inspect", rc=0, out="")
        assert wait_app_ready(r) is True
        assert "no podman healthcheck is configured" in capsys.readouterr().err

    def test_configured_but_unreported_healthcheck_keeps_polling(self, mk_runner) -> None:
        # kube play wires every livenessProbe into a podman healthcheck: an
        # EMPTY .State.Health.Status while .Config.Healthcheck says one IS
        # configured means "not reported yet", never "healthy" — the gate
        # must poll to the deadline, not false-green.
        r = mk_runner("", {"READY_WAIT_SECONDS": "0"})
        r.script("{{.State.Health.Status}}", rc=0, out="")
        r.script("{{if .Config.Healthcheck}}configured{{end}}", rc=0, out="configured\n")
        assert wait_app_ready(r) is False

    def test_never_healthy_times_out(self, mk_runner) -> None:
        r = mk_runner("", {"READY_WAIT_SECONDS": "0"})
        r.script("podman", "inspect", rc=0, out="starting\n")
        assert wait_app_ready(r) is False

    def test_inspect_failure_is_not_no_health_info(self, mk_runner) -> None:
        # A failing inspect (container being recreated, engine busy) must
        # keep polling toward the deadline, NOT silently pass the gate —
        # that false-green is exactly what the gate exists to eliminate.
        r = mk_runner("", {"READY_WAIT_SECONDS": "0"})
        r.script("podman", "inspect", rc=125, out="")
        assert wait_app_ready(r) is False


class TestStartInstanceTimers:
    def _armed(self, runner) -> None:
        (runner.settings.emr_home / "container").mkdir(parents=True, exist_ok=True)

    def test_all_timers_present_and_started(self, mk_runner, tmp_path: Path) -> None:
        sysd = tmp_path / "systemd"
        sysd.mkdir()
        r = mk_runner("", {"CARLOS_SYSTEMD_DIR": str(sysd)})
        self._armed(r)
        for t in ("backup", "binlog", "docs", "backup-verify", "monitor"):
            (sysd / f"{r.settings.instance}-{t}.timer").touch()
        assert start_instance_timers(r) is True

    def test_missing_timer_is_loud_and_nonzero(self, mk_runner, tmp_path: Path, capsys) -> None:
        # Once the .deployed marker is armed, a MISSING timer means the
        # schedule silently never fires — that must surface as False (play
        # exits nonzero), not a quiet skip.
        sysd = tmp_path / "systemd"
        sysd.mkdir()
        r = mk_runner("", {"CARLOS_SYSTEMD_DIR": str(sysd)})
        self._armed(r)
        for t in ("backup", "binlog", "docs", "backup-verify"):  # no monitor
            (sysd / f"{r.settings.instance}-{t}.timer").touch()
        assert start_instance_timers(r) is False
        assert "monitor.timer is NOT installed" in capsys.readouterr().err

    def test_failed_start_is_nonzero(self, mk_runner, tmp_path: Path, capsys) -> None:
        sysd = tmp_path / "systemd"
        sysd.mkdir()
        r = mk_runner("", {"CARLOS_SYSTEMD_DIR": str(sysd)})
        self._armed(r)
        for t in ("backup", "binlog", "docs", "backup-verify", "monitor"):
            (sysd / f"{r.settings.instance}-{t}.timer").touch()
        r.script("systemctl", "start", rc=1)
        assert start_instance_timers(r) is False
        assert "could not start" in capsys.readouterr().err


class TestGuardVerb:
    def _deploy(self, runner) -> None:
        (runner.settings.emr_home / "container").mkdir(parents=True, exist_ok=True)
        (runner.settings.emr_home / "container" / ".deployed").touch()

    def test_not_deployed_passes(self, mk_runner) -> None:
        assert cmd_guard(mk_runner()) == 0

    def test_deployed_all_volumes_present(self, mk_runner) -> None:
        r = mk_runner()
        self._deploy(r)
        d = r.settings.data_dir
        (d / DATADIR_SIGNATURE).mkdir(parents=True)
        (d / "mariadb-binlog").mkdir()
        (d / "mariadb-binlog" / "binlog.000001").write_text("x")
        (d / "CarlosDocument").mkdir()
        (d / "CarlosDocument" / "doc1.pdf").write_text("x")
        assert cmd_guard(r) == 0

    def test_empty_binlog_dir_fails(self, mk_runner, capsys) -> None:
        # An unmounted mountpoint leaves the empty underlying dir in place —
        # existence alone must not pass on a deployed instance (PITR would
        # silently break).
        r = mk_runner()
        self._deploy(r)
        d = r.settings.data_dir
        (d / DATADIR_SIGNATURE).mkdir(parents=True)
        (d / "mariadb-binlog").mkdir()
        (d / "CarlosDocument").mkdir()
        (d / "CarlosDocument" / "doc1.pdf").write_text("x")
        assert cmd_guard(r) == 1
        assert "UNMOUNTED" in capsys.readouterr().err

    def test_deployed_missing_datadir_fails(self, mk_runner, capsys) -> None:
        r = mk_runner()
        self._deploy(r)
        assert cmd_guard(r) == 1
        assert "BLANK database" in capsys.readouterr().err

    def test_docs_min_files_zero_optout(self, mk_runner) -> None:
        r = mk_runner("", {"CARLOS_DOCS_MIN_FILES": "0"})
        self._deploy(r)
        d = r.settings.data_dir
        (d / DATADIR_SIGNATURE).mkdir(parents=True)
        (d / "mariadb-binlog").mkdir()
        (d / "mariadb-binlog" / "binlog.000001").write_text("x")
        assert cmd_guard(r) == 0

    def test_accept_empty_env_passes(self, mk_runner) -> None:
        r = mk_runner("", {"CARLOS_ACCEPT_EMPTY_DATADIR": "1"})
        self._deploy(r)
        assert cmd_guard(r) == 0

    def test_signature_helper(self, tmp_path: Path) -> None:
        assert not datadir_initialized(tmp_path)
        (tmp_path / DATADIR_SIGNATURE).mkdir(parents=True)
        assert datadir_initialized(tmp_path)


class TestDbIsolationGate:
    def _cnf(self, runner, content: str) -> None:
        p = runner.settings.conf_dir / "mariadb" / "zz-carlos.cnf"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)

    def test_loopback_bind_passes(self, mk_runner) -> None:
        r = mk_runner()
        self._cnf(r, "[mysqld]\nbind_address = 127.0.0.1\n")
        db_isolation_gate(r)

    def test_hyphen_spelling_accepted(self, mk_runner) -> None:
        r = mk_runner()
        self._cnf(r, "[mysqld]\nbind-address = 127.0.0.1\n")
        db_isolation_gate(r)

    def test_missing_bind_refused(self, mk_runner) -> None:
        r = mk_runner()
        self._cnf(r, "[mysqld]\n")
        with pytest.raises(CtlError, match="edge network"):
            db_isolation_gate(r)

    def test_nonloopback_bind_refused(self, mk_runner) -> None:
        # A presence-only check would pass 0.0.0.0 — require LOOPBACK.
        r = mk_runner()
        self._cnf(r, "[mysqld]\nbind_address = 0.0.0.0\n")
        with pytest.raises(CtlError, match="edge network"):
            db_isolation_gate(r)

    def test_exposed_override_warns(self, mk_runner, capsys) -> None:
        r = mk_runner("", {"CARLOS_ALLOW_DB_EXPOSED": "1"})
        self._cnf(r, "[mysqld]\n")
        db_isolation_gate(r)
        assert "CARLOS_ALLOW_DB_EXPOSED" in capsys.readouterr().err


class TestValidateRendered:
    def _render(self, runner, obs: bool = True) -> None:
        s = runner.settings
        files = [s.rendered_yaml, s.rendered_waf_yaml] + ([s.rendered_obs_yaml] if obs else [])
        for f in files:
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text("apiVersion: v1\nkind: Pod\n")

    def test_clean_render_passes(self, mk_runner) -> None:
        r = mk_runner()
        self._render(r)
        validate_rendered(r)

    def test_missing_spec_refused(self, mk_runner) -> None:
        with pytest.raises(CtlError, match="no rendered pod spec"):
            validate_rendered(mk_runner())

    def test_stray_token_refused(self, mk_runner) -> None:
        r = mk_runner()
        self._render(r)
        r.settings.rendered_yaml.write_text("image: @CARLOS_IMAGE@\n")
        with pytest.raises(CtlError, match="unrendered token"):
            validate_rendered(r)

    def test_leftover_jinja_refused(self, mk_runner) -> None:
        r = mk_runner()
        self._render(r)
        r.settings.rendered_yaml.write_text("image: {{ carlos_image }}\n")
        with pytest.raises(CtlError, match="Jinja"):
            validate_rendered(r)

    def test_obs_disabled_skips_obs_yaml(self, mk_runner) -> None:
        r = mk_runner("OBS_ENABLED=0\n")
        self._render(r, obs=False)
        validate_rendered(r)  # obs yaml absent, but not required

    def test_apache_ssl_protocols_warns(self, mk_runner, capsys) -> None:
        r = mk_runner("WAF_SSL_PROTOCOLS=all -SSLv3 -TLSv1\n")
        self._render(r)
        validate_rendered(r)
        assert "Apache mod_ssl" in capsys.readouterr().err


class TestSeedBackupStamps:
    def test_seeds_all_three_once(self, mk_runner) -> None:
        r = mk_runner()
        seed_backup_stamps(r)
        for stamp in (".last-full-ok", ".last-binlog-ok", ".last-docs-ok"):
            assert (r.settings.emr_home / "backup" / stamp).is_file()


class TestReadyBudgets:
    def test_default_budgets_cover_each_containers_startup_allowance(
        self, mk_runner
    ) -> None:
        # Finding S13: one shared 900s budget under-funded the db's 1200s
        # first-boot startupProbe allowance — a healthy slow deploy read as
        # failed with no markers/timers armed.
        from carlos_ctl.lifecycle2 import ready_budgets

        r = mk_runner()
        s = r.settings
        b = ready_budgets(r)
        assert b[f"{s.app_pod}-db"] == 1320
        # carlos matches the db (review finding): its command serializes
        # behind the db's wait-for-3306, so its healthy-time is db-ready-time
        # plus Tomcat boot — a smaller budget re-created the S13 false fail.
        assert b[f"{s.app_pod}-carlos"] == 1320
        assert b[f"{s.app_pod}-drugref"] == 1320
        assert b[f"{s.waf_pod}-waf"] == 420

    def test_explicit_ready_wait_seconds_overrides_every_budget(self, mk_runner) -> None:
        from carlos_ctl.lifecycle2 import ready_budgets

        r = mk_runner("", {"READY_WAIT_SECONDS": "300"})
        assert set(ready_budgets(r).values()) == {300}


class TestHealthcheckFallbackProbe:
    # Finding S15: no healthcheck wired (podman never mapped the probe) used
    # to warn and green the gate; it now execs the pod spec's own probe.

    def test_unwired_healthcheck_greens_only_on_probe_success(
        self, mk_runner, capsys
    ) -> None:
        r = mk_runner()
        r.script("{{.State.Health.Status}}", rc=0, out="")
        r.script("{{if .Config.Healthcheck}}configured{{end}}", rc=0, out="")
        # FakeRunner default rc=0 makes the fallback exec succeed.
        assert wait_app_ready(r) is True
        assert r.called_with("exec", f"{r.settings.app_pod}-db")
        assert "degrades to exec'ing the probe" in capsys.readouterr().err

    def test_unwired_healthcheck_with_failing_probe_times_out(
        self, mk_runner, capsys
    ) -> None:
        r = mk_runner("", {"READY_WAIT_SECONDS": "0"})
        r.script("{{.State.Health.Status}}", rc=0, out="")
        r.script("{{if .Config.Healthcheck}}configured{{end}}", rc=0, out="")
        r.script("podman", "exec", rc=1)
        assert wait_app_ready(r) is False
        assert "degrades to exec'ing the probe" in capsys.readouterr().err


class TestHealthcheckNeverRuns:
    """Third shape (measured live): the healthcheck IS configured but podman
    never EXECUTES it — status pinned at 'starting', .State.Health.Log empty
    — because podman drives healthchecks from transient systemd timers. The
    gate used to poll the full per-container budget and then report the app
    was not serving, about a stack that was serving fine."""

    def test_never_run_healthcheck_falls_back_to_the_declared_probe(
        self, mk_runner, capsys, monkeypatch
    ) -> None:
        import carlos_ctl.lifecycle2 as l2

        monkeypatch.setattr(l2, "_NEVER_RAN_GRACE", 0)
        r = mk_runner()
        r.script("{{.State.Health.Status}}", rc=0, out="starting\n")
        r.script("{{len .State.Health.Log}}", rc=0, out="0\n")
        # FakeRunner default rc=0 makes the fallback exec succeed.
        assert wait_app_ready(r) is True
        assert r.called_with("exec", f"{r.settings.app_pod}-db")
        assert "has not run once" in capsys.readouterr().err

    def test_never_run_with_failing_probe_still_fails_closed(
        self, mk_runner, monkeypatch
    ) -> None:
        import carlos_ctl.lifecycle2 as l2

        monkeypatch.setattr(l2, "_NEVER_RAN_GRACE", 0)
        r = mk_runner("", {"READY_WAIT_SECONDS": "0"})
        r.script("{{.State.Health.Status}}", rc=0, out="starting\n")
        r.script("{{len .State.Health.Log}}", rc=0, out="0\n")
        r.script("podman", "exec", rc=1)
        assert wait_app_ready(r) is False

    def test_a_check_that_HAS_run_keeps_normal_polling(
        self, mk_runner, monkeypatch
    ) -> None:
        # A slow app produces FAILING log entries; that must stay on the
        # normal polling path (never shortcut to the fallback probe).
        import carlos_ctl.lifecycle2 as l2

        monkeypatch.setattr(l2, "_NEVER_RAN_GRACE", 0)
        r = mk_runner("", {"READY_WAIT_SECONDS": "0"})
        r.script("{{.State.Health.Status}}", rc=0, out="starting\n")
        r.script("{{len .State.Health.Log}}", rc=0, out="3\n")
        assert wait_app_ready(r) is False
        assert not r.called_with("exec", f"{r.settings.app_pod}-db")


class TestSerialPollingDeadlineFloor:
    """Pass-17 H5, measured live: the deadlines are absolute from ONE t0 but
    the containers are polled SERIALLY, so the LAST-polled container (the waf,
    which also carries the SMALLEST budget) could find its deadline already
    expired and be failed WITHOUT EVER BEING PROBED. On a host whose podman
    healthcheck timers do not run — the very case _NEVER_RAN_GRACE exists for
    — the three preceding containers burn 3 x grace before the waf's first
    poll, so its 420 s budget is always gone: `play` reported "the app is not
    serving" (no .deployed, no timers) while the front door served 200 and the
    waf's own declared probe returned 0."""

    def test_last_container_still_gets_a_probe_when_t0_budget_is_spent(
        self, mk_runner, monkeypatch
    ) -> None:
        import carlos_ctl.lifecycle2 as l2

        # Model the live failure exactly: the waf's absolute budget is
        # ALREADY SPENT when its poll starts (budget 0), and the never-ran
        # grace is NON-zero, so the first iteration cannot reach the fallback
        # probe. Without the floor the deadline check fires first and the waf
        # is failed unprobed; with it, the grace elapses and the probe runs.
        monkeypatch.setattr(l2, "_NEVER_RAN_GRACE", 1)
        r = mk_runner()
        s = r.settings
        # Just the waf, with its budget already spent — the state the serial
        # loop leaves it in after the three app-pod containers.
        monkeypatch.setattr(l2, "ready_budgets", lambda _r: {f"{s.waf_pod}-waf": 0})
        r.script("{{.State.Health.Status}}", rc=0, out="starting\n")
        r.script("{{len .State.Health.Log}}", rc=0, out="0\n")
        # FakeRunner default rc=0 => the declared probe succeeds.
        assert l2.wait_app_ready(r) is True
        assert r.called_with("exec", f"{s.waf_pod}-waf")

    def test_the_floor_does_not_green_a_container_whose_probe_fails(
        self, mk_runner, monkeypatch
    ) -> None:
        # The floor buys time to PROBE, never a free pass: a failing probe
        # must still fail the gate.
        import carlos_ctl.lifecycle2 as l2

        monkeypatch.setattr(l2, "_NEVER_RAN_GRACE", 0)
        r = mk_runner()
        s = r.settings
        monkeypatch.setattr(l2, "ready_budgets", lambda _r: {f"{s.waf_pod}-waf": 0})
        r.script("{{.State.Health.Status}}", rc=0, out="starting\n")
        r.script("{{len .State.Health.Log}}", rc=0, out="0\n")
        r.script("podman", "exec", rc=1)
        assert l2.wait_app_ready(r) is False

    def test_an_explicit_ready_wait_is_never_silently_extended(
        self, mk_runner, monkeypatch
    ) -> None:
        # READY_WAIT_SECONDS is the operator's direct statement of patience
        # (and the hermetic suite's instant-timeout knob) — the floor must not
        # stretch it to grace-length per container.
        import time

        import carlos_ctl.lifecycle2 as l2

        monkeypatch.setattr(l2, "_NEVER_RAN_GRACE", 900)
        r = mk_runner("", {"READY_WAIT_SECONDS": "0"})
        r.script("{{.State.Health.Status}}", rc=0, out="starting\n")
        r.script("{{len .State.Health.Log}}", rc=0, out="0\n")
        r.script("podman", "exec", rc=1)
        started = time.time()
        assert l2.wait_app_ready(r) is False
        assert time.time() - started < 30


class TestWafNoRootGate:
    def test_root_process_fails_the_gate(self, mk_runner, capsys) -> None:
        from carlos_ctl.lifecycle2 import waf_no_root_gate

        r = mk_runner()
        r.script("podman", "top", rc=0, out="USER\nnginx\nroot\n")
        assert waf_no_root_gate(r) is False
        assert "ROOT process" in capsys.readouterr().err

    def test_nonroot_processes_pass(self, mk_runner) -> None:
        from carlos_ctl.lifecycle2 import waf_no_root_gate

        r = mk_runner()
        r.script("podman", "top", rc=0, out="USER\nnginx\nnginx\n")
        assert waf_no_root_gate(r) is True

    def test_unreadable_top_passes_but_is_left_to_check(self, mk_runner) -> None:
        from carlos_ctl.lifecycle2 import waf_no_root_gate

        r = mk_runner()
        r.script("podman", "top", rc=1, out="")
        assert waf_no_root_gate(r) is True


class TestRuntimeVersionFloor:
    # C24: the podman >= 4.9 / systemd >= 248 floors were prose-only; check
    # (and asserts.yml) now verify them, tolerating unparseable output.

    def test_old_podman_is_below_floor(self, mk_runner) -> None:
        from carlos_ctl.lifecycle2 import runtime_version_ok

        r = mk_runner()
        r.script("podman", "--version", rc=0, out="podman version 4.4.1\n")
        assert runtime_version_ok(
            r, ["podman", "--version"], r"(\d+)\.(\d+)", (4, 9)
        ) is False

    def test_modern_podman_meets_floor(self, mk_runner) -> None:
        from carlos_ctl.lifecycle2 import runtime_version_ok

        r = mk_runner()
        r.script("podman", "--version", rc=0, out="podman version 5.2.0\n")
        assert runtime_version_ok(
            r, ["podman", "--version"], r"(\d+)\.(\d+)", (4, 9)
        ) is True

    def test_systemd_floor(self, mk_runner) -> None:
        from carlos_ctl.lifecycle2 import runtime_version_ok

        r = mk_runner()
        r.script("systemctl", "--version", rc=0, out="systemd 247 (247.3-7)\n")
        assert runtime_version_ok(
            r, ["systemctl", "--version"], r"systemd (\d+)", (248,)
        ) is False

    def test_unparseable_output_is_none_not_fail(self, mk_runner) -> None:
        from carlos_ctl.lifecycle2 import runtime_version_ok

        r = mk_runner()
        r.script("podman", "--version", rc=0, out="weird build string\n")
        assert runtime_version_ok(
            r, ["podman", "--version"], r"(\d+)\.(\d+)", (4, 9)
        ) is None


class TestDownStopRecheck:
    """`pod stop` exits nonzero for post-stop CLEANUP errors too (cgroup
    teardown; verified live: rc 125 with the pod already Exited). The podman
    branch must mirror the systemd branch's is-active recheck: only a pod NOT
    affirmatively stopped counts as a stop failure — but an unknown state
    stays a failure (the rc gates `down && umount` maintenance scripting)."""

    def _runner(self, mk_runner, tmp_path):
        r = mk_runner(
            "INSTANCE=carlos\n",
            extra_env={"CARLOS_QUADLET_DIR": str(tmp_path / "quadlet-none")},
        )
        return r

    def test_cleanup_error_with_pod_exited_is_not_a_failure(
        self, mk_runner, tmp_path, capsys
    ) -> None:
        from carlos_ctl.lifecycle2 import cmd_down

        r = self._runner(mk_runner, tmp_path)
        r.script("podman", "pod", "exists", "carlos-app", rc=0)
        r.script("podman", "pod", "stop", rc=125)
        r.script("podman", "pod", "inspect", out="Exited\n")
        assert cmd_down(r, []) == 0
        assert "did NOT stop" not in capsys.readouterr().err

    def test_still_running_pod_is_a_failure(self, mk_runner, tmp_path, capsys) -> None:
        from carlos_ctl.lifecycle2 import cmd_down

        r = self._runner(mk_runner, tmp_path)
        r.script("podman", "pod", "exists", "carlos-app", rc=0)
        r.script("podman", "pod", "stop", rc=125)
        r.script("podman", "pod", "inspect", out="Running\n")
        assert cmd_down(r, []) == 1
        assert "did NOT stop" in capsys.readouterr().err


class TestCmdEnable:
    """`enable` is the documented recovery from `down --disable` (README,
    "Patching & rebooting the host"), so its exit code and its verdict text
    have to be right on the DEFAULT TLS mode, not just on acme."""

    def _installed(self, runner, tmp_path: Path, timers) -> None:
        sysd = tmp_path / "systemd"
        sysd.mkdir(exist_ok=True)
        for t in timers:
            (sysd / f"{runner.settings.instance}-{t}.timer").touch()

    def test_selfsigned_instance_enables_cleanly(self, mk_runner, tmp_path: Path, capsys) -> None:
        # cert-renew.timer is rendered ONLY in acme mode (cleanup.yml removes
        # it otherwise). Enabling it unconditionally made `enable` return 1 on
        # every default install and tell the operator "the EMR will NOT start
        # at the next boot" about a host whose pod units had just been
        # unmasked correctly.
        sysd = tmp_path / "systemd"
        sysd.mkdir(exist_ok=True)
        r = mk_runner("", {"CARLOS_SYSTEMD_DIR": str(sysd)})
        self._installed(r, tmp_path, ("backup", "binlog", "docs", "backup-verify", "monitor"))
        r.script("systemctl", "enable", "carlos-cert-renew.timer", rc=1)
        assert cmd_enable(r) == 0
        err = capsys.readouterr().err
        assert "will NOT start at the next boot" not in err
        assert not r.called_with("enable", "carlos-cert-renew.timer")

    def test_acme_instance_still_enables_cert_renew(self, mk_runner, tmp_path: Path) -> None:
        sysd = tmp_path / "systemd"
        sysd.mkdir(exist_ok=True)
        r = mk_runner("CARLOS_TLS_MODE=acme\n", {"CARLOS_SYSTEMD_DIR": str(sysd)})
        self._installed(
            r, tmp_path,
            ("backup", "binlog", "docs", "backup-verify", "monitor", "cert-renew"),
        )
        assert cmd_enable(r) == 0
        assert r.called_with("enable", "carlos-cert-renew.timer")

    def test_uninstalled_timer_warns_but_does_not_claim_systemd_is_broken(
        self, mk_runner, tmp_path: Path, capsys
    ) -> None:
        sysd = tmp_path / "systemd"
        sysd.mkdir(exist_ok=True)
        r = mk_runner("", {"CARLOS_SYSTEMD_DIR": str(sysd)})
        self._installed(r, tmp_path, ("backup", "binlog", "docs", "backup-verify"))
        assert cmd_enable(r) == 0
        err = capsys.readouterr().err
        assert "carlos-monitor.timer" in err
        assert "re-run the provisioning playbook" in err

    def test_real_systemctl_failure_still_fails(self, mk_runner, tmp_path: Path, capsys) -> None:
        # The fix must not swallow the case the rc check exists for: an
        # INSTALLED timer that systemctl refuses to enable.
        sysd = tmp_path / "systemd"
        sysd.mkdir(exist_ok=True)
        r = mk_runner("", {"CARLOS_SYSTEMD_DIR": str(sysd)})
        self._installed(r, tmp_path, ("backup", "binlog", "docs", "backup-verify", "monitor"))
        r.script("systemctl", "enable", "carlos-monitor.timer", rc=1)
        assert cmd_enable(r) == 1
        assert "will NOT start at the next boot" in capsys.readouterr().err

    def test_failed_unmask_still_fails(self, mk_runner, tmp_path: Path) -> None:
        sysd = tmp_path / "systemd"
        sysd.mkdir(exist_ok=True)
        r = mk_runner("", {"CARLOS_SYSTEMD_DIR": str(sysd)})
        self._installed(r, tmp_path, ("backup", "binlog", "docs", "backup-verify", "monitor"))
        r.script("systemctl", "--user", rc=1)
        assert cmd_enable(r) == 1
