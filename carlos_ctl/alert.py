# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Alert dispatcher (`carlos-ctl alert <subject> [detail]`) + alert-test.

Writes a WARNING to the journal and, when configured, POSTs to ALERT_WEBHOOK
and/or emails ALERT_EMAIL. Invoked two ways:
  - OnFailure=<instance>-alert@%n.service on the backup/binlog/verify/guard
    units (systemd passes the failed unit name), and
  - the monitor, with a check-failure detail.

Delivery accounting: with off-box channels configured, at least ONE must
succeed or the verb exits nonzero — a webhook 404 / dead MTA must not look
like a delivered page. Each channel is still attempted independently (webhook
AND email when both are set), so either one is a fallback for the other.
Journal-only installs (no channel configured) keep exiting 0."""

from __future__ import annotations

import contextlib
import json
import platform
import re
import sys
import time
from typing import List

from .runner import Runner
from .util import CtlError, curl_config_quote, log, warn


def dispatch(runner: Runner, subject_suffix: str, detail: str = "") -> bool:
    """Send one alert through every configured channel. Returns True when
    delivery is healthy (nothing configured, or ≥1 channel delivered)."""
    s = runner.settings
    subject = f"{s.instance} alert: {subject_suffix or 'unspecified'}"
    host = platform.node() or "unknown"
    msg = f"[{host}] {subject}" + (f" — {detail}" if detail else "")

    channels_configured = False
    channels_delivered = False

    # 1. Journal (always; best-effort fall back to stderr if logger is absent).
    if not runner.have("logger") or not runner.ok(
        ["logger", "-t", "carlos-alert", "-p", "daemon.warning", "--", msg]
    ):
        import sys

        print(f"ALERT: {msg}", file=sys.stderr)

    def journal_err(text: str) -> None:
        if not runner.have("logger") or not runner.ok(
            ["logger", "-t", "carlos-alert", "-p", "daemon.err", "--", text]
        ):
            import sys

            print(f"ALERT: {text}", file=sys.stderr)

    # 2. Optional webhook (generic JSON {"text": ...}, e.g. Slack/Mattermost).
    webhook = s.get("ALERT_WEBHOOK")
    if webhook:
        channels_configured = True
        # Pass the webhook URL via `curl -K -` (config on stdin), NOT on argv:
        # a capability URL on the command line is visible in
        # /proc/<pid>/cmdline to any local user while curl runs. json.dumps
        # escapes every control character, so a control byte in an alert
        # detail can never emit a malformed webhook body.
        body = json.dumps({"text": msg})
        try:
            curl_config = f"url = {curl_config_quote(webhook, 'ALERT_WEBHOOK')}\n"
        except CtlError as e:
            journal_err(f"alert webhook not delivered — {e}")
            curl_config = None
        # --retry 2: one transient blip (DNS hiccup, webhook-side 5xx) must
        # not cost the page — this is the path that tells a human the EMR is
        # broken. Retries are curl-internal (connection/5xx class), bounded
        # well inside the 15s budget per attempt.
        if curl_config is not None and runner.have("curl") and runner.ok(
            [
                "curl", "-fsS", "-m", "15", "--retry", "2", "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", body, "-K", "-",
            ],
            input_text=curl_config,
        ):
            channels_delivered = True
        else:
            journal_err("alert webhook POST failed")

    # 3. Optional email (only if a sendmail-compatible MTA is present).
    email = s.get("ALERT_EMAIL")
    if email:
        channels_configured = True
        if runner.have("sendmail"):
            mail = f"To: {email}\nSubject: {subject}\n\n{msg}\n"
            # timeout=30: sendmail must not block the page forever on a wedged
            # smarthost. A hang reads as a delivery failure (ok() → False) so
            # the "NO configured alert channel delivered" guard below fires,
            # instead of the alert oneshot sitting in 'activating' until its
            # unit TimeoutStartSec kills it (carlos-alert@.service).
            if runner.ok(["sendmail", "-t"], input_text=mail, timeout=30):
                channels_delivered = True
            else:
                journal_err("alert email send failed (sendmail timed out or exited nonzero)")
        else:
            # ALERT_EMAIL is set but no MTA is installed — surface the
            # misconfiguration so alerts don't silently fall back to journal-only.
            journal_err(
                f"ALERT_EMAIL is set ({email}) but no sendmail-compatible MTA is installed "
                f"— email alerts are DISABLED"
            )

    if channels_configured and not channels_delivered:
        journal_err("NO configured alert channel delivered — the page did NOT go out")
        return False
    return True


def cmd_alert(runner: Runner, args: List[str]) -> int:
    """OnFailure= entry point: the failing unit's name is the subject. The
    15-minute binlog/docs timers page THROUGH here on every failing run, so a
    repo unreachable overnight would fire ~32 identical pages — the exact
    alert-fatigue flood the monitor's own throttle guards against. Apply the
    same per-key throttle (keyed on the unit/subject, windowed by
    ALERT_REMIND_HOURS): within the window, journal-only; a delivered page
    (or a first occurrence) starts the window. Re-arm is purely by mtime: a
    stamp older than the window re-pages. The monitor's recovery sweep
    deliberately SKIPS these `onfailure-*` stamps (they are ours, not its), so
    a still-failing unit keeps its throttle between monitor runs — the
    accepted trade is that a unit which recovers then re-fails inside the
    window stays journal-only until the stamp ages out."""
    subject = args[0] if args else "unspecified"
    # JOIN the remaining words, don't take args[1] alone: an unquoted detail
    # ("carlos-ctl alert backup db is down") delivered the page as "backup — db"
    # and silently dropped the rest against a real webhook.
    # Deliberately NOT the db-backup-style refusal: this is the paging path, and
    # refusing a malformed invocation means the page does not go out AT ALL,
    # which is strictly worse than delivering it. Reassembling matches what the
    # caller meant, and a quoted detail is unaffected (one arg, joined with
    # itself).
    detail = " ".join(args[1:])
    s = runner.settings
    key = "onfailure-" + re.sub(r"[^A-Za-z0-9_.-]", "_", subject)
    state_dir = s.emr_home / "monitor" / "state"
    remind = s.get_int_or("ALERT_REMIND_HOURS", 24)
    with contextlib.suppress(OSError):
        state_dir.mkdir(parents=True, exist_ok=True)
    sf = state_dir / key
    if sf.is_file():
        with contextlib.suppress(OSError):
            if time.time() - sf.stat().st_mtime < remind * 3600:
                # Within the window — journal-only, do not re-deliver.
                if not (runner.have("logger") and runner.ok(
                    ["logger", "-t", "carlos-alert", "--",
                     f"{subject} still failing (delivery throttled): {detail}"]
                )):
                    print(f"{subject} still failing (throttled): {detail}", file=sys.stderr)
                return 0
    delivered = dispatch(runner, subject, detail)
    if delivered:
        try:
            sf.touch()
        except OSError as exc:
            # A stamp that cannot be persisted means the throttle is dead and
            # every future failure re-pages — say so instead of silently
            # re-flooding (the unit sandbox needs ReadWritePaths= on the state
            # dir; a silent suppress here hid exactly that misconfiguration).
            from .util import warn

            warn(
                f"could not persist alert throttle stamp {sf} ({exc}) — repeated "
                f"failures of '{subject}' will RE-PAGE on every occurrence until "
                f"the stamp dir is writable (check the alert unit's sandbox)"
            )
    return 0 if delivered else 1


def check_alert_channel(runner: Runner) -> None:
    """Warn loudly when no off-box alert channel is configured, so a default
    install does not silently send every alert to the journal only (where
    nothing pages a human)."""
    s = runner.settings
    if not s.get("ALERT_WEBHOOK") and not s.get("ALERT_EMAIL") \
            and not s.flag("ALERT_JOURNAL_ONLY"):
        warn(
            f"no ALERT_WEBHOOK or ALERT_EMAIL set — backup/monitor/disk/cert alerts go to "
            f"the JOURNAL ONLY, so nothing off-box will page you. Set one in {s.env_file} "
            f"(then prove delivery with 'carlos-ctl alert-test'), or set "
            f"ALERT_JOURNAL_ONLY=1 to acknowledge journal-only alerting and silence this "
            f"warning."
        )


def cmd_alert_test(runner: Runner) -> int:
    """Prove the alert channel actually DELIVERS, end to end, through the
    exact dispatch path the timers and the monitor use. A configured-but-
    broken webhook URL or MTA otherwise stays invisible until the first real
    incident goes unnoticed — the alert path is itself a single point of
    failure and must be testable on demand."""
    s = runner.settings
    check_alert_channel(runner)
    # The webhook URL is a bearer-token capability secret — report only
    # whether it is configured, never its value.
    hook_state = "configured" if s.get("ALERT_WEBHOOK") else "unset"
    log(
        f"Dispatching a test alert (webhook: {hook_state}, "
        f"email: {s.get('ALERT_EMAIL') or 'unset'})"
    )
    host = platform.node() or "unknown-host"
    if dispatch(
        runner, "alert-test",
        f"test alert from carlos-ctl alert-test on {host} — if you can read this off-box, "
        f"delivery works",
    ):
        log(
            "alert dispatch reported success — CONFIRM the message actually arrived "
            "(webhook channel / inbox) before relying on it"
        )
    else:
        raise CtlError(
            f"alert dispatch FAILED — no configured channel delivered (see stderr above / "
            f"journalctl -t carlos-alert); fix ALERT_WEBHOOK/ALERT_EMAIL in {s.env_file} "
            f"and re-run"
        )
    # Also exercise the OnFailure path itself: the backup/binlog/verify units
    # page via `OnFailure=<instance>-alert@%n.service`, a code path the direct
    # dispatch above never touches. A broken template unit would otherwise
    # stay invisible until a real 3am failure. Best-effort.
    if runner.systemd_running() and (s.systemd_dir / f"{s.instance}-alert@.service").is_file():
        if runner.ok(["systemctl", "start", f"{s.instance}-alert@alert-test.service"]):
            log(f"OnFailure template path exercised ({s.instance}-alert@alert-test.service)")
        else:
            warn(
                f"could not start {s.instance}-alert@alert-test.service — the OnFailure "
                f"paging path may be broken "
                f"(journalctl -u {s.instance}-alert@alert-test.service)"
            )
    return 0
