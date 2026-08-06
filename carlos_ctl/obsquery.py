# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Read-only queries against the obs pod's stores (VictoriaMetrics /
VictoriaLogs / vmalert), used by `check` and the monitor. All host-loopback,
all best-effort — callers treat empty as "no data / unreachable".

Every probe uses ``store_curl()``. Store credentials are passed to
``curl -K -`` through standard input rather than exposed in process arguments.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any, Dict, List, Optional

from .runner import Runner
from .util import CtlError, curl_config_quote, warn


def store_curl(
    runner: Runner, url: str, *,
    args: Optional[List[str]] = None, timeout: int = 8,
    with_auth: bool = True,
) -> subprocess.CompletedProcess:
    """ONE chokepoint for every store/vmalert HTTP probe. The URL and (when
    the instance has one) the obs basic-auth credential ride the `-K -`
    stdin config — off-argv, like every credential in this CLI. A missing/
    unreadable password file simply omits the credential, which is correct
    in BOTH transition directions: an auth-off store ignores the header, an
    auth-on store 401s a credential-less probe loudly. Query bodies
    (--data-urlencode) stay on argv — they are not secrets. with_auth=False
    exists for check's positive enforcement probe (a deliberately
    credential-less request that MUST fail on an authed store)."""
    s = runner.settings
    # The URL is internally constructed (loopback + a fixed path) — a bad char
    # here means a corrupted port/host setting, so let the CtlError propagate.
    cfg = f"url = {curl_config_quote(url, 'obs store URL')}\n"
    if with_auth:
        try:
            pw = s.obs_http_password_file.read_text().strip()
        except OSError:
            pw = ""
        if pw:
            user = s.get("OBS_HTTP_USER") or "obs"
            # A user:pw that can't ride a curl config line would corrupt the
            # probe; OMIT the credential and warn (an auth-on store then 401s
            # loudly, the correct fail-safe) rather than send a broken config.
            try:
                cfg += f"user = {curl_config_quote(f'{user}:{pw}', 'obs credential')}\n"
            except CtlError as e:
                warn(f"obs probe sent WITHOUT auth — {e}")
    # --noproxy '*', matching the front-door probes: every store URL is host
    # loopback, but curl honors an ambient https_proxy/http_proxy — an
    # operator triaging from a proxied shell would otherwise get a wall of
    # false store-unreachable FAILs (and false vm-wedged pages that then arm
    # the throttle against the real thing).
    return runner.run(
        ["curl", "-sf", "--noproxy", "*", "-m", str(timeout), *(args or []), "-K", "-"],
        input_text=cfg, capture=True, quiet=True,
    )


def vm_scalar(runner: Runner, query: str) -> str:
    """Value of the first result of an instant PromQL query, or '' — the bash
    vm_scalar contract (callers compare against '1' etc.)."""
    port = runner.settings.get("VICTORIAMETRICS_PORT")
    cp = store_curl(
        runner, f"http://127.0.0.1:{port}/api/v1/query",
        args=["--data-urlencode", f"query={query}"],
    )
    body = cp.stdout if cp.returncode == 0 else ""
    if not body:
        return ""
    try:
        data = json.loads(body)
        result = data["data"]["result"]
        if result:
            return str(result[0]["value"][1])
    except (ValueError, KeyError, IndexError, TypeError):
        pass
    return ""


def vl_query(runner: Runner, logsql: str) -> Optional[str]:
    """Raw response body for a LogsQL query limited to one entry, or None if
    the store itself is unreachable. Non-empty body => at least one entry."""
    port = runner.settings.get("VICTORIALOGS_PORT")
    cp = store_curl(
        runner, f"http://127.0.0.1:{port}/select/logsql/query",
        args=["--data-urlencode", f"query={logsql}", "--data", "limit=1"],
    )
    if cp.returncode != 0:
        return None
    return cp.stdout or ""


def vl_count(runner: Runner, logsql: str) -> Optional[int]:
    """Count of entries matching a LogsQL filter (via `| stats count() as n`),
    or None when the store is unreachable / the response can't be parsed.
    Used for rate-style checks (WAF 5xx burst) the metric pipeline doesn't
    cover — podman/app state is not scraped into VictoriaMetrics."""
    port = runner.settings.get("VICTORIALOGS_PORT")
    cp = store_curl(
        runner, f"http://127.0.0.1:{port}/select/logsql/query",
        args=["--data-urlencode", f"query={logsql} | stats count() as n"],
    )
    if cp.returncode != 0:
        return None
    # VictoriaLogs streams one JSON object per line; the stats result carries
    # the "n" field. Be tolerant of an empty body (no matches => 0).
    body = (cp.stdout or "").strip()
    if not body:
        return 0
    try:
        for line in body.splitlines():
            obj = json.loads(line)
            if "n" in obj:
                return int(obj["n"])
    except (ValueError, KeyError, TypeError):
        return None
    return 0


def vmalert_firing(runner: Runner) -> Optional[List[Dict[str, Any]]]:
    """Firing alerts from vmalert's /api/v1/alerts. None when the response is
    missing or UNPARSEABLE — a malformed 200 must be distinguishable from a
    healthy empty alert list, or a corrupt response reads as 'no alerts
    firing' (the caller alerts on None; vmalert_reachable does NOT cover
    this case, since `curl -sf` passes any 2xx regardless of body)."""
    port = runner.settings.get("VMALERT_PORT", "8880")
    cp = store_curl(runner, f"http://127.0.0.1:{port}/api/v1/alerts")
    body = cp.stdout if cp.returncode == 0 else ""
    if not body:
        return None
    try:
        data = json.loads(body)
        alerts = data["data"]["alerts"]
        if not isinstance(alerts, list):
            return None
        return [a for a in alerts if isinstance(a, dict) and a.get("state") == "firing"]
    except (ValueError, KeyError, TypeError):
        return None


def vmalert_reachable(runner: Runner) -> bool:
    port = runner.settings.get("VMALERT_PORT", "8880")
    return store_curl(runner, f"http://127.0.0.1:{port}/api/v1/alerts").returncode == 0
