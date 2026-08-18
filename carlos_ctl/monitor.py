# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Health monitoring for the ``carlos-ctl monitor`` command.

The monitor relays metric-derived alerts from vmalert and performs local checks
that do not have metric equivalents, including backup freshness, certificate
expiry, container health, database liveness, and systemd unit state. Alerts are
throttled by stable condition keys and become immediately eligible again after
recovery.
"""

from __future__ import annotations

import contextlib
import os
import re
import time
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set

from . import alert as alert_mod
from . import obsquery
from .runner import Runner
from .util import CtlError, curl_config_quote, restic_local_path, warn


class MonitorRun:
    def __init__(self, runner: Runner) -> None:
        self.runner = runner
        self.s = runner.settings
        self.fail = False
        self.fired: Set[str] = set()
        self.state_dir = self.s.emr_home / "monitor" / "state"
        with contextlib.suppress(OSError):
            self.state_dir.mkdir(parents=True, exist_ok=True)
        self.remind_hours = self.s.get_int_or("ALERT_REMIND_HOURS", 24)

    def alert(self, msg: str, key: str = "", remind_hours: Optional[int] = None) -> None:
        """Dispatch a failed check, subject to per-condition throttling.

        A condition reported within its reminder window is written to the
        journal without another external notification. ``remind_hours`` can
        override the global interval for an individual condition.
        """
        self.fail = True
        # Print every failure for interactive invocations. Timer-driven runs
        # capture the same output in the system journal.
        import sys as _sys

        print(f"FAIL {msg}", file=_sys.stderr)
        window = self.remind_hours if remind_hours is None else remind_hours
        if key and self.state_dir.is_dir():
            self.fired.add(key)
            sf = self.state_dir / key
            if sf.is_file():
                age = time.time() - sf.stat().st_mtime
                if age < window * 3600:
                    throttled = f"still failing (delivery throttled): {msg}"
                    # have() first: a missing `logger` binary makes runner.ok
                    # raise FileNotFoundError, which would abort the whole sweep
                    # before the heartbeat. Fall back to stderr either way.
                    if not (self.runner.have("logger") and self.runner.ok(
                        ["logger", "-t", "carlos-monitor", "--", throttled]
                    )):
                        import sys

                        print(throttled, file=sys.stderr)
                    return
        delivered = alert_mod.dispatch(self.runner, "monitor", msg)
        if not delivered:
            warn(f"alert dispatch reported DELIVERY FAILURE for: {msg}")
        # Start the reminder window only for a page that actually WENT OUT —
        # a failed delivery must not be throttled as if it had been received,
        # or a webhook blip at first occurrence silences the condition for a
        # full ALERT_REMIND_HOURS. (Journal-only installs count as delivered
        # by choice.)
        if key and self.state_dir.is_dir() and delivered:
            with contextlib.suppress(OSError):
                (self.state_dir / key).touch()

    @contextlib.contextmanager
    def isolated(self, label: str) -> Iterator[None]:
        """Per-check isolation: a crash inside ONE check (unexpected podman
        output, OSError on a vanished path) must not abort the sweep — the
        remaining checks and the heartbeat at the end still run, and the
        crash itself pages. Without this, a crash between the first check
        and the heartbeat block would ALSO silence the dead-man's switch,
        stacking a monitor bug on top of whatever it was checking for."""
        try:
            yield
        except Exception as e:  # noqa: BLE001 — isolation boundary, reported below
            self.fail = True  # even if the alert below ALSO crashes
            with contextlib.suppress(Exception):
                self.alert(
                    f"monitor check '{label}' CRASHED ({type(e).__name__}: {e}) — "
                    f"the remaining checks still ran; fix the monitor",
                    f"monitor-check-crash-{label}",
                )

    def within_boot_grace(self) -> bool:
        """Boot grace: the pods are USER units this (system-timer-driven)
        monitor cannot order after, so liveness checks that fire while the
        stack is still starting after a reboot would page for a self-healing
        condition. Disk/cert/backup-freshness checks stay active (they are
        boot-independent)."""
        grace = self.s.get_int_or("BOOT_GRACE_SECONDS", 900)
        try:
            with open("/proc/uptime") as f:
                return float(f.read().split()[0]) < grace
        except (OSError, ValueError, IndexError):
            return False

    def recovery_sweep(self) -> None:
        """Any keyed condition OWNED BY THIS MONITOR that did NOT fire this run
        has recovered: clear its state file so the NEXT occurrence pages
        immediately instead of waiting out the reminder window. The
        `onfailure-*` stamps are NOT ours — they belong to `carlos-ctl alert`
        (the OnFailure= path) and are keyed differently from anything in
        `self.fired`, so sweeping them would delete a live throttle mid-outage
        and collapse alert's 24h window to the monitor interval. alert
        self-expires them by mtime, so skip them here."""
        if not self.state_dir.is_dir():
            return
        for sf in self.state_dir.iterdir():
            if sf.name.startswith("onfailure-"):
                continue
            if sf.name not in self.fired:
                with contextlib.suppress(OSError):
                    sf.unlink()


def _check_disk(m: MonitorRun) -> None:
    """Percent free on each tracked path's filesystem, deduped by mountpoint.
    Includes the rootless overlay store and the persistent journal — commonly
    on a DIFFERENT filesystem than EMR_HOME. (vmalert also watches
    node_filesystem_avail_bytes when the obs pod runs; this local check is
    the obs-independent floor and the only one when obs is disabled.)"""
    s = m.s
    graphroot = ""
    with contextlib.suppress(KeyError):
        import pwd

        graphroot = pwd.getpwnam(s.service_user).pw_dir + "/.local/share/containers"
    min_free = s.get_int_or("DISK_MIN_FREE", 10)
    seen: Set[str] = set()
    paths = [
        s.data_dir / "mariadb-mnt", s.data_dir / "mariadb-binlog",
        s.emr_home / "logs", s.emr_home / "backup", s.emr_home / "metrics",
    ]
    if graphroot:
        paths.append(Path(graphroot))
    paths.append(s.journal_dir)
    for p in paths:
        if not p.exists():
            continue
        # A statvfs that fails on an EXISTING path is itself a problem — a
        # full-disk check that silently skips the filesystem it cannot read
        # hides exactly the condition it exists to catch.
        try:
            st = os.statvfs(p)
        except OSError:
            m.alert(
                f"cannot read free space for {p} (statvfs failed) — the disk check cannot "
                f"cover this filesystem",
                f"df-fail-{str(p).replace('/', '_')}",
            )
            continue
        mount = _mountpoint_of(p)
        if mount in seen:
            continue
        seen.add(mount)
        # Match df's Use% denominator (used + avail, EXCLUDING the root
        # reserve) as the bash `100 - Use%` did — /f_blocks reads a few
        # points lower on ext4 and shifts the documented threshold semantics.
        used = st.f_blocks - st.f_bfree
        denom = st.f_bavail + used
        if denom <= 0:
            continue
        free_pct = int(100 * st.f_bavail / denom)
        if free_pct < min_free:
            m.alert(
                f"low disk: {free_pct}% free on {mount} (holds {p}; threshold "
                f"{min_free}%)",
                f"disk-{mount.replace('/', '_')}",
            )


def _mountpoint_of(path: Path) -> str:
    p = path.resolve()
    while not os.path.ismount(p) and p != p.parent:
        p = p.parent
    return str(p)


def _check_tls(m: MonitorRun) -> None:
    s, runner = m.s, m.runner
    if not runner.have("openssl"):
        # "cannot check" is NOT "healthy": without openssl BOTH cert-expiry
        # checks are dead — alert instead of silently unmonitoring TLS expiry.
        m.alert(
            "openssl not found on the monitor's PATH — TLS certificate expiry CANNOT be "
            "checked; treating as a fault, not health",
            "tool-missing-openssl",
        )
        return
    warn_days = s.get_int_or("CERT_EXPIRY_WARN_DAYS", 21)
    cert = s.conf_dir / "waf" / "certs" / "fullchain.pem"
    if cert.is_file():
        if not runner.ok(["openssl", "x509", "-checkend", str(warn_days * 86400),
                          "-noout", "-in", str(cert)]):
            if runner.ok(["openssl", "x509", "-checkend", "0", "-noout", "-in", str(cert)]):
                m.alert(f"TLS certificate expires within {warn_days} days ({cert})",
                        "cert-expiring")
            else:
                m.alert(f"TLS certificate has EXPIRED ({cert})", "cert-expired")
    elif (s.emr_home / "container" / ".deployed").is_file():
        # A DEPLOYED instance whose cert FILE has vanished (removed/unmounted
        # post-deploy) would otherwise slip BOTH expiry checks silently — the
        # timer is the only detector once past deploy (play/check cover
        # deploy-time only). The WAF keeps serving its in-memory cert until
        # restarted, so nothing else catches this.
        m.alert(
            f"TLS certificate file {cert} is MISSING on a deployed instance — expiry can "
            f"no longer be monitored, and the next WAF restart will fail to start. "
            f"Restore the cert+key.",
            "cert-file-missing",
        )
    # Also check the cert the WAF actually SERVES: a renewal that replaced the
    # file on disk but did not restart the pod reads healthy above while the
    # WAF keeps serving the OLD cert. Only alerts when the endpoint answers
    # with a cert (a down WAF is caught by the liveness sweep).
    bind_ip = s.get("BIND_IP")
    https_port = s.get("HTTPS_PORT")
    # List-argv pipeline, never a shell: BIND_IP/SERVER_NAME come from the
    # env file, and interpolating config values into `sh -c` would breach
    # the parse-don't-source boundary (runner contract: no shell=True).
    probe = ["openssl", "s_client",
             "-connect", f"{bind_ip}:{https_port}",
             "-servername", s.get("SERVER_NAME") or "localhost"]
    # timeout(1) is near-universal but not gated by have("openssl") — a
    # missing binary raising FileNotFoundError would kill the WHOLE sweep
    # (backup freshness, heartbeat), which is strictly worse than one
    # unbounded probe (s_client self-terminates on connect failure).
    if runner.have("timeout"):
        probe = ["timeout", "10", *probe]
    try:
        handshake = runner.run(probe, input_text="\n", capture=True)
    except OSError:
        return
    served = ""
    if handshake.stdout:
        x509 = runner.run(["openssl", "x509"],
                          input_text=handshake.stdout, capture=True)
        if x509.returncode == 0:
            served = x509.stdout or ""
    if served:
        cp = runner.run(
            ["openssl", "x509", "-checkend", str(warn_days * 86400), "-noout"],
            input_text=served, quiet=True,
        )
        if cp.returncode != 0:
            m.alert(
                f"TLS cert SERVED by the WAF ({bind_ip}:{https_port}) expires within "
                f"{warn_days} days — a renewal may have replaced the file without "
                f"restarting the pod (run 'carlos-ctl play')",
                "cert-served-expiring",
            )


def _check_liveness(m: MonitorRun) -> None:
    """Local container presence / unhealthy / crash-loop / DB-liveness sweep
    + the pod-unit is-active bridge. Cheap, local, and deliberately store-
    independent: it must still work while the obs pod is down."""
    s, runner = m.s, m.runner
    running: List[str] = []
    if runner.have("podman"):
        # rc-aware, not runner.output(): a failing `podman ps` (stale
        # XDG_RUNTIME_DIR, boltdb lock, runuser/service-user breakage) is
        # "the check could not run", NOT "every container is down" — the
        # rc-swallowing form fired a 12-message container-down storm with the
        # actual podman stderr discarded, arming 12 wrong throttle keys.
        # House rule: cannot-check is alerted AS A FAULT (one alert).
        cp = runner.run(
            runner.podman_user_argv(["ps", "--format", "{{.Names}}"]),
            capture=True,
        )
        if cp.returncode != 0:
            m.alert(
                f"container liveness sweep could not run: `podman ps` failed "
                f"(rc {cp.returncode}): {(cp.stderr or '').strip()[:300]} — container "
                f"state is UNKNOWN, not necessarily down; fix podman/the service user",
                "tool-failed-podman-ps",
            )
            _pod_unit_bridge(m)
            return
        running = (cp.stdout or "").splitlines()
        expected = [f"{s.app_pod}-db", f"{s.app_pod}-carlos", f"{s.app_pod}-drugref",
                    f"{s.waf_pod}-waf"]
        if s.obs_enabled:
            expected += [
                f"{s.app_pod}-mysqld-exporter", f"{s.app_pod}-vmagent",
                f"{s.obs_pod}-victorialogs", f"{s.obs_pod}-victoria-metrics",
                f"{s.obs_pod}-logcollect", f"{s.obs_pod}-logview",
                f"{s.obs_pod}-node-exporter", f"{s.obs_pod}-vmalert",
            ]
        for c in expected:
            if c not in running:
                m.alert(f"container not running: {c}", f"container-down-{c}")
        # RUNNING is not HEALTHY: a container failing its livenessProbe
        # restarts forever while staying LISTED in `podman ps`. Alert on
        # podman's own health verdict, and on a rising restart count (a
        # crash-loop between sweeps). RestartCount state lives OUTSIDE the
        # throttle state dir so the recovery sweep can't wipe the baseline.
        restarts_dir = s.emr_home / "monitor" / "restarts"
        with contextlib.suppress(OSError):
            restarts_dir.mkdir(parents=True, exist_ok=True)
        unhealthy = runner.output(runner.podman_user_argv(
            ["ps", "--filter", "health=unhealthy", "--format", "{{.Names}}"]
        )).splitlines()
        # Instance-scoped like the presence and restart-count checks: two
        # instances may share the SERVICE_USER (one rootless engine), and an
        # unscoped sweep would page THIS instance for the sibling's unhealthy
        # container — wrong-instance attribution plus duplicate pages from
        # both instances' monitors.
        own_prefixes = (f"{s.app_pod}-", f"{s.waf_pod}-", f"{s.obs_pod}-")
        for uc in unhealthy:
            if uc and uc.startswith(own_prefixes):
                m.alert(f"container UNHEALTHY (liveness probe failing): {uc}",
                        f"container-unhealthy-{uc}")
        rc_containers = [f"{s.app_pod}-db", f"{s.app_pod}-carlos",
                         f"{s.app_pod}-drugref", f"{s.waf_pod}-waf"]
        if s.obs_enabled:
            # The obs pod defines no livenessProbes, so the unhealthy filter
            # above can never match its containers — a flapping vmalert /
            # VictoriaMetrics that is merely UP at sweep time evaded detection
            # entirely. RestartCount is the only crash-loop signal for them.
            rc_containers += [
                f"{s.obs_pod}-victorialogs", f"{s.obs_pod}-victoria-metrics",
                f"{s.obs_pod}-vmalert", f"{s.obs_pod}-logcollect",
                f"{s.obs_pod}-logview", f"{s.obs_pod}-node-exporter",
                f"{s.app_pod}-vmagent", f"{s.app_pod}-mysqld-exporter",
            ]
        for rcc in rc_containers:
            if rcc not in running:
                continue
            # Id + RestartCount together: RestartCount alone is
            # blind to a crash-loop that manifests as whole-POD recreation —
            # fresh containers return at RestartCount=0, so the rising-count
            # compare never fires and the baseline was silently rewritten.
            # The Id tells recreation apart from restart-in-place.
            insp = runner.output(runner.podman_user_argv(
                ["inspect", rcc, "--format", "{{.Id}} {{.RestartCount}}"]
            )).strip()
            parts = insp.split()
            if len(parts) != 2 or not parts[0] or not parts[1].isdigit():
                # inspect failed/timed out for a RUNNING container: skipping
                # silently would hide a crash-loop for a full sweep interval
                # with no trace — leave a journal note (guarded + stderr
                # fallback: a missing logger must not crash the sweep).
                note = (f"monitor: could not read Id/RestartCount for running container "
                        f"{rcc} (inspect failed) — crash-loop detection skipped this "
                        f"sweep for it")
                if not (runner.have("logger") and runner.ok(
                        ["logger", "-t", "carlos-monitor", "--", note])):
                    import sys

                    print(note, file=sys.stderr)
                continue
            ctr_id, rc_now = parts
            # State file: `<id> <count> <recreate-streak>`. A pre-upgrade
            # single-field file (count only) is adopted as a same-id baseline
            # so the first post-upgrade sweep keeps the rising-count compare
            # instead of resetting it; missing/corrupt state re-baselines.
            state_file = restarts_dir / rcc
            try:
                fields = state_file.read_text().split()
            except OSError:
                fields = []
            if len(fields) == 3 and fields[1].isdigit() and fields[2].isdigit():
                prev_id, rc_prev, streak = fields[0], fields[1], int(fields[2])
            elif len(fields) == 1 and fields[0].isdigit():
                prev_id, rc_prev, streak = ctr_id, fields[0], 0
            else:
                prev_id, rc_prev, streak = ctr_id, rc_now, 0
            if prev_id == ctr_id:
                if int(rc_now) > int(rc_prev):
                    m.alert(
                        f"container crash-looping: {rcc} restarted "
                        f"{int(rc_now) - int(rc_prev)} time(s) since the last sweep",
                        f"container-restarting-{rcc}",
                    )
                # A stable id is the recovery signal for pod-level churn.
                streak = 0
            else:
                # Recreated since the last sweep. ONE recreation is normal
                # operations (`play`/`rebuild` replace the pod), so only
                # CONSECUTIVE-sweep recreations page — sweep count, not
                # wall-clock, because sweeps ARE the sampling cadence
                # (2 consecutive ≈ 30 min at the default 15-min timer). The
                # streak is deliberately NOT reset on alert: recovery is a
                # stable id (above), and the alert throttle dedupes an
                # ongoing incident.
                streak += 1
                if streak >= 2:
                    m.alert(
                        f"container repeatedly recreated: {rcc} came back as a new "
                        f"container on {streak} consecutive monitor sweeps — a "
                        f"pod-level crash-loop (or repeated redeploys; one play/"
                        f"rebuild never pages this)",
                        f"container-recreated-{rcc}",
                    )
            with contextlib.suppress(OSError):
                state_file.write_text(f"{ctr_id} {rc_now} {streak}\n")
        # Unexpected break-glass panel PRESENT: the pma container is on-demand
        # and TTL-bounded, so a lingering one means a dropped/forgotten
        # session left a PHP/Apache panel onto the full PHI database serving.
        # The presence checks above only catch EXPECTED containers being
        # absent — this is the inverse (an unexpected container present).
        pma_ctr = f"{s.instance}-pma-ondemand"
        if pma_ctr in running:
            m.alert(
                f"break-glass phpMyAdmin ({pma_ctr}) is RUNNING — an on-demand DB admin "
                f"panel onto the full PHI database is up. If this is not an active "
                f"session, a tunnel/client dropped and left it serving: stop it "
                f"(the --ttl bound should auto-remove it)",
                "pma-lingering",
            )
        # Authoritative DB liveness, INDEPENDENT of the metrics tier: if the
        # db container is up, confirm the server actually accepts connections
        # on 3306 (cred-free, mirrors the db liveness probe).
        if f"{s.app_pod}-db" in running:
            if not runner.ok(runner.podman_user_argv([
                "exec", f"{s.app_pod}-db", "bash", "-c",
                "exec 3<>/dev/tcp/127.0.0.1/3306",
            ])):
                m.alert(
                    f"MariaDB not accepting connections on 3306 ({s.app_pod}-db is running "
                    f"but the server is down)",
                    "db-not-accepting",
                )
    else:
        # "cannot check" is NOT "healthy" — without podman EVERY container/DB
        # liveness check above is dead; alert instead of reading green.
        m.alert(
            "podman not found on the monitor's PATH — container and DB liveness checks "
            "CANNOT run; treating as a fault, not health",
            "tool-missing-podman",
        )

    _pod_unit_bridge(m)


def _pod_unit_bridge(m: MonitorRun) -> None:
    """Pod-unit health bridge (replaces the quadlet OnFailure=, which a USER
    unit cannot route to the system alert template). A failed pod service —
    e.g. it died before its containers existed — is alerted here. Split out
    of _check_liveness so a failing `podman ps` (which aborts the container
    sweep) still gets the unit states checked."""
    s, runner = m.s, m.runner
    if runner.systemd_running():
        units = [f"{s.instance}.service", f"{s.waf_pod}.service"]
        if s.obs_enabled:
            units.insert(1, f"{s.obs_pod}.service")
        for u in units:
            # output_any_rc: is-active PRINTS 'failed' but exits 3 — the
            # rc-gated output() would blank it and this alert could never fire.
            state = runner.output_any_rc(runner.systemctl_user_argv(["is-active", u])).strip()
            # Keyed per-unit so a sustained failure pages once per reminder
            # window, not every sweep (avoids alert-fatigue muting).
            if state == "failed":
                m.alert(
                    f"pod unit {u} is in 'failed' state (service user '{s.service_user}')",
                    f"pod-unit-failed-{u}",
                )
    else:
        # Deliberately reports "no usable systemd", not "systemctl not found":
        # the binary is present on most such hosts (container images, WSL,
        # chroots) and only the manager is missing, so naming the tool sent
        # operators looking for a PATH problem that does not exist. The pods
        # legitimately run without units there (the documented `podman kube
        # play` fallback), but their unit-level health genuinely cannot be
        # read — the container-level sweep above is the substitute.
        m.alert("no usable systemd on this host — pod-unit health cannot be checked "
                "(the container liveness sweep still runs)", "tool-missing-systemctl")


def _check_front_door(m: MonitorRun) -> None:
    """End-to-end front-door probe on a DEPLOYED instance: client path ->
    nft redirect -> WAF TLS -> proxy -> Tomcat, exactly what a clinician's
    browser traverses. Two documented blind spots this closes:

      - a WAF stranded on a CACHED app-pod IP after an app-only crash-restart
        (nginx resolves BACKEND once at startup) serves 502 indefinitely
        while every container reads running and the heartbeat stays green;
      - a flushed/missing nft DNAT leaves external clients with nothing while
        on-host probes ride the OUTPUT hook and look healthy — hence the
        second, root-only leg asserting the prerouting table is loaded.

    Residual (documented): on-host probing cannot prove reachability beyond
    the host (upstream firewall/DNS) — pair HEARTBEAT_URL with an external
    HTTPS prober for that. -k on purpose: cert validity is _check_tls's
    jurisdiction (one condition, one alert), and the selfsigned TLS mode is
    a legitimate default posture."""
    s = m.s
    runner = m.runner
    if not (s.emr_home / "container" / ".deployed").is_file():
        return
    if not runner.have("curl"):
        m.alert("curl not found on the monitor's PATH — the front door cannot be "
                "probed", "tool-missing-curl")
        return
    bind_ip, https_port = s.get("BIND_IP"), s.get("HTTPS_PORT")
    server = s.get("SERVER_NAME") or "localhost"
    cp = runner.run(
        ["curl", "-ks", "--noproxy", "*", "-m", "10", "-o", "/dev/null",
         "-w", "%{http_code}",
         "--connect-to", f"{server}:{https_port}:{bind_ip}:{https_port}",
         f"https://{server}:{https_port}/"],
        capture=True, quiet=True,
    )
    code = (cp.stdout or "").strip()
    if code.startswith(("2", "3")):
        pass  # healthy
    elif code in ("502", "503", "504"):
        m.alert(
            f"front door serves HTTP {code}: the WAF answers but the backend does "
            f"not — the app is down, or the WAF cached a stale app-pod IP from "
            f"before an app-only restart (nginx resolves BACKEND once at startup); "
            f"'carlos-ctl play' restarts both in order",
            "front-door-502",
        )
    else:
        m.alert(
            f"NOTHING serves the front door https://{bind_ip}:{https_port}/ "
            f"(curl reported '{code or 'no response'}') — nft redirect flushed, WAF "
            f"pod down, or TLS broken; check systemctl status {s.instance}-nft "
            f"and the {s.waf_pod} pod",
            "front-door-down",
        )
    # Root-only second leg: the HTTP probe above traverses the OUTPUT-hook
    # DNAT, so a flushed PREROUTING chain (what external clients hit) can
    # hide behind a green probe. Suppressed under the hermetic harness
    # (CARLOS_SYSTEMD_DIR set), same as validate's foreign-nft check.
    import os as _os

    if (
        _os.geteuid() == 0
        and runner.have("nft")
        and not runner.settings._env.get("CARLOS_SYSTEMD_DIR")  # noqa: SLF001
    ):
        cp = runner.run(
            ["nft", "list", "table", "ip", f"{s.instance}-nat"],
            capture=True, quiet=True,
        )
        listing = cp.stdout or ""
        if (
            cp.returncode != 0
            or "prerouting" not in listing
            or f"dport {https_port}" not in listing
        ):
            m.alert(
                f"the front-door DNAT table ip {s.instance}-nat is not loaded (or lacks "
                f"its prerouting :{https_port} rule) — EXTERNAL clients cannot reach "
                f"the EMR even though on-host probes traverse the output hook and can "
                f"read healthy; systemctl restart {s.instance}-nft.service",
                "front-door-nat-missing",
            )


def _check_vmalert(m: MonitorRun) -> None:
    """Relay vmalert's continuously-evaluated rule state through the alert
    path. vmalert being unreachable while its container runs is itself a
    failure — a dead alerting engine must not read as 'no alerts'."""
    runner = m.runner
    s = m.s
    if not runner.have("curl"):
        m.alert(
            "curl not found on the monitor's PATH — the vmalert rule-state probe CANNOT "
            "run; treating as a fault, not health",
            "tool-missing-curl",
        )
        return
    running: List[str] = []
    if runner.have("podman"):
        running = runner.output(
            runner.podman_user_argv(["ps", "--format", "{{.Names}}"])
        ).splitlines()
    # A running-yet-wedged VictoriaMetrics must not silently turn ALL
    # metric-derived alerting off: vmalert stays perfectly reachable while
    # every rule evaluates against the dead datasource (absent() needs a
    # SUCCESSFUL query to fire), so /api/v1/alerts reads green. Probe the
    # store's own /health while its container is listed running.
    # (VictoriaLogs needs no twin probe: it is a vmagent scrape target, so a
    # wedged VL fires ScrapeTargetDown{job="victorialogs"} through vmalert.)
    if f"{s.obs_pod}-victoria-metrics" in running and obsquery.store_curl(
        runner, f"http://127.0.0.1:{s.get('VICTORIAMETRICS_PORT')}/health"
    ).returncode != 0:
        m.alert(
            f"VictoriaMetrics is RUNNING but /health is unreachable "
            f"(127.0.0.1:{s.get('VICTORIAMETRICS_PORT')}) — a wedged store means every "
            f"vmalert rule (mysql_up, scrape health, disk, log staleness) silently reads "
            f"green; restart the obs pod",
            "vm-wedged",
        )
    # Probe vmalert only while its container is LISTED running: a down
    # container already pages container-down-<obs>-vmalert from the liveness
    # sweep, and a second unreachable page here would be duplicate noise.
    if f"{s.obs_pod}-vmalert" not in running:
        return
    if not obsquery.vmalert_reachable(runner):
        m.alert(
            f"vmalert unreachable on 127.0.0.1:{s.get('VMALERT_PORT')} — metric-derived "
            f"alerting (mysql_up, scrape health, disk, log staleness) is NOT being "
            f"evaluated",
            "vmalert-unreachable",
        )
        return
    firing = obsquery.vmalert_firing(runner)
    if firing is None:
        m.alert(
            f"vmalert on 127.0.0.1:{s.get('VMALERT_PORT')} answered but its "
            f"/api/v1/alerts response could not be parsed — treating as a fault (a "
            f"corrupt response must not read as 'no alerts firing')",
            "vmalert-response-malformed",
        )
        return
    for a in firing:
        name = str(a.get("name", "unnamed-rule"))
        summary = ""
        annotations = a.get("annotations") or {}
        if isinstance(annotations, dict):
            summary = str(annotations.get("summary", "") or annotations.get("description", ""))
        value = a.get("value", "")
        detail = summary or f"rule '{name}' firing (value {value})"
        # Fold identifying labels into the throttle key: DiskLow fires per
        # MOUNTPOINT and ScrapeTargetDown per JOB — one shared key would
        # journal-throttle a NEW mountpoint filling up (or a second scrape
        # job dying) inside another instance's reminder window.
        labels = a.get("labels") or {}
        qualifier = ""
        if isinstance(labels, dict):
            qualifier = str(labels.get("mountpoint") or labels.get("job") or "")
        # The key becomes a STATE FILENAME: sanitize the whole thing (rule
        # names and label values come from a config file / exporters) and
        # bound its length, or an unlinkable/untouchable key silently
        # defeats the throttle and re-pages every sweep.
        key = f"vmalert-{name}" + (f"-{qualifier}" if qualifier else "")
        key = re.sub(r"[^A-Za-z0-9._-]", "_", key)[:200]
        m.alert(f"vmalert: {detail}", key)


def _check_waf_5xx(m: MonitorRun) -> None:
    """Detect sustained HTTP 5xx responses in the WAF access-log stream.

    The application liveness probe covers the login redirect but not
    authenticated routes, so it cannot detect every application failure. The
    companion stream-silence check distinguishes an idle error count from a
    broken logging pipeline. Update both queries when changing the WAF log
    format or stream labels.
    """
    s, runner = m.s, m.runner
    if not runner.have("curl"):
        return
    window = s.get_int_or("WAF_5XX_WINDOW_MIN", 10)
    threshold = s.get_int_or("WAF_5XX_MAX", 25)
    # Status sits right after the request's closing quote in the combined
    # log format: `... HTTP/1.x" 5xx ...`. Regex-match that position so a
    # 5-series byte count or a "500" in a URL doesn't false-trip.
    query = (
        f'_stream:{{stream="waf-access"}} _time:{window}m '
        f'~"HTTP/[0-9.]+\\" 5[0-9][0-9] "'
    )
    count = obsquery.vl_count(runner, query)
    if count is not None and count > threshold:
        m.alert(
            f"WAF served {count} HTTP 5xx responses in the last {window} min "
            f"(threshold {threshold}) — the app is up but erroring; check the "
            f"DB connection pool and recent deploys (liveness probes stay green while "
            f"/carlos/ still 302s)",
            "waf-5xx-burst",
        )
    # Require two consecutive empty windows. The first sweep after maintenance
    # may run before its front-door probe has reached VictoriaLogs; the next
    # sweep should contain that probe unless log shipping is unavailable.
    if (m.s.emr_home / "container" / ".deployed").is_file():
        total = obsquery.vl_count(runner, '_stream:{stream="waf-access"} _time:60m')
        strike = m.s.emr_home / "monitor" / "waf-stream-zero-strike"
        if total == 0:
            if strike.is_file():
                m.alert(
                    "the waf-access log stream produced ZERO lines across two "
                    "consecutive sweeps on a deployed instance — the monitor's own "
                    "front-door probes guarantee traffic, so 5xx surveillance is "
                    "BLIND: the WAF log format/stream label drifted or log shipping "
                    "is down; check vector + the nginx access log",
                    "waf-access-stream-silent",
                )
            else:
                with contextlib.suppress(OSError):
                    strike.parent.mkdir(parents=True, exist_ok=True)
                    strike.touch()
        elif total is not None:
            with contextlib.suppress(OSError):
                strike.unlink(missing_ok=True)


def _check_cert_restart_marker(m: MonitorRun) -> None:
    """Report certificate consumers that have not loaded a renewed certificate.

    The renewal command records failed consumer restarts in a marker file. The
    monitor continues reporting that marker until a restart succeeds.
    """
    from .tlsops import cert_restart_marker

    marker = cert_restart_marker(m.runner)
    if not marker.is_file():
        return
    try:
        units = " ".join(marker.read_text().split()) or "the cert consumers"
    except OSError:
        units = "the cert consumers"
    m.alert(
        f"a RENEWED certificate is installed on disk but {units} could not be "
        f"restarted — the front door still serves the OLD cert (self-concealing "
        f"until expiry). Restart by hand or wait for the next cert-renew run; the "
        f"marker {marker} clears when the restart succeeds",
        "cert-restart-needed",
    )


def _check_systemd_failed(m: MonitorRun) -> None:
    """Failed SYSTEM units for this instance: OnFailure= pages
    exactly once, at failure time — if the channel was down at that moment
    (or the failing unit IS the alert dispatcher), the failure sits invisible
    in `systemctl --failed` forever. Sweep the instance prefix so a
    persistently failed backup/binlog/docs/backup-verify/cert-renew/nft/
    guard oneshot — or a failed alert@ dispatch — keeps nagging until fixed.
    The secrets unit keeps its dedicated check (specific remediation text);
    the monitor's own unit is skipped (it is running this sweep)."""
    s, runner = m.s, m.runner
    if not runner.systemd_running():
        return
    out = runner.output_any_rc(
        ["systemctl", "--failed", "--plain", "--no-legend", f"{s.instance}-*"]
    )
    # Suffix ALLOWLIST, not a bare prefix match : instance
    # names may contain hyphens, so on a multi-instance host `clinic-*`
    # would also sweep up `clinic-a-backup.service` belonging to instance
    # `clinic-a` — duplicate pages with wrong-instance attribution, and the
    # sibling's secrets/monitor units nagged past their dedicated handling.
    own_suffixes = {
        "backup.service", "binlog.service", "docs.service",
        "backup-verify.service", "cert-renew.service", "nft.service",
        "guard.service",
    }
    prefix = f"{s.instance}-"
    for line in out.splitlines():
        fields = line.split()
        unit = fields[0] if fields else ""
        if not unit or not unit.startswith(prefix):
            continue
        suffix = unit[len(prefix):]
        if suffix not in own_suffixes and not suffix.startswith("alert@"):
            continue
        key = re.sub(r"[^A-Za-z0-9._-]", "_", f"failed-unit-{unit}")[:200]
        m.alert(
            f"systemd unit {unit} is in a FAILED state — its OnFailure page (if any) "
            f"fired once at failure time and nothing has re-alerted since; "
            f"systemctl status {unit}, fix the cause, then systemctl reset-failed {unit}",
            key,
        )


def _check_nft_hostfw(m: MonitorRun) -> None:
    """The inet <instance>-hostfw default-deny table: the nft
    apply unit is FAIL-OPEN — if all its retries fail, the pods still start
    with no host firewall loaded, and the only page was that unit's
    OnFailure. Re-verify the table is present and default-deny whenever the
    instance expects one (HOSTFW_ENABLED, rendered from
    carlos_host_firewall_enabled). Root-only, suppressed under the hermetic
    harness (CARLOS_SYSTEMD_DIR) — same conditions as the front-door NAT
    leg in _check_front_door."""
    s, runner = m.s, m.runner
    if s.get("HOSTFW_ENABLED", "0") != "1":
        return
    if (
        os.geteuid() != 0
        or not runner.have("nft")
        or runner.settings._env.get("CARLOS_SYSTEMD_DIR")  # noqa: SLF001
    ):
        return
    cp = runner.run(
        ["nft", "list", "table", "inet", f"{s.instance}-hostfw"],
        capture=True, quiet=True,
    )
    listing = cp.stdout or ""
    if cp.returncode != 0 or "policy drop" not in listing:
        m.alert(
            f"host firewall table inet {s.instance}-hostfw is not loaded (or lost its "
            f"default-deny 'policy drop') — the host is running FAIL-OPEN with no "
            f"default-deny firewall; systemctl restart {s.instance}-nft.service and "
            f"verify with 'nft list table inet {s.instance}-hostfw'",
            "hostfw-table-missing",
        )


def _check_db_isolation(m: MonitorRun) -> None:
    """Verify that the WAF cannot reach the application database port.

    This recurring check protects the split-pod isolation boundary and reuses
    the probe run by ``check``.
    """
    from .lifecycle2 import waf_db_isolation_broken

    s = m.s
    names = m.runner.output(m.runner.podman_user_argv(["ps", "--format", "{{.Names}}"]))
    if f"{s.waf_pod}-waf" not in names.splitlines():
        return  # waf down: the liveness/pod-unit checks own that condition
    broken = waf_db_isolation_broken(m.runner)
    if broken is True:
        m.alert(
            f"the waf container CAN reach {s.app_pod}:3306 — WAF/DB ISOLATION BROKEN: "
            f"the internet-facing edge pod has a network path to the PHI database. "
            f"Merge 'bind_address = 127.0.0.1' into the mariadb conf and re-play "
            f"('carlos-ctl check' shows the same probe)",
            "waf-db-isolation-broken",
        )
    elif broken is None:
        # Probe could not RUN while the waf is up (bash/timeout missing from
        # a rebased image, exec infrastructure error): "cannot check" is a
        # fault, not health — the boundary check would otherwise silently
        # stop probing forever (house rule, same as the missing-tool alerts).
        m.alert(
            f"the WAF->{s.app_pod}:3306 isolation probe could not RUN (podman exec "
            f"failed — bash/timeout missing from the waf image?) — the WAF/DB "
            f"boundary is UNVERIFIED until fixed",
            "waf-db-isolation-unverified",
        )


def cmd_monitor(runner: Runner) -> int:
    # Relay unexpected failures that occur outside the per-check isolation
    # boundary. The unit has no OnFailure handler because that would duplicate
    # alerts for ordinary check failures. Re-raise after dispatching so systemd
    # also records the monitor run as failed.
    try:
        return _run_monitor(runner)
    except Exception as e:  # noqa: BLE001 — last-resort crash relay
        with contextlib.suppress(Exception):
            alert_mod.dispatch(
                runner, "monitor",
                f"the monitor sweep CRASHED before completing "
                f"({type(e).__name__}: {e}) — on-host alerting is DOWN until fixed",
            )
        raise


def _run_monitor(runner: Runner) -> int:
    s = runner.settings
    m = MonitorRun(runner)

    # Every check group runs inside m.isolated(): one crash pages and moves
    # on instead of skipping the rest of the sweep and the heartbeat.
    with m.isolated("disk"):
        _check_disk(m)
    with m.isolated("tls"):
        _check_tls(m)
    with m.isolated("cert-restart"):
        _check_cert_restart_marker(m)

    in_grace = m.within_boot_grace()
    if in_grace:
        # have() guard: a missing `logger` binary would raise FileNotFoundError
        # here and abort the sweep BEFORE the heartbeat block below — the
        # watchdog must never be the thing that hangs (or crashes) the sweep.
        if runner.have("logger"):
            runner.run(
                ["logger", "-t", "carlos-monitor",
                 f"within boot grace ({s.get('BOOT_GRACE_SECONDS', '900')}s after boot) — "
                 f"skipping container/pod/DB liveness checks"],
                quiet=True,
            )
    else:
        with m.isolated("liveness"):
            _check_liveness(m)
        with m.isolated("front-door"):
            _check_front_door(m)
        with m.isolated("db-isolation"):
            _check_db_isolation(m)
        if s.obs_enabled:
            with m.isolated("vmalert"):
                _check_vmalert(m)
            with m.isolated("waf-5xx"):
                _check_waf_5xx(m)

    # App still on DB ROOT: least-privilege provisioning is best-effort at
    # play (a slow DB or a missing root password degrades to a warning), so
    # an internet-facing app can keep running with GRANT ALL. Only the manual
    # `check` verb noticed before — surface it as a recurring page.
    with m.isolated("app-db-root"):
        if s.properties_file.is_file():
            from .util import first_match

            try:
                # errors="replace": a non-UTF-8 byte in the (ansible-rendered)
                # file must not raise UnicodeDecodeError (a ValueError, NOT an
                # OSError) and abort the whole monitor sweep.
                db_user = first_match(
                    s.properties_file.read_text(errors="replace").splitlines(),
                    "db_username",
                )
            except OSError:
                db_user = None
            if db_user == "root":
                m.alert(
                    f"app connects to MariaDB as ROOT (db_username=root in "
                    f"{s.properties_file.name}) — an app-layer compromise would own the "
                    f"whole PHI database; run 'carlos-ctl db-users' to switch to "
                    f"least-privilege accounts",
                    "app-db-root",
                )

    # Sealed-secrets render health: a failed unseal (TPM/Secure-Boot change)
    # leaves the app on the __SEALED__ placeholder password; catch it here
    # (the app container is up so liveness reads green). No-op on non-sealed
    # installs (unit absent -> is-failed is false).
    with m.isolated("secrets-unit"):
        if runner.systemd_running() and runner.ok(
            ["systemctl", "is-failed", f"{s.instance}-secrets.service"]
        ):
            m.alert(
                f"secrets unit {s.instance}-secrets.service is FAILED — sealed app "
                f"credentials did not render; the app may be authenticating with the "
                f"__SEALED__ placeholder",
                "secrets-unit-failed",
            )

    # JVM heap dump present (an OOM occurred; large plaintext PHI on disk).
    # .jfr recordings are NOT alerted: the flight recorder runs always-on with
    # dumponexit, so a .jfr is a NORMAL artifact.
    with m.isolated("heap-dump"):
        logs_dir = s.emr_home / "logs"
        if logs_dir.is_dir() and (
            any(logs_dir.glob("*.hprof")) or any(logs_dir.glob("*/*.hprof"))
        ):
            m.alert(
                f"JVM heap dump present under {logs_dir} — an OOM occurred and left a "
                f"large plaintext memory image (PHI); analyze and delete",
                "heap-dump-present",
            )

    # Backup freshness: the backup verb writes these stamps on each successful
    # run, so a silently-stopped timer / failing backup surfaces here even
    # though OnFailure= only covers runs that actually execute and exit
    # nonzero. A MISSING stamp is itself an alert: backups that never ran must
    # not read green (or ping the dead-man's switch healthy).
    with m.isolated("failed-units"):
        _check_systemd_failed(m)
    with m.isolated("hostfw"):
        _check_nft_hostfw(m)
    with m.isolated("backup-freshness"):
        _check_backup_freshness(m)
    with m.isolated("repo-posture"):
        _check_repo_posture(m)
    with m.isolated("build-posture"):
        _check_build_posture(m)
    with m.isolated("guard-marker"):
        _check_accept_marker(m)
    with m.isolated("channel-config"):
        _check_channel_config(m)

    with m.isolated("recovery-sweep"):
        m.recovery_sweep()

    # Off-host dead-man's-switch: ping ONLY when every check passed; the
    # external service alerts when the expected ping stops arriving. /fail on
    # failure actively signals a detected problem. The heartbeat URL (a
    # capability URL) travels via `curl -K -` config on stdin, NOT argv.
    heartbeat = s.get("HEARTBEAT_URL")
    if heartbeat and runner.have("curl"):
        if not m.fail and in_grace:
            # A healthy ping semantically asserts "monitored AND healthy" —
            # during boot grace the liveness checks were SKIPPED, so nothing
            # verified the pods. Withhold the healthy ping (a /fail on a real
            # failure above still goes out); the external service's own
            # missed-ping window absorbs the one skipped tick. have() guard
            # like every other logger call: a host without `logger` must not
            # crash the sweep tail.
            if runner.have("logger"):
                runner.run(["logger", "-t", "carlos-monitor",
                            "boot grace — healthy heartbeat ping withheld (liveness "
                            "was not checked this run)"], quiet=True)
        else:
            url = heartbeat if not m.fail else heartbeat.rstrip("/") + "/fail"
            try:
                cfg = f"url = {curl_config_quote(url, 'HEARTBEAT_URL')}\n"
            except CtlError as e:
                # A HEARTBEAT_URL that can't ride a curl config line can't be
                # pinged — skip it and warn; the external service's own
                # missed-ping alarm then fires (fail-safe: the dead-man switch
                # trips off-box rather than us sending a corrupt config).
                warn(f"HEARTBEAT_URL not pinged — {e}")
            else:
                runner.run(["curl", "-fsS", "-m", "10", "--retry", "2", "-K", "-"],
                           input_text=cfg, quiet=True)

    if not m.fail:
        print("==> monitor: all checks OK")
        return 0
    return 1


def _check_backup_freshness(m: MonitorRun) -> None:
    """Backup freshness: the backup verb writes these stamps on each
    successful run, so a silently-stopped timer / failing backup surfaces
    here even though OnFailure= only covers runs that actually execute and
    exit nonzero. A MISSING stamp is itself an alert: backups that never ran
    must not read green (or ping the dead-man's switch healthy)."""
    s = m.s
    now = time.time()
    thresholds = {
        ".last-full-ok": (s.get_int_or("BACKUP_MAX_AGE_HOURS", 26) * 3600, "full db"),
        ".last-binlog-ok": (s.get_int_or("BINLOG_MAX_AGE_MIN", 35) * 60, "binlog"),
        ".last-docs-ok": (s.get_int_or("DOCS_MAX_AGE_MIN", 35) * 60, "documents"),
        # The weekly drill: 8 days = one full cycle + a day of margin. A drill
        # that runs and fails pages via OnFailure; this stamp catches the
        # drill that silently STOPS RUNNING (timer disabled, unit removed) —
        # otherwise operators believe backups are verified-restorable while
        # nothing has checked in months.
        ".last-verify-ok": (s.get_int_or("VERIFY_MAX_AGE_HOURS", 192) * 3600,
                            "restore drill"),
    }
    for stamp, (max_age, label) in thresholds.items():
        f = s.emr_home / "backup" / stamp
        key_label = label.replace(" ", "_")
        if not f.is_file():
            m.alert(
                f"{label} backup has NO success stamp ({f}) — backups may have NEVER run "
                f"on this host (timers not started, or $EMR_HOME/backup replaced); run "
                f"'carlos-ctl play' to seed the baseline and 'carlos-ctl backup' to verify",
                f"backup-stamp-missing-{key_label}",
            )
            continue
        try:
            mtime = f.stat().st_mtime
        except OSError:
            # The stamp vanished between the check and here (dir replaced/
            # unmounted mid-run) — alert instead of a wrong age computation.
            m.alert(
                f"{label} backup stamp {f} became unreadable mid-check (backup dir "
                f"removed/unmounted?)",
                f"backup-stamp-unreadable-{key_label}",
            )
            continue
        age = now - mtime
        if age > max_age:
            m.alert(
                f"{label} backup is STALE: last success {int(age / 60)} min ago "
                f"(threshold {int(max_age / 60)} min) — timer stopped or backups failing?",
                f"backup-stale-{key_label}",
            )

def _check_repo_posture(m: MonitorRun) -> None:
    """Local-only restic repository (DR posture): a backup that lives on the
    machine it protects is not disaster recovery. Unsealed installs: read
    (never execute — service-user-owned) RESTIC_REPOSITORY from the
    plaintext restic.env. SEALED installs (restic.env shredded): read the
    non-secret .repo-posture marker every backup run refreshes — without it
    a sealed local-only install had no recurring DR alarm at all."""
    s = m.s
    # flag(), not == "1": play's gate accepts true/yes/on for the same ack —
    # a spelling mismatch here would page every sweep about a posture the
    # operator already deliberately accepted at go-live.
    if not s.flag("CARLOS_ACCEPT_LOCAL_REPO"):
        restic_env = s.conf_dir / "restic" / "restic.env"
        local_repo = ""
        if restic_env.is_file():
            from .util import first_match

            repo = first_match(restic_env.read_text().splitlines(),
                               "RESTIC_REPOSITORY") or ""
            if restic_local_path(repo):
                local_repo = repo
        else:
            posture = s.emr_home / "backup" / ".repo-posture"
            try:
                if posture.is_file() and posture.read_text().strip() == "local":
                    local_repo = "sealed install; posture marker says local"
            except OSError:
                pass
        if local_repo:
            m.alert(
                f"backups are LOCAL-ONLY ({local_repo}) — a disk failure/ransomware/fire "
                f"takes the EMR and its backups together; set an OFFSITE "
                f"RESTIC_REPOSITORY (s3:/rest:/sftp:/b2:) or CARLOS_ACCEPT_LOCAL_REPO=1 "
                f"to accept the risk",
                "restic-repo-local",
            )

def _check_build_posture(m: MonitorRun) -> None:
    """Recurring supply-chain nag on a DEPLOYED instance: build and play both
    warn when the images were dev-mode built (moving source ref, no tarball
    checksum), but those are one-shot lines that scroll away — a production
    PHI instance quietly running unpinned images for months is drift, not a
    choice. CARLOS_ACCEPT_UNPINNED_BUILD=1 is the deliberate ack (mirrors
    CARLOS_ACCEPT_LOCAL_REPO)."""
    s = m.s
    if not (s.emr_home / "container" / ".deployed").is_file():
        return
    if s.flag("CARLOS_ACCEPT_UNPINNED_BUILD"):
        return
    mode_file = s.emr_home / "build" / ".build-mode"
    try:
        dev_built = mode_file.is_file() and mode_file.read_text().strip() != "release"
    except OSError:
        return
    if dev_built:
        # Wording matches lifecycle2's play warning: dev-mode means "not
        # release-gated", not necessarily "no checksum" — the auto default may
        # deploy a sha256-verified release WAR, but only the release gate pins
        # every source (incl. the DrugRef compile) and the dependency lock.
        m.alert(
            "the deployed images were NOT built under CARLOS_BUILD_MODE=release — "
            "rebuild with it (pinned 40-hex refs + content checksums) for an audited "
            "production image, or set CARLOS_ACCEPT_UNPINNED_BUILD=1 to accept the "
            "posture",
            "build-unpinned",
        )

def _check_accept_marker(m: MonitorRun) -> None:
    """A surviving accept-empty-datadir marker is a STANDING acceptance of
    blank-database initialization: the in-pod db-init keys on it, so as long
    as it exists an unmounted data volume at reboot initializes a BLANK
    database without refusal. It is meant to live only from an accept-play
    to the next normal play — nag until it is consumed."""
    s = m.s
    accept_marker = s.emr_home / "container" / "guard" / "accept-empty-datadir"
    if accept_marker.is_file():
        m.alert(
            f"accept-empty-datadir marker present ({accept_marker}) — the blank-datadir "
            f"guard is DISARMED until a normal 'carlos-ctl play' clears it; if the "
            f"accepted fresh datadir is up, re-run play now",
            "accept-empty-marker-present",
        )

def _check_channel_config(m: MonitorRun) -> None:
    """Alerting-config drift on a DEPLOYED instance. play gates go-live on
    both of these, but carlos-app.env can be edited (or restored from a DR
    copy that strips URLs) AFTER go-live without another play — this is the
    recurring nag that catches that drift."""
    s = m.s
    if not (s.emr_home / "container" / ".deployed").is_file():
        return
    # Off-host dead-man's-switch is MANDATORY once deployed: every check in
    # this sweep runs ON the box, so a total host/monitor death produces no
    # on-host alert — only the external heartbeat catches that.
    if not s.get("HEARTBEAT_URL"):
        if not s.flag("CARLOS_NO_HEARTBEAT"):
            # CARLOS_NO_HEARTBEAT=1 is the same deliberate ack play's go-live
            # gate honors (require_heartbeat) — without it this would nag every
            # reminder window forever on an instance whose operator consciously
            # accepted the blind spot, training them to mute the channel.
            # Mirrors the ALERT_JOURNAL_ONLY handling below.
            m.alert(
                "HEARTBEAT_URL is not set on a DEPLOYED instance — the off-host "
                "dead-man's-switch is DISABLED, so a total host or monitor failure "
                "would go undetected. Set HEARTBEAT_URL (e.g. a healthchecks.io ping "
                "URL) in carlos-app.env and restart the monitor timer, or set "
                "CARLOS_NO_HEARTBEAT=1 to accept the blind spot.",
                "heartbeat-unset",
            )
        else:
            # Acked blind spot: the ack silences the daily nag,
            # but a PHI instance whose total-failure mode is SILENT should not
            # fade from memory entirely. Remind WEEKLY via a NON-FAILING
            # advisory dispatch — the accepted posture must not flip the sweep
            # to exit 1 every 15 minutes (that would mark the monitor unit
            # failed and /fail the heartbeat of an otherwise-healthy stack),
            # it just needs to resurface the decision periodically.
            key = "no-heartbeat-configured"
            m.fired.add(key)  # keeps recovery_sweep from resetting the window
            sf = m.state_dir / key
            due = True
            with contextlib.suppress(OSError):
                due = (not sf.is_file()
                       or time.time() - sf.stat().st_mtime >= 168 * 3600)
            if due and alert_mod.dispatch(
                m.runner, "monitor",
                "reminder (weekly): CARLOS_NO_HEARTBEAT=1 — this DEPLOYED instance "
                "runs with NO off-host dead-man's switch, so a total host or monitor "
                "death goes UNDETECTED. Set HEARTBEAT_URL in carlos-app.env to close "
                "the blind spot.",
            ):
                with contextlib.suppress(OSError):
                    sf.touch()
    # No delivery channel at all: every alert this sweep raises would land in
    # the journal nobody watches. ALERT_JOURNAL_ONLY=1 is the deliberate ack
    # (same contract as play's go-live gate); without it, empty channels on a
    # deployed instance are drift, not a choice. This alert itself is
    # journal-only by construction — the heartbeat /fail ping (or the
    # external missed-ping alarm) is what carries it off-box.
    # flag(), not == "1": play/check_alert_channel accept true/yes/on for this
    # ack — a spelling mismatch here would fail the sweep (and ping the
    # heartbeat /fail) every 15 minutes forever on a compliant install.
    if (
        not s.get("ALERT_WEBHOOK")
        and not s.get("ALERT_EMAIL")
        and not s.flag("ALERT_JOURNAL_ONLY")
    ):
        m.alert(
            "no alert channel is configured on a DEPLOYED instance (ALERT_WEBHOOK and "
            "ALERT_EMAIL both empty, no ALERT_JOURNAL_ONLY=1 ack) — alerts only reach "
            "the local journal; set a channel in carlos-app.env",
            "alert-channel-unset",
        )


# Keep a reference for the vmalert integration test (imported there).
FIRING_KEY_PREFIX: Dict[str, str] = {"vmalert": "vmalert-"}
