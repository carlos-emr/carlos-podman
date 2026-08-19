# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Pod lifecycle commands and go-live validation gates.

This module contains mutating lifecycle operations such as ``play``, ``down``,
``enable``, and ``check``. Read-only status operations live in
:mod:`carlos_ctl.lifecycle`, while image lifecycle operations live in
:mod:`carlos_ctl.build`. Ansible renders deployment artifacts; these commands
validate and apply those artifacts at runtime.
"""

from __future__ import annotations

import contextlib
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import validate
from .runner import Runner
from .util import CtlError, chown_to_service_user, log, restic_local_path, warn

_JINJA_MARKER = re.compile(r"\{\{|\{%")


def require_alert_channel(runner: Runner) -> None:
    """Hard gate for go-live: a stock install whose alerts go only to the
    journal pages NOBODY — every backup/disk/cert/liveness alert lands where
    nothing reads it, and DR quietly rots. Refuse until a channel exists or
    journal-only is explicitly acknowledged.

    SCOPE: this and the other go-live gates (require_heartbeat,
    preflight_db_root_guard, db_isolation_gate) run in `play` ONLY. A reboot or
    `systemctl --user start` autostarts the pods via the quadlet, bypassing all
    of them — only the blank-datadir guard has a boot-time counterpart
    (carlos-guard.service). The residual is narrow: db-root/isolation are baked
    into carlos.properties/zz-carlos.cnf and don't drift, and alert/heartbeat
    are set-once posture. The monitor's channel/heartbeat checks are the
    running-state backstop that catches a posture that drifted post-deploy."""
    s = runner.settings
    if not s.get("ALERT_WEBHOOK") and not s.get("ALERT_EMAIL") and not s.flag("ALERT_JOURNAL_ONLY"):
        raise CtlError(
            f"no ALERT_WEBHOOK or ALERT_EMAIL set — refusing go-live: every backup/monitor/"
            f"disk/cert alert would go to the JOURNAL ONLY, where nothing pages a human. Set "
            f"one in {s.env_file} (then prove delivery with 'carlos-ctl alert-test'), or set "
            f"ALERT_JOURNAL_ONLY=1 to explicitly accept journal-only alerting."
        )


def require_heartbeat(runner: Runner) -> None:
    """All on-host alerting fails silent if the WHOLE host (or the monitor
    timer) dies — only an off-host dead-man's switch catches that. Refuse
    go-live without a HEARTBEAT_URL unless the operator explicitly accepts
    the blind spot."""
    s = runner.settings
    if not s.get("HEARTBEAT_URL") and not s.flag("CARLOS_NO_HEARTBEAT"):
        raise CtlError(
            f"HEARTBEAT_URL unset — no off-host dead-man's switch: if this host (or the "
            f"monitor timer) dies outright, NOTHING external notices. Point it at a "
            f"healthchecks-style ping URL in {s.env_file}, or set CARLOS_NO_HEARTBEAT=1 to "
            f"explicitly accept no external liveness signal. That ack means choosing to "
            f"run a PHI system whose total-failure mode is SILENT — the monitor will "
            f"remind you weekly until a heartbeat is configured."
        )


def require_dr_posture(runner: Runner) -> None:
    """FIRST-go-live gate (mirrors require_heartbeat): a local-path restic
    repository dies with the host it protects — disk failure, ransomware, or
    fire takes the EMR and its only backups together. The monitor nags about
    it forever, but go-live is the one moment the operator is certainly
    present — refuse until the repo is offsite or the posture is explicitly
    accepted (CARLOS_ACCEPT_LOCAL_REPO=1, the same ack the nag honors).
    Already-deployed instances are never blocked (emergency re-plays must
    not depend on backup posture)."""
    s = runner.settings
    if (s.emr_home / "container" / ".deployed").is_file():
        return
    if s.flag("CARLOS_ACCEPT_LOCAL_REPO"):
        return
    restic_env = s.conf_dir / "restic" / "restic.env"
    if not restic_env.is_file():
        return  # sealed/unprovisioned — the monitor's posture nag covers it
    from .util import first_match

    repo = first_match(restic_env.read_text().splitlines(), "RESTIC_REPOSITORY") or ""
    # restic_local_path, not startswith("/"): `local:` / relative spellings
    # are the same host and must not bypass the go-live DR refusal.
    if restic_local_path(repo):
        raise CtlError(
            f"RESTIC_REPOSITORY is a LOCAL path ({repo}) — refusing first go-live: a "
            f"backup on the machine it protects is not disaster recovery (fire/"
            f"ransomware/disk death takes both). Point it at an offsite backend "
            f"(s3:/rest:/sftp:/b2:) in {restic_env}, or set CARLOS_ACCEPT_LOCAL_REPO=1 "
            f"to accept the posture explicitly (the monitor keeps nagging)."
        )


def preflight_db_root_guard(runner: Runner) -> None:
    """Refuse to deploy the app on the MariaDB root account unless
    auto-provisioning can fix it right after start (password available) or
    the operator explicitly accepts root (CARLOS_ALLOW_DB_ROOT=1). Runs
    BEFORE the pods start so the app never comes up as root only to be left
    that way by a silent downgrade. Provisioned installs (db_username !=
    root) are never blocked — an emergency restart must not depend on the
    root password being present."""
    s = runner.settings
    if not s.properties_file.is_file():
        return
    from .config import warn_if_persisted_oneshot

    warn_if_persisted_oneshot(
        s, "CARLOS_ALLOW_DB_ROOT",
        "this override is meant to be a ONE-SHOT shell prefix "
        "('CARLOS_ALLOW_DB_ROOT=1 carlos-ctl play'); remove the line or the app can "
        "silently keep deploying as MariaDB root",
    )
    from .util import first_match

    # DrugRef runs against its OWN database on the same MariaDB with a separate
    # account (db_user in drugref2.properties). It is a lesser exposure than the
    # app-as-root (the drugref schema holds no PHI), so this WARNS rather than
    # refusing — but a root drugref account is still an unnecessary blast radius
    # on the PHI server and must not pass unremarked.
    if s.drugref_properties_file.is_file():
        drugref_user = first_match(
            s.drugref_properties_file.read_text().splitlines(), "db_user"
        )
        if drugref_user == "root":
            warn(
                "DrugRef is configured as MariaDB ROOT (db_user=root in "
                "drugref2.properties) — give it a least-privilege account scoped to the "
                "drugref database instead; a root drugref account can reach the PHI schema"
            )

    username = first_match(s.properties_file.read_text().splitlines(), "db_username")
    if username != "root":
        return
    if s.get("CARLOS_DB_ROOT_PASSWORD"):
        return  # auto-provisioning runs post-start
    if s.get("CARLOS_ALLOW_DB_ROOT", "0") == "1":
        warn(
            "CARLOS_ALLOW_DB_ROOT=1 — deploying with the app as MariaDB ROOT "
            "(least-privilege provisioning skipped)"
        )
        return
    raise CtlError(
        f"app is configured as MariaDB ROOT (db_username=root in carlos.properties) and "
        f"CARLOS_DB_ROOT_PASSWORD is unset — refusing to deploy on the root account. Set "
        f"CARLOS_DB_ROOT_PASSWORD in {s.env_file} (play then auto-provisions least-privilege "
        f"accounts), or set CARLOS_ALLOW_DB_ROOT=1 to override once."
    )


def datadir_guard(runner: Runner) -> None:
    """Datadir-signature guard. An initialized MariaDB datadir ALWAYS holds a
    `mysql/` system-schema dir. So a DEPLOYED instance (.deployed) whose
    datadir lacks it means the data volume is unmounted or wiped — the
    `type: Directory` volume passes because provisioning pre-created the empty
    mountpoint dir, and MariaDB would initialize a BLANK database over it with
    no error anywhere. Refuse. (A genuine first install has no .deployed yet,
    so an empty datadir there is expected and allowed;
    CARLOS_ACCEPT_EMPTY_DATADIR=1 forces a fresh datadir on purpose.)"""
    from .config import warn_if_persisted_oneshot
    from .guard import datadir_initialized

    s = runner.settings
    warn_if_persisted_oneshot(
        s, "CARLOS_ACCEPT_EMPTY_DATADIR",
        "this override is meant to be a ONE-SHOT shell prefix "
        "('CARLOS_ACCEPT_EMPTY_DATADIR=1 carlos-ctl play'); remove the line or a future "
        "unmounted/wiped datadir will silently initialize a BLANK database",
    )
    deployed = (s.emr_home / "container" / ".deployed").is_file()
    if deployed and not s.flag("CARLOS_ACCEPT_EMPTY_DATADIR") \
            and not datadir_initialized(s.data_dir):
        raise CtlError(
            f"deployed instance but {s.data_dir}/mariadb-mnt holds no initialized MariaDB "
            f"datadir (no mysql/ system schema) — the data volume is unmounted or wiped, and "
            f"starting now would initialize a BLANK database. Mount the data volume, or set "
            f"CARLOS_ACCEPT_EMPTY_DATADIR=1 to accept a fresh datadir on purpose."
        )
    # Sync the reboot guard's accept-empty-datadir marker to THIS play's
    # intent so the boot-time guard unit and the in-pod db-init refusal (both
    # of which cannot read this shell's env) agree with the play-time decision.
    # BOTH sync failures are fatal: an unwritable marker silently discards the
    # operator's acceptance, and an UNCLEARABLE stale marker is worse — it
    # would let a future unmounted/empty datadir initialize a BLANK database
    # at the next reboot (the in-pod stop keys on this marker). The dangerous
    # direction must fail closed, not `except OSError: pass`.
    guard_dir = s.emr_home / "container" / "guard"
    marker = guard_dir / "accept-empty-datadir"
    if s.flag("CARLOS_ACCEPT_EMPTY_DATADIR"):
        try:
            guard_dir.mkdir(parents=True, exist_ok=True)
            marker.touch()
            # 0644 for the same rootless-restic-readability reason as the
            # .deployed markers (see start_instance_timers).
            marker.chmod(0o644)
        except OSError as e:
            raise CtlError(
                f"could not write the accept-empty-datadir marker ({marker}): {e} — the "
                f"in-pod guard would refuse the empty datadir this play just accepted; "
                f"fix the filesystem and re-run"
            ) from None
    else:
        try:
            marker.unlink(missing_ok=True)
        except OSError as e:
            raise CtlError(
                f"could not CLEAR a stale accept-empty-datadir marker ({marker}): {e} — a "
                f"surviving marker lets a future empty/unmounted datadir initialize a "
                f"BLANK database at reboot; remove it by hand, then re-run play"
            ) from None


def db_isolation_gate(runner: Runner) -> None:
    """WAF/DB isolation hard gate: without `bind_address = 127.0.0.1` in the
    MariaDB cnf the server listens on all interfaces, so the WAF pod (which
    shares the edge network) can reach MariaDB directly, bypassing the app.
    Require a LOOPBACK bind, not merely the presence of a bind_address line —
    a carried-over 'bind_address = 0.0.0.0' would satisfy a presence-only
    check while still exposing MariaDB. (Tolerates the 'bind-address' hyphen
    spelling MariaDB also accepts.)"""
    s = runner.settings
    cnf = s.conf_dir / "mariadb" / "zz-carlos.cnf"
    if not cnf.is_file():
        # Absent cnf is NOT a pass: with no drop-in at all MariaDB binds every
        # interface, which is exactly the exposure this gate exists to refuse.
        # The role installs the file on every run, so its absence means broken
        # provisioning — fail closed with the same override as below.
        if s.get("CARLOS_ALLOW_DB_EXPOSED", "0") == "1":
            warn(
                f"CARLOS_ALLOW_DB_EXPOSED=1 — deploying WITHOUT {cnf}; MariaDB has no "
                f"loopback bind_address drop-in and may be reachable from the edge "
                f"network (WAF pod)"
            )
            return
        raise CtlError(
            f"{cnf} is missing — without it MariaDB has no loopback bind_address and "
            f"listens on ALL interfaces (the WAF pod could reach it over the edge "
            f"network). Re-run the provisioning playbook (it installs the cnf), or set "
            f"CARLOS_ALLOW_DB_EXPOSED=1 to deploy anyway."
        )
    # LAST directive wins, exactly as MariaDB reads option files: a cnf with a
    # loopback bind_address followed by 0.0.0.0 listens on ALL interfaces —
    # any() over the lines passed that as isolated. skip-networking (no TCP
    # at all) also satisfies the isolation contract.
    loopback_pat = re.compile(
        r"^\s*bind[_-]address\s*=\s*(127\.0\.0\.1|::1|localhost)(\s|$)"
    )
    any_bind_pat = re.compile(r"^\s*bind[_-]address\s*=")
    skip_net_pat = re.compile(r"^\s*skip[_-]networking\b")
    isolated = False
    for line in cnf.read_text().splitlines():
        if loopback_pat.match(line):
            isolated = True
        elif any_bind_pat.match(line):
            isolated = False  # a later non-loopback bind overrides
        elif skip_net_pat.match(line):
            isolated = True
    if isolated:
        return
    if s.get("CARLOS_ALLOW_DB_EXPOSED", "0") == "1":
        warn(
            "CARLOS_ALLOW_DB_EXPOSED=1 — deploying without a loopback bind_address in "
            "zz-carlos.cnf; MariaDB may be reachable from the edge network (WAF pod)"
        )
        return
    raise CtlError(
        f"no loopback bind_address in {cnf} — MariaDB would listen on non-loopback "
        f"interfaces and the WAF pod could reach it directly over the edge network "
        f"(bypassing the app). Merge 'bind_address = 127.0.0.1' from the repo's "
        f"conf/mariadb/zz-carlos.cnf, or set CARLOS_ALLOW_DB_EXPOSED=1 to deploy anyway."
    )


def validate_rendered(runner: Runner) -> None:
    """What remains of the bash cmd_render now that Ansible renders: verify
    the installed pod specs are complete and internally consistent before
    handing them to podman. A literal @FOO@ or un-rendered Jinja marker
    reaching podman becomes an invalid image/port/value and the pod fails
    with a confusing error far from the cause."""
    from .util import stray_tokens

    s = runner.settings
    # Migration guard: an operator-set Apache-style WAF_SSL_PROTOCOLS value
    # ("all -SSLv3 ...") makes the nginx CRS variant refuse to start with an
    # opaque config error — name the problem here instead.
    protos = s.get("WAF_SSL_PROTOCOLS")
    if "all" in protos or " -" in protos:
        warn(
            f"WAF_SSL_PROTOCOLS='{protos}' looks like Apache mod_ssl syntax — the WAF is the "
            f"nginx CRS variant, which needs an explicit TLS version list (e.g. 'TLSv1.2 "
            f"TLSv1.3'). Update it in the playbook host_vars or the WAF will not start."
        )
    yamls = [s.rendered_yaml, s.rendered_waf_yaml]
    if s.obs_enabled:
        yamls.insert(1, s.rendered_obs_yaml)
    for f in yamls:
        if not f.is_file():
            raise CtlError(
                f"no rendered pod spec at {f} — run the provisioning playbook "
                f"(ansible/site.yml) first"
            )
        stray = stray_tokens(f).strip()
        if stray:
            raise CtlError(f"unrendered token(s) in {f}: {stray} — re-run the playbook")
        if _JINJA_MARKER.search(f.read_text()):
            raise CtlError(
                f"un-rendered Jinja markers in {f} — the playbook render failed or the file "
                f"was copied from a template; re-run the playbook"
            )
        # The pod specs carry no plaintext secrets (the db secret is referenced
        # by NAME, credentials come from mounted files) — force 0644 so the
        # rootless restic file backup can read them regardless of umask.
        try:
            f.chmod(0o644)
        except OSError:
            pass
    # Container-memory vs JVM-heap margin invariant.
    validate.check_mem_margin("carlos", s.get("CARLOS_MEM_LIMIT"), s.get("CARLOS_JAVA_XMX"), 2048)
    validate.check_mem_margin("drugref", s.get("DRUGREF_MEM_LIMIT"), s.get("DRUGREF_JAVA_XMX"), 512)


def _pull_images(runner: Runner, yamls: List[Path]) -> None:
    """--pull: refresh every referenced image for the CURRENT tags before
    (re)starting. Neither `podman kube play` (default IfNotPresent for a
    pinned tag) nor the quadlet path re-pulls a same-tag security rebuild.
    Collect failures and REFUSE to deploy on any — a silent stale-image
    deploy defeats the point of --pull. Locally-built images skipped."""
    s = runner.settings
    log("Pulling images for their current tags (--pull)")
    images = set()
    img_re = re.compile(r'image: "([^"]+)"')
    for f in yamls:
        images.update(img_re.findall(f.read_text()))
    failed = []
    for img in sorted(images):
        if not img or img.startswith("localhost/"):
            continue
        if not runner.ok(runner.podman_user_argv(["pull", img])):
            failed.append(img)
    if failed:
        if s.get("CARLOS_ALLOW_STALE_IMAGES", "0") == "1":
            warn(
                f"pull failed for: {' '.join(failed)} — deploying with the images already "
                f"present (CARLOS_ALLOW_STALE_IMAGES=1)"
            )
        else:
            raise CtlError(
                f"image pull failed for: {' '.join(failed)} — refusing to deploy with stale "
                f"images (--pull was requested to refresh them). Retry, or set "
                f"CARLOS_ALLOW_STALE_IMAGES=1 to deploy what is already present."
            )


# Lockstep with the probe commands in carlos-app.yaml.j2 / carlos-waf.yaml.j2
# (keep in sync when a probe there changes): when podman never wired the pod
# spec's livenessProbe into a healthcheck, the readiness gate execs the SAME
# probe directly instead of trusting "started". Keyed by the
# container-name suffix after the pod prefix.
_FALLBACK_PROBES: Dict[str, List[str]] = {
    "db": [
        "bash", "-c",
        "healthcheck.sh --connect 2>/dev/null"
        " || mariadb-admin ping --silent 2>/dev/null"
        " || exec 3<>/dev/tcp/127.0.0.1/3306",
    ],
    "carlos": [
        "bash", "-c",
        "exec 3<>/dev/tcp/127.0.0.1/8080; printf 'GET /carlos/ HTTP/1.0\\r\\n"
        "Host: 127.0.0.1\\r\\n\\r\\n' >&3; head -n1 <&3 | grep -qE '^HTTP/1\\.[01] [23]'",
    ],
    "drugref": [
        "bash", "-c",
        "exec 3<>/dev/tcp/127.0.0.1/8180; printf 'GET /drugref2/ HTTP/1.0\\r\\n"
        "Host: 127.0.0.1\\r\\n\\r\\n' >&3; head -n1 <&3 | grep -qE '^HTTP/1\\.[01] [23]'",
    ],
    "waf": ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/18000"],
}


# How long a CONFIGURED healthcheck may report nothing at all before the gate
# concludes podman is not running it and falls back to the declared probe.
# Comfortably above the specs' longest startPeriod/interval pair (90s + 30s)
# so a genuinely-slow first check is never mistaken for a dead timer.
_NEVER_RAN_GRACE = 180


def _wait_container_healthy(
    runner: Runner, ctr: str, deadline: float,
    fallback_probe: Optional[List[str]] = None,
) -> bool:
    """Wait for a container healthcheck or fallback probe to succeed.

    Empty and ``starting`` health states continue polling while Podman reports
    a configured healthcheck. If no healthcheck is configured, execute the
    supplied fallback probe inside the container. Some Podman environments
    configure healthchecks without scheduling them; after
    ``_NEVER_RAN_GRACE`` seconds with an empty health log, execute the same
    fallback probe. Return ``False`` when the deadline expires or no supported
    probe can establish health.
    """
    import time

    warned_fallback = False
    warned_never_ran = False
    t_start = time.time()
    while True:
        # timeout=15 per probe: a wedged `podman inspect` must not block the
        # loop past `deadline` (checked only between iterations). A timed-out
        # probe returns rc 124 → falls through to the deadline check and
        # retries, so the deadline stays authoritative and the gate can never
        # hang indefinitely.
        cp = runner.run(
            runner.podman_user_argv(
                ["inspect", ctr, "--format", "{{.State.Health.Status}}"]
            ),
            capture=True,
            timeout=15,
        )
        status = (cp.stdout or "").strip()
        if cp.returncode == 0:
            if status == "healthy":
                return True
            if not status or status == "<nil>":
                cfg = runner.run(
                    runner.podman_user_argv(
                        [
                            "inspect", ctr, "--format",
                            "{{if .Config.Healthcheck}}configured{{end}}",
                        ]
                    ),
                    capture=True,
                    timeout=15,
                )
                if cfg.returncode == 0 and "configured" not in (cfg.stdout or ""):
                    if fallback_probe is None:
                        # No probe mapping for this container: we cannot
                        # verify it is serving — warn loudly rather than
                        # silently green it (compatibility path).
                        warn(
                            f"{ctr}: no podman healthcheck is configured, so the readiness "
                            f"gate cannot confirm it is actually serving — trusting "
                            f"'started'. If the pod spec declares a livenessProbe, this "
                            f"podman build did not map it; verify the container by hand "
                            f"and consider a newer podman."
                        )
                        return True
                    if not warned_fallback:
                        warn(
                            f"{ctr}: no podman healthcheck is configured (this podman "
                            f"build did not map the pod spec's livenessProbe) — the "
                            f"readiness gate degrades to exec'ing the probe command "
                            f"directly in the container; consider a newer podman."
                        )
                        warned_fallback = True
                    # timeout=15 like the inspects above : the
                    # probe bodies block indefinitely against a socket that
                    # accepts but never answers (JVM in GC death), and podman
                    # exec itself can wedge on exactly the degraded builds
                    # this path serves — an unbounded exec would turn the
                    # fail-closed gate into an indefinite hang.
                    probe_cp = runner.run(
                        runner.podman_user_argv(["exec", ctr, *fallback_probe]),
                        capture=True, quiet=True, timeout=15,
                    )
                    if probe_cp.returncode == 0:
                        return True
                    # Probe failed: keep polling toward the deadline — fail
                    # CLOSED rather than arming timers on an unverified app.
            elif (status == "starting" and fallback_probe is not None
                    and time.time() - t_start >= _NEVER_RAN_GRACE):
                # Has the check ever RUN? An empty log after the grace period
                # means podman never executed it (no healthcheck timers), not
                # that the app is slow — a slow app produces failing log
                # entries, which keep us on the normal polling path.
                hlog = runner.run(
                    runner.podman_user_argv(
                        ["inspect", ctr, "--format", "{{len .State.Health.Log}}"]
                    ),
                    capture=True, timeout=15,
                )
                if hlog.returncode == 0 and (hlog.stdout or "").strip() in ("0", ""):
                    if not warned_never_ran:
                        warn(
                            f"{ctr}: its healthcheck is configured but has not run once in "
                            f"{_NEVER_RAN_GRACE}s (podman drives healthchecks from transient "
                            f"systemd timers — is the service user's systemd --user manager "
                            f"working?). Falling back to exec'ing the declared probe directly "
                            f"so a working stack is not failed for a broken timer."
                        )
                        warned_never_ran = True
                    probe_cp = runner.run(
                        runner.podman_user_argv(["exec", ctr, *fallback_probe]),
                        capture=True, quiet=True, timeout=15,
                    )
                    if probe_cp.returncode == 0:
                        return True
        if time.time() >= deadline:
            return False
        time.sleep(5)


def ready_budgets(runner: Runner) -> Dict[str, int]:
    """Return the readiness timeout for each required container.

    Database, CARLOS, and DrugRef receive 1,320 seconds to cover their
    1,200-second startup probes and dependent startup work. The WAF receives
    420 seconds for TLS and initialization. ``READY_WAIT_SECONDS`` overrides
    every default, and the database-user provisioning wait uses the same
    database allowance.
    """
    s = runner.settings
    containers = (
        f"{s.app_pod}-db",
        f"{s.app_pod}-carlos",
        f"{s.app_pod}-drugref",
        f"{s.waf_pod}-waf",
    )
    if s.get("READY_WAIT_SECONDS"):
        v = s.get_int_or("READY_WAIT_SECONDS", 900)
        return {ctr: v for ctr in containers}
    defaults = {"db": 1320, "carlos": 1320, "drugref": 1320, "waf": 420}
    return {ctr: defaults[ctr.rsplit("-", 1)[-1]] for ctr in containers}


def wait_app_ready(runner: Runner) -> bool:
    """Post-start readiness gate: `systemctl restart` rc 0 only means systemd
    started the units — Tomcat can be minutes from serving, the WAR can have
    failed to deploy, and (the WAF's documented failure mode) the front-door
    nginx exits when it cannot resolve the backend hostname. Gate on the
    db AND carlos AND drugref AND waf containers reaching healthy, so `play`
    (and the rebuild/rollback that trust its exit code) cannot report green
    while the database, the front door, or drug-interaction checking is
    down. The db gate rides the pod's real-ping livenessProbe
    (healthcheck.sh/mariadb-admin), so "port open but server not answering"
    no longer passes.

    Budgets are PER CONTAINER (see ready_budgets — the declared startup probes). Deadlines are
    absolute from one t0 because the containers start CONCURRENTLY: a
    container that took 900 s of the db's budget to become healthy really has
    had 900 s, so the next one should not get a fresh full budget on top.

    But the polling is SERIAL, so a container polled LATE can find its
    absolute deadline already expired — and then it is failed without ever
    being probed once. That is not theoretical: the waf carries the SMALLEST
    budget (420 s) and is polled LAST, and on a host where podman's
    healthcheck timers never run (the degraded case _NEVER_RAN_GRACE exists
    for) each of the three preceding containers burns 180 s of grace before
    its fallback probe fires — ~540 s, so the waf's deadline is gone before
    its first poll. Measured live: front door serving 200 and the waf's own
    declared probe returning 0, while `play` reported "the app is not
    serving", wrote NO .deployed marker and armed NO timers.

    So each DEFAULT-budget deadline is FLOORED at "enough time, from the
    moment this container's own polling starts, for the fallback path to run
    at all": the never-ran grace plus one poll interval. That keeps the
    concurrent-start accounting for the healthy case and makes the
    degraded-host fallback reachable for every container, not just the first.

    The floor is deliberately NOT applied when READY_WAIT_SECONDS is set
    explicitly: that knob is the operator's (and the hermetic suite's) direct
    statement of how long they are willing to wait, and silently extending it
    to ~grace-length per container would be the opposite of what they asked
    for."""
    import time

    budgets = ready_budgets(runner)
    explicit_wait = bool(runner.settings.get("READY_WAIT_SECONDS"))
    t0 = time.time()
    for ctr, budget in budgets.items():
        probe = _FALLBACK_PROBES.get(ctr.rsplit("-", 1)[-1])
        deadline = t0 + budget
        if probe is not None and not explicit_wait:
            deadline = max(deadline, time.time() + _NEVER_RAN_GRACE + 5)
        if not _wait_container_healthy(runner, ctr, deadline, probe):
            return False
    return True


def waf_no_root_gate(runner: Runner) -> bool:
    """Runtime no-root assertion for the internet-facing WAF container: the
    spec deliberately pins no runAsUser/runAsNonRoot (the CRS image assigns
    its own nginx uid, and pinning a wrong guess would break the image), so
    the compensating control is proving the ABSENCE of root processes live.
    `cmd_check` asserts the same thing on demand; this gate makes a fresh
    deploy fail loudly instead of leaving a root edge process to be found at
    the next manual check. An unreadable `podman top` passes (cannot verify
    — check/monitor keep watching); a visible root process fails."""
    s = runner.settings
    top = runner.output(runner.podman_user_argv(["top", f"{s.waf_pod}-waf", "user"]))
    users = {u.strip() for u in top.splitlines()[1:] if u.strip()}
    if "root" in users:
        warn(
            f"{s.waf_pod}-waf is running a ROOT process — the CRS image should run "
            f"entirely as its own unprivileged nginx user. Refusing to call this "
            f"deploy green; inspect the waf image (a rebased/edited image that "
            f"defaults to root?) before going live."
        )
        return False
    return True


def waf_db_isolation_broken(runner: Runner) -> Optional[bool]:
    """Cross-pod isolation probe: can the internet-facing WAF container open
    the app pod's 3306? True = BROKEN (the edge can reach the PHI database),
    False = isolated, None = cannot probe (waf container not running). The
    split-pod topology's entire security argument rests on this boundary, so
    it is asserted by `check`/`play` AND re-checked by the recurring monitor."""
    s = runner.settings
    names = runner.output(runner.podman_user_argv(["ps", "--format", "{{.Names}}"]))
    if f"{s.waf_pod}-waf" not in names.splitlines():
        return None
    cp = runner.run(
        runner.podman_user_argv([
            "exec", f"{s.waf_pod}-waf", "timeout", "5", "bash", "-c",
            f"exec 3<>/dev/tcp/{s.app_pod}/3306",
        ]),
        capture=True, quiet=True, timeout=30,
    )
    if cp.returncode == 0:
        return True  # the connect SUCCEEDED — boundary broken
    if cp.returncode in (1, 124):
        # 1 = bash's connect refused/unreachable, 124 = the in-container
        # `timeout 5` expired: the probe RAN and the port is unreachable.
        return False
    # Anything else (125/126/127...) is podman/exec infrastructure failure —
    # bash or timeout missing from a rebased WAF image, container
    # mid-restart. Mapping that to "isolated" would fail OPEN: the boundary
    # would read intact forever while the probe silently stopped probing
    # . None = cannot verify; callers surface it.
    return None


def seed_backup_stamps(runner: Runner) -> None:
    """Seed the backup-freshness stamp files at the first successful play.
    The monitor alerts on an ABSENT stamp (backups that never ran must not
    look green), so a baseline dated from go-live gives a fresh install
    exactly the configured staleness window before its first alert."""
    s = runner.settings
    backup_dir = s.emr_home / "backup"
    try:
        backup_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        warn(
            f"could not create {backup_dir} to seed backup stamps — the monitor will report "
            f"missing-stamp until the first real backup runs"
        )
        return
    for stamp in (".last-full-ok", ".last-binlog-ok", ".last-docs-ok", ".last-verify-ok"):
        p = backup_dir / stamp
        if not p.is_file():
            try:
                p.touch()
            except OSError:
                warn(
                    f"could not seed {p} — the monitor will report a missing {stamp} stamp "
                    f"until the first real backup runs"
                )


def start_instance_timers(runner: Runner) -> bool:
    """Start the instance timers after a successful deploy. Provisioning
    installs and enables them WITHOUT --now (they would fire — and page —
    against a down stack before the first play); this makes play the moment
    the schedule goes live. The .deployed go-live marker is what the timer
    units' ConditionPathExists gates on.

    Returns False when any expected timer is MISSING or failed to start —
    once the .deployed marker is armed, a missing backup/monitor timer means
    the schedule silently never fires (no OnFailure, no monitor sweep to
    notice), so play must surface it as a nonzero exit, not a quiet skip."""
    s = runner.settings
    # A silently-swallowed failure here would leave backups and the monitor
    # NEVER firing and the guard disarmed, with no alert — so fail LOUD.
    guard_dir = s.emr_home / "container" / "guard"
    try:
        guard_dir.mkdir(parents=True, exist_ok=True)
        guard_dir.chmod(0o755)
        # Explicit 0644: touch() inherits the ambient umask, and a play run
        # from a umask-077 shell (QUICKSTART step 2 sets exactly that) left
        # these root-owned 0600 — unreadable inside the rootless restic
        # userns, failing every subsequent nightly files snapshot. Non-secret
        # empty markers; same fix class as .repo-posture / the DR env copy.
        (s.emr_home / "container" / ".deployed").touch()
        (s.emr_home / "container" / ".deployed").chmod(0o644)
        (guard_dir / "deployed").touch()
        (guard_dir / "deployed").chmod(0o644)
    except OSError:
        raise CtlError(
            f"could not write the go-live marker(s) under {s.emr_home}/container — the "
            f"backup/monitor timers would NEVER fire (ConditionPathExists) and the reboot "
            f"blank-datadir guard would stay disarmed; fix permissions on "
            f"{s.emr_home}/container and re-run 'carlos-ctl play'"
        ) from None
    if not runner.systemd_running():
        # The no-systemd fallback is a DOCUMENTED mode (README, "Each pod runs
        # as a systemd service" — play/down fall back to plain rootless
        # `podman kube play`/`kube down`), and every OTHER no-systemd branch in
        # this tree says so out loud (cmd_down logs it, cmd_enable refuses,
        # tlsops warns it cannot restart the cert consumers). This one returned
        # True in silence — so on such a host `play` wrote the go-live markers
        # and exited 0 with NO backups, NO binlog shipping, NO document
        # snapshots, NO restore drill and NO monitor sweep scheduled, and
        # nothing in the output hinted at it. The monitor cannot cover the gap
        # either: its own missing-unit check (_check_systemd_failed) returns
        # early without systemctl, and it is itself one of the jobs that never
        # runs. Say it once, every play, with the exact commands an external
        # scheduler has to fire.
        warn(
            f"no usable systemd on this host — the pods were started directly, but NO schedule "
            f"is armed: the backup, binlog-ship, document-snapshot, restore-drill and "
            f"monitor jobs will NEVER run, and nothing else will notice. Drive them from "
            f"an external scheduler (cron/BusyBox crond) with EMR_HOME={s.emr_home}: "
            f"'carlos-ctl backup full' (nightly), 'carlos-ctl backup binlogs' and "
            f"'carlos-ctl backup docs' (every 15 min), 'carlos-ctl backup verify' "
            f"(weekly), 'carlos-ctl monitor' (hourly), and 'carlos-ctl guard' before the "
            f"pods at boot"
        )
        return True
    all_ok = True
    timer_set = ["backup", "binlog", "docs", "backup-verify", "monitor"]
    if (s.get("CARLOS_TLS_MODE") or "selfsigned") == "acme":
        # The daily certbot renewal exists only in acme mode (the playbook
        # renders/enables it there) — mode-gated so the missing-unit warning
        # below cannot false-fire on the other modes.
        timer_set.append("cert-renew")
    for t in timer_set:
        unit = f"{s.instance}-{t}.timer"
        if not (s.systemd_dir / unit).is_file():
            warn(
                f"{unit} is NOT installed — the scheduled {t} job will never run; "
                f"re-run the provisioning playbook to install it"
            )
            all_ok = False
            continue
        # enable AND start: `down --disable` disables these timers and tells
        # the operator `play` reverses it. `start` alone honored that only
        # until the next reboot — the timers then stayed disabled forever
        # (backups, binlog shipping, doc snapshots, the verify drill, and the
        # monitor that would have flagged the stale backups, all silently
        # dead). enable is idempotent, so the normal play path pays nothing.
        if not runner.ok(["systemctl", "enable", unit]):
            warn(f"could not enable {unit} — it will not survive a reboot; "
                 f"enable it by hand: systemctl enable {unit}")
            all_ok = False
        if not runner.ok(["systemctl", "start", unit]):
            warn(f"could not start {unit} — start it by hand: systemctl start {unit}")
            all_ok = False
    return all_ok


def cmd_play(runner: Runner, args: List[str]) -> int:
    s = runner.settings
    do_pull = False
    for arg in args:
        if arg == "--pull":
            do_pull = True
        else:
            raise CtlError("usage: carlos-ctl play [--pull]")
    validate.validate_instance(runner)
    validate.port_in_use_preflight(runner)
    # Cover the upgrade path where an operator re-plays without re-running the
    # playbook: move a pre-existing age key to the root-only dir before
    # anything reads it, and re-pin conf/secrets to root.
    from . import secrets as secrets_mod

    secrets_mod.migrate_age_key_location(runner)
    secrets_mod.harden_secrets_ownership(runner)
    if not runner.ok(runner.podman_user_argv(["network", "exists", s.edge_net_name])):
        raise CtlError(
            f"no '{s.edge_net_name}' network — run the provisioning playbook first "
            f"(added with the WAF/DB isolation split)"
        )
    if not s.properties_file.is_file():
        raise CtlError(f"no {s.properties_file} — run the provisioning playbook first")
    preflight_db_root_guard(runner)
    datadir_guard(runner)
    db_isolation_gate(runner)
    if not s.drugref_properties_file.is_file():
        raise CtlError(f"no {s.drugref_properties_file} — run the provisioning playbook first")
    # The WAF cannot start without its TLS material; catch that here with a
    # clear message instead of an opaque waf-init crash-loop. Mode-aware:
    # selfsigned (the default) GENERATES a missing pair so provisioning alone
    # yields a startable WAF; the other two modes refuse with their remedy.
    certs = s.conf_dir / "waf" / "certs"
    tls_mode = s.get("CARLOS_TLS_MODE") or "selfsigned"
    if tls_mode == "selfsigned" and runner.have("openssl"):
        from . import tlsops

        tlsops.ensure_selfsigned_cert(runner)
    if not (certs / "fullchain.pem").is_file() or not (certs / "privkey.pem").is_file():
        if tls_mode == "acme":
            raise CtlError(
                f"no TLS cert/key at {certs}/{{fullchain,privkey}}.pem — acme mode: run "
                f"'carlos-ctl cert-renew' once (DNS for {s.get('SERVER_NAME')} must point "
                f"here) before the first play"
            )
        raise CtlError(
            f"no TLS cert/key at {certs}/{{fullchain,privkey}}.pem — place them first "
            f"(the WAF will not start without them)"
        )
    # Near-expiry (or unparseable) cert warning at go-live — warn only
    # (a self-signed/dummy cert should not block a dev deploy).
    warn_days = s.get_int("CERT_EXPIRY_WARN_DAYS")
    if runner.have("openssl") and not runner.ok([
        "openssl", "x509", "-checkend", str(warn_days * 86400), "-noout",
        "-in", str(certs / "fullchain.pem"),
    ]):
        warn(
            f"the TLS cert at {certs}/fullchain.pem expires within {warn_days} days (or is "
            f"not parseable) — renew it before/soon after go-live"
        )
    if s.obs_enabled:
        # The obs-pod log collector needs its config; the mysqld-exporter its
        # credentials file. Catch missing files here, not as a pod error.
        for p in (
            s.conf_dir / "vector" / "journald-collector.toml",
            s.conf_dir / "vmagent" / "scrape.yml",
            s.conf_dir / "caddy" / "Caddyfile",
        ):
            if not p.is_file():
                raise CtlError(f"no {p} — run the provisioning playbook first")
        if not s.exporter_mycnf_file.is_file():
            raise CtlError(f"no {s.exporter_mycnf_file} — run the provisioning playbook first")
        # Normalize the exporter cnf and the logview Caddyfile ownership on
        # every play: each is read by a NON-root container uid (65534 for the
        # mysqld-exporter, 10013 for caddy — drop-ALL, no DAC_OVERRIDE) out of
        # a 0600 render, so the map has to run INSIDE the userns where those
        # ids resolve to the service user's subuids.
        #
        # The pre-chown is load-bearing, not tidiness: chown(2) refuses a file
        # whose CURRENT owner or group is outside the userns id_map, and host
        # root's uid/gid 0 are never mapped. Any root-written replacement
        # (`db-users` / `rotate db` rewrite the exporter cnf; an operator edit
        # or a restored backup can do the same to either file) therefore makes
        # the unshare chown EPERM forever — and `play` is exactly the remedy
        # both warnings below name, so it must be able to repair the state, not
        # only re-observe it.
        for target, ctr_uid, breakage in (
            (s.exporter_mycnf_file, "65534", "MariaDB metrics will be MISSING"),
            (s.conf_dir / "caddy" / "Caddyfile", "10013",
             "caddy cannot read its config and the PHI log view will crash-loop"),
        ):
            chown_to_service_user(target, s.service_user)
            if not runner.ok(runner.podman_user_argv(
                ["unshare", "chown", f"{ctr_uid}:{ctr_uid}", str(target)]
            )):
                # Do NOT name `play` as the remedy here — this IS play, and
                # that self-referential advice is what let the pre-fix EPERM
                # loop look actionable for as long as it did.
                warn(
                    f"could not chown {target} to container uid {ctr_uid} inside the "
                    f"userns — {breakage}. Check the file's owner:group "
                    f"(stat -c '%U:%G') and the {s.service_user} subuid/subgid ranges "
                    f"in /etc/subuid, /etc/subgid; re-run the provisioning playbook "
                    f"if they are missing"
                )
    # context.xml is a managed conf file the rendered app spec subPath-mounts:
    # a missing source fails the carlos container with an opaque error.
    if not (s.conf_dir / "tomcat" / "context.xml").is_file():
        raise CtlError(
            f"no {s.conf_dir}/tomcat/context.xml — the playbook installs it; re-run the "
            f"provisioning playbook"
        )
    if not runner.ok(runner.podman_user_argv(["secret", "exists", s.db_secret])):
        raise CtlError(f"no '{s.db_secret}' secret — run the provisioning playbook first")
    # If secrets are sealed, materialize the /run fragments before the pod
    # starts. A start failure is NOT swallowed silently: the deploy continues
    # (the pod's __SEALED__ guard is the hard stop), but the operator must see why.
    if (s.systemd_dir / f"{s.instance}-secrets.service").is_file():
        if runner.systemd_running():
            if not runner.ok(["systemctl", "start", f"{s.instance}-secrets.service"]):
                warn(
                    f"could not start {s.instance}-secrets.service — sealed credential "
                    f"fragments were NOT materialized; the app pod will fail its "
                    f"__SEALED__ guard (journalctl -u {s.instance}-secrets.service)"
                )
        else:
            # No systemctl: the unit exists but nothing can start it, so the
            # /run fragments would never be materialized and the pod would die
            # on its __SEALED__ guard with no explanation. `secrets render` IS
            # the unit's ExecStart — run it inline so the documented
            # no-systemd fallback can actually deploy a SEALED install, and
            # say what must happen at every boot (the fragments live in tmpfs).
            log("no usable systemd — rendering the sealed credential fragments inline "
                "(this is what the secrets unit would have done)")
            from . import secrets as secrets_mod
            try:
                secrets_mod.cmd_secrets_render(runner)
            except CtlError as e:
                warn(
                    f"inline secrets render FAILED ({e}) — the app pod will fail its "
                    f"__SEALED__ guard; fix the age key/bundle and re-run 'carlos-ctl play'"
                )
            else:
                warn(
                    f"the rendered fragments live in {s.run_secrets_dir} (tmpfs — gone at "
                    f"reboot) and no systemd unit will recreate them: run 'carlos-ctl "
                    f"secrets render' BEFORE the pods start on every boot"
                )
    require_alert_channel(runner)
    require_heartbeat(runner)
    require_dr_posture(runner)
    validate_rendered(runner)
    # Supply-chain posture, surfaced where it matters (deploy time): a
    # dev-mode build fetched a MOVING source ref with no checksum — fine for
    # iteration, but a production PHI instance should run a release build
    # (pinned 40-hex refs + source SHA256s). Warn, never block.
    mode_file = s.emr_home / "build" / ".build-mode"
    with contextlib.suppress(OSError):
        if mode_file.is_file() and mode_file.read_text().strip() != "release":
            # Wording: "not release-gated", not "no source checksum" — a
            # dev-mode CARLOS build may be a sha256-verified release WAR (the
            # auto default), but the DrugRef compile and the dependency-lock
            # posture are only pinned under the release gate.
            warn(
                "the installed images were NOT built under CARLOS_BUILD_MODE=release — "
                "for production, rebuild with it (per app: a source-compiled app needs "
                "its 40-hex ref + *_SRC_SHA256; a WAR-artifact app needs its pinned "
                "WAR sha256)"
            )
    yamls = [s.rendered_yaml, s.rendered_waf_yaml] + (
        [s.rendered_obs_yaml] if s.obs_enabled else []
    )
    if do_pull:
        _pull_images(runner, yamls)
    # Pre-cutover smoke: `--replace` DESTROYS the running pod before the new
    # image proves anything, so a corrupt/unstartable image otherwise costs
    # downtime until a manual rollback. A container that cannot even exec
    # /bin/true (broken layer, missing runtime linkage) must fail HERE, with
    # the old pod still serving. Deliberately cheap — a full boot is the
    # readiness gate's job after cutover; this closes only the
    # cannot-start-at-all class. Skipped when the image is absent locally
    # (a --pull play fetches at start; failure there already aborts).
    for image in (s.get("CARLOS_IMAGE"), s.get("DRUGREF_IMAGE")):
        if not runner.ok(runner.podman_user_argv(["image", "exists", image])):
            continue
        if runner.podman_user(
            ["run", "--rm", "--entrypoint", "/bin/true", image], quiet=True
        ).returncode != 0:
            raise CtlError(
                f"pre-cutover smoke FAILED: {image} cannot start a trivial process — "
                f"refusing to replace the running pods with it (they are untouched); "
                f"rebuild ('carlos-ctl build') or roll back ('carlos-ctl rollback')"
            )
    # Observability first (stores + collector lead the app; both tolerate the
    # other being down — journald buffers, vmagent remote_write buffers), then
    # the app, then the WAF that fronts it (it serves 502s until the app is
    # up). App and waf run with the journald log driver so logcollect can
    # tail them.
    services = ([f"{s.obs_pod}.service"] if s.obs_enabled else []) \
        + [f"{s.instance}.service", f"{s.waf_pod}.service"]
    if (s.quadlet_dir() / f"{s.instance}.kube").is_file() and runner.systemd_running():
        log(
            f"Starting {(s.obs_pod + ', ') if s.obs_enabled else ''}{s.app_pod}, then "
            f"{s.waf_pod} pods (user units under '{s.service_user}')"
        )
        # Unconditional unmask: `down --disable` masks the units for
        # reboot-persistent maintenance, and restart on a masked unit errors.
        runner.systemctl_user(["unmask", *services], quiet=True)
        if runner.systemctl_user(["daemon-reload"]).returncode != 0:
            raise CtlError(
                f"systemd user daemon-reload failed for '{s.service_user}' — refusing to "
                f"start the pods against stale unit definitions"
            )
        # A start failure ABORTS the deploy before any go-live bookkeeping
        # (the bash ran these bare under `set -e`): touching the .deployed
        # markers / arming the timers for a stack that never came up would
        # report success to the operator (and Ansible), flip the blank-datadir
        # guard semantics, and page from every timer against a dead DB.
        for svc in services:
            if runner.systemctl_user(["restart", svc]).returncode != 0:
                raise CtlError(
                    f"failed to start {svc} — deploy aborted (no go-live markers or timers "
                    f"were touched); inspect with: journalctl --user -M "
                    f"{s.service_user}@ -u {svc}"
                )
    else:
        if s.obs_enabled:
            log(f"Starting {s.obs_pod} pod")
            if runner.podman_user([
                "kube", "play", "--replace", "--network", s.net_name, str(s.rendered_obs_yaml)
            ]).returncode != 0:
                raise CtlError(f"kube play failed for {s.rendered_obs_yaml} — deploy aborted")
        log(f"Starting {s.app_pod} pod (journald log driver)")
        if runner.podman_user([
            "kube", "play", "--replace", "--network", s.net_name,
            "--network", s.edge_net_name, "--log-driver", "journald", str(s.rendered_yaml),
        ]).returncode != 0:
            raise CtlError(f"kube play failed for {s.rendered_yaml} — deploy aborted")
        log(f"Starting {s.waf_pod} pod (journald log driver)")
        if runner.podman_user([
            "kube", "play", "--replace", "--network", s.edge_net_name,
            "--log-driver", "journald", str(s.rendered_waf_yaml),
        ]).returncode != 0:
            raise CtlError(f"kube play failed for {s.rendered_waf_yaml} — deploy aborted")
    runner.podman_user([
        "pod", "ps", "--filter", f"name={s.obs_pod}",
        "--filter", f"name={s.app_pod}", "--filter", f"name={s.waf_pod}",
    ])
    # Least-privilege by default: if the app is still configured as DB root,
    # provision the dedicated accounts now and bounce the app so it never
    # keeps running as root. False means the app was left on root by a failure
    # the operator did NOT opt into — gated at the end of play as a deploy
    # failure so an internet-facing app never silently steady-states as DB root.
    from . import dbops

    db_least_priv_ok = dbops.maybe_provision_db_users(runner)
    # Confirm the app is actually SERVING before any go-live bookkeeping.
    # `systemctl restart` returns 0 once systemd STARTED the units, not once
    # the app is healthy — a DB that then crash-loops (bad secret, wiped
    # datadir) still passes that gate. Arming .deployed + the timers for such a
    # started-but-unhealthy stack would page from every timer against a dead DB
    # AND, because the blank-datadir reboot guard keys on .deployed, refuse to
    # start at the next reboot (bricking it). So readiness now GATES the
    # bookkeeping: an app that never turns healthy is a loud nonzero exit with
    # NO markers written and NO schedule armed.
    if not wait_app_ready(runner):
        warn(
            f"the {s.app_pod} containers did NOT all reach 'healthy' within "
            f"READY_WAIT_SECONDS — the app is not serving, so NO go-live markers were "
            f"written and NO timers were armed. Inspect: journalctl (service user) / "
            f"podman logs {s.app_pod}-carlos. If this followed a rebuild, "
            f"'carlos-ctl rollback' restores the previous images."
        )
        return 1
    # Edge no-root gate (C24): fail the deploy — before any marker/timer is
    # armed — if the WAF container is running a root process (see
    # waf_no_root_gate for why the spec carries no runAsUser pin).
    if not waf_no_root_gate(runner):
        return 1
    # A healthy deploy just (re)started both cert consumers with whatever is
    # staged in conf/waf/certs — a pending cert-restart retry marker is now
    # satisfied. Clearing it here stops the monitor nagging for up to a day
    # after the operator already remediated via play .
    from .tlsops import cert_restart_marker

    with contextlib.suppress(OSError):
        cert_restart_marker(runner).unlink(missing_ok=True)
    # Health confirmed — the acceptance the operator granted for THIS play is
    # spent: with the datadir now verifiably initialized, consume the
    # accept-empty-datadir marker so it cannot silently pre-accept a FUTURE
    # unmounted/wiped data volume at reboot (the marker previously survived
    # until the next no-flag play, which could be months later — an unbounded
    # standing acceptance of the exact catastrophe the guard exists for).
    from .guard import datadir_initialized

    _accept_marker = s.emr_home / "container" / "guard" / "accept-empty-datadir"
    if _accept_marker.is_file() and datadir_initialized(s.data_dir):
        try:
            _accept_marker.unlink()
            log("accept-empty-datadir marker consumed — the datadir is initialized; "
                "future empty-datadir starts will refuse again")
        except OSError as e:
            warn(
                f"could not consume the accept-empty-datadir marker ({_accept_marker}): "
                f"{e} — while it survives, an unmounted/wiped data volume at reboot "
                f"would initialize a BLANK database; remove it by hand"
            )
    # NOW seed the backup-freshness stamps (so the monitor's
    # missing-stamp alert has a baseline dated from go-live), THEN arm the
    # timers + .deployed / guard-deployed markers provisioning only enabled.
    seed_backup_stamps(runner)
    # Record the schema the now-healthy :latest runs against — the baseline
    # rollback's schema-compatibility guard compares (best-effort; warns).
    dbops.record_schema_fingerprint(runner)
    timers_ok = start_instance_timers(runner)
    if not timers_ok:
        # The stack IS serving, but the backup/monitor schedule is not fully
        # armed — a green exit here would hide it from the operator/Ansible.
        warn(
            "the stack is up but one or more scheduled timers is missing or failed to "
            "start (see warnings above) — fix the schedule before treating this deploy "
            "as complete"
        )
        return 1
    if not db_least_priv_ok:
        # The stack IS serving, but the app is still connected to MariaDB as
        # ROOT because least-privilege provisioning could not complete — an
        # app-tier compromise would own the entire PHI database. A green exit
        # here would hide that. Fail loudly (the monitor's app-db-root check
        # keeps paging until it is fixed).
        warn(
            "the stack is up but the app is still connected to MariaDB as ROOT and "
            "least-privilege provisioning did not complete (see warnings above) — an "
            "internet-facing EMR must not run on the DB root account. Fix the cause and "
            "run 'carlos-ctl db-users', or set CARLOS_SKIP_AUTO_DB_USERS=1 / "
            "CARLOS_ALLOW_DB_ROOT=1 to consciously accept root"
        )
        return 1
    return 0


def cmd_down(runner: Runner, args: List[str]) -> int:
    s = runner.settings
    disable = False
    if args == ["--disable"]:
        disable = True
    elif args:
        raise CtlError("usage: carlos-ctl down [--disable]")
    # Waf first, then app, then obs (reverse of start order). Every step is
    # best-effort so a failure stopping one pod never leaves the others running.
    # cert-renew exists only in acme mode; stop/disable of an absent unit
    # is quiet+harmless, so the list is unconditional here.
    timers = ("backup", "binlog", "docs", "backup-verify", "monitor", "cert-renew")
    services = [f"{s.waf_pod}.service", f"{s.instance}.service", f"{s.obs_pod}.service"]
    stop_failures: List[str] = []
    if (s.quadlet_dir() / f"{s.instance}.kube").is_file() and runner.systemd_running():
        for svc in services:
            # Best-effort continuation, but NOT silent success: `down` gates
            # maintenance scripting (`down && umount ...`-style), so a pod
            # that failed to stop — MariaDB still running against a PHI
            # datadir about to be unmounted — must surface in the exit code.
            # A failed stop of an ABSENT unit (obs profile off, no waf) is
            # harmless; only a unit still ACTIVE after the stop counts.
            if runner.systemctl_user(["stop", svc], quiet=True).returncode != 0 \
                    and runner.ok(
                        runner.systemctl_user_argv(["is-active", "--quiet", svc])
                    ):
                stop_failures.append(svc)
        # The schedule tracks the stack: binlog/docs runs against an
        # intentionally-down DB would just fire OnFailure pages every 15
        # minutes for the whole maintenance window. `play` re-arms them.
        for t in timers:
            runner.run(["systemctl", "stop", f"{s.instance}-{t}.timer"], quiet=True)
        # The quadlet units are WantedBy=default.target under a lingering user
        # manager, so a plain `down` is resurrected by the next REBOOT. For
        # maintenance that must survive a reboot, --disable masks the pod
        # units (and disables the timers); `play` (or `enable`) reverses both.
        if disable:
            if not runner.ok(runner.systemctl_user_argv(["mask", *services])):
                warn("could not mask the pod units — a reboot will restart the pods")
            for t in timers:
                runner.run(["systemctl", "disable", f"{s.instance}-{t}.timer"], quiet=True)
            log(
                "pod units MASKED and timers disabled — a reboot will NOT restart them; "
                "re-enable with 'carlos-ctl play' (or 'carlos-ctl enable')"
            )
        else:
            log(
                "pods stopped and timers stopped — NOTE: a reboot restarts both (units stay "
                "enabled); use 'carlos-ctl down --disable' for reboot-persistent maintenance"
            )
    else:
        if disable:
            log("no systemd pod units on this host — nothing restarts at reboot, "
                "--disable is a no-op")
        for y in (s.rendered_waf_yaml, s.rendered_yaml, s.rendered_obs_yaml):
            if y.is_file():
                runner.podman_user(["kube", "down", str(y)], quiet=True)
        for pod in (s.waf_pod, s.app_pod, s.obs_pod):
            if runner.ok(runner.podman_user_argv(["pod", "exists", pod])):
                if runner.podman_user(["pod", "stop", pod], quiet=True).returncode != 0:
                    # Mirror the systemd branch's is-active recheck: `pod
                    # stop` exits nonzero for post-stop cleanup errors too
                    # (cgroup teardown), with every container already down —
                    # A stop may return rc 125 after all containers have exited. Count a
                    # failure when the pod is NOT affirmatively stopped; an
                    # unknown/errored state stays a failure (fail-safe: this
                    # rc gates `down && umount` maintenance scripting).
                    state = runner.output(runner.podman_user_argv(
                        ["pod", "inspect", pod, "--format", "{{.State}}"]
                    )).strip()
                    if state not in ("Exited", "Stopped", "Dead"):
                        stop_failures.append(pod)
                runner.podman_user(["pod", "rm", pod], quiet=True)
    if stop_failures:
        warn(
            f"down: {', '.join(stop_failures)} did NOT stop — containers may still be "
            f"running (and writing) during your maintenance; investigate before "
            f"unmounting or touching the data volumes"
        )
        return 1
    return 0


def cmd_enable(runner: Runner) -> int:
    """Undo `down --disable` WITHOUT starting the pods now: unmask the pod
    units so the next boot (or the next `play`) starts them again."""
    s = runner.settings
    if not runner.systemd_running():
        raise CtlError("no usable systemd on this host — nothing is masked")
    # rc-checked: this verb is the recovery path from `down --disable` — a
    # swallowed systemctl failure (broken user manager, wrong SERVICE_USER)
    # Verify unmasking before reporting success; masked pods cannot start at
    # the next boot.
    failed: List[str] = []
    if runner.systemctl_user(
        ["unmask", f"{s.waf_pod}.service", f"{s.instance}.service", f"{s.obs_pod}.service"],
        quiet=True,
    ).returncode != 0:
        failed.append("pod-unit unmask")
    # SAME mode gate + installed-check as start_instance_timers: the
    # cert-renew timer is rendered ONLY in acme mode (cleanup.yml removes it
    # in the others), so enabling it unconditionally made `enable` report
    # failure on EVERY selfsigned/manual instance — i.e. on the DEFAULT TLS
    # mode. `enable` is the documented recovery from `down --disable` (README,
    # "Patching & rebooting the host"), so an operator finishing planned
    # maintenance was told "the EMR will NOT start at the next boot" about a
    # host whose pod units had just been unmasked correctly — and the nonzero
    # rc broke `carlos-ctl enable && ...` scripting. A timer whose unit file
    # is genuinely absent is still surfaced, but as its own warning naming the
    # playbook (the same wording start_instance_timers uses); only a REAL
    # systemctl failure counts toward the "did not fully apply" verdict.
    timer_set = ["backup", "binlog", "docs", "backup-verify", "monitor"]
    if (s.get("CARLOS_TLS_MODE") or "selfsigned") == "acme":
        timer_set.append("cert-renew")
    missing: List[str] = []
    for t in timer_set:
        unit = f"{s.instance}-{t}.timer"
        if not (s.systemd_dir / unit).is_file():
            missing.append(unit)
            continue
        if runner.run(["systemctl", "enable", unit], quiet=True).returncode != 0:
            failed.append(unit)
    if missing:
        warn(
            f"not installed, so nothing to re-enable: {', '.join(missing)} — the "
            f"scheduled job(s) will never run; re-run the provisioning playbook to "
            f"install them"
        )
    if failed:
        warn(
            f"enable did NOT fully apply — failed: {', '.join(failed)}. The masked "
            f"units/timers stay off (the EMR will NOT start at the next boot); fix "
            f"the systemd user manager for '{s.service_user}' and re-run"
        )
        return 1
    log(
        "pod units unmasked and timers re-enabled — they start at the next boot, or now "
        "with 'carlos-ctl play'"
    )
    return 0


# Documented runtime floors (README Requirements): podman >= 4.9, systemd
# >= 248. asserts.yml enforces the same at provisioning time; cmd_check
# re-verifies the live host.
_RUNTIME_FLOORS = (
    (["podman", "--version"], r"(\d+)\.(\d+)", (4, 9), "podman"),
    (["systemctl", "--version"], r"systemd (\d+)", (248,), "systemd"),
)


def runtime_version_ok(
    runner: Runner, argv: List[str], pattern: str, floor: Tuple[int, ...]
) -> Optional[bool]:
    """Compare a tool's reported version against a documented floor.
    True = at/above floor, False = below, None = unparseable (callers warn
    rather than fail: tool presence is asserted separately and an unknown
    version format must not fail a working host)."""
    out = runner.output(argv)
    match = re.search(pattern, out)
    if not match:
        return None
    got = tuple(int(g) for g in match.groups() if g is not None)
    return got >= floor


def cmd_check(runner: Runner) -> int:
    """Run read-only post-deployment validation.

    The checks cover runtime behavior that static manifests cannot establish,
    including cross-pod reachability, network isolation, telemetry pipelines,
    the front door, and host security posture.
    """
    from . import obsquery
    from .obsquery import vl_query, vm_scalar

    s = runner.settings
    if not runner.have("podman"):
        raise CtlError("podman not found")
    if not runner.have("curl"):
        raise CtlError("curl not found (needed for store queries)")

    counts = {"pass": 0, "fail": 0}

    def ok(msg: str) -> None:
        counts["pass"] += 1
        print(f"ok   {msg}")

    def bad(msg: str) -> None:
        counts["fail"] += 1
        import sys

        print(f"FAIL {msg}", file=sys.stderr)

    running = runner.output(runner.podman_user_argv(["ps", "--format", "{{.Names}}"])).splitlines()

    def ctr_up(name: str) -> bool:
        return name in running

    # No systemctl at all: the runtime-floor loop below SKIPS the systemd
    # check (tool absent), every unit-shaped probe in this verb and in the
    # monitor short-circuits, and `play` could only start the pods directly —
    # so an operator running `check` on such a host gets a page of green with
    # no hint that the backup/monitor schedule does not exist. Posture
    # warning, not a FAIL: play/down on plain `podman kube play` is a
    # documented mode, and nothing the operator can do here would ever clear
    # a hard failure (an external scheduler is invisible to us).
    if not runner.systemd_running():
        warn(
            "no usable systemd on this host — the pods run via the documented plain "
            "`podman kube play` fallback, but NO systemd timer exists: backups, binlog "
            "shipping, document snapshots, the restore drill and the monitor sweep only "
            "run if an external scheduler invokes 'carlos-ctl' for them, and the "
            "boot-time datadir guard is not wired either. See 'carlos-ctl play' output "
            "for the exact commands"
        )

    # -1. Runtime version floors (README Requirements; asserts.yml enforces
    # the same at provisioning — this re-checks the LIVE host, e.g. after a
    # distro downgrade/reinstall): podman >= 4.9, systemd >= 248. Old
    # runtimes fail in version-shaped ways (livenessProbes never wired into
    # healthchecks, kube play rejecting specs). Unparseable output is a
    # warn-not-fail: tool presence is asserted above and an unknown format
    # must not fail a working host.
    for argv, pattern, floor, label in _RUNTIME_FLOORS:
        if argv[0] != "podman" and not runner.have(argv[0]):
            continue
        verdict = runtime_version_ok(runner, argv, pattern, floor)
        if verdict is None:
            warn(f"could not parse the {label} version — skipping the floor check")
        elif verdict:
            ok(f"{label} meets the documented version floor "
               f"({'.'.join(str(v) for v in floor)}+)")
        else:
            bad(f"{label} is OLDER than the documented floor "
                f"{'.'.join(str(v) for v in floor)} (README Requirements) — "
                f"probes/kube-play/user-manager control degrade in version-shaped ways")

    # 0. effective identities — RUNTIME behavior (not spec-restating): the
    # WAF spec deliberately carries no runAsNonRoot pin (image-assigned nginx
    # uid), so prove the absence of root processes live; and the app's DB
    # account is the difference between an app-layer compromise reading one
    # schema and it owning the whole PHI database.
    if ctr_up(f"{s.waf_pod}-waf"):
        top = runner.output(runner.podman_user_argv(["top", f"{s.waf_pod}-waf", "user"]))
        users = {u.strip() for u in top.splitlines()[1:] if u.strip()}
        if "root" in users:
            bad(f"{s.waf_pod}-waf has a ROOT process — the CRS image should run entirely "
                f"as its own unprivileged nginx user")
        elif users:
            ok("waf runs non-root (podman top)")
    if s.properties_file.is_file():
        from .util import first_match

        props_lines = s.properties_file.read_text().splitlines()
        db_user = first_match(props_lines, "db_username")
        if db_user == "root":
            bad("app connects to MariaDB as ROOT (db_username=root in carlos.properties) "
                "— run 'carlos-ctl db-users' to switch to least-privilege accounts")
        elif db_user:
            ok(f"app DB account is least-privilege (db_username={db_user})")
        # PGP_KEY guards outbound PGP-encrypted exports: a live CHANGE_ME
        # placeholder means anything a module encrypts is keyed to a value
        # the site does not control.
        if first_match(props_lines, "PGP_KEY") == "CHANGE_ME":
            warn("carlos.properties still carries PGP_KEY=CHANGE_ME — fine while no "
                 "PGP-exporting module is enabled, but replace it before enabling one "
                 "(exports would be encrypted to a placeholder key)")
        # Current CARLOS develop refuses first boot without a pre-provisioned
        # encryption key (the read-only config mount blocks its
        # generate-and-persist fallback). A pre-key properties file keeps
        # working on the OLD image, so this is the net that catches the gap
        # BEFORE a rebuild turns it into a boot failure.
        # Distinguish ABSENT from PRESENT-BUT-BLANK: the app fails boot on
        # either, but the playbook's additive migration only APPENDS a missing
        # line — it will not touch a present blank one, so the remediation
        # differs. (first_match returns "" for both "key absent" and
        # "key=<blank>"; disambiguate on the raw line.)
        key_present = any(
            ln.lstrip().startswith("encryption.util.secret.key")
            and "=" in ln for ln in props_lines
        )
        if not first_match(props_lines, "encryption.util.secret.key"):
            if key_present:
                warn("carlos.properties has a BLANK encryption.util.secret.key — the "
                     "next rebuild to current CARLOS develop will FAIL first boot. Set a "
                     "value on the existing line (openssl rand -base64 32); the playbook "
                     "will NOT overwrite a present line")
            else:
                warn("carlos.properties has no encryption.util.secret.key — the running "
                     "image may not need it yet, but the next rebuild to current CARLOS "
                     "develop will FAIL first boot. Re-run the playbook (it appends the "
                     "key from carlos_encryption_secret_key when the line is absent)")
    # 0b. Binary logging must be OPEN, not merely configured. MariaDB latches
    # logging off for the rest of the server process the first time it cannot
    # open a new binlog file (full binlog volume, ownership change), and
    # `@@log_bin` keeps reading 1 afterwards — so every other guard in this
    # deployment believed PITR was healthy while the chain had stopped. The
    # 15-minute ship now fails on this too, but `check` is the verb an
    # operator runs when something feels wrong, and it must be able to SAY it.
    if ctr_up(f"{s.app_pod}-db"):
        # 11.4+ spelling first, then the pre-11.4 one — an unsupported
        # statement errors, an OPEN binlog returns one row, a CLOSED one
        # returns zero rows with rc 0 (which is exactly why rc alone misses it).
        for stmt in ("SHOW BINLOG STATUS", "SHOW MASTER STATUS"):
            # `-e MYSQL_PWD` (the bare NAME) forwards the password by
            # environment, never as a podman argv token — the same off-argv
            # credential rule every other db probe in this tree follows.
            cp = runner.podman_user(
                ["exec", "-i", "-e", "MYSQL_PWD", f"{s.app_pod}-db",
                 "mariadb", "-uroot", "-N", "-B", "-e", stmt],
                env={"MYSQL_PWD": s.get("CARLOS_DB_ROOT_PASSWORD")},
                capture=True, quiet=True,
            )
            if cp.returncode != 0:
                continue  # wrong spelling for this server version — try the other
            if (cp.stdout or "").strip():
                ok(f"binary logging is OPEN at runtime ({stmt}) — PITR chain is advancing")
            else:
                bad(
                    f"binary logging is CLOSED at runtime ({stmt} returned no row) — "
                    f"MariaDB has turned it off for the rest of this server process "
                    f"(full binlog volume or a permissions change on "
                    f"{s.data_dir}/mariadb-binlog). POINT-IN-TIME RECOVERY IS DEAD: no "
                    f"new transactions are logged and the shipped chain can never reach "
                    f"them. '@@log_bin' still reads 1, so only this probe sees it. Fix "
                    f"the cause, then RESTART the db container ('carlos-ctl logs db' "
                    f"shows 'Turning logging off for the whole duration')"
                )
            break
        else:
            warn(
                "could not probe the runtime binary-logging state (no root password, or "
                "the db refused both SHOW BINLOG STATUS spellings) — a latched-off binlog "
                "would be invisible here; check 'carlos-ctl logs db' by hand"
            )

    # Apply the same boundary check to DrugRef. Using the database root account
    # gives that service privileges across the entire instance.
    if s.drugref_properties_file.is_file():
        from .util import first_match

        dr_user = first_match(
            s.drugref_properties_file.read_text().splitlines(), "db_user"
        )
        if dr_user == "root":
            bad("drugref connects to MariaDB as ROOT (db_user=root in "
                "drugref2.properties) — run 'carlos-ctl db-users' to switch to the "
                "least-privilege drugref account")
        elif dr_user:
            ok(f"drugref DB account is least-privilege (db_user={dr_user})")

    # 1. pods, containers, networks, log driver
    pods = [(s.app_pod, "'carlos-ctl play'"), (s.waf_pod, "'carlos-ctl play'")]
    if s.obs_enabled:
        pods.insert(1, (s.obs_pod, "'carlos-ctl play'"))
    for pod, remedy in pods:
        if runner.ok(runner.podman_user_argv(["pod", "exists", pod])):
            ok(f"{pod} pod exists")
        else:
            bad(f"{pod} pod missing — {remedy}")
    for net in (s.net_name, s.edge_net_name):
        if runner.ok(runner.podman_user_argv(["network", "exists", net])):
            ok(f"{net} network exists")
        else:
            bad(f"{net} network missing — run the provisioning playbook")
    containers = [f"{s.app_pod}-db", f"{s.app_pod}-drugref", f"{s.app_pod}-carlos",
                  f"{s.waf_pod}-waf"]
    if s.obs_enabled:
        containers += [
            f"{s.app_pod}-mysqld-exporter", f"{s.app_pod}-vmagent",
            f"{s.obs_pod}-node-exporter", f"{s.obs_pod}-victorialogs",
            f"{s.obs_pod}-victoria-metrics", f"{s.obs_pod}-logcollect",
            f"{s.obs_pod}-logview", f"{s.obs_pod}-vmalert",
        ]
    for c in containers:
        if ctr_up(c):
            ok(f"container up: {c}")
        else:
            bad(f"container not running: {c}")
    for c in (f"{s.app_pod}-carlos", f"{s.waf_pod}-waf"):
        drv = runner.output(runner.podman_user_argv(
            ["inspect", c, "--format", "{{.HostConfig.LogConfig.Type}}"]
        )).strip()
        if drv == "journald":
            ok(f"{c} uses the journald log driver")
        else:
            bad(f"{c} log driver is '{drv or 'unknown'}', expected journald")

    # 1b. WAF/DB isolation — the point of the split-pod topology. Probes run
    # from inside the waf container over the edge network via bash /dev/tcp.
    if ctr_up(f"{s.waf_pod}-waf"):
        # (a) the waf CAN reach the app's TLS connector by pod name (proves
        # the proxy path — BACKEND is https://<app-pod>:8443). The bare TCP
        # open closes mid-TLS-handshake, so each run of this MANUAL verb
        # leaves one handshake-error line in the app's shipped log stream —
        # accepted noise (the periodic WAF liveness probe deliberately
        # avoids this class of noise by probing its own plain listener).
        if runner.ok(runner.podman_user_argv([
            "exec", f"{s.waf_pod}-waf", "timeout", "5", "bash", "-c",
            f"exec 3<>/dev/tcp/{s.app_pod}/8443",
        ])):
            ok(f"waf reaches {s.app_pod}:8443 (TLS backend) over {s.edge_net_name}")
        else:
            bad(
                f"waf cannot reach {s.app_pod}:8443 — pod-name DNS or the edge network is "
                f"broken. If aardvark registers container names (not pod names), point the "
                f"waf pod's BACKEND at https://{s.app_pod}-carlos:8443, then re-play."
            )
        # (a2) the PLAINTEXT connector must NOT be reachable cross-pod: it is
        # loopback-pinned (address=127.0.0.1 in server.xml) so no PHI can
        # transit the edge network unencrypted. Reachable = a server.xml
        # regression (the address pin dropped in an upstream sync).
        if runner.ok(runner.podman_user_argv([
            "exec", f"{s.waf_pod}-waf", "timeout", "5", "bash", "-c",
            f"exec 3<>/dev/tcp/{s.app_pod}/8080",
        ])):
            bad(
                f"waf CAN reach {s.app_pod}:8080 — the PLAINTEXT Tomcat connector is "
                f"exposed on the edge network (server.xml lost its address=127.0.0.1 "
                f"pin?); PHI would transit unencrypted. Restore the pin and re-play."
            )
        else:
            ok(f"waf cannot reach {s.app_pod}:8080 (plaintext connector loopback-only)")
        # (b) the waf must NOT reach MariaDB — bind_address=127.0.0.1 keeps
        # 3306 off the app pod's network interfaces (connect must fail).
        # Shared probe: the recurring monitor re-asserts the same boundary
        # so a drift between plays is caught within a sweep.
        isolation = waf_db_isolation_broken(runner)
        if isolation is True:
            bad(
                f"waf CAN reach {s.app_pod}:3306 — WAF/DB ISOLATION BROKEN: merge "
                f"'bind_address = 127.0.0.1' into {s.conf_dir}/mariadb/zz-carlos.cnf and re-play"
            )
        elif isolation is False:
            ok(f"waf cannot reach {s.app_pod}:3306 (MariaDB isolated from the edge pod)")
        else:
            bad(
                "the WAF->3306 isolation probe could not RUN (podman exec failed — "
                "bash/timeout missing from the waf image?) — the boundary is "
                "UNVERIFIED, not verified-intact"
            )
        # (c) the waf must NOT reach the unauthenticated PHI log store either —
        # the waf pod is deliberately edge-net-only. This pins the trust
        # boundary that keeps the unauthenticated store an accepted risk.
        if s.obs_enabled:
            if runner.ok(runner.podman_user_argv([
                "exec", f"{s.waf_pod}-waf", "timeout", "5", "bash", "-c",
                f"exec 3<>/dev/tcp/{s.obs_pod}/9428",
            ])):
                bad(
                    f"waf CAN reach {s.obs_pod}:9428 — the internet-facing WAF has a route to "
                    f"the unauthenticated PHI log store; the WAF pod must join ONLY "
                    f"{s.edge_net_name} (never {s.net_name})"
                )
            else:
                ok(f"waf cannot reach {s.obs_pod}:9428 (PHI log store isolated from the edge pod)")

    # 1d. THE front door, end to end: client -> nft redirect -> WAF TLS ->
    # proxy -> Tomcat. 2xx/3xx proves the whole chain; 502/503 means the
    # WAF+TLS work but the backend isn't answering.
    bind_ip, https_port, server = s.get("BIND_IP"), s.get("HTTPS_PORT"), s.get("SERVER_NAME")
    fd_code = runner.output([
        "curl", "-ks", "--noproxy", "*", "-m", "10", "-o", "/dev/null",
        "-w", "%{http_code}",
        "--connect-to", f"{server}:{https_port}:{bind_ip}:{https_port}",
        f"https://{server}:{https_port}/",
    ]).strip()
    if fd_code in ("502", "503"):
        bad(
            f"front door: WAF answers on https://{bind_ip}:{https_port}/ but the backend does "
            f"not (HTTP {fd_code}) — app still starting, or the waf->app proxy path is broken"
        )
    elif fd_code.startswith(("2", "3")):
        ok(f"front door serves https://{bind_ip}:{https_port}/ (HTTP {fd_code})")
        # Security headers on the PHI front door. nginx add_header does NOT
        # inherit into a block with its own add_header — probe the SERVED HSTS
        # header so that regression is caught here instead of silently
        # shipping an unprotected front door.
        headers = runner.output([
            "curl", "-ksI", "--noproxy", "*", "-m", "10",
            "--connect-to", f"{server}:{https_port}:{bind_ip}:{https_port}",
            f"https://{server}:{https_port}/",
        ])
        if any(line.lower().startswith("strict-transport-security:")
               for line in headers.splitlines()):
            ok("front door sets the HSTS security header")
        else:
            bad(
                "front door serves but is MISSING the Strict-Transport-Security header — the "
                "nginx-headers.conf include is not applying (add_header suppressed by a "
                "server/location block? see conf/waf/nginx-headers.conf)"
            )
    else:
        bad(
            f"front door unreachable on https://{bind_ip}:{https_port}/ (got "
            f"'{fd_code or '000'}') — nft redirect, WAF, or TLS is broken"
        )

    # 1e. DrugRef reachable from the CARLOS container over pod loopback.
    if ctr_up(f"{s.app_pod}-carlos"):
        if runner.ok(runner.podman_user_argv([
            "exec", f"{s.app_pod}-carlos", "timeout", "5", "bash", "-c",
            "exec 3<>/dev/tcp/127.0.0.1/8180",
        ])):
            ok("drugref answers on pod loopback :8180")
        else:
            bad(
                "drugref not reachable on 127.0.0.1:8180 from the carlos container — "
                "drug/interaction lookups will fail"
            )

    if s.obs_enabled:
        # 2. stores reachable (host loopback; authenticated via store_curl)
        vm_port = s.get("VICTORIAMETRICS_PORT")
        vl_port = s.get("VICTORIALOGS_PORT")
        vm_ok = obsquery.store_curl(
            runner, f"http://127.0.0.1:{vm_port}/health", timeout=5
        ).returncode == 0
        if vm_ok:
            ok(f"VictoriaMetrics reachable (127.0.0.1:{vm_port})")
        else:
            bad(f"VictoriaMetrics unreachable on 127.0.0.1:{vm_port}")
        vl_ok = vl_query(runner, "_time:1m") is not None
        if vl_ok:
            ok(f"VictoriaLogs reachable (127.0.0.1:{vl_port})")
        else:
            bad(f"VictoriaLogs unreachable on 127.0.0.1:{vl_port}")
        # 2b. store-auth ENFORCEMENT: with a credential provisioned, a
        # deliberately credential-less query must be REJECTED — the exact
        # regression (any local process reading 180d of PHI-adjacent logs)
        # the auth exists to close.
        if s.obs_http_password_file.is_file() and vm_ok:
            if obsquery.store_curl(
                runner, f"http://127.0.0.1:{vm_port}/api/v1/query",
                args=["--data-urlencode", "query=up"],
                timeout=5, with_auth=False,
            ).returncode != 0:
                ok("store auth enforced (credential-less query rejected)")
            else:
                bad(
                    "the metrics store answered a CREDENTIAL-LESS query although an obs "
                    "http credential is provisioned — store auth is not enforced; re-run "
                    "the playbook and 'carlos-ctl play' so the stores pick up "
                    "-httpAuth.* (or set carlos_obs_http_auth: false deliberately)"
                )

        # 3. metrics pipeline: scrape + cross-pod remote-write + DNS + creds
        if vm_ok:
            total_up = vm_scalar(runner, "count(up)")
            if (not total_up or total_up == "0") and ctr_up(f"{s.app_pod}-vmagent"):
                bad(
                    f"no metrics in VictoriaMetrics though vmagent is running — most likely "
                    f"CROSS-POD DNS: vmagent cannot resolve '{s.obs_pod}'. If aardvark "
                    f"registers container names (not pod names), set the app pod's "
                    f"-remoteWrite.url to http://{s.obs_pod}-victoria-metrics:8428/api/v1/write "
                    f"(and the waf pod's BACKEND to https://{s.app_pod}-carlos:8443), then re-play."
                )
            else:
                for j in ("node", "mariadb", "vmagent"):
                    if vm_scalar(runner, f'count(up{{job="{j}"}} == 1)') == "1":
                        ok(f"metrics target up: {j}")
                    else:
                        bad(f"metrics target not up in VM: {j}")
                if vm_scalar(runner, "mysql_up") == "1":
                    ok("mysqld-exporter connected to MariaDB (mysql_up==1)")
                else:
                    bad(
                        "mysql_up != 1 — mysqld-exporter cannot read its .my.cnf or connect "
                        "to the db"
                    )
        else:
            bad("skipping metrics checks — VictoriaMetrics unreachable")

        # 4. log pipeline: journald driver + collector/journalctl + shipping
        if vl_ok:
            for stream in ("carlos", "db", "waf-access"):
                out = vl_query(runner, f'_stream:{{stream="{stream}"}} _time:10m')
                if out:
                    ok(f"logs flowing for stream '{stream}'")
                else:
                    bad(
                        f"no '{stream}' logs in the last 10m — journald collector may be down "
                        f"(check: journalctl (service user) {s.obs_pod}-logcollect)"
                    )
        else:
            bad("skipping log checks — VictoriaLogs unreachable")
        if ctr_up(f"{s.obs_pod}-logcollect"):
            # Scan stdout AND stderr (the bash's `2>&1` was load-bearing):
            # `podman logs` replays the container's stderr on stderr, and
            # Vector emits its ERROR lines there — stdout-only scanning
            # false-greens exactly the broken-collector case this exists for.
            cp = runner.run(runner.podman_user_argv(
                ["logs", "--tail", "50", f"{s.obs_pod}-logcollect"]
            ), capture=True)
            logs = (cp.stdout or "") + (cp.stderr or "")
            if re.search(r"journalctl.*(not found|no such file)|permission denied", logs, re.I):
                bad(
                    "logcollect reports a journalctl/permission error — is VECTOR_IMAGE the "
                    "-debian variant (it needs journalctl)?"
                )
            else:
                ok("logcollect running without journalctl errors")
    else:
        log("observability pod disabled (OBS_ENABLED=0) — store/pipeline checks skipped; "
            "logs stay in journald (podman logs / journalctl)")

    # 5. host prerequisites
    if s.journal_dir.is_dir():
        ok(f"persistent journald ({s.journal_dir})")
    else:
        bad(
            f"{s.journal_dir} missing — journald not persistent; a store outage won't "
            f"backfill across a reboot"
        )
    cert = s.conf_dir / "waf" / "certs" / "fullchain.pem"
    warn_days = s.get_int("CERT_EXPIRY_WARN_DAYS")
    if cert.is_file():
        if runner.ok(["openssl", "x509", "-checkend", str(warn_days * 86400),
                      "-noout", "-in", str(cert)]):
            ok(f"TLS cert valid (> {warn_days}d)")
        else:
            bad(f"TLS cert expires within {warn_days} days (or already expired)")
    else:
        bad(f"no TLS cert at {cert}")
    # DR posture: a LOCAL restic repository is not disaster recovery (a disk
    # loss/ransomware/fire takes the EMR and its backups together). Warn
    # (posture, not a hard check failure) unless explicitly accepted.
    from .util import first_match

    repo = ""
    repo_env = s.conf_dir / "restic" / "restic.env"
    if repo_env.is_file():
        repo = first_match(repo_env.read_text().splitlines(), "RESTIC_REPOSITORY") or ""
    elif s.secrets_bundle.is_file():
        from . import secrets as secrets_mod

        try:
            env_text = secrets_mod.bundle_get(runner, "restic", "env")
            repo = first_match(env_text.splitlines(), "RESTIC_REPOSITORY") or ""
        except CtlError:
            repo = ""
    if not repo:
        repo = s.get("RESTIC_REPOSITORY")
    if restic_local_path(repo) and not s.flag("CARLOS_ACCEPT_LOCAL_REPO"):
        warn(
            f"restic repository is LOCAL ({repo}) — a local-only backup dies with the host "
            f"(disk failure, ransomware, theft, fire). Set an OFFSITE RESTIC_REPOSITORY "
            f"(s3:/rest:/sftp:/b2:) in {repo_env}, or CARLOS_ACCEPT_LOCAL_REPO=1 to accept "
            f"this posture."
        )
    check_swap_encryption(runner)

    print(f"\n{counts['pass']} passed, {counts['fail']} failed")
    return 0 if counts["fail"] == 0 else 1


def check_swap_encryption(runner: Runner) -> None:
    """Best-effort warning when active swap looks unencrypted: decrypted
    secret material (the age key, restic env, PHI dumps) is staged in tmpfs,
    which can page to swap under memory pressure and survive a reboot in
    cleartext. Heuristic only — dm-crypt swap shows as /dev/mapper/* or
    /dev/dm-*, zram is RAM-backed; anything else gets the warning."""
    if not runner.have("swapon"):
        return
    out = runner.output(["swapon", "--noheadings", "--show=NAME"])
    for dev in out.splitlines():
        dev = dev.strip()
        if not dev:
            continue
        if dev.startswith(("/dev/mapper/", "/dev/dm-", "/dev/zram", "zram")):
            continue
        warn(
            f"active swap on '{dev}' does not look encrypted — decrypted secrets and PHI "
            f"staged in tmpfs can page to it in cleartext. Use encrypted swap (dm-crypt), "
            f"zram, or no swap."
        )
