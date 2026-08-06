# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Within-instance validation gates shared by `play` (and the setup wizard).

Cross-INSTANCE collision checking (port sets, EMR_HOME, name-prefix overlap
across the registry) moved to the Ansible role's assert tasks — the playbook
sees every instance's host_vars at once. What stays here is everything that
must hold at RUNTIME for this one instance, plus the live-host probes Ansible
cannot know (a foreign nft table, a foreign listener on our ports)."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Optional

from .config import _DEFAULTS, PORT_DEFAULTS, ROOTLESS_PUBLISHED_PORTS, Settings
from .runner import Runner
from .util import CtlError, size_to_mib, warn

_INSTANCE_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")

# The highest container id this deployment needs mapped into the service
# user's rootless userns. 65534 is `nobody`/`nogroup`: the mysqld-exporter
# runs as it (the pod spec's runAsUser, and the uid `play` maps its 0600
# my.cnf to), and — less obviously — apt-get drops to it INSIDE the image
# builds, so a range that cannot reach it also breaks `carlos-ctl build`.
# The other pinned ids (10001 carlos/drugref, 10013 caddy, 999 mariadb) are
# all below it, so one ceiling covers them.
#
# A grant of COUNT sub-ids maps container ids 1..COUNT (podman's map is
# `0 <uid> 1` + `1 <base> <COUNT>`), so covering 65534 needs COUNT >= 65534 —
# measured live: base 165536 with the exporter file at host uid 231069 =
# 165536 + 65534 - 1. The conventional grant is 65536, which is why the
# remedy still says "widen to 65536" rather than to this bare minimum.
MAX_CONTAINER_ID = 65534


def _first_subid_grant(user: str, path: Path) -> Optional[int]:
    """Width (count) of the FIRST /etc/subuid|subgid grant for `user`, or None
    when the file is unreadable or carries no grant for them.

    The FIRST line specifically: rootless podman 4.9 builds the userns map
    from one grant, so appending a SECOND range to a user who already has a
    narrow one does not widen the map (measured: grants `165536:34464` +
    `200000:65536` produced `1 165536 34464` and nothing else). The remedy is
    always to widen the existing grant, never to add another."""
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return None
    for line in lines:
        fields = line.split(":")
        if len(fields) != 3 or fields[0] != user:
            continue
        try:
            return int(fields[2])
        except ValueError:
            return None
    return None


def subid_map_preflight(runner: Runner) -> None:
    """Warn when subordinate ID grants cannot map required container IDs.

    Existing service accounts may have ranges narrower than the 65,536 IDs
    allocated by the Ansible role. Such ranges prevent image builds and
    rootless ownership changes for containers that use IDs up to 65,534. This
    runtime check warns because the CLI does not own the host allocation; the
    Ansible role enforces the requirement during provisioning.
    """
    s = runner.settings
    # Overridable only so the hermetic suite can point at fixture files —
    # production always reads /etc (same doctrine as CARLOS_SYSTEMD_DIR).
    subid_dir = Path(s._env.get("CARLOS_SUBID_DIR", "/etc"))  # noqa: SLF001
    for fname, kind in (("subuid", "uid"), ("subgid", "gid")):
        width = _first_subid_grant(s.service_user, subid_dir / fname)
        if width is None:
            continue  # unreadable/absent: podman itself will say so, loudly
        if width >= MAX_CONTAINER_ID:
            continue
        warn(
            f"{subid_dir / fname}: the first grant for '{s.service_user}' maps only "
            f"{width} sub{kind}s, but this deployment pins container {kind} "
            f"{MAX_CONTAINER_ID} (mysqld-exporter, and apt inside the image builds) — "
            f"an unmapped id makes chown(2) fail with EINVAL. WIDEN THE EXISTING "
            f"GRANT to the conventional 65536 (rootless podman maps from the "
            f"FIRST grant only, so appending a second range does NOT help): "
            f"usermod --del-sub{kind}s <old-range> --add-sub{kind}s <base>-<base+65535> "
            f"{s.service_user}, then 'podman system migrate' as that user"
        )


# podman's ROOTLESS NETWORK NAMESPACE hides part of the filesystem from
# itself. Measured on podman 4.9.3 — the documented floor — from
# /proc/self/mountinfo inside `podman unshare --rootless-netns`:
#   * /run is replaced UNCONDITIONALLY (mount(runDir, "/run", MS_BIND|MS_REC)),
#     in every podman version.
#   * the CNI state dir is bind-mounted over from an EMPTY scratch dir, and
#     podman walks UP from it to the first path that EXISTS ("if /var/lib/cni
#     does not exist, use the parent dir") — so on a host without
#     /var/lib/cni the mask lands on /var/lib. Unconditional in podman 4.x;
#     podman 5 gates it on the CNI backend.
CNI_STATE_DIR = "/var/lib/cni"
_ALWAYS_MASKED_PREFIXES = ("/run/", "/var/run/")


def graphroot_preflight(runner: Runner) -> None:
    """Refuse to deploy when podman's graphroot is hidden inside podman's own
    rootless network namespace.

    netavark reads its network definitions from `<graphroot>/networks`. When
    that path falls under what the netns masks, the definitions are gone
    exactly where they have to be resolved, and EVERY named bridge network
    fails at container start with

        unable to find network with name or ID <net>: network not found

    Every pod here is on a named bridge network (`carlos-net`, `carlos-edge`),
    so `play` dies on its first `podman kube play` with that message and
    nothing pointing at the cause — the network genuinely exists, `podman
    network ls` and `podman network inspect` both show it, and only the
    namespace that matters cannot see it.

    Ask podman where the graphroot ACTUALLY is rather than deriving it from
    the service user's home: a site-supplied storage.conf
    (`rootless_storage_path`) can move it, and then the home says nothing
    about where the hazard applies.

    REFUSE, not warn: unlike the subuid width probe (which degrades one
    sidecar), this means no container starts at all, so there is no working
    deploy to protect by continuing."""
    s = runner.settings
    graphroot = runner.output(
        runner.podman_user_argv(["info", "--format", "{{.Store.GraphRoot}}"])
    ).strip()
    if not graphroot:
        return  # podman itself is unhappy; it reports that far more clearly
    probe = graphroot.rstrip("/") + "/"
    # Fail CLOSED on a malformed override: an empty or relative
    # CARLOS_CNI_STATE_DIR would make the prefix match below unsatisfiable
    # (and is_dir() would resolve against cwd), silently disabling the
    # /var/lib branch of this guard. The knob is test-only; a bad value must
    # degrade to the real default, not to no protection.
    cni_dir = Path(s._env.get("CARLOS_CNI_STATE_DIR") or CNI_STATE_DIR)  # noqa: SLF001
    if not cni_dir.is_absolute():
        cni_dir = Path(CNI_STATE_DIR)
    if probe.startswith(_ALWAYS_MASKED_PREFIXES):
        why = (
            "podman's rootless network namespace replaces /run unconditionally "
            "(and /run is tmpfs, so an engine store there would not survive a reboot)"
        )
        remedy = (
            "point the store outside /run — set carlos_service_user_home in host_vars "
            "(it is the graphroot's parent) or rootless_storage_path in "
            "/etc/containers/storage.conf — then re-run the playbook"
        )
    elif probe.startswith(str(cni_dir.parent) + "/") and not cni_dir.is_dir():
        why = (
            f"podman's rootless network namespace bind-mounts an empty dir over the CNI "
            f"state dir, walking UP from {cni_dir} to the first path that EXISTS — and "
            f"{cni_dir} does not exist on this host, so it masks {cni_dir.parent}"
        )
        remedy = (
            f"mkdir -p {cni_dir}   (moves the mask off {cni_dir.parent}; the "
            f"provisioning playbook creates it), or move the store outside "
            f"{cni_dir.parent}"
        )
    else:
        return
    raise CtlError(
        f"podman's graphroot for service user '{s.service_user}' is {graphroot}, which "
        f"podman hides from its own rootless network namespace: {why}. netavark reads "
        f"<graphroot>/networks, so INSIDE that namespace every named bridge network "
        f"resolves as 'network not found' and no pod can start — even though 'podman "
        f"network ls' on the host lists them. Fix: {remedy}."
    )


def validate_image_digests(settings: Settings) -> None:
    """Warn when a THIRD-PARTY image override drops its `@sha256:` digest pin.
    The defaults pin every non-local image by digest so a re-pushed tag can't
    silently change what a PHI system runs; an operator override in
    carlos-app.env that uses a bare tag defeats that content-addressing with no
    other signal. The two locally-built images (localhost/carlos-app,
    localhost/carlos-drugref) are exempt — they carry no registry digest.
    Warn, don't fail: a tag-only override may be a deliberate (if weaker)
    choice, but it must never pass unremarked."""
    unpinned = []
    for key in (k for k in _DEFAULTS if k.endswith("_IMAGE")):
        value = settings.get(key)
        if not value or value.startswith("localhost/"):
            continue
        if "@sha256:" not in value:
            unpinned.append(f"{key}={value}")
    if unpinned:
        warn(
            "third-party image reference(s) are NOT digest-pinned (no @sha256:) — a "
            "re-pushed tag could silently change what runs on a PHI host; pin them with "
            "'<repo>:<tag>@sha256:<digest>' in carlos-app.env: " + ", ".join(unpinned)
        )


def validate_instance_name(settings: Settings) -> None:
    """INSTANCE feeds systemd unit names, pod names, the nftables table, the
    journal-filter prefixes, and uninstall's "$INSTANCE-*" globs — enforce a
    safe charset up front."""
    if not _INSTANCE_RE.match(settings.instance):
        raise CtlError(
            f"INSTANCE='{settings.instance}' — use lowercase letters, digits, and '-' only "
            f"(it names systemd units, pods, and the nftables table)"
        )


def validate_bind_ip(settings: Settings) -> None:
    """Reject a BIND_IP that would silently defeat the nftables gate. The
    redirect and log-view filter are IPv4 `table ip` rules keyed on
    `ip daddr $BIND_IP`, so an IPv6 literal never matches, and 0.0.0.0 matches
    EVERY destination — a no-op front-door gate while services still bind all
    interfaces (the PHI log view would be internet-reachable behind only
    shared basic-auth). Fail closed."""
    ip = settings.get("BIND_IP")
    if ":" in ip:
        raise CtlError(
            f"BIND_IP={ip} looks like IPv6, but the nftables redirect/gate is IPv4-only "
            f"(table ip) — set an IPv4 address"
        )
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        raise CtlError(
            f"BIND_IP={ip} is not a valid IPv4 address — set the host IPv4 that end users "
            f"reach the WAF on"
        ) from None
    if ip == "0.0.0.0" and not settings.flag("CARLOS_ALLOW_ANY_BIND"):  # noqa: S104
        raise CtlError(
            "BIND_IP=0.0.0.0 makes the nftables 'ip daddr' gate a no-op (it matches every "
            "destination) while services bind ALL interfaces — the PHI log view would be "
            "internet-reachable behind only shared basic-auth. Set a specific host IPv4, or "
            "CARLOS_ALLOW_ANY_BIND=1 to accept binding all interfaces on purpose."
        )


def validate_log_view_cidr(settings: Settings) -> None:
    """Validate LOG_VIEW_ALLOW_CIDR BEFORE it reaches the nft ruleset. It is
    emitted verbatim into `ip saddr <cidr> accept`; a malformed value fails
    `nft -f`, which must never leave the PHI log-view drop-gate uninstalled.
    Accept a single IPv4 CIDR, a comma/brace set of them, the literal
    `rfc1918`, or empty (auto-derive at provisioning)."""
    v = settings.get("LOG_VIEW_ALLOW_CIDR")
    if not v or v == "rfc1918":
        return
    stripped = v.replace("{", "").replace("}", "").replace(" ", "")
    for tok in stripped.split(","):
        if not tok:
            continue
        try:
            ipaddress.IPv4Network(tok, strict=False)
            if "/" not in tok:
                raise ValueError("prefix required")
        except ValueError:
            raise CtlError(
                f"LOG_VIEW_ALLOW_CIDR='{v}' is not a valid IPv4 CIDR (or comma/brace set), "
                f"e.g. 10.0.0.0/24, or the literal 'rfc1918' — a malformed value would fail "
                f"the nftables apply and leave the PHI log view unfiltered"
            ) from None


def validate_ports(settings: Settings) -> None:
    """Range + numeric validity for every published port, rootless >=1024 for
    the directly-bound ones, and within-instance uniqueness (HTTPS_PORT ==
    HTTPS_PUBLISH_PORT would make the nft redirect a no-op, and duplicated
    listener ports cannot both bind)."""
    owner: dict = {}
    for var, _default in PORT_DEFAULTS:
        val = settings.get(var)
        if not val.isdigit() or not (1 <= int(val) <= 65535):
            raise CtlError(f"{var}='{val}' is not a valid TCP port (1-65535)")
        if val in owner:
            raise CtlError(
                f"{var}={val} duplicates {owner[val]} — every port of an instance must be unique"
            )
        owner[val] = var
    for var in ROOTLESS_PUBLISHED_PORTS:
        if int(settings.get(var)) < 1024:
            raise CtlError(
                f"{var}={settings.get(var)} is below 1024 — the rootless engine cannot bind a "
                f"privileged port; use >=1024 (only HTTPS_PORT may be privileged, since root "
                f"installs the nftables redirect)"
            )


def check_foreign_nft_claim(runner: Runner) -> None:
    """Live-host check Ansible cannot do from vars alone: a FOREIGN nft table
    already claiming this front door (catches a manual/unregistered redirect).
    Skipped in the hermetic suite, which sets CARLOS_SYSTEMD_DIR and stubs nft."""
    s = runner.settings
    if s._env.get("CARLOS_SYSTEMD_DIR") or not runner.have("nft"):  # noqa: SLF001
        return
    cp = runner.run(["nft", "list", "tables", "ip"], capture=True)
    if cp.returncode != 0:
        # Fail OPEN but never silently: an errored probe (kernel without
        # nf_tables, permission) is not "no foreign claim" — say so, so a
        # front-door collision is not later misread as impossible.
        warn(
            "could not list nftables tables (nft errored) — SKIPPING the foreign "
            "front-door-claim check; verify no other instance redirects "
            f"{s.get('BIND_IP')}:{s.get('HTTPS_PORT')} by hand (nft list tables ip)"
        )
        return
    tables = cp.stdout or ""
    for line in tables.splitlines():
        table = line.split()[-1] if line.split() else ""
        if not table.endswith("-nat") or table == f"{s.instance}-nat":
            continue
        ruleset = runner.output(["nft", "list", "table", "ip", table])
        if f"ip daddr {s.get('BIND_IP')} tcp dport {s.get('HTTPS_PORT')} " in ruleset:
            raise CtlError(
                f"nftables table '{table}' already redirects "
                f"{s.get('BIND_IP')}:{s.get('HTTPS_PORT')} — another instance owns this front "
                f"door; choose a distinct HTTPS_PORT or BIND_IP for '{s.instance}'"
            )


def validate_instance(runner: Runner) -> None:
    """The within-instance slice of the bash check_instance_collisions."""
    validate_instance_name(runner.settings)
    validate_bind_ip(runner.settings)
    validate_log_view_cidr(runner.settings)
    validate_ports(runner.settings)
    validate_image_digests(runner.settings)
    graphroot_preflight(runner)
    subid_map_preflight(runner)
    check_foreign_nft_claim(runner)


def port_in_use_preflight(runner: Runner) -> None:
    """Refuse to play onto host ports a FOREIGN process already holds: `podman
    kube play` would otherwise fail with an opaque bind error long after setup
    said OK. Skipped when this instance's own pod is already up (a re-play
    legitimately holds its own ports). Best-effort: no ss => skip with a note."""
    s = runner.settings
    if not runner.have("ss"):
        warn("ss not found — skipping the host port-in-use preflight")
        return
    waf_up = obs_up = pma_up = False
    if runner.have("podman"):
        names = runner.output(
            runner.podman_user_argv(["ps", "--format", "{{.Names}}"])
        ).splitlines()
        if f"{s.app_pod}-carlos" in names:
            return  # our pod already runs — it owns these ports
        # A PARTIAL-outage recovery: the app pod is down but the WAF (holding
        # HTTPS_PUBLISH_PORT), obs (LOG_VIEW/store ports), or an on-demand pma
        # (PMA_PORT) is still up. Those are OUR listeners, not a foreign
        # process — treating them as "in use by another listener" would refuse
        # a legitimate recovery play and push the operator toward the blanket
        # CARLOS_SKIP_PORT_PREFLIGHT bypass. Exempt only the ports whose owning
        # pod we can SEE running, so a genuinely-foreign holder still trips.
        waf_up = any(n.startswith(f"{s.waf_pod}-") for n in names)
        obs_up = any(n.startswith(f"{s.obs_pod}-") for n in names)
        pma_up = any(n.startswith(f"{s.instance}-pma-ondemand") for n in names)
    from .config import OBS_PORTS

    # Which of OUR listeners already holds each published port — so a live
    # waf/obs/pma is not misread as a foreign process squatting the port.
    own_holder = {"HTTPS_PUBLISH_PORT": waf_up, "PMA_PORT": pma_up}
    for _p in OBS_PORTS:
        own_holder[_p] = obs_up

    ports = ["HTTPS_PUBLISH_PORT", "LOG_VIEW_PORT", "VICTORIALOGS_PORT",
             "VICTORIAMETRICS_PORT", "PMA_PORT", "VMALERT_PORT"]
    if not s.obs_enabled:
        ports = [p for p in ports if p not in OBS_PORTS]
    for var in ports:
        p = s.get(var)
        if not p:
            continue
        if own_holder.get(var):
            continue  # our own waf/obs/pma legitimately holds this port
        cp = runner.run(["ss", "-tlnH", f"sport = :{p}"], capture=True)
        if cp.returncode != 0:
            # Fail OPEN but never silently — an ss error is not "port free".
            warn(
                f"ss errored probing port {p} — SKIPPING the in-use preflight for it; "
                f"if 'podman kube play' fails with a bind error, check the port by hand"
            )
            continue
        if (cp.stdout or "").strip():
            if not s.flag("CARLOS_SKIP_PORT_PREFLIGHT"):
                raise CtlError(
                    f"host port {p} is already in use by another listener and this instance is "
                    f"not running — 'podman kube play' would fail with an opaque bind error. "
                    f"Free the port, offset this instance's ports in {s.env_file}, or set "
                    f"CARLOS_SKIP_PORT_PREFLIGHT=1 to bypass."
                )
            # Bypass engaged, but a real conflict was POSITIVELY detected — never
            # let that pass unremarked: the opaque bind failure would otherwise
            # look like an unrelated podman error.
            warn(
                f"host port {p} IS in use by another listener, but CARLOS_SKIP_PORT_PREFLIGHT=1 "
                f"suppressed the refusal — 'podman kube play' may still fail with a bind error"
            )


def check_mem_margin(name: str, mem_limit: str, java_xmx: str, min_margin_mib: int) -> None:
    """Guard the container-memory-vs-JVM-heap invariant: -Xmx must sit below
    the container memory limit by a non-heap margin so a Java OutOfMemoryError
    (which writes the heap dump) fires before the cgroup OOM-killer SIGKILLs
    the process. die on the clearly-broken case; warn on a thin margin."""
    lim = size_to_mib(mem_limit)
    if lim is None:
        warn(f"cannot parse {name} memory limit '{mem_limit}' — skipping margin check")
        return
    xmx = size_to_mib(java_xmx)
    if xmx is None:
        warn(f"cannot parse {name} JVM Xmx '{java_xmx}' — skipping margin check")
        return
    if xmx >= lim:
        raise CtlError(
            f"{name}: JVM -Xmx ({java_xmx}) >= container memory limit ({mem_limit}) — the heap "
            f"alone meets/exceeds the cgroup limit, so the OOM-killer will SIGKILL the JVM "
            f"before any heap dump. Lower *_JAVA_XMX or raise *_MEM_LIMIT."
        )
    if lim - xmx < min_margin_mib:
        warn(
            f"{name}: only {lim - xmx}MiB of non-heap headroom (limit {mem_limit} minus Xmx "
            f"{java_xmx}); CARLOS wants ~2-4Gi so a Java OOM writes the heap dump before the "
            f"cgroup OOM-killer fires. Consider raising *_MEM_LIMIT."
        )
