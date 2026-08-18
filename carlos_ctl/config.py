# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Instance configuration: carlos-app.env parsing, defaults, derived identity.

PRECEDENCE (matches the bash sourcing order): value from carlos-app.env
> process environment > built-in default. EMR_HOME is special: the process
environment (or /usr/local/emr) selects WHICH env file to read, and the file
may then re-point EMR_HOME — the hermetic test suite relies on exactly that.

SECURITY BOUNDARY — parse, don't source: the bash sourced carlos-app.env
(root-owned, acceptable) but had to hand-parse service-user-owned files.
Python never executes any of them: every file is parsed as KEY=value lines
with one layer of shell quoting decoded (the %q forms a sourcing shell would
have decoded for free). A hostile line is inert data.
"""

from __future__ import annotations

import os
import pwd
import re
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Tuple

from .util import CtlError, shell_unquote_value

_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Acknowledgement-knob truthy spellings. Shared by Settings.flag() and the
# persisted-oneshot warning so the two never drift (a value that flag() honors
# as ON must also trip the "left persisted in the env file" warning).
_TRUTHY_FLAGS = frozenset({"1", "true", "yes", "on"})

# Host ports, one per published service. Defined ONCE (VAR, default) and used
# both to seed the settings and to drive the play-time port preflight — the
# guard can never compare stale literals. (Cross-instance collision checking
# itself moved to the Ansible role's assert tasks.)
PORT_DEFAULTS: List[Tuple[str, int]] = [
    ("HTTPS_PORT", 443),
    ("HTTPS_PUBLISH_PORT", 8443),
    ("VICTORIALOGS_PORT", 9428),
    ("VICTORIAMETRICS_PORT", 8428),
    ("LOG_VIEW_PORT", 9443),
    ("PMA_PORT", 9444),
    # vmalert's HTTP API (rule state + /api/v1/alerts), obs pod, host loopback.
    ("VMALERT_PORT", 8880),
    # acme-mode only: where certbot's transient HTTP-01 listener publishes;
    # root's nftables redirects :80 here during renewal. No steady-state
    # listener, so it is deliberately NOT in port_in_use_preflight.
    ("HTTP_PUBLISH_PORT", 8081),
]
# Ports the ROOTLESS engine binds directly — cannot be <1024. HTTPS_PORT is
# NOT here: it is the user-facing front door redirected by ROOT's nftables.
ROOTLESS_PUBLISHED_PORTS = [
    "HTTPS_PUBLISH_PORT", "LOG_VIEW_PORT", "VICTORIALOGS_PORT",
    "VICTORIAMETRICS_PORT", "PMA_PORT", "VMALERT_PORT", "HTTP_PUBLISH_PORT",
]
# Ports the obs pod owns — not bound (and not preflighted) when OBS_ENABLED=0.
OBS_PORTS = ["LOG_VIEW_PORT", "VICTORIALOGS_PORT", "VICTORIAMETRICS_PORT", "VMALERT_PORT"]

# Third-party images pinned by DIGEST (repo:tag@sha256:...): the tag is
# human-readable, the digest makes the pull content-addressed — a re-pushed
# tag can't change what a PHI system runs. Resolve new digests with
#   skopeo inspect --format '{{.Digest}}' docker://<repo>:<tag>
# Digests below resolved 2026-07 (carried over from the bash verbatim).
_DEFAULTS: Dict[str, str] = {
    "BIND_IP": "127.0.0.1",
    "INSTANCE": "carlos",
    "SERVICE_USER": "carlos",
    "SERVER_NAME": "emr.example.ca",
    "CARLOS_IMAGE": "localhost/carlos-app:latest",
    "DRUGREF_IMAGE": "localhost/carlos-drugref:latest",
    "DB_IMAGE": "docker.io/library/mariadb:11.4.12@sha256:a794d9eb009e20de605858a11f32f63b4075cbd197c650436f0e3b457e4caed7",
    "VICTORIALOGS_IMAGE": "docker.io/victoriametrics/victoria-logs:v1.51.0@sha256:e16dd33a95623cc21730cf5285344ed9f97419eeaff7d24b039c135beb85ee7e",
    # DEBIAN variant on purpose: Vector's journald source shells out to
    # journalctl, which the -alpine image does NOT ship (Vector #23016).
    "VECTOR_IMAGE": "docker.io/timberio/vector:0.56.0-debian@sha256:93b072b416fd29152f1bfe5bd2925a0b48999aeb069f3ae000691f82a135c200",
    "CADDY_IMAGE": "docker.io/library/caddy:2.11.4@sha256:af5fdcd76f2db5e4e974ee92f96ee8c0fc3edb55bd4ba5032547cbf3f65e486d",
    # v1.136.0 is the current OSS LTS line for the VictoriaMetrics images.
    "VICTORIAMETRICS_IMAGE": "docker.io/victoriametrics/victoria-metrics:v1.136.0@sha256:593b533bfbea439f2fd8aed306294cb6a5b362e7932681ebb476cc6aaef70841",
    "VMAGENT_IMAGE": "docker.io/victoriametrics/vmagent:v1.136.0@sha256:30efe54696dfb352fe89a1a8b0c977cfce5507f81b85741632bd810fa3e4fe86",
    # -notifier.blackhole (the monitor-relay alerting design) exists since
    # v1.94 (VictoriaMetrics#4122); digest resolved 2026-07 from Docker Hub.
    "VMALERT_IMAGE": "docker.io/victoriametrics/vmalert:v1.136.0@sha256:e756ea8839f295b4e789a739c3ac80d70404e11b918973506a6182aacca2b11e",
    "NODE_EXPORTER_IMAGE": "quay.io/prometheus/node-exporter:v1.11.1@sha256:0f422f62c15f154af8d8572b23d623aebfb10cec73a5c654d18f911f3f9df241",
    "MYSQLD_EXPORTER_IMAGE": "quay.io/prometheus/mysqld-exporter:v0.19.0@sha256:eacb4b18e2ec1e0abdf2d64851b68526c964f6d9cb3e9458fb5d5f5062ea94c1",
    "METRICS_RETENTION": "180d",
    # Pinned to a dated build of the CRS 4.25 LTS line, NGINX variant
    # (ModSecurity v3) — see the WAF env contract note in the Ansible template.
    "WAF_IMAGE": "docker.io/owasp/modsecurity-crs:4.25.1-nginx-202607160307@sha256:a7d2e948d26ec310a127b261e4b9010ff2467b9f5f7eaed4921450bb7865ba08",
    "LOG_RETENTION": "180d",
    # A container's *_MEM_LIMIT must exceed its JVM *_JAVA_XMX by a non-heap
    # margin (~2-4Gi for CARLOS) so a Java OutOfMemoryError — which writes the
    # heap dump — fires before the cgroup OOM-killer SIGKILLs the process.
    "CARLOS_MEM_LIMIT": "12Gi",
    "CARLOS_JAVA_XMS": "4g",
    "CARLOS_JAVA_XMX": "8g",
    "DRUGREF_MEM_LIMIT": "2Gi",
    "DRUGREF_JAVA_XMS": "256m",
    "DRUGREF_JAVA_XMX": "1g",
    "DB_MEM_LIMIT": "6Gi",
    "VICTORIALOGS_MEM_LIMIT": "2Gi",
    "WAF_MEM_LIMIT": "1Gi",
    "CADDY_MEM_LIMIT": "256Mi",
    "VICTORIAMETRICS_MEM_LIMIT": "2Gi",
    "VMAGENT_MEM_LIMIT": "512Mi",
    "VMALERT_MEM_LIMIT": "256Mi",
    "NODE_EXPORTER_MEM_LIMIT": "128Mi",
    "MYSQLD_EXPORTER_MEM_LIMIT": "128Mi",
    "LOGCOLLECT_MEM_LIMIT": "512Mi",
    "CARLOS_CPU_LIMIT": "4",
    "DRUGREF_CPU_LIMIT": "2",
    "DB_CPU_LIMIT": "4",
    "VICTORIALOGS_CPU_LIMIT": "2",
    "WAF_CPU_LIMIT": "2",
    "CADDY_CPU_LIMIT": "1",
    "VICTORIAMETRICS_CPU_LIMIT": "2",
    "VMAGENT_CPU_LIMIT": "1",
    "VMALERT_CPU_LIMIT": "1",
    "NODE_EXPORTER_CPU_LIMIT": "1",
    "MYSQLD_EXPORTER_CPU_LIMIT": "1",
    "LOGCOLLECT_CPU_LIMIT": "1",
    "TZ": "America/Toronto",
    "LOG_VERBOSITY": "INFO",
    "DB_AUTO_UPGRADE": "1",
    "WAF_PARANOIA": "1",
    # 5/4, matching the ansible defaults (carlos_waf_anomaly_*). The WAF pod
    # renders these from the ansible var directly, so this default is only a
    # fallback — but it must not disagree with the role's secure value (10/5
    # would let a clean single-signature attack through, logged not blocked).
    "WAF_ANOMALY_INBOUND": "5",
    "WAF_ANOMALY_OUTBOUND": "4",
    # nginx ssl_protocols syntax (the WAF is the nginx CRS variant).
    "WAF_SSL_PROTOCOLS": "TLSv1.2 TLSv1.3",
    "WAF_SSL_CIPHERS": (
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
    ),
    # ABFHKZ = headers + matched rules, NO bodies (C/E/I/J carry PHI) — a
    # conscious HIPAA/PIPEDA decision, see README "WAF audit log & PHI".
    "WAF_AUDIT_LOG_PARTS": "ABFHKZ",
    "LOG_VIEW_USER": "logview",
    "LOG_VIEW_PASSWORD": "",
    "LOG_VIEW_ALLOW_CIDR": "",
    "PHPMYADMIN_IMAGE": "docker.io/library/phpmyadmin:5.2.3@sha256:aa4e217ae760c8f609840c28f612d86d017db5e37b5d4543764309f28fba2eb8",
    "RESTIC_PASSWORD": "",
    "RESTIC_IMAGE": "docker.io/restic/restic:0.19.0@sha256:7f44e0057b82348597568ea209360762d0b38f8e1dbc8ad859661ac1055e45f2",
    "BACKUP_ONCALENDAR": "*-*-* 01:30:00",
    "BINLOG_ONCALENDAR": "*:0/15",
    "DOCS_ONCALENDAR": "*:0/15",
    "BACKUP_VERIFY_ONCALENDAR": "Sun *-*-* 04:30:00",
    # Every 15 min — the monitor relays vmalert's firing rules, so its
    # cadence is the metric-alert PAGING ceiling (evaluation is continuous).
    "MONITOR_ONCALENDAR": "*:0/15",
    "ALERT_WEBHOOK": "",
    "ALERT_EMAIL": "",
    "HEARTBEAT_URL": "",
    "CERT_EXPIRY_WARN_DAYS": "21",
    "POD_DNS": "",
    # CARLOS version selection. `auto` (the default) resolves the newest
    # GitHub release of carlos-emr/carlos (non-prerelease > prerelease >
    # CARLOS_SOURCE_BRANCH HEAD) on the FIRST build and pins the answer in
    # $EMR_HOME/build/.source-pin — later builds stay on that pin, offline,
    # until `carlos-ctl source update`/`set`/`clear`. Any other value is a
    # manual ref (branch/tag/sha) with the historical build-from-source
    # semantics; env files rendered before this default flip carry
    # CARLOS_REF=develop and keep behaving exactly as they did. See
    # carlos_ctl/source.py for the full contract.
    "CARLOS_REF": "auto",
    # Artifact for the selected version: `auto` prefers a release's published
    # carlos-<tag>.war (sha256-verified, no Maven compile), falling back to a
    # source compile; `war`/`source` force one side. The auto choice is
    # persisted in the source pin like the version is.
    "CARLOS_ARTIFACT": "auto",
    # The no-releases fallback branch for auto resolution. The app repo's
    # default branch is `develop` (it has no `main`).
    "CARLOS_SOURCE_BRANCH": "develop",
    "DRUGREF_REF": "master",
    "CARLOS_SRC_SHA256": "",
    "DRUGREF_SRC_SHA256": "",
    "CARLOS_DB_ROOT_PASSWORD": "",
    # Observability profile: 1 = obs pod + vmagent/mysqld-exporter in the app
    # pod + vmalert-backed monitoring; 0 = journald-only logging, monitor runs
    # its own liveness sweep. Written by the Ansible role from
    # carlos_obs_enabled; toggling it is a playbook re-run + `play`.
    "OBS_ENABLED": "1",
    # 1 = the role installed the inet <instance>-hostfw default-deny table
    # (carlos_host_firewall_enabled), so the guard/monitor must verify it is
    # actually loaded — the nft oneshot is fail-open (a failed apply still
    # lets the pods start). Written by the Ansible role; defaults to 0 so
    # pre-existing env files (which lack the key) see no behavior change
    # until the playbook re-renders.
    "HOSTFW_ENABLED": "0",
    # Basic-auth username for the obs stores (VL/VM/vmalert); the password
    # lives ONLY in $EMR_HOME/secrets-private/obs-http-password (root 0600).
    "OBS_HTTP_USER": "obs",
    # Front-door TLS mode: selfsigned (auto-generated pair, the default) |
    # manual (operator-placed) | acme (certbot via cert-renew + daily timer).
    "CARLOS_TLS_MODE": "selfsigned",
    # acme-mode contact address (Let's Encrypt requires one).
    "ACME_EMAIL": "",
    # Digest-pinned like every third-party image (resolved 2026-07).
    "CERTBOT_IMAGE": "docker.io/certbot/certbot:v4.2.0@sha256:9626d72120577cf72da4fc7948806e9993598981720a4cbe04340a502468d67b",
}


# Every key carlos-ctl reads that is NOT in _DEFAULTS/PORT_DEFAULTS:
# acknowledgement flags, one-shot rotation inputs, monitor/backup thresholds,
# and the backup tunables whose primary home is restic.env (Settings is their
# documented fallback). Settings warns about carlos-app.env keys outside this
# union — a typo'd knob otherwise silently no-ops to its default.
_EXTRA_KNOWN_KEYS = frozenset({
    "EMR_HOME", "ENV_FILE", "JOURNAL_DIR", "CARLOS_TMPFILES_DIR",
    "AGE_ESCROW_CONFIRMED", "RESTIC_ESCROW_CONFIRMED",
    "ALERT_JOURNAL_ONLY", "ALERT_REMIND_HOURS",
    "BACKUP_MAX_AGE_HOURS", "BINLOG_MAX_AGE_MIN", "DOCS_MAX_AGE_MIN",
    "VERIFY_MAX_AGE_HOURS", "BOOT_GRACE_SECONDS", "DISK_MIN_FREE",
    "READY_WAIT_SECONDS", "WAF_5XX_WINDOW_MIN", "WAF_5XX_MAX",
    "CARLOS_ACCEPT_EMPTY_DATADIR", "CARLOS_ACCEPT_LOCAL_REPO",
    "CARLOS_ACCEPT_SCHEMA_MISMATCH", "CARLOS_ACCEPT_UNPINNED_BUILD",
    "CARLOS_ACCEPT_NEW_BINLOG_IDENTITY", "CARLOS_ACCEPT_BINLOG_IDENTITY_MISMATCH",
    "CARLOS_ALLOW_ANY_BIND", "CARLOS_ALLOW_DB_EXPOSED", "CARLOS_ALLOW_DB_ROOT",
    "CARLOS_ALLOW_NON_INNODB", "CARLOS_ALLOW_STALE_IMAGES",
    "CARLOS_BUILD_MODE", "CARLOS_DB_NEW_ROOT_PASSWORD",
    "CARLOS_DB_APP_PASSWORD", "CARLOS_DB_DRUGREF_PASSWORD",
    "CARLOS_DB_BACKUP_PASSWORD", "CARLOS_DB_EXPORTER_PASSWORD",
    "CARLOS_DOCS_MIN_FILES", "CARLOS_DRILL_ALLOW_NO_PITR", "CARLOS_INIT_REPO",
    "CARLOS_NO_HEARTBEAT",
    # Read via Settings.get in the attended-recovery unwrap (secrets.py) —
    # registering it kills the spurious unknown-key warning for operators who
    # persist it in carlos-app.env per the README. Deliberately NOT in
    # SECRET_ENV_KEYS: the value is a PATH to a passphrase file, not a
    # secret, so the DR secrets-stripped env copy correctly KEEPS the line.
    "CARLOS_RECOVERY_PASSPHRASE_FILE",
    # Build-context knobs. They live here — and are read through Settings.get,
    # not os.environ — so the documented configuration surface actually works:
    # carlos-app.env is where the CLI usage and the README tell operators to
    # put configuration, but these two were process-env-ONLY. Setting
    # CARLOS_EXTRA_CA_BUNDLE there (the natural place, and the one an Ansible
    # carlos_extra_env line writes to) both warned "carlos-ctl does not read
    # this key" AND silently did nothing, so a host behind a TLS-inspecting
    # proxy still failed its Maven fetch — twenty minutes into the build, with
    # a bare PKIX error. Neither value is a secret (they are paths).
    "CARLOS_BUILD_DIR", "CARLOS_EXTRA_CA_BUNDLE",
    # Manual/air-gapped WAR channel: with a manual CARLOS_REF and
    # CARLOS_ARTIFACT=war, these name the WAR to download and its sha256
    # (auto mode resolves both from the release and stores them in the source
    # pin instead). Public release-asset URLs/digests — deliberately NOT in
    # SECRET_ENV_KEYS, so the DR secrets-stripped env copy keeps them.
    "CARLOS_WAR_URL", "CARLOS_WAR_SHA256",
    "CARLOS_RESTORE_ACCEPT_UNSHIPPED",
    "CARLOS_RESTORE_BASE_DUMP_ONLY",
    "CARLOS_RESTORE_CONFIRMED", "CARLOS_SEAL_NO_TPM",
    "OBS_HTTP_NEW_PASSWORD",
    "CARLOS_SETUP_ALLOW_PLAINTEXT", "CARLOS_VAULT_PASSWORD_FILE",
    "SOURCE_DATE_EPOCH",
    "CARLOS_SKIP_AUTO_DB_USERS", "CARLOS_SKIP_PORT_PREFLIGHT",
    "CARLOS_STOP_BEFORE_DUMP_OK", "CARLOS_STOP_PAST_CHAIN_END_OK",
    "CARLOS_UNINSTALL_CONFIRMED", "CARLOS_UNINSTALL_INSTANCE",
    "RESTIC_NEW_PASSWORD", "RESTIC_REPOSITORY",
    "BACKUP_KEEP", "BACKUP_KEEP_BINLOG", "BACKUP_KEEP_DOCS",
    "CHECK_READ_DATA_DOW", "VERIFY_TMPFS_SIZE", "VERIFY_MEM_LIMIT",
})


# Known keys whose VALUES are secrets or capability URLs — everything the
# DR "secrets-stripped" env copy must drop. Defined next to
# the registry above so the strip and the registry cannot drift; the DR
# writer keeps a key only when it is BOTH known AND not listed here
# (unknown keys are dropped and warned — an operator's custom secret with
# an unrecognizable name must fail SAFE, not ride into the backup).
SECRET_ENV_KEYS = frozenset({
    "CARLOS_DB_ROOT_PASSWORD", "CARLOS_DB_NEW_ROOT_PASSWORD",
    "CARLOS_DB_APP_PASSWORD", "CARLOS_DB_DRUGREF_PASSWORD",
    "CARLOS_DB_BACKUP_PASSWORD", "CARLOS_DB_EXPORTER_PASSWORD",
    "LOG_VIEW_PASSWORD", "OBS_HTTP_NEW_PASSWORD",
    "RESTIC_PASSWORD", "RESTIC_NEW_PASSWORD", "RESTIC_REPOSITORY",
    "ALERT_WEBHOOK", "HEARTBEAT_URL",
})


def known_keys() -> frozenset:
    """The full set of env keys carlos-ctl consumes (defaults + ports +
    extras) — ONE registry, so the unknown-key warning can never drift from
    what the code actually reads."""
    return frozenset(_DEFAULTS) | {k for k, _ in PORT_DEFAULTS} | _EXTRA_KNOWN_KEYS


def parse_env_file(text: str, whitelist: Optional[Iterable[str]] = None) -> Dict[str, str]:
    """KEY=value parser with the bash read_env_whitelist semantics: ltrim,
    skip blanks/comments, strip a leading `export `, enforce a shell-name key,
    and decode one layer of shell quoting (the %q forms sourcing decoded for
    free). Never executes anything — a hostile line is inert data."""
    allowed = set(whitelist) if whitelist is not None else None
    out: Dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.lstrip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        if "=" not in line:
            # A non-blank, non-comment line with no '=' is almost always a typo
            # (a wrapped value, a stray word) — the bash source silently ignored
            # it, which hid the mistake. Warn, then skip.
            from .util import warn

            warn(f"ignoring malformed env line (no '='): {line.rstrip()!r}")
            continue
        key, val = line.split("=", 1)
        if not _KEY_RE.match(key):
            continue
        if allowed is not None and key not in allowed:
            continue
        # Decode exactly what a sourcing shell would have: $'...' ANSI-C and
        # backslash forms via shell_unquote_value; otherwise strip ONE layer of
        # surrounding matching quotes (shell syntax, not part of the value) —
        # literal removal only, never evaluation.
        if val.startswith("$'"):
            # An ANSI-C-quoted value may carry an inline comment. Decode only
            # the quoted token: falling through with the comment attached made
            # shell_unquote_value miss its closing-quote check and return the
            # whole line comment-included minus its backslashes, with NO
            # warning — and $'...' is exactly the form the role renders for
            # non-shell-safe root passwords, so one hand-added trailing
            # comment silently broke root DB auth everywhere.
            m = re.match(r"^\$'(?:[^'\\]|\\.)*'", val)
            if m and m.end() < len(val):
                trailer = val[m.end():].lstrip(" \t")
                if trailer == "" or trailer.startswith("#"):
                    out[key] = shell_unquote_value(m.group(0))
                    continue
                from .util import warn

                warn(
                    f"{key} has trailing text after its $'...' quoted value — a "
                    f"sourcing shell would concatenate them; quote the whole value "
                    f"or remove the trailer"
                )
            out[key] = shell_unquote_value(val)
        elif len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
            out[key] = val[1:-1]
        else:
            # A value that OPENS with a quote but did not match the
            # fully-quoted branch above is usually a quoted value with an
            # inline comment (KEY="a b" # note, KEY='a #b' # note). Find the
            # close quote; when only a comment (or nothing) follows, the
            # quoted body is what a sourcing shell assigned — without this,
            # the literal quotes leak into the value (shell_unquote_value
            # only decodes the forms printf %q emits, never double quotes).
            if val[:1] in ('"', "'"):
                close = val.find(val[0], 1)
                if close > 0:
                    trailer = val[close + 1 :].lstrip(" \t")
                    if trailer == "" or trailer.startswith("#"):
                        out[key] = val[1:close]
                        continue
            # bash inline-comment semantics on an UNQUOTED value: a ` #` (hash
            # after whitespace) starts a comment the sourcing shell would drop,
            # while `a#b` (no leading space) and any quoted `#` are literal.
            # Match that so `KEY=value  # note` does not smuggle the comment
            # into the value — a real bug the bash source did not have.
            hashpos = val.find(" #")
            tabhash = val.find("\t#")
            cut = min([p for p in (hashpos, tabhash) if p >= 0], default=-1)
            if cut >= 0:
                from .util import warn

                warn(
                    f"stripped an inline comment from {key} (bash drops ' #...' on an "
                    f"unquoted value) — quote the value if the '#' is part of it"
                )
                # Whitespace before the '#' terminated the value word in
                # bash; it is never part of the value.
                val = val[:cut].rstrip(" \t")
            out[key] = shell_unquote_value(val)
    return out


def warn_if_persisted_oneshot(settings: Settings, key: str, hint: str) -> None:
    """Warn LOUDLY when a ONE-SHOT override flag is left PERSISTED in the env
    file. Overrides like CARLOS_ALLOW_DB_ROOT / CARLOS_ACCEPT_EMPTY_DATADIR are
    meant to be a shell prefix on a single command ('KEY=1 carlos-ctl play');
    but carlos-app.env is read on every invocation, so a line persisted there
    silently keeps satisfying the guard forever. Parse the file the SAME way
    the setting is read (parse_env_file strips `export ` and one quote layer)
    so `export KEY=1` / KEY="1" trip the warning too."""
    from .util import warn

    ef = settings.env_file
    if not ef.is_file():
        return
    # Match flag()'s truthiness (1/true/yes/on), NOT a literal "1": the guards
    # this warns about are read via flag(), so a persisted CARLOS_ACCEPT_EMPTY_
    # DATADIR=true keeps DISARMING the guard on every boot while the old "== 1"
    # check stayed silent — the fail-open half never warned.
    persisted = parse_env_file(ef.read_text(errors="replace")).get(key, "").strip().lower()
    if persisted in _TRUTHY_FLAGS:
        warn(f"{key}={persisted} is PERSISTED in {ef} — {hint}")


def read_registry(path: Path) -> Dict[str, str]:
    """One instance-registry file → dict (value may contain '='). The registry
    is WRITTEN by the Ansible role; this CLI only reads it."""
    out: Dict[str, str] = {}
    if not path.is_file():
        return out
    # errors="replace": the registry is role-written ASCII, but a corrupted
    # byte must degrade the entry, not crash every --instance/instances call.
    for line in path.read_text(errors="replace").splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k] = v
    return out


def registry_entry(name: str, environ: Mapping[str, str]) -> Dict[str, str]:
    """Read one instance's registry entry, fail-closed on an unregistered
    name. The registry is written by the Ansible role; the CLI only reads."""
    reg_dir = Path(environ.get("CARLOS_INSTANCE_REGISTRY_DIR", "/etc/carlos-podman/instances"))
    reg_file = reg_dir / f"{name}.conf"
    if not reg_file.is_file():
        raise CtlError(
            f"no registered instance '{name}' (looked in {reg_dir}) — run its provisioning "
            f"playbook first, or list them with 'carlos-ctl instances'"
        )
    entry = read_registry(reg_file)
    entry.setdefault("_REG_FILE", str(reg_file))
    return entry


def resolve_instance_home(name: str, environ: Mapping[str, str]) -> str:
    """`--instance <name>` selector: resolve EMR_HOME from the registry BEFORE
    the env file is read, so a mutating verb targets the NAMED instance instead
    of whatever EMR_HOME happens to be in the environment (the two-instance
    wrong-target footgun). Fail-closed on an unregistered name."""
    entry = registry_entry(name, environ)
    home = entry.get("EMR_HOME", "")
    if not home:
        raise CtlError(f"registry entry {entry['_REG_FILE']} has no EMR_HOME")
    return home


class Settings:
    """Resolved per-invocation configuration for one instance."""

    def __init__(self, environ: Optional[Mapping[str, str]] = None) -> None:
        env = dict(environ if environ is not None else os.environ)
        # EMR_HOME (or its default) selects the env file; the file may then
        # re-point EMR_HOME — same order as the bash source.
        emr_home = env.get("EMR_HOME", "/usr/local/emr")
        env_file = Path(env.get("ENV_FILE", f"{emr_home}/container/carlos-app.env"))
        file_vals: Dict[str, str] = {}
        if env_file.is_file():
            # errors="replace", NOT strict: Settings() is constructed before
            # verb dispatch, so a single non-UTF-8 byte (a pasted cp1252 dash
            # in a comment) raising UnicodeDecodeError here would kill EVERY
            # verb — including `alert` (the OnFailure dispatcher) and
            # `monitor` before its crash-relay exists — silencing the whole
            # paging pipeline at once. A value that decodes dirty still fails
            # closed downstream (validate_db_password / flag()); same
            # hardening the monitor's carlos.properties read already has.
            file_vals = parse_env_file(env_file.read_text(errors="replace"))
            # A typo'd knob (CARLOS_ACCEPT_EMPTY_DATADIRR=1) parses fine, is
            # kept-but-orphaned, and the intended setting silently no-ops to
            # its default — warn instead of letting a misconfiguration hide.
            # Durable extras belong in host_vars carlos_extra_env, which only
            # makes sense for keys carlos-ctl actually reads.
            unknown = sorted(k for k in file_vals if k not in known_keys())
            if unknown:
                from .util import warn

                warn(
                    f"{env_file} carries key(s) carlos-ctl does not read: "
                    f"{', '.join(unknown)} — a typo'd knob silently falls back to its "
                    f"default; fix the name (set durable extras via carlos_extra_env "
                    f"in host_vars)"
                )
        self._vals: Dict[str, str] = {}
        merged_keys = set(_DEFAULTS) | set(file_vals) | {k for k, _ in PORT_DEFAULTS}
        for key in merged_keys:
            if key in file_vals:
                self._vals[key] = file_vals[key]
            elif key in env:
                self._vals[key] = env[key]
            else:
                self._vals[key] = _DEFAULTS.get(key, "")
        for key, default in PORT_DEFAULTS:
            if key not in file_vals and key not in env:
                self._vals[key] = str(default)
        # Environment-only knobs consulted at check time (kept out of _DEFAULTS
        # so `get` returns the live environment for them, file value winning).
        self._env = env
        # `--instance <name>` resolves EMR_HOME from the registry and exports
        # CARLOS_EMR_HOME_PINNED. That pin is AUTHORITATIVE: without it, the
        # normal precedence lets the selected instance's own carlos-app.env
        # re-point EMR_HOME (a stale/copied line), so every mutating verb —
        # and the lock/target banner meant to prevent exactly this — would act
        # on a DIFFERENT instance's home. Warn loudly on a mismatch; the
        # selector still wins (the registry is the operator's explicit intent,
        # and refusing would brick --instance on a merely-stale env file).
        pinned = env.get("CARLOS_EMR_HOME_PINNED", "")
        if pinned:
            self.emr_home = Path(pinned)
            file_home = file_vals.get("EMR_HOME")
            if file_home and file_home != pinned:
                from .util import warn
                warn(
                    f"--instance resolved EMR_HOME={pinned} from the registry, but "
                    f"{env_file} re-points EMR_HOME={file_home} — the explicit --instance "
                    f"selector WINS (everything derives from {pinned}); reconcile the "
                    f"registry entry and the env file so they agree"
                )
        else:
            self.emr_home = Path(file_vals.get("EMR_HOME", env.get("EMR_HOME", emr_home)))
        # Absolute from here on. Every path handed to the rootless engine
        # (pod specs, socket dir, build context) derives from this one, and
        # that crossing now runs from a FIXED working directory (Runner's
        # cross-user cwd pin — `runuser` hard-fails when the service user
        # cannot enter the caller's cwd, e.g. /root). A relative EMR_HOME
        # would resolve against two different directories on the two sides of
        # the boundary; anchor it in THIS process's cwd, once, where the
        # operator's intent is unambiguous. (A relative EMR_HOME is already a
        # footgun — the registry, the units and the env file all record it —
        # so normalizing costs nothing.)
        self.emr_home = Path(os.path.abspath(self.emr_home))
        self.env_file = env_file

        # --- derived identity: everything host-global derives from INSTANCE
        # so a second pod-group coexists on one host with distinct names.
        # An --instance selector pins the identity from the REGISTRY: the env
        # file inside the selected home may be missing (unmounted volume — the
        # very incident --instance serves) or stale-copied, and falling back
        # to the default 'carlos' would aim every pod/unit/nft name at a
        # DIFFERENT instance.
        pinned_instance = env.get("CARLOS_INSTANCE_PINNED", "")
        self.instance = pinned_instance or self.get("INSTANCE")
        if pinned_instance:
            file_instance = file_vals.get("INSTANCE")
            if file_instance and file_instance != pinned_instance:
                from .util import warn

                warn(
                    f"--instance pinned identity '{pinned_instance}' from the registry, "
                    f"but {env_file} says INSTANCE={file_instance} — the registry WINS; "
                    f"reconcile the env file (a stale copy from another instance?)"
                )
        self.app_pod = f"{self.instance}-app"
        self.obs_pod = f"{self.instance}-obs"
        self.waf_pod = f"{self.instance}-waf"
        self.net_name = f"{self.instance}-net"
        self.edge_net_name = f"{self.instance}-edge"
        self.db_secret = f"{self.instance}-db"
        self.service_user = self.get("SERVICE_USER")

        # --- paths (system paths overridable ONLY so the hermetic test suite
        # can run without touching the host — production uses the defaults).
        eh = self.emr_home
        self.conf_dir = eh / "container" / "conf"
        self.credstore_dir = Path(env.get("CARLOS_CREDSTORE_DIR", "/etc/credstore.encrypted"))
        self.systemd_dir = Path(env.get("CARLOS_SYSTEMD_DIR", "/etc/systemd/system"))
        # sd_booted(3)'s own test: systemd creates /run/systemd/system when —
        # and only when — it is running as the init system. This is what
        # Runner.systemd_running() checks IN ADDITION to the binary being on
        # PATH, because the binary's presence proves nothing: Debian/Ubuntu
        # ship systemctl inside containers, WSL images and chroots where
        # systemd never booted, and there EVERY call exits nonzero with
        # "System has not been booted with systemd as init system (PID 1)".
        # The no-systemd fallbacks (play/down's plain `podman kube play`,
        # seal's inline credential render) keyed on the binary alone, so on
        # such a host they never engaged. Overridable ONLY so the hermetic
        # suites can model both shapes.
        self.systemd_runtime_dir = Path(
            env.get("CARLOS_SYSTEMD_RUNTIME_DIR", "/run/systemd/system")
        )
        # Where the role installs the instance tmpfiles.d file (defaults match
        # the role's carlos_tmpfiles_dir); the CARLOS_TMPFILES_DIR override
        # keeps uninstall correct on a customized dir AND lets the hermetic
        # suite redirect the removal.
        self.tmpfiles_dir = Path(env.get("CARLOS_TMPFILES_DIR", "/etc/tmpfiles.d"))
        # JOURNAL_DIR is the operator knob (env-file settable, as the bash
        # monitor read it); CARLOS_JOURNAL_DIR is the hermetic-test override
        # and wins so the suite never touches the host journal.
        self.journal_dir = Path(
            env.get("CARLOS_JOURNAL_DIR") or self.get("JOURNAL_DIR") or "/var/log/journal"
        )
        self.instance_registry_dir = Path(
            env.get("CARLOS_INSTANCE_REGISTRY_DIR", "/etc/carlos-podman/instances")
        )
        # Alert-channel fallback (root-only sidecar OUTSIDE $EMR_HOME): the
        # capability URLs normally live in carlos-app.env — on the very volume
        # whose failure-to-mount is the highest-severity condition the guard
        # pages about. With the env file gone, the guard's OnFailure alert was
        # journal-only. The role mirrors the three channel keys to
        # <registry>/<instance>.alert.env (root:root 0600); they fill in ONLY
        # when the resolved value is empty — a non-empty env-file/process-env
        # value always wins, and blanking the var in host_vars re-renders BOTH
        # files empty, so the sidecar can never resurrect a retired channel.
        # An unreadable/absent sidecar is a silent skip (non-root callers).
        _chan_keys = ("ALERT_WEBHOOK", "ALERT_EMAIL", "HEARTBEAT_URL")
        if any(not self._vals.get(k) for k in _chan_keys):
            # self.instance (the --instance PINNED identity), NOT
            # self.get('INSTANCE'): the sidecar exists for exactly the
            # unmounted-volume incident where the env file is gone, so
            # get('INSTANCE') would fall back to the default 'carlos' and read
            # the WRONG instance's channels — cross-instance alert misdelivery
            # under the one condition the sidecar is meant to survive
            #
            _sidecar = self.instance_registry_dir / f"{self.instance}.alert.env"
            try:
                # errors="replace" for the same last-resort-channel reason as
                # the env-file read above: the sidecar exists precisely for
                # when things are broken, so it must never be the crash.
                _side_vals = parse_env_file(
                    _sidecar.read_text(errors="replace"), whitelist=_chan_keys
                )
            except OSError:
                _side_vals = {}
            for _k in _chan_keys:
                if not self._vals.get(_k) and _side_vals.get(_k):
                    self._vals[_k] = _side_vals[_k]
        self.run_secrets_dir = Path(
            env.get("CARLOS_RUN_SECRETS_DIR", f"/run/{self.instance}-emr")
        )
        self.quadlet_dir_override = env.get("CARLOS_QUADLET_DIR", "")
        self.secrets_dir = self.conf_dir / "secrets"
        self.secrets_bundle = self.secrets_dir / "secrets.enc.yaml"
        # The age PRIVATE key lives OUTSIDE the pod-mounted / backed-up /
        # chown-swept container/ tree, in a root-only dir — the master key
        # never sits in the rootless-readable tree.
        self.secrets_private_dir = eh / "secrets-private"
        self.age_key_file = self.secrets_private_dir / "age-key.txt"
        # Attended-recovery copy of the same age key, wrapped with an
        # operator passphrase (openssl AES-256-CBC + PBKDF2) by `seal` on
        # TPM hosts: if the TPM unseal fails at boot, the render can prompt
        # for this passphrase instead of taking the EMR down. Root-only,
        # outside the pod-mounted/backed-up tree, same as the key itself.
        self.age_key_recovery_file = self.secrets_private_dir / "age-key.recovery.enc"
        # The obs stores' basic-auth credential: root-only 0600,
        # OUTSIDE the pod-mounted/backed-up tree; regenerable (a playbook
        # re-run mints and re-renders every consumer), so never sealed.
        self.obs_http_password_file = self.secrets_private_dir / "obs-http-password"
        self.age_pub_file = self.secrets_dir / "age-recipient.pub"
        self.age_marker = self.secrets_dir / "RESTORE-README.txt"
        self.cred_age = f"{self.instance}-age"
        # Legacy per-fragment blob names — retained ONLY for seal's migration
        # reader; new installs never create these.
        self.cred_restic = f"{self.instance}-restic"
        self.cred_backup_db = f"{self.instance}-backup-db"
        self.cred_db_fragment = f"{self.instance}-db-fragment"
        self.cred_drugref_fragment = f"{self.instance}-drugref-db-fragment"
        self.data_dir = eh / "data"
        self.rendered_yaml = eh / "container" / f"{self.app_pod}.yaml"
        self.rendered_obs_yaml = eh / "container" / f"{self.obs_pod}.yaml"
        self.rendered_waf_yaml = eh / "container" / f"{self.waf_pod}.yaml"
        self.db_socket_dir = eh / "run" / "db-socket"
        self.properties_file = self.conf_dir / "carlos" / "carlos.properties"
        self.drugref_properties_file = self.conf_dir / "drugref" / "drugref2.properties"
        self.exporter_mycnf_file = self.conf_dir / "metrics" / "exporter.my.cnf"
        if "RESTIC_REPOSITORY" not in self._vals or not self._vals["RESTIC_REPOSITORY"]:
            self._vals["RESTIC_REPOSITORY"] = str(eh / "backup" / "restic-repo")

    # -- accessors ---------------------------------------------------------

    def get(self, key: str, default: str = "") -> str:
        if key in self._vals:
            return self._vals[key]
        return self._env.get(key, default)

    def get_int(self, key: str) -> int:
        val = self.get(key)
        try:
            return int(val)
        except ValueError:
            raise CtlError(f"{key}='{val}' is not a number") from None

    def get_int_or(self, key: str, default: int) -> int:
        """Best-effort integer knob for the MONITOR path: a malformed value
        (DISK_MIN_FREE=10%) must degrade THAT knob to its default, not crash
        the whole sweep — a dead monitor pages nothing and never signals the
        heartbeat, which is strictly worse than one mis-thresholded check
        (the bash's per-check arithmetic failure had the same degrade-only
        blast radius)."""
        val = self.get(key, str(default)) or str(default)
        try:
            return int(val)
        except ValueError:
            from .util import warn

            warn(f"{key}='{val}' is not a number — using the default ({default})")
            return default

    def flag(self, key: str) -> bool:
        """Acknowledgement-knob truthiness. Accepts 1/true/yes/on (and their
        0/false/no/off negatives); a truthy-LOOKING but unrecognized value
        (a typo like 'y' or 'enabled') fails CLOSED — these knobs disable a
        safety refusal, so an ambiguous value must NOT silently enable it — but
        warns so the typo is not swallowed."""
        v = self.get(key).strip().lower()
        if v in _TRUTHY_FLAGS:
            return True
        if v in ("", "0", "false", "no", "off"):
            return False
        from .util import warn

        warn(
            f"{key}={self.get(key)!r} is not a recognized boolean (use 1/true/yes/on or "
            f"0/false/no/off) — treating it as UNSET (the safety default)"
        )
        return False

    @property
    def obs_enabled(self) -> bool:
        """Strict boolean parse, default ENABLED. The old `!= "0"` coercion
        read ANY non-"0" string as enabled — a hand-edited OBS_ENABLED=false
        silently ran the full obs stack (the exact opposite of the operator's
        written intent). Role-rendered envs always write 1/0, so only
        hand-edits change behavior — and for those, `false/no/off` now means
        what it says. Unrecognized values warn and keep the default
        (enabled), mirroring flag()'s treat-typos-as-unset contract."""
        v = self.get("OBS_ENABLED", "1").strip().lower()
        if v in ("1", "true", "yes", "on", ""):
            return True
        if v in ("0", "false", "no", "off"):
            return False
        from .util import warn

        warn(
            f"OBS_ENABLED={self.get('OBS_ENABLED')!r} is not a recognized boolean "
            f"(use 1/true/yes/on or 0/false/no/off) — treating it as ENABLED "
            f"(the default)"
        )
        return True

    def service_uid(self) -> int:
        try:
            return pwd.getpwnam(self.service_user).pw_uid
        except KeyError:
            raise CtlError(
                f"service user '{self.service_user}' does not exist — run the provisioning "
                f"playbook (ansible/site.yml) first"
            ) from None

    def quadlet_dir(self) -> Path:
        """Quadlets install to the root-managed PER-USER path (podman >= 4.9).
        The CARLOS_QUADLET_DIR override (test suite) is used verbatim."""
        if self.quadlet_dir_override:
            return Path(self.quadlet_dir_override)
        return Path(f"/etc/containers/systemd/users/{self.service_uid()}")
