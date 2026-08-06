# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Front-door TLS material — the three modes of CARLOS_TLS_MODE:

  selfsigned (default)  auto-generated pair; play regenerates a missing or
                        expired SELF-ISSUED cert (operator-placed certs are
                        never clobbered). Zero manual steps to a starting
                        WAF; browsers warn until a real cert replaces it.
  manual                the operator places fullchain.pem/privkey.pem; play
                        refuses without them (the historical behavior).
  acme                  certbot (official image, one-shot rootless container,
                        HTTP-01 standalone on HTTP_PUBLISH_PORT behind the
                        acme-mode port-80 DNAT) issues/renews; the daily
                        <instance>-cert-renew.timer keeps it fresh.

Both the WAF and the obs pod's log view serve the SAME pair (their init
containers copy it from conf/waf/certs at pod start), so any renewal
restarts both pods — and only those two; the app pod is untouched, so the
WAF's cached-backend-IP behavior is never triggered by a renewal."""

from __future__ import annotations

import contextlib
import hashlib
import os
import pwd
import re
from pathlib import Path

from .runner import Runner
from .util import CtlError, log, warn

# Ten years on purpose: the browser ~398-day lifetime cap applies only to
# publicly-trusted chains, and a self-signed default should not demand
# regeneration churn. The monitor's CERT_EXPIRY_WARN_DAYS check remains the
# prompt when it does eventually near expiry.
_SELF_SIGNED_DAYS = 3650


def _certs_dir(runner: Runner) -> Path:
    return runner.settings.conf_dir / "waf" / "certs"


def _chown_service_user(runner: Runner, *paths: Path) -> None:
    with contextlib.suppress(OSError, KeyError):
        uid = pwd.getpwnam(runner.settings.service_user).pw_uid
        for p in paths:
            os.chown(p, uid, -1)


def _cert_is_self_issued_for(runner: Runner, cert: Path, server: str) -> bool:
    """True only when the cert is OURS to replace: self-issued (issuer ==
    subject) AND carrying the instance's SERVER_NAME CN. An operator-placed
    cert — even an expired one — must never be clobbered by regeneration."""
    cp = runner.run(
        ["openssl", "x509", "-noout", "-subject", "-issuer", "-in", str(cert)],
        capture=True, quiet=True,
    )
    if cp.returncode != 0:
        return False
    subject = issuer = ""
    for line in (cp.stdout or "").splitlines():
        if line.startswith("subject="):
            subject = line[len("subject="):].strip()
        elif line.startswith("issuer="):
            issuer = line[len("issuer="):].strip()
    if not subject or subject != issuer:
        return False
    # An empty SERVER_NAME must NEVER match — otherwise a substring test would
    # classify an operator cert of ANY CN as "ours". Anchor the CN to a whole
    # RDN token (both `subject=CN = x, O = y` and legacy `/CN=x/O=y` forms) and
    # re.escape it so a dotted name's '.' can't act as a wildcard.
    if not server:
        return False
    stripped = subject.replace(" ", "")
    return re.search(rf"(?:^|[,/])CN={re.escape(server)}(?:[,/]|$)", stripped) is not None


def ensure_selfsigned_cert(runner: Runner) -> bool:
    """Generate the self-signed pair when absent (or expired AND self-issued
    for this SERVER_NAME). Returns True when a new pair was written. The
    key lands 0640 / cert 0644, service-user-owned — waf-init and obs-init
    (container root == the service user) copy them out of the 0700 dir."""
    s = runner.settings
    certs = _certs_dir(runner)
    fullchain, privkey = certs / "fullchain.pem", certs / "privkey.pem"
    # Exactly one of the pair present looks like a half-placed operator cert
    # (mid-scp, or a botched copy). Regenerating would overwrite the one they
    # DID place with a self-signed file — refuse loudly instead of silently
    # clobbering it (the have_both guard below only protects a complete pair).
    if fullchain.is_file() != privkey.is_file():
        present = fullchain if fullchain.is_file() else privkey
        missing = privkey if fullchain.is_file() else fullchain
        raise CtlError(
            f"exactly one of the front-door TLS pair exists in {certs} "
            f"({present.name} present, {missing.name} missing) — this looks like a "
            f"half-placed operator certificate. REFUSING to generate a self-signed pair "
            f"over it. Restore the missing file, or delete {present.name} to let "
            f"selfsigned mode regenerate a complete pair."
        )
    have_both = fullchain.is_file() and privkey.is_file()
    if have_both:
        # Regenerate only an EXPIRED cert that is provably ours.
        if runner.ok(["openssl", "x509", "-checkend", "0", "-noout",
                      "-in", str(fullchain)]):
            return False
        if not _cert_is_self_issued_for(runner, fullchain, s.get("SERVER_NAME")):
            warn(
                f"the TLS cert at {fullchain} is EXPIRED but operator-placed "
                f"(not our self-signed) — refusing to overwrite it; renew it "
                f"yourself or switch CARLOS_TLS_MODE"
            )
            return False
        log("selfsigned TLS mode: regenerating the expired self-signed pair")
    else:
        # (The half-pair case cannot reach here — the XOR guard above already
        # raised on it. A previous elif re-encoded that case with a WEAKER
        # contract — warn + continue-without-a-pair — which a future edit to
        # the guard could silently resurrect; the hard refusal is the one
        # behavior.)
        log("selfsigned TLS mode: generating the front-door TLS pair")
    certs.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        certs.chmod(0o700)
    server = s.get("SERVER_NAME") or "localhost"
    cp = runner.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-days", str(_SELF_SIGNED_DAYS), "-nodes",
        "-subj", f"/CN={server}",
        "-addext", f"subjectAltName=DNS:{server},IP:{s.get('BIND_IP') or '127.0.0.1'}",
        "-keyout", str(privkey), "-out", str(fullchain),
    ], quiet=True)
    if cp.returncode != 0:
        raise CtlError(
            f"openssl could not generate the self-signed TLS pair in {certs} — "
            f"fix openssl or place certificates manually (CARLOS_TLS_MODE=manual)"
        )
    with contextlib.suppress(OSError):
        privkey.chmod(0o640)
        fullchain.chmod(0o644)
    _chown_service_user(runner, certs, privkey, fullchain)
    log(f"generated a {_SELF_SIGNED_DAYS}-day self-signed cert for {server} "
        f"(browsers will warn; replace {certs}/{{fullchain,privkey}}.pem with a "
        f"real pair, or use CARLOS_TLS_MODE=acme)")
    return True


def _sha256_file(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def cert_restart_marker(runner: Runner) -> Path:
    """Marker recording that a renewed cert is INSTALLED on disk but a
    consumer pod restart FAILED — the WAF/log view keep serving the OLD cert
    until they restart. cmd_cert_renew retries the restarts and clears the
    marker on its next run even when the cert is not due; the monitor nags
    while the marker persists."""
    return runner.settings.conf_dir / "waf" / ".cert-restart-needed"


def _restart_cert_consumers(runner: Runner) -> list:
    """Restart the two cert consumers (waf + obs log view, app pod
    untouched); returns the units whose restart FAILED."""
    s = runner.settings
    if not (s.emr_home / "container" / ".deployed").is_file():
        # First-time acme issuance (README quick start runs cert-renew BEFORE
        # the first play): the consumer units are not deployed yet, so a
        # failed restart is the expected state, not an incident — the first
        # `play` starts the pods with this cert already staged. Escalating
        # here (rc 1 + marker) would fail a documented runbook step.
        log("cert-renew: instance not yet deployed — skipping consumer restarts "
            "(the first 'carlos-ctl play' starts the pods with the new cert in place)")
        return []
    failed = []
    for unit, label in ((f"{s.waf_pod}.service", "waf"),
                        (f"{s.obs_pod}.service", "obs log view")):
        if label.startswith("obs") and not s.obs_enabled:
            continue
        if not runner.systemd_running():
            warn(f"systemctl not available — cannot restart the {label} pod; it "
                 f"still serves the OLD cert")
            failed.append(unit)
            continue
        if not runner.ok(runner.systemctl_user_argv(["restart", unit])):
            warn(f"could not restart {unit} — the {label} still serves the OLD cert")
            failed.append(unit)
    return failed


def cmd_cert_renew(runner: Runner) -> int:
    """acme-mode issuance/renewal: run the official certbot image as a
    one-shot rootless container (HTTP-01 standalone published on
    BIND_IP:HTTP_PUBLISH_PORT — the acme-mode nftables rule redirects :80
    there), then install a CHANGED cert into conf/waf/certs and restart the
    two consumers (waf + obs log view). Unchanged cert = "not due", exit 0
    (the daily timer runs this unconditionally)."""
    s = runner.settings
    mode = s.get("CARLOS_TLS_MODE") or "selfsigned"
    if mode != "acme":
        raise CtlError(
            f"cert-renew is the acme-mode verb (CARLOS_TLS_MODE={mode or 'selfsigned'}): "
            f"selfsigned regenerates at 'carlos-ctl play'; manual certs are "
            f"operator-renewed. Set carlos_tls_mode: acme in host_vars first."
        )
    email = s.get("ACME_EMAIL")
    if not email:
        raise CtlError(
            "ACME_EMAIL is unset — set carlos_acme_email in host_vars (Let's Encrypt "
            "requires a contact address) and re-run the playbook"
        )
    server = s.get("SERVER_NAME")
    if not server or server == "localhost":
        raise CtlError("SERVER_NAME must be a real public DNS name for ACME HTTP-01")
    acme_root = s.conf_dir / "waf" / "acme"
    acme_etc, acme_lib = acme_root / "etc", acme_root / "lib"
    for d in (acme_etc, acme_lib):
        d.mkdir(parents=True, exist_ok=True)
    _chown_service_user(runner, acme_root, acme_etc, acme_lib)
    certs = _certs_dir(runner)
    installed = certs / "fullchain.pem"
    before = _sha256_file(acme_etc / "live" / server / "fullchain.pem")
    log(f"cert-renew: running certbot (HTTP-01 standalone on "
        f"{s.get('BIND_IP')}:{s.get('HTTP_PUBLISH_PORT')}; :80 arrives via the "
        f"acme nftables redirect)")
    cp = runner.podman_user([
        "run", "--rm", "--pull=missing",
        "-p", f"{s.get('BIND_IP')}:{s.get('HTTP_PUBLISH_PORT')}:80",
        "-v", f"{acme_etc}:/etc/letsencrypt",
        "-v", f"{acme_lib}:/var/lib/letsencrypt",
        s.get("CERTBOT_IMAGE"),
        "certonly", "--standalone", "--non-interactive", "--agree-tos",
        "--keep-until-expiring", "-m", email, "-d", server,
    ])
    if cp.returncode != 0:
        raise CtlError(
            f"certbot failed — the cert at {installed} is UNCHANGED; check DNS for "
            f"{server}, that :80 reaches this host, and the certbot output above"
        )
    live_chain = acme_etc / "live" / server / "fullchain.pem"
    live_key = acme_etc / "live" / server / "privkey.pem"
    after = _sha256_file(live_chain)
    if not after:
        raise CtlError(
            f"certbot exited 0 but {live_chain} is unreadable — the cert at "
            f"{installed} is UNCHANGED; inspect {acme_etc}/live/"
        )
    marker = cert_restart_marker(runner)
    if after == before and after == _sha256_file(installed):
        if marker.is_file():
            # A prior run installed this cert but could not restart the
            # consumers — the cert being "not due" must NOT skip the retry,
            # or the old cert is served until it expires.
            log("cert-renew: certificate not due, but a previous run could not "
                "restart the consumers — retrying the pod restarts (the renewed "
                "cert is already on disk)")
            failed = _restart_cert_consumers(runner)
            if failed:
                with contextlib.suppress(OSError):
                    marker.write_text("\n".join(failed) + "\n")
                    # 0644, not umask-subject: a 0600 root marker under
                    # container/ is unreadable in the rootless restic userns
                    # and fails every nightly files snapshot while it exists.
                    marker.chmod(0o644)
                warn(f"cert-renew: {', '.join(failed)} STILL could not be restarted "
                     f"— the old cert remains in service; returning nonzero so "
                     f"OnFailure pages")
                return 1
            with contextlib.suppress(OSError):
                marker.unlink()
            log("cert-renew: consumers restarted — they now serve the renewed cert")
            return 0
        log("cert-renew: certificate not due for renewal — nothing to do")
        return 0
    # COPY (not symlink): waf-init/obs-init `cp` real files out of the 0700
    # certs dir; a symlink into the acme tree would dangle inside the pods.
    # Stage-then-rename, key FIRST: two direct write_bytes() calls left a
    # crash window installing the NEW chain over the OLD key — and because
    # the not-due check above hashes only fullchain.pem, every later daily
    # run then read "not due" and never repaired the mismatched pair (found
    # seventh pass). os.replace() is atomic per file; ordering key-first
    # means a crash between the two leaves old-chain+new-key, which the
    # chain-hash check DOES treat as due and re-completes next run.
    certs.mkdir(parents=True, exist_ok=True)
    new_key = certs / ".privkey.pem.new"
    new_chain = certs / ".fullchain.pem.new"
    new_key.write_bytes(live_key.read_bytes())
    new_chain.write_bytes(live_chain.read_bytes())
    with contextlib.suppress(OSError):
        new_key.chmod(0o640)
        new_chain.chmod(0o644)
    os.replace(new_key, certs / "privkey.pem")
    os.replace(new_chain, certs / "fullchain.pem")
    _chown_service_user(runner, certs / "fullchain.pem", certs / "privkey.pem")
    # Restart ONLY the two cert consumers; the app pod is untouched. A failed
    # restart must be LOUD: write the retry marker and exit
    # nonzero so the unit's OnFailure pages — warning and returning 0 left
    # the old cert in service, invisibly, until it expired.
    failed = _restart_cert_consumers(runner)
    if failed:
        with contextlib.suppress(OSError):
            marker.write_text("\n".join(failed) + "\n")
            # 0644 — same rootless-restic-readability rationale as above.
            marker.chmod(0o644)
        warn(f"cert-renew: the renewed certificate for {server} is INSTALLED on disk "
             f"but {', '.join(failed)} could not be restarted — the OLD cert stays in "
             f"service until they restart. Returning nonzero so OnFailure pages; the "
             f"next daily run retries the restarts, and the monitor nags while the "
             f"marker persists.")
        return 1
    with contextlib.suppress(OSError):
        marker.unlink()
    log(f"cert-renew: installed the renewed certificate for {server}")
    return 0
