# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Guided new-instance setup. The bash wizard scaffolded the instance itself
(init + bootstrap); provisioning now belongs to the Ansible role, so the
wizard's job is to capture the site answers and EMIT a host_vars file the
playbook consumes — one source of truth, no second provisioning path."""

from __future__ import annotations

import getpass
import json
import os
import sys
from pathlib import Path

from .runner import Runner
from .util import CtlError, log


def _ask(prompt: str, default: str = "") -> str:
    """Interactive shows the prompt + [default]; non-interactive (the test
    suite / a pipe) reads a line from stdin so the whole wizard is scriptable
    and hermetically testable."""
    if sys.stdin.isatty():
        suffix = f" [{default}]" if default else ""
        ans = input(f"{prompt}{suffix}: ").strip()
    else:
        ans = sys.stdin.readline().strip()
    return ans or default


def _ask_secret(prompt: str) -> str:
    if sys.stdin.isatty():
        return getpass.getpass(f"{prompt}: ")
    return sys.stdin.readline().rstrip("\n")


def cmd_setup(runner: Runner) -> int:
    from .secrets import validate_db_password

    s = runner.settings
    out_dir = Path(s._env.get("CARLOS_HOST_VARS_DIR", "ansible/host_vars"))  # noqa: SLF001

    log(f"CARLOS instance setup — answers become an Ansible host_vars file in {out_dir}/. "
        f"Enter accepts the [default].")
    inst = _ask("Instance name (unique per host)", "carlos")
    # Validate the instance name up front — it becomes the host_vars FILENAME
    # (out_dir / f"{inst}.yml"), so the same charset gate that protects systemd
    # unit / nft table names also fences the write path against traversal.
    from .config import Settings as _Settings
    from .validate import validate_bind_ip, validate_instance_name, validate_ports

    validate_instance_name(_Settings({"INSTANCE": inst, "ENV_FILE": "/nonexistent"}))
    target = out_dir / f"{inst}.yml"
    # Refuse to clobber a completed setup — edit the vars file directly.
    if target.is_file():
        raise CtlError(
            f"{target} already exists (setup completed) — edit it directly, or remove it "
            f"to re-run setup"
        )
    emr_home = _ask("EMR_HOME on the target host", "/usr/local/emr")
    # Default aligned with the role default (127.0.0.1): the old made-up LAN
    # address (192.168.20.250) matched no real site and disagreed with
    # defaults/main.yml — an Enter-through-the-wizard install got a listener
    # address that was wrong everywhere.
    bind = _ask("BIND_IP (host IP end users reach the WAF on)", "127.0.0.1")
    server = _ask("Public server name (TLS vhost)", "emr.example.ca")
    # Front-door TLS: selfsigned needs nothing further (a pair is generated
    # at provision/play; browsers warn until replaced); manual = the operator
    # places the files; acme = certbot needs a contact address + public DNS.
    tls_mode = _ask("TLS mode [selfsigned|manual|acme]", "selfsigned").lower()
    if tls_mode not in ("selfsigned", "manual", "acme"):
        raise CtlError(f"TLS mode '{tls_mode}' is not one of selfsigned|manual|acme")
    acme_email = ""
    if tls_mode == "acme":
        acme_email = _ask("ACME contact email (Let's Encrypt requires one)", "")
        if not acme_email:
            raise CtlError("acme mode needs a contact email (carlos_acme_email)")
    dbpw = _ask_secret("MariaDB root password (existing DB: its current password)")
    validate_db_password(dbpw, "the MariaDB root password")
    # ON and BC are the provinces CARLOS implements billing for; 'generic' is
    # the explicit fallback. Constrain the value (rather than silently treating
    # any typo as generic) so a mistyped 'On'/'Ontario' is caught here, not
    # discovered as wrong billing behavior after go-live.
    province = _ask("Billing province [ON|BC|generic]", "ON")
    _prov_norm = {"on": "ON", "bc": "BC", "generic": "generic"}
    if province.lower() not in _prov_norm:
        raise CtlError(
            f"billing province '{province}' is not one of ON|BC|generic — "
            f"CARLOS implements billing for ON and BC; use 'generic' for anywhere else"
        )
    province = _prov_norm[province.lower()]
    tz = _ask("Container timezone", "America/Toronto")
    alert = _ask("Alert email (Enter to skip)", "")
    # The off-host dead-man's-switch: the ONLY thing that catches a total host
    # or monitor death (every monitor check runs on the box).
    heartbeat = _ask(
        "Heartbeat ping URL for the monitor dead-man's-switch (e.g. healthchecks.io; "
        "Enter to skip)", "")
    # Not fatal (channels can be added in host_vars later), but the operator
    # must know NOW: play independently refuses go-live without an alert
    # channel AND without a heartbeat — each skipped item here is a gate the
    # deploy will stop at (unless its documented opt-out is acknowledged).
    if not alert:
        log(
            "WARNING: no alert email — 'carlos-ctl play' will REFUSE go-live until an "
            "alert channel (carlos_alert_email / carlos_alert_webhook) is set in the "
            "host_vars file, or ALERT_JOURNAL_ONLY=1 acknowledges journal-only alerting"
        )
    if not heartbeat:
        log(
            "WARNING: no heartbeat URL — 'carlos-ctl play' will REFUSE go-live until "
            "carlos_heartbeat_url is set in the host_vars file (the off-host dead-man's "
            "switch), or CARLOS_NO_HEARTBEAT=1 acknowledges running without one"
        )
    obs = _ask("Deploy the observability pod (metrics/logs/log-view)? [yes/no]", "yes")
    # Ports: 443 is fine (root installs the nftables redirect); a non-default
    # instance sharing a BIND_IP must offset the rest — suggest an offset set.
    off = 0 if inst == "carlos" else 10000
    https = _ask("User-facing HTTPS port", "443")
    pub = _ask("WAF publish port (>=1024, rootless)", str(8443 + off))
    logview = _ask("Log-view port (>=1024)", str(9443 + off))
    vlogs = _ask("VictoriaLogs port (127.0.0.1)", str(9428 + off))
    vmetr = _ask("VictoriaMetrics port (127.0.0.1)", str(8428 + off))
    vmalert = _ask("vmalert port (127.0.0.1)", str(8880 + off))
    pma = _ask("phpMyAdmin port (127.0.0.1)", str(9444 + off))

    # Validate BIND_IP and the whole port set with the SAME gates play/asserts
    # enforce, so a bad answer fails HERE (before a host_vars file exists)
    # rather than at provision time. ENV_FILE points nowhere so the probe reads
    # only these answers, never a real env file under emr_home.
    _probe = _Settings({
        "ENV_FILE": "/nonexistent",
        "BIND_IP": bind,
        "HTTPS_PORT": https,
        "HTTPS_PUBLISH_PORT": pub,
        "LOG_VIEW_PORT": logview,
        "VICTORIALOGS_PORT": vlogs,
        "VICTORIAMETRICS_PORT": vmetr,
        "PMA_PORT": pma,
        "VMALERT_PORT": vmalert,
    })
    validate_bind_ip(_probe)
    validate_ports(_probe)

    out_dir.mkdir(parents=True, exist_ok=True)
    # json.dumps every string scalar (JSON is a YAML subset): unquoted, YAML
    # 1.1's implicit resolver booleanizes bare ON/on/no/off/yes/true/false —
    # so the DEFAULT Ontario answer rendered `carlos_billing_province: true`
    # and the role's own province assert refused the wizard's output. The
    # same hazard applies to any wizard-typed scalar (an instance named `on`
    # passes validate_instance_name and would boolify too).
    q = json.dumps
    lines = [
        "# Generated by `carlos-ctl setup`. Consumed by ansible/site.yml — see",
        "# ansible/roles/carlos_podman/defaults/main.yml for ALL options.",
        "---",
        f"carlos_instance: {q(inst)}",
        f"carlos_emr_home: {q(emr_home)}",
        f"carlos_bind_ip: {q(bind)}",
        f"carlos_server_name: {q(server)}",
        f"carlos_https_port: {https}",
        f"carlos_https_publish_port: {pub}",
        f"carlos_log_view_port: {logview}",
        f"carlos_victorialogs_port: {vlogs}",
        f"carlos_victoriametrics_port: {vmetr}",
        f"carlos_vmalert_port: {vmalert}",
        f"carlos_pma_port: {pma}",
        f"carlos_tz: {q(tz)}",
        f"carlos_obs_enabled: {'true' if obs.lower().startswith('y') else 'false'}",
        f"carlos_billing_province: {q(province)}",
    ]
    if tls_mode != "selfsigned":
        lines.append(f"carlos_tls_mode: {q(tls_mode)}")
    if acme_email:
        lines.append(f"carlos_acme_email: {q(acme_email)}")
    if alert:
        lines.append(f"carlos_alert_email: {q(alert)}")
    if heartbeat:
        lines.append(f"carlos_heartbeat_url: {q(heartbeat)}")
    # Vault the password inline when possible: the plaintext form in a repo
    # checkout is one habitual `git add -A` away from leaking the full-PHI-
    # access root credential into history (host_vars/*.yml is gitignored as a
    # second line of defense, but vaulting is the real fix).
    vaulted = ""
    # Non-interactive vaulting: scripted/CI setup used to skip
    # vaulting entirely (the isatty gate) and silently persist the
    # full-PHI-access root credential in plaintext. A vault password source
    # (CARLOS_VAULT_PASSWORD_FILE here, or ansible's own
    # ANSIBLE_VAULT_PASSWORD_FILE / vault_password_file in ansible.cfg) lets
    # encrypt_string run headless.
    vault_pw_file = s.get("CARLOS_VAULT_PASSWORD_FILE")
    has_vault_source = bool(
        vault_pw_file or os.environ.get("ANSIBLE_VAULT_PASSWORD_FILE")
    )
    if runner.have("ansible-vault") and (sys.stdin.isatty() or has_vault_source):
        wants = True
        if sys.stdin.isatty():
            wants = _ask("Encrypt the DB password with ansible-vault now? [yes/no]",
                         "yes").lower().startswith("y")
        if wants:
            argv = ["ansible-vault", "encrypt_string", "--stdin-name",
                    "carlos_db_root_password"]
            if vault_pw_file:
                argv += ["--vault-password-file", vault_pw_file]
            cp = runner.run(argv, input_text=dbpw, capture=True)
            if cp.returncode == 0 and "!vault" in (cp.stdout or ""):
                vaulted = cp.stdout.strip()
            else:
                log("ansible-vault did not produce an encrypted value — falling back to "
                    "plaintext; vault it by hand before committing")
    if not vaulted and not sys.stdin.isatty() \
            and s.get("CARLOS_SETUP_ALLOW_PLAINTEXT", "0") != "1":
        raise CtlError(
            "refusing to persist the MariaDB root password in PLAINTEXT from a "
            "non-interactive run — provide a vault password source "
            "(CARLOS_VAULT_PASSWORD_FILE=<file> or ANSIBLE_VAULT_PASSWORD_FILE) so it "
            "can be encrypted, or set CARLOS_SETUP_ALLOW_PLAINTEXT=1 to accept "
            "plaintext host_vars knowingly (0600 + gitignore are the only guards)."
        )
    if vaulted:
        lines += [
            "# Vaulted by `carlos-ctl setup` (ansible-vault encrypt_string).",
            vaulted,
        ]
    else:
        # json.dumps, NOT Python repr: a JSON string is valid YAML with the
        # same escaping rules, while repr produces Python-only forms (single
        # quotes around embedded ', backslash escapes YAML reads differently)
        # that silently corrupt the password when Ansible parses the file.
        lines += [
            "# The MariaDB root password: prefer Ansible Vault for this value",
            "# (ansible-vault encrypt_string). Written plaintext here only because",
            "# setup ran interactively — vault it before committing to any repo.",
            "# NOTE: ansible/host_vars/*.yml is gitignored for exactly this reason.",
            f"carlos_db_root_password: {json.dumps(dbpw)}",
        ]

    # Machine-generated app encryption key (AES-256, base64): current carlos
    # develop refuses first boot without one pre-provisioned — the app would
    # otherwise generate a key and try to persist it into carlos.properties,
    # which the pod mounts read-only. Generated here so the operator never has
    # to invent it. base64 output is [A-Za-z0-9+/=] only, so the quoted YAML
    # scalar below needs no further escaping.
    import base64
    import secrets as _secrets

    enc_key = base64.b64encode(_secrets.token_bytes(32)).decode()
    key_header = [
        "# App encryption key (AES-256, base64) the EMR uses for stored credentials",
        "# (fax provider passwords etc). REQUIRED at first boot by current carlos",
        "# develop. Generated by setup. Rotating it orphans values encrypted under",
        "# the old key; escrow it with the other instance secrets.",
    ]
    # Same secret tier as the db password (it protects stored credentials), so
    # when the operator vaulted the password above, the key must not become
    # the one plaintext secret left in the file — vault it the same way.
    key_vaulted = ""
    if vaulted:
        if not has_vault_source and sys.stdin.isatty():
            # Two separate encrypt_string runs, two independent "New Vault
            # password" prompts: differing answers (each individually
            # confirmed, so no typo guard trips) produce a host_vars file
            # whose two secrets decrypt under DIFFERENT vault passwords —
            # discovered only as a decrypt failure at provision time with no
            # hint which value is under which. Say so up front.
            log("NOTE: ansible-vault will prompt again for the app encryption key — "
                "enter the SAME vault password you used for the db password (two "
                "different answers make the file undecryptable as a whole)")
        argv = ["ansible-vault", "encrypt_string", "--stdin-name",
                "carlos_encryption_secret_key"]
        if vault_pw_file:
            argv += ["--vault-password-file", vault_pw_file]
        cp = runner.run(argv, input_text=enc_key, capture=True)
        if cp.returncode == 0 and "!vault" in (cp.stdout or ""):
            key_vaulted = cp.stdout.strip()
        elif not sys.stdin.isatty() \
                and s.get("CARLOS_SETUP_ALLOW_PLAINTEXT", "0") != "1":
            # Same fail-closed policy as the db password's S19 gate above: a
            # headless run whose vaulting broke mid-way must not quietly leave
            # the stored-credential data key as the one plaintext secret in
            # the file while exiting 0 — the warning would scroll past in CI.
            raise CtlError(
                "ansible-vault encrypted the db password but FAILED on the app "
                "encryption key — refusing to persist it in PLAINTEXT from a "
                "non-interactive run. Fix the vault password source and re-run "
                "setup, or set CARLOS_SETUP_ALLOW_PLAINTEXT=1 to accept "
                "plaintext knowingly."
            )
        else:
            log("ansible-vault did not encrypt the app encryption key — writing "
                "plaintext; vault it by hand alongside the db password")
    if key_vaulted:
        lines += key_header + [key_vaulted]
    else:
        lines += key_header + [
            "# Vault this value like the db password before committing anywhere.",
            f'carlos_encryption_secret_key: "{enc_key}"',
        ]

    # O_EXCL|O_NOFOLLOW: the target was just is_file()-checked as absent, so an
    # existing file/symlink here means one was planted between the check and
    # this write (TOCTOU) — fail closed rather than follow it and land the
    # 0600 plaintext-password write on the symlink's target. Matches the
    # staged-secret discipline in dbops/util.
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    log(f"Wrote {target} (0600)")

    tls_step = {
        "selfsigned": "nothing to do — a self-signed pair is generated "
                      "automatically (browsers warn; replace "
                      f"{emr_home}/container/conf/waf/certs/* for a real cert)",
        "manual": f"place cert + key at {emr_home}/container/conf/waf/certs/"
                  "{fullchain,privkey}.pem",
        "acme": f"once DNS for {server} points here: "
                f"sudo EMR_HOME={emr_home} carlos-ctl cert-renew",
    }[tls_mode]
    print(f"""
==> Setup captured for instance '{inst}'. NEXT STEPS:
  1. Review {target} (vault the db password: ansible-vault encrypt_string)
  2. Provision the host:      sudo ansible-playbook -i <inventory> ansible/site.yml
  3. Build images:            sudo EMR_HOME={emr_home} carlos-ctl build
     (the first build resolves + PINS the newest CARLOS and DrugRef GitHub
      releases, published WARs preferred — 'carlos-ctl source' shows/changes
      the pins)
  4. TLS ({tls_mode} mode): {tls_step}
  5. Start:                   sudo EMR_HOME={emr_home} carlos-ctl play && carlos-ctl check
  6. FRESH INSTALL ONLY — load the CARLOS schema before first login (reusing an
     existing OpenO/OSCAR datadir? SKIP this). MariaDB publishes no TCP port,
     so pipe the Flyway migration SQL through 'carlos-ctl db'. From a
     github.com/carlos-emr/carlos checkout:
       sudo EMR_HOME={emr_home} carlos-ctl db -e 'CREATE DATABASE IF NOT EXISTS oscar DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci'
       ...then apply database/mysql/migration/ files in version order (common +
       province interleaved), starting with common/V1__baseline_schema.sql —
       see migration/README.md upstream and README, "Schema", for the list.
  7. Seal secrets (single master) and ESCROW the age key OFF-HOST:
                              sudo EMR_HOME={emr_home} carlos-ctl seal
  8. Load the DrugRef database (see README, DrugRef).

  Review/complete these site-specific carlos.properties values by hand
  (the playbook renders billregion/ws_endpoint_url_base/TESTING/keystore
  passwords from the vars above — see README, carlos.properties):
    - Ontario billing IDs (only if billregion=ON): clinic_no / clinic_view /
      dataCenterId / billcenter — from your OHIP registration
    - PGP_KEY (only if you enable PGP export — needs a real key in the GPG keyring)
    - module credentials you enable: email.*, mcedt.*, hcv.*, OMD_HRM_*
  Clinic NAME / address are set in the app's Administration UI (database), not here.
""")
    return 0
