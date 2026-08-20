#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
# Ansible role checks. The core legs: syntax, lint, a full localhost
# check-mode render into a temp prefix (both obs profiles, token-free
# output), second-run idempotency, and the obs-profile toggle round trip
# (on -> off -> on). Around those, focused render legs pin the role's edge
# behavior: cross-instance collision asserts, the TLS modes, the host
# firewall + front-door NAT rules, obs/log-view credential character
# handling, PIN-encryption derivation, sidecar-config parsing, and a
# render->CLI lockstep pass (the CLI reads what the role rendered). Needs
# ansible-core (+ passlib with bcrypt<4.1, netaddr, ansible.utils) on the
# runner — skipped with a notice when ansible-playbook is absent so the
# hermetic CLI suite stays runnable anywhere.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/ansible"

if ! command -v ansible-playbook >/dev/null 2>&1; then
    # The bcrypt<4.1 pin is NOT optional: passlib 1.7.4's bcrypt backend
    # self-tests with a >72-byte secret, which bcrypt >= 4.1 rejects, so a
    # plain `pip install passlib` (which pulls bcrypt 5.x) makes the role's
    # own G1 control-node gate fail — following this hint without the pin
    # installs exactly the combination that cannot run.
    echo "ansible-playbook not found — skipping the Ansible checks (pip install" \
         "ansible-core passlib 'bcrypt<4.1' netaddr; ansible-galaxy collection" \
         "install ansible.utils)"
    exit 0
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/carlos-ansible-checks.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

echo "==> syntax check"
ansible-playbook -i localhost, --syntax-check site.yml

if command -v ansible-lint >/dev/null 2>&1; then
    echo "==> ansible-lint (advisory)"
    # ADVISORY, not a gate: the CI workflow pins ansible-lint UNPINNED on
    # purpose ("a new release flagging new style rules is acceptable churn"),
    # so a linter bump adding a rule must not hard-fail the build. Deliberate
    # house conventions are trimmed in .ansible-lint; whatever remains is
    # printed as a nudge but does not abort the run (which would take the real
    # gates below — syntax, --check render, idempotency, collision asserts,
    # PHI/token/lockstep checks — down with it under `set -e`).
    ansible-lint site.yml roles/carlos_podman || \
        echo "NOTE: ansible-lint reported style findings above (advisory — not a CI gate)"
else
    echo "ansible-lint not found — skipping lint"
fi

# --- render checks -----------------------------------------------------------------
# The full role needs root + systemd + podman; the RENDER contract (every
# template produces token-free output for both obs profiles) is checkable
# anywhere with a small render-only playbook that templates every file into a
# temp prefix twice (idempotency: second run changed=0).
render_play="$WORK/render.yml"
cat > "$render_play" <<'EOF'
# Render-only exercise of every carlos_podman template (no host mutation).
- hosts: localhost
  connection: local
  gather_facts: false
  # Role defaults + derived identity, exactly as the role loads them; the
  # test-specific values arrive as EXTRA VARS (-e @overrides) so they win.
  vars_files:
    - "{{ playbook_dir }}/../roles/carlos_podman/defaults/main.yml"
    - "{{ playbook_dir }}/../roles/carlos_podman/vars/main.yml"
  tasks:
    - name: Render every template
      template:
        src: "{{ item }}"
        dest: "{{ carlos_out }}/{{ item | basename | regex_replace('[.]j2$', '') }}"
        mode: "0600"
      loop: "{{ query('fileglob', playbook_dir ~ '/../roles/carlos_podman/templates/*.j2')
                + query('fileglob', playbook_dir ~ '/../roles/carlos_podman/templates/systemd/*.j2') }}"
EOF
mkdir -p "$WORK/plays"
cp "$render_play" "$WORK/plays/render.yml"
ln -s "$ROOT/ansible/roles" "$WORK/plays/../roles" 2>/dev/null || true

overrides() {  # overrides <outdir> <obs> — write the extra-vars file
    cat > "$WORK/overrides.json" <<OVR
{
  "carlos_out": "$1",
  "carlos_obs_enabled": $2,
  "carlos_service_uid": 990,
  "carlos_db_root_password": "test-root-pw",
  "carlos_encryption_secret_key": "dGVzdC1lbmNyeXB0aW9uLWtleS0zMi1ieXRlcy1iNjQhIQ==",
  "carlos_log_view_hash": "\$2b\$14\$renderhash",
  "carlos_log_view_allow": "192.168.20.0/24",
  "carlos_log_view_filter_enabled": true,
  "carlos_restic_password_effective": "render-restic-pw",
  "carlos_obs_http_password_effective": "render-obs-pw",
  "carlos_pin_encrypted_effective": "yes",
  "carlos_tomcat_keystore_password": "render-ks",
  "carlos_tomcat_truststore_password": "render-ts"
}
OVR
}

run_render() {  # run_render <outdir> <obs>
    mkdir -p "$1"
    overrides "$1" "$2"
    ANSIBLE_ROLES_PATH="$ROOT/ansible/roles" \
        ansible-playbook -i localhost, -e "@$WORK/overrides.json" "$WORK/plays/render.yml"
}

# The --check scenarios below drive site.yml with EXPLICIT extra-vars, and
# each one asserts on a var they deliberately leave at its ROLE DEFAULT. Run
# them against a COPY of the play outside $ROOT/ansible: ansible auto-loads
# host_vars/ next to the playbook, and $ROOT/ansible/host_vars/<instance>.yml
# is exactly what `carlos-ctl setup` writes (and .gitignore anticipates) on a
# developer's own machine. With the default instance name that file is
# host_vars/carlos.yml and every scenario host here is named `carlos`, so a
# provisioned checkout silently fed its own site config into all 12 gates.
# Measured: with a local host_vars setting carlos_server_name, the acme
# placeholder-hostname gate flipped from pass to "was NOT refused" — and the
# masking direction is worse, since a local value that happens to satisfy a
# scenario turns a genuinely broken assert green.
# The role resolves the repo's verbatim conf/, Containerfiles and carlos_ctl/
# sources through `{{ playbook_dir }}/..`, so the copy needs a sibling that
# points back at the checkout.
mkdir -p "$WORK/play"
cp "$ROOT/ansible/site.yml" "$WORK/play/site.yml"
# Mirror every top-level entry EXCEPT ansible/ (whose host_vars are the
# contamination this isolation exists to drop) so a newly-referenced sibling
# never has to be added here by hand.
for sib in "$ROOT"/* "$ROOT"/.extra-ca-bundle.crt; do
    [ -e "$sib" ] || continue
    base="$(basename "$sib")"
    [ "$base" = ansible ] && continue
    ln -sfn "$sib" "$WORK/$base"
done
PLAY="$WORK/play/site.yml"

fail=0

echo "==> full-role --check completes (the documented drift-review flow)"
# site.yml advertises `--check --diff` as THE drift review; it must be able to
# COMPLETE against any host state, including a fresh one (read-only probes are
# check_mode:false, registered results are default()-guarded, and fresh-host
# lookups are tolerated in check mode). The stubs dir supplies the host tools
# `command -v` probes for, so this runs anywhere the CLI suite runs.
check_inv="$WORK/check-inventory"
printf 'carlos ansible_host=localhost ansible_connection=local\n' > "$check_inv"
# carlos_service_user: a name that exists on NO host. host.yml's getent probe is
# check_mode:false (the relocation refusal needs the real passwd row), so with
# the default name a dev machine whose 'carlos' account has a different home
# than the play's carlos_service_user_home false-fails this stage — the same
# host-state leak M1 closed for host_vars. A nonexistent user makes the probe
# come back empty and the refusal skip via its `when:`; CI (no carlos user)
# already proves the play completes in exactly that state.
# carlos_run_secrets_dir rides with it: the role var derives /run/<instance>-emr,
# and on a machine with a LIVE carlos instance that path exists — check mode
# then has to resolve the throwaway owner against the real passwd to diff it
# ("chown failed: failed to look up user"). Redirecting it into $WORK keeps the
# stage off the host's /run entirely, same as carlos_emr_home.
cat > "$WORK/check-vars.json" <<OVR
{
  "carlos_emr_home": "$WORK/check-prefix/emr",
  "carlos_service_user": "carlos-gate-nouser",
  "carlos_run_secrets_dir": "$WORK/check-prefix/run-carlos-emr",
  "carlos_db_root_password": "test-root-pw",
  "carlos_encryption_secret_key": "dGVzdC1lbmNyeXB0aW9uLWtleS0zMi1ieXRlcy1iNjQhIQ==",
  "ansible_python_interpreter": "$(command -v python3)"
}
OVR
if ! PATH="$ROOT/tests/stubs:$PATH" ANSIBLE_ROLES_PATH="$ROOT/ansible/roles" \
        ansible-playbook -i "$check_inv" -e "@$WORK/check-vars.json" \
        --check "$PLAY" > "$WORK/check-run.log" 2>&1; then
    echo "FAIL: site.yml --check aborted — the documented drift review is broken"
    tail -40 "$WORK/check-run.log"
    fail=1
fi

echo "==> cross-instance collision asserts (unified address:port set)"
# One instance's HTTPS_PUBLISH_PORT colliding with a SIBLING's PMA_PORT on the
# shared default bind (127.0.0.1) crosses the old loopback/BIND_IP grouping —
# the assert must refuse it (README: "collisions are refused, not warned").
# carlos_emr_home must ride per-host in the INVENTORY here — an extra-var
# would override both hosts to one home and trip the emr_home assert instead.
# carlos_service_user rides as an extra-var on purpose: both hosts must share
# it (same-engine sibling semantics), and the throwaway name keeps the
# check_mode:false getent probe off the real passwd database (see the
# check-vars.json comment) for the coexistence run, which completes the play.
# carlos_run_secrets_dir: same rationale as check-vars.json — keep the
# coexistence run off the host's real /run/<instance>-emr. Sharing one value
# across both hosts is fine here: nothing asserts sibling distinctness for it,
# and --check never creates the directory.
cat > "$WORK/two-host-vars.json" <<OVR
{
  "carlos_service_user": "carlos-gate-nouser",
  "carlos_run_secrets_dir": "$WORK/check-prefix/run-emr",
  "carlos_db_root_password": "test-root-pw",
  "carlos_encryption_secret_key": "dGVzdC1lbmNyeXB0aW9uLWtleS0zMi1ieXRlcy1iNjQhIQ==",
  "ansible_python_interpreter": "$(command -v python3)"
}
OVR
collide_inv="$WORK/collide-inventory"
cat > "$collide_inv" <<INV
carlos  ansible_host=localhost ansible_connection=local carlos_emr_home=$WORK/check-prefix/emr
clinicb ansible_host=localhost ansible_connection=local carlos_instance=clinicb carlos_emr_home=$WORK/check-prefix/emr-b carlos_pma_port=8443
INV
if PATH="$ROOT/tests/stubs:$PATH" ANSIBLE_ROLES_PATH="$ROOT/ansible/roles" \
        ansible-playbook -i "$collide_inv" -e "@$WORK/two-host-vars.json" \
        --check "$PLAY" > "$WORK/collide-run.log" 2>&1; then
    echo "FAIL: a cross-group port collision (publish 8443 vs sibling pma 8443) was NOT refused"
    fail=1
elif ! grep -q "listener clash" "$WORK/collide-run.log"; then
    echo "FAIL: the two-instance collision run failed for the wrong reason:"
    tail -20 "$WORK/collide-run.log"
    fail=1
fi
# The documented per-instance-IP pattern (own bind_ip, offset loopback ports)
# must still pass the whole --check.
coexist_inv="$WORK/coexist-inventory"
# carlos_host_firewall_enabled=false on the SIBLING per the documented
# single-owner contract: the host firewall is host-global, so only one
# instance may own it. The sibling assert used to be vacuous here (role
# defaults are invisible in sibling hostvars — review finding); now that it
# resolves the default (true) correctly, the documented coexistence pattern
# must actually follow the documented contract.
cat > "$coexist_inv" <<INV
carlos  ansible_host=localhost ansible_connection=local carlos_emr_home=$WORK/check-prefix/emr
clinicb ansible_host=localhost ansible_connection=local carlos_instance=clinicb carlos_emr_home=$WORK/check-prefix/emr-b carlos_bind_ip=127.0.0.2 carlos_victorialogs_port=19428 carlos_victoriametrics_port=18428 carlos_vmalert_port=18880 carlos_pma_port=19444 carlos_host_firewall_enabled=false
INV
# The DEFAULT-config pair (both silently owning the host firewall) must now
# be REFUSED — this was the mutual front-door blackhole the vacuous assert
# shipped undetected.
dualfw_inv="$WORK/dualfw-inventory"
cat > "$dualfw_inv" <<INV
carlos  ansible_host=localhost ansible_connection=local carlos_emr_home=$WORK/check-prefix/emr
clinicb ansible_host=localhost ansible_connection=local carlos_instance=clinicb carlos_emr_home=$WORK/check-prefix/emr-b carlos_bind_ip=127.0.0.2 carlos_victorialogs_port=19428 carlos_victoriametrics_port=18428 carlos_vmalert_port=18880 carlos_pma_port=19444
INV
if PATH="$ROOT/tests/stubs:$PATH" ANSIBLE_ROLES_PATH="$ROOT/ansible/roles" \
        ansible-playbook -i "$dualfw_inv" -e "@$WORK/two-host-vars.json" \
        --check "$PLAY" > "$WORK/dualfw-run.log" 2>&1; then
    echo "FAIL: two default-config instances (both owning the host firewall) were NOT refused"
    fail=1
elif ! grep -q "ONE instance per machine" "$WORK/dualfw-run.log"; then
    echo "FAIL: the dual-hostfw run failed for the wrong reason:"
    tail -20 "$WORK/dualfw-run.log"
    fail=1
fi
if ! PATH="$ROOT/tests/stubs:$PATH" ANSIBLE_ROLES_PATH="$ROOT/ansible/roles" \
        ansible-playbook -i "$coexist_inv" -e "@$WORK/two-host-vars.json" \
        --check "$PLAY" > "$WORK/coexist-run.log" 2>&1; then
    echo "FAIL: the documented per-instance-IP coexistence pattern was refused:"
    tail -20 "$WORK/coexist-run.log"
    fail=1
fi

echo "==> render (obs enabled)"
run_render "$WORK/render-on" true
echo "==> render (obs disabled)"
run_render "$WORK/render-off" false
echo "==> idempotency (second obs-on render must report changed=0 templates)"
overrides "$WORK/render-on" true
out="$(ANSIBLE_ROLES_PATH="$ROOT/ansible/roles" \
        ansible-playbook -i localhost, -e "@$WORK/overrides.json" "$WORK/plays/render.yml")"
if grep -qE 'changed=[1-9]' <<<"$out"; then
    echo "FAIL: second render reported changes (non-idempotent template output)"
    fail=1
fi

echo "==> token-free renders"
for d in "$WORK/render-on" "$WORK/render-off"; do
    if grep -rE '@[A-Z0-9_]+@' "$d" >/dev/null 2>&1; then
        echo "FAIL: stray @TOKEN@ in $d"
        grep -rE '@[A-Z0-9_]+@' "$d" | head
        fail=1
    fi
    # Only OUR markers count: vmalert rules legitimately carry Prometheus
    # templating ({{ $labels.* }}, {{ $value }}), which is not Jinja residue.
    if grep -rE '\{\{ *carlos_|\{%' "$d" >/dev/null 2>&1; then
        echo "FAIL: un-rendered Jinja markers in $d"
        grep -rlE '\{\{ *carlos_|\{%' "$d" | head
        fail=1
    fi
done

echo "==> restic.env carries a NON-EMPTY RESTIC_PASSWORD (regression guard)"
# The template must read carlos_restic_password_effective (the derived
# password), not the raw carlos_restic_password (default '') — a blank
# RESTIC_PASSWORD breaks every backup on a default install.
for d in "$WORK/render-on" "$WORK/render-off"; do
    if ! grep -qE '^RESTIC_PASSWORD=.+' "$d/restic.env"; then
        echo "FAIL: $d/restic.env has an EMPTY RESTIC_PASSWORD"
        fail=1
    fi
done

echo "==> capability URLs never ride in the 0644 registry entry"
# The alert webhook/heartbeat are bearer capabilities: they belong ONLY in
# the 0600 alert.env sidecar, never in the world-readable registry.conf.
if grep -qE 'WEBHOOK|HEARTBEAT' "$WORK/render-on/registry.conf"; then
    echo "FAIL: registry.conf carries alert-channel capability URLs (0644 file)"
    fail=1
fi
if ! grep -q 'ALERT_WEBHOOK=' "$WORK/render-on/alert.env"; then
    echo "FAIL: alert.env sidecar did not render its channel keys"
    fail=1
fi

echo "==> TLS modes: acme port-80 redirect renders only in acme mode"
if grep -q "dport 80 dnat" "$WORK/render-on/nat.nft"; then
    echo "FAIL: the port-80 DNAT rendered outside acme mode"
    fail=1
fi
mkdir -p "$WORK/render-acme"
overrides "$WORK/render-acme" true
python3 - "$WORK/overrides.json" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
d["carlos_tls_mode"] = "acme"
d["carlos_acme_email"] = "ops@example.ca"
json.dump(d, open(p, "w"))
PY
ANSIBLE_ROLES_PATH="$ROOT/ansible/roles" \
    ansible-playbook -i localhost, -e "@$WORK/overrides.json" "$WORK/plays/render.yml" \
    > /dev/null
if ! grep -q "dport 80 dnat" "$WORK/render-acme/nat.nft"; then
    echo "FAIL: acme mode did not render the port-80 HTTP-01 redirect"
    fail=1
fi
if ! grep -q "^CARLOS_TLS_MODE=acme" "$WORK/render-acme/carlos-app.env"; then
    echo "FAIL: acme mode did not render CARLOS_TLS_MODE into carlos-app.env"
    fail=1
fi

echo "==> source selection: the default render carries the auto version/artifact keys"
# carlos_ref defaults to `auto` (release-first sticky resolution) and the
# CLI's resolver reads CARLOS_ARTIFACT/CARLOS_SOURCE_BRANCH from the same
# render — a template that drops one silently reverts an instance to manual
# semantics (or the built-in default) on the next playbook run.
for want in "^CARLOS_REF=auto" "^CARLOS_ARTIFACT=auto" "^CARLOS_SOURCE_BRANCH=main" \
            "^CARLOS_IMAGE_REPO=ghcr.io/carlos-emr/carlos-app" \
            "^DRUGREF_REF=auto" "^DRUGREF_ARTIFACT=auto" "^DRUGREF_SOURCE_BRANCH=master" \
            "^DRUGREF_IMAGE_REPO=ghcr.io/carlos-emr/carlos-drugref"; do
    if ! grep -q "$want" "$WORK/render-on/carlos-app.env"; then
        echo "FAIL: the default render is missing '$want' in carlos-app.env"
        fail=1
    fi
done

echo "==> host firewall: default-ON renders the default-deny table with SSH + daddr-qualified log-view"
# hostfw is ON by default now (finding 48). The default render must carry the
# drop-policy input chain, the SSH allow (or you lock yourself out), and the
# daddr-qualified log-view accepts (finding 58b — a bare saddr rule would admit
# the log-view port on every local address).
if ! grep -q "table inet carlos-hostfw" "$WORK/render-on/nat.nft"; then
    echo "FAIL: hostfw default-ON did not render the default-deny table"
    fail=1
fi
if ! grep -q "policy drop" "$WORK/render-on/nat.nft"; then
    echo "FAIL: hostfw table has no drop policy"
    fail=1
fi
if ! grep -qE "tcp dport 22 accept" "$WORK/render-on/nat.nft"; then
    echo "FAIL: hostfw allow set is missing the SSH port (lockout risk)"
    fail=1
fi
if ! grep -qE "ip daddr .* ip saddr .* tcp dport .* accept" "$WORK/render-on/nat.nft"; then
    echo "FAIL: hostfw log-view accept is not daddr-qualified (finding 58b)"
    fail=1
fi
# A bad SSH port must fail the playbook (assert), never silently render a
# lockout ruleset.
echo "==> host firewall: a malformed SSH port fails the safety assert"
badssh_inv="$WORK/badssh-inventory"
printf 'carlos ansible_host=localhost ansible_connection=local\n' > "$badssh_inv"
cat > "$WORK/badssh-vars.json" <<OVR
{
  "carlos_emr_home": "$WORK/check-prefix/emr",
  "carlos_db_root_password": "test-root-pw",
  "carlos_encryption_secret_key": "dGVzdC1lbmNyeXB0aW9uLWtleS0zMi1ieXRlcy1iNjQhIQ==",
  "carlos_host_firewall_ssh_port": "not-a-port",
  "ansible_python_interpreter": "$(command -v python3)"
}
OVR
if PATH="$ROOT/tests/stubs:$PATH" ANSIBLE_ROLES_PATH="$ROOT/ansible/roles" \
        ansible-playbook -i "$badssh_inv" -e "@$WORK/badssh-vars.json" \
        --check "$PLAY" > "$WORK/badssh-run.log" 2>&1; then
    echo "FAIL: a malformed carlos_host_firewall_ssh_port was NOT refused"
    fail=1
elif ! grep -q "valid TCP port" "$WORK/badssh-run.log"; then
    echo "FAIL: playbook failed but not on the SSH-port safety assert"
    tail -20 "$WORK/badssh-run.log"
    fail=1
fi

echo "==> config safety asserts: billing province enum, acme placeholder hostname"
# Finding c10: a typo'd province renders a broken billregion; acme mode with
# the placeholder SERVER_NAME would burn Let's Encrypt rate limit on a domain
# the operator does not control. Both must refuse before host mutation.
badprov_inv="$WORK/badprov-inventory"
printf 'carlos ansible_host=localhost ansible_connection=local\n' > "$badprov_inv"
cat > "$WORK/badprov-vars.json" <<OVR
{
  "carlos_emr_home": "$WORK/check-prefix/emr",
  "carlos_db_root_password": "test-root-pw",
  "carlos_encryption_secret_key": "dGVzdC1lbmNyeXB0aW9uLWtleS0zMi1ieXRlcy1iNjQhIQ==",
  "carlos_billing_province": "QC",
  "ansible_python_interpreter": "$(command -v python3)"
}
OVR
if PATH="$ROOT/tests/stubs:$PATH" ANSIBLE_ROLES_PATH="$ROOT/ansible/roles" \
        ansible-playbook -i "$badprov_inv" -e "@$WORK/badprov-vars.json" \
        --check "$PLAY" > "$WORK/badprov-run.log" 2>&1; then
    echo "FAIL: an unimplemented carlos_billing_province was NOT refused"
    fail=1
elif ! grep -q "provinces CARLOS implements" "$WORK/badprov-run.log"; then
    echo "FAIL: playbook failed but not on the billing-province assert"
    tail -20 "$WORK/badprov-run.log"
    fail=1
fi
cat > "$WORK/acmehost-vars.json" <<OVR
{
  "carlos_emr_home": "$WORK/check-prefix/emr",
  "carlos_db_root_password": "test-root-pw",
  "carlos_encryption_secret_key": "dGVzdC1lbmNyeXB0aW9uLWtleS0zMi1ieXRlcy1iNjQhIQ==",
  "carlos_tls_mode": "acme",
  "carlos_acme_email": "ops@example.ca",
  "ansible_python_interpreter": "$(command -v python3)"
}
OVR
if PATH="$ROOT/tests/stubs:$PATH" ANSIBLE_ROLES_PATH="$ROOT/ansible/roles" \
        ansible-playbook -i "$badprov_inv" -e "@$WORK/acmehost-vars.json" \
        --check "$PLAY" > "$WORK/acmehost-run.log" 2>&1; then
    echo "FAIL: acme mode with the placeholder SERVER_NAME was NOT refused"
    fail=1
elif ! grep -q "placeholder 'emr.example.ca'" "$WORK/acmehost-run.log"; then
    echo "FAIL: playbook failed but not on the acme server-name assert"
    tail -20 "$WORK/acmehost-run.log"
    fail=1
fi

echo "==> config safety asserts: obs credential rejects curl/TOML-hostile chars (M8)"
# An obs password with a double quote silently corrupted the TOML/curl config
# it renders into; the playbook must refuse it before host mutation.
cat > "$WORK/badobs-vars.json" <<OVR
{
  "carlos_emr_home": "$WORK/check-prefix/emr",
  "carlos_db_root_password": "test-root-pw",
  "carlos_encryption_secret_key": "dGVzdC1lbmNyeXB0aW9uLWtleS0zMi1ieXRlcy1iNjQhIQ==",
  "carlos_obs_http_password": "bad\"pw",
  "ansible_python_interpreter": "$(command -v python3)"
}
OVR
if PATH="$ROOT/tests/stubs:$PATH" ANSIBLE_ROLES_PATH="$ROOT/ansible/roles" \
        ansible-playbook -i "$badprov_inv" -e "@$WORK/badobs-vars.json" \
        --check "$PLAY" > "$WORK/badobs-run.log" 2>&1; then
    echo "FAIL: an obs password with a double quote was NOT refused"
    fail=1
elif ! grep -q "double quote or backslash" "$WORK/badobs-run.log"; then
    echo "FAIL: playbook failed but not on the obs-password safety assert"
    tail -20 "$WORK/badobs-run.log"
    fail=1
elif grep -q 'bad"pw' "$WORK/badobs-run.log"; then
    echo "FAIL: the obs password value leaked into the assert output"
    fail=1
fi

echo "==> config safety asserts: obs credential rejects control characters (pass-8 M3)"
# A control character (pasted newline/tab) passed the quote/backslash assert
# but crash-loops the log collector at TOML load; the playbook must refuse it
# before host mutation, like `carlos-ctl rotate obs` does at rotate time.
# JSON-escaped \t reaches ansible as a REAL tab via the -e file's JSON layer.
cat > "$WORK/ctrlobs-vars.json" <<OVR
{
  "carlos_emr_home": "$WORK/check-prefix/emr",
  "carlos_db_root_password": "test-root-pw",
  "carlos_encryption_secret_key": "dGVzdC1lbmNyeXB0aW9uLWtleS0zMi1ieXRlcy1iNjQhIQ==",
  "carlos_obs_http_password": "bad\tpw",
  "ansible_python_interpreter": "$(command -v python3)"
}
OVR
if PATH="$ROOT/tests/stubs:$PATH" ANSIBLE_ROLES_PATH="$ROOT/ansible/roles" \
        ansible-playbook -i "$badprov_inv" -e "@$WORK/ctrlobs-vars.json" \
        --check "$PLAY" > "$WORK/ctrlobs-run.log" 2>&1; then
    echo "FAIL: an obs password with a control character (tab) was NOT refused"
    fail=1
elif ! grep -q "control characters" "$WORK/ctrlobs-run.log"; then
    echo "FAIL: playbook failed but not on the obs-password control-char assert"
    tail -20 "$WORK/ctrlobs-run.log"
    fail=1
elif grep -q "$(printf 'bad\tpw')" "$WORK/ctrlobs-run.log"; then
    echo "FAIL: the obs password value leaked into the assert output"
    fail=1
fi

echo "==> config safety asserts: obs username rejects a colon (ninth-pass L4)"
# RFC 7617 basic auth splits on the FIRST colon, so a colon in the obs username
# silently moves part of it into the password — every store client 401s. The
# playbook must refuse it before host mutation.
cat > "$WORK/colonobs-vars.json" <<OVR
{
  "carlos_emr_home": "$WORK/check-prefix/emr",
  "carlos_db_root_password": "test-root-pw",
  "carlos_encryption_secret_key": "dGVzdC1lbmNyeXB0aW9uLWtleS0zMi1ieXRlcy1iNjQhIQ==",
  "carlos_obs_http_user": "obs:clinic",
  "ansible_python_interpreter": "$(command -v python3)"
}
OVR
if PATH="$ROOT/tests/stubs:$PATH" ANSIBLE_ROLES_PATH="$ROOT/ansible/roles" \
        ansible-playbook -i "$badprov_inv" -e "@$WORK/colonobs-vars.json" \
        --check "$PLAY" > "$WORK/colonobs-run.log" 2>&1; then
    echo "FAIL: an obs username with a colon was NOT refused"
    fail=1
elif ! grep -q "colon" "$WORK/colonobs-run.log"; then
    echo "FAIL: playbook failed but not on the obs-username colon assert"
    tail -20 "$WORK/colonobs-run.log"
    fail=1
fi

echo "==> config safety asserts: carlos_emr_home rejects whitespace (ninth-pass L2)"
# A space in the path makes systemd word-split Environment=EMR_HOME=... so every
# timer/guard/alert unit operates on a different, nonexistent home. Refuse it.
cat > "$WORK/spacehome-vars.json" <<OVR
{
  "carlos_emr_home": "$WORK/check prefix/emr",
  "carlos_db_root_password": "test-root-pw",
  "carlos_encryption_secret_key": "dGVzdC1lbmNyeXB0aW9uLWtleS0zMi1ieXRlcy1iNjQhIQ==",
  "ansible_python_interpreter": "$(command -v python3)"
}
OVR
if PATH="$ROOT/tests/stubs:$PATH" ANSIBLE_ROLES_PATH="$ROOT/ansible/roles" \
        ansible-playbook -i "$badprov_inv" -e "@$WORK/spacehome-vars.json" \
        --check "$PLAY" > "$WORK/spacehome-run.log" 2>&1; then
    echo "FAIL: a carlos_emr_home with whitespace was NOT refused"
    fail=1
elif ! grep -q "whitespace" "$WORK/spacehome-run.log"; then
    echo "FAIL: playbook failed but not on the emr_home whitespace assert"
    tail -20 "$WORK/spacehome-run.log"
    fail=1
fi

echo "==> same-engine siblings must agree on carlos_drugref_ref (ninth-pass M2)"
# Two instances sharing a service user (one image store) that disagree on
# carlos_drugref_ref: a build in one silently retags the drugref image the
# other runs. The assert must refuse — extends the pass-7 same-engine gate to
# the drugref ref (a static presence check on the assert's `that:` list).
if ! grep -q "carlos_drugref_ref" "$ROOT/ansible/roles/carlos_podman/tasks/asserts.yml"; then
    echo "FAIL: the same-engine assert does not compare carlos_drugref_ref"
    fail=1
fi

echo "==> control-node bcrypt/passlib gate is present and pinned (G1)"
# The role must probe password_hash('bcrypt') early (it fails mid-play on
# bcrypt >= 4.1), and both the role and README must name the bcrypt<4.1 pin.
# The FAILING path can't be exercised here — this CI venv is pinned so passlib
# works — so this is a static presence check, not a negative-assert run.
if ! grep -q "password_hash('bcrypt')" "$ROOT/ansible/roles/carlos_podman/tasks/asserts.yml"; then
    echo "FAIL: the control-node bcrypt probe is missing from asserts.yml"
    fail=1
fi
if ! grep -q "bcrypt<4.1" "$ROOT/ansible/roles/carlos_podman/tasks/asserts.yml" \
   || ! grep -q "bcrypt<4.1" "$ROOT/README.md"; then
    echo "FAIL: the bcrypt<4.1 pin is not documented in both asserts.yml and README.md"
    fail=1
fi

echo "==> userns chown hand-over sets BOTH uid and gid (pass-14 H1)"
# The exporter cnf and the log-view Caddyfile are handed to non-root CONTAINER
# uids (65534 / 10013) by a rootless `podman unshare chown`. chown(2) refuses
# a file whose current owner OR group sits outside the userns id_map, and host
# uid/gid 0 are never mapped — so a bare `chown <user> <file>` (group left as
# root on a root-rendered file) makes the unshare chown EPERM every run:
# verified live, carlos:root -> EPERM, carlos:carlos -> ok. Static shape check:
# every pre-chown feeding a `podman unshare chown` must name a group.
inst_yml="$ROOT/ansible/roles/carlos_podman/tasks/instance.yml"
while read -r line; do
    # `chown "{{ carlos_service_user }}" ...` — no ':' after the user var.
    if grep -qE 'chown "\{\{ carlos_service_user \}\}" ' <<<"$line"; then
        echo "FAIL: pre-chown without a group before a userns chown: $line"
        fail=1
    fi
done < <(grep -n 'chown "{{ carlos_service_user }}' "$inst_yml" || true)
for f in metrics/exporter.my.cnf caddy/Caddyfile; do
    if ! grep -q "chown \"{{ carlos_service_user }}:{{ carlos_service_user }}\" \"{{ carlos_conf_dir }}/$f\"" \
         "$inst_yml"; then
        echo "FAIL: $f is not handed over with BOTH uid and gid before its userns chown"
        fail=1
    fi
done

echo "==> a too-narrow pre-existing subuid/subgid grant is asserted (pass-15 H1)"
# The grant task is SKIPPED whenever the user already has any subuid line, so
# a narrow pre-existing grant survives with nothing checking its WIDTH — and
# rootless podman maps from the FIRST grant only, so container id 65534 (the
# mysqld-exporter; apt inside the image builds) then falls outside the map.
# Static shape check on host.yml: the assert must exist, compare against
# 65534, and tell the operator to WIDEN rather than append.
host_yml="$ROOT/ansible/roles/carlos_podman/tasks/host.yml"
defaults_yml="$ROOT/ansible/roles/carlos_podman/defaults/main.yml"
asserts_yml="$ROOT/ansible/roles/carlos_podman/tasks/asserts.yml"
if ! grep -q "65534" "$host_yml"; then
    echo "FAIL: host.yml does not assert the subuid/subgid grant covers container id 65534"
    fail=1
fi
if ! grep -qi "WIDEN the existing one" "$host_yml"; then
    echo "FAIL: the subid-width assert does not tell the operator to WIDEN the first grant"
    fail=1
fi
# The CLI side must warn too (build, before a long doomed build; play, before
# the exporter chown fails).
if ! grep -q "subid_map_preflight" "$ROOT/carlos_ctl/validate.py" \
   || ! grep -q "subid_map_preflight" "$ROOT/carlos_ctl/build.py"; then
    echo "FAIL: subid_map_preflight is not wired into validate.py and build.py"
    fail=1
fi

echo "==> the traversal parents are declared BEFORE any 0700 leaf (pass-17 H1)"
# `ansible.builtin.file` stamps the item's `mode:` onto every INTERMEDIATE
# directory it has to create, root-owned. When the tree loop led with a 0700
# leaf, a FRESH host got $EMR_HOME, container/, container/conf/ and conf/waf/
# as root:root 0700 — and the ownership sweep lists only the LEAVES, so
# nothing handed them over. The rootless engine could then not TRAVERSE into
# any pod-mounted path ("statfs .../carlos.properties: permission denied"),
# i.e. `kube play` failed on its first volume. Verified live; missed for 16
# passes because every prior test ran scripts/dev-setup.sh first, which
# mkdir -p's those parents 0755.
#
# Shape check: each shared parent must appear in the loop, and every one of
# them must be declared BEFORE the first entry carrying an explicit mode
# more restrictive than 0755.
tree_block="$(awk '/^- name: Instance directory tree$/{f=1} f{print} f&&/^$/{exit}' "$inst_yml")"
# The boundary is the first OWNER-ONLY (0700) leaf: that is the mode whose
# accidental inheritance locked the rootless engine out of every parent.
first_restrictive="$(grep -n 'mode: "0700"' <<<"$tree_block" | head -1 | cut -d: -f1)"
if [ -z "$first_restrictive" ]; then
    echo "FAIL: could not locate a 0700 entry in the instance directory tree"
    fail=1
fi
for parent in \
    '{{ carlos_emr_home }}' \
    '{{ carlos_emr_home }}/container' \
    '{{ carlos_conf_dir }}' \
    '{{ carlos_conf_dir }}/waf' \
    '{{ carlos_data_dir }}' \
    '{{ carlos_emr_home }}/logs' \
    '{{ carlos_emr_home }}/metrics' \
    '{{ carlos_emr_home }}/monitor' \
    '{{ carlos_emr_home }}/backup' \
    '{{ carlos_emr_home }}/run'; do
    ln="$(grep -n "path: \"$parent\"[,}]" <<<"$tree_block" | head -1 | cut -d: -f1)"
    if [ -z "$ln" ]; then
        echo "FAIL: traversal parent '$parent' is not declared in the instance directory tree"
        fail=1
    elif [ -n "$first_restrictive" ] && [ "$ln" -gt "$first_restrictive" ]; then
        echo "FAIL: traversal parent '$parent' is declared AFTER a restrictive-mode leaf —" \
             "ansible would have created it with that leaf's mode on a fresh host"
        fail=1
    fi
done
# conf/ must stay root-OWNED (secrets-recipient injection) but group-traversable
# by the service user; data/logs/metrics must be service-user-owned.
if ! grep -q 'path: "{{ carlos_conf_dir }}", group: "{{ carlos_service_user }}", mode: "0750"' \
     <<<"$tree_block"; then
    echo "FAIL: conf/ is not root-owned + service-user-group 0750 (traversal without write)"
    fail=1
fi
for svc_owned in '{{ carlos_data_dir }}' '{{ carlos_emr_home }}/logs' '{{ carlos_emr_home }}/metrics'; do
    if ! grep -A1 "path: \"$svc_owned\", owner: \"{{ carlos_service_user }}\"" <<<"$tree_block" \
         | grep -q 'group: "{{ carlos_service_user }}"'; then
        echo "FAIL: $svc_owned is not handed to the service user (rootless traversal)"
        fail=1
    fi
done

echo "==> the engine store is kept clear of podman's rootless-netns masks (pass-18 H1)"
# podman's rootless network namespace hides part of the filesystem from itself:
# /run unconditionally, and the CNI state dir's nearest EXISTING parent —
# podman walks up from /var/lib/cni ("if /var/lib/cni does not exist, use the
# parent dir"), so on a netavark-only host that lands on /var/lib. The service
# user's home is the graphroot's parent, and netavark reads its network
# definitions from <graphroot>/networks, so a store under either prefix makes
# every named bridge network fail with "unable to find network with name or ID
# <net>: network not found" while `podman network ls` lists it — and
# `carlos-ctl play` aborts on its first `kube play`. Measured on podman 4.9.3
# with two pristine accounts differing only in store location.
if grep -q 'home: "/var/lib/' "$host_yml"; then
    echo "FAIL: the service account's home is hardcoded under /var/lib"
    fail=1
fi
if ! grep -q 'home: "{{ carlos_service_user_home }}"' "$host_yml"; then
    echo "FAIL: the service account's home is not driven by carlos_service_user_home"
    fail=1
fi
if ! grep -q 'path: /var/lib/cni' "$host_yml"; then
    echo "FAIL: the role does not ensure /var/lib/cni exists — the backstop for a"
    echo "      store pointed under /var/lib by host_vars or a site storage.conf"
    fail=1
fi
svc_home_default="$(grep -E '^carlos_service_user_home:' "$defaults_yml" | head -1)"
case "$svc_home_default" in
    # ONE pattern, not `*'/run/'*|*'/var/run/'*`: the second alternative is
    # dead — '/var/run/carlos' contains the substring '/run/' and is already
    # matched by the first. shellcheck flags the pair (SC2221/SC2222) as a
    # WARNING, and CI runs `shellcheck -S warning` as a hard gate BEFORE the
    # hermetic e2e suite step — so the redundant alternative turned the whole
    # e2e job red and left `sudo tests/run-tests.sh` SKIPPED on every run
    # since it landed (main included). Both spellings still fail here.
    *'/run/'*)
        echo "FAIL: the carlos_service_user_home DEFAULT is under a masked prefix:"
        echo "      $svc_home_default"
        fail=1 ;;
    "") echo "FAIL: carlos_service_user_home has no default in defaults/main.yml"; fail=1 ;;
esac
# /run has no escape hatch, so an explicit home there must be refused. Drive
# the assert for real rather than grepping for the task.
for bad_home in /run/carlos /var/run/carlos; do
    cat > "$WORK/badhome-vars.json" <<OVR
{
  "carlos_emr_home": "$WORK/check-prefix/emr",
  "carlos_db_root_password": "test-root-pw",
  "carlos_encryption_secret_key": "dGVzdC1lbmNyeXB0aW9uLWtleS0zMi1ieXRlcy1iNjQhIQ==",
  "carlos_service_user_home": "$bad_home",
  "ansible_python_interpreter": "$(command -v python3)"
}
OVR
    if PATH="$ROOT/tests/stubs:$PATH" ANSIBLE_ROLES_PATH="$ROOT/ansible/roles" \
            ansible-playbook -i "$badprov_inv" -e "@$WORK/badhome-vars.json" \
            --check "$PLAY" > "$WORK/badhome-run.log" 2>&1; then
        echo "FAIL: carlos_service_user_home=$bad_home was NOT refused"
        fail=1
    elif ! grep -q "replaces /run unconditionally" "$WORK/badhome-run.log"; then
        echo "FAIL: $bad_home failed the playbook, but not on the masked-store assert:"
        tail -20 "$WORK/badhome-run.log"
        fail=1
    fi
done
# ...and /var/lib must NOT be in that refusal list: the /var/lib/cni task makes
# such a store work, and a blanket refusal would be a policy the code cannot
# justify (it would also fail the FHS-canonical layout for no reason). Checked
# statically against the assert's own condition list — driving it would need a
# service account that does not exist on the check host, which fails later
# tasks for unrelated reasons.
masked_assert="$(awk '/^- name: carlos_service_user_home, when set,/{f=1} f{print} f&&/^$/{exit}' \
    "$asserts_yml")"
if [ -z "$masked_assert" ]; then
    echo "FAIL: the masked-store assert on carlos_service_user_home is gone"
    fail=1
else
    for must in "'\^/run/'" "'\^/var/run/'"; do
        grep -q "match($must)" <<<"$masked_assert" || {
            echo "FAIL: the masked-store assert no longer refuses $must —"
            echo "      podman replaces /run unconditionally, in every version"
            fail=1
        }
    done
    if grep -q "match('\^/var/lib/')" <<<"$masked_assert"; then
        echo "FAIL: the masked-store assert refuses /var/lib — the /var/lib/cni task"
        echo "      makes that store location work, so refusing it is unjustified"
        fail=1
    fi
fi

# The relocation guard: changing carlos_service_user_home on a provisioned host
# must REFUSE rather than silently repoint podman at an empty graphroot
# (ansible.builtin.user rewrites /etc/passwd but does not move the directory).
if ! grep -q "would orphan the engine store" "$host_yml"; then
    echo "FAIL: no guard against silently relocating an existing account's home —"
    echo "      a carlos_service_user_home change would orphan the image store"
    fail=1
fi
if grep -qE '^[[:space:]]*move_home:' "$host_yml"; then
    echo "FAIL: move_home is back — relocating a live engine store must stay a"
    echo "      deliberate operator step, not a side effect of a playbook run"
    fail=1
fi

echo "==> the TLS re-stat is unconditional (role re-run idempotency, pass-17 H2)"
# `register:` on a SKIPPED task overwrites the variable with the skip result
# ({changed: false, skipped: true}) — no `.stat`. With `when: _tls_selfsigned
# is changed` on the re-stat, every playbook run AFTER the first (where the
# generation task is skipped by its `creates:`) destroyed _tls_cert.stat and
# aborted the play at the next task's `when: not _tls_cert.stat.exists`, so
# the documented "edit host_vars -> re-run the playbook" loop was broken for
# every provisioned selfsigned install. --check cannot catch it (a fresh check
# prefix always reports the generation task changed).
restat_block="$(awk '/^- name: Re-check TLS material after generation$/{f=1} f{print} f&&/^$/{exit}' \
                "$inst_yml")"
if grep -qE '^  when:' <<<"$restat_block"; then
    echo "FAIL: the TLS re-stat is conditional again — a skipped run clobbers _tls_cert.stat"
    fail=1
fi
# Same class anywhere else: a conditionally-registered var dereferenced with
# .stat/.rc/.content must be guarded (is skipped / is defined / | default).
while read -r loc; do
    echo "FAIL: unguarded dereference of a conditionally-registered variable: $loc"
    fail=1
done < <(
    python3 - "$inst_yml" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
blocks = re.split(r"\n(?=- name:)", text)
cond = set()
for b in blocks:
    m = re.search(r"^\s*register:\s*(\S+)", b, re.M)
    if m and re.search(r"^  when:", b, re.M):
        cond.add(m.group(1))
for b in blocks:
    own = re.search(r"^\s*register:\s*(\S+)", b, re.M)
    for reg in cond:
        if own and own.group(1) == reg:
            continue  # same task: not evaluated when the task is skipped
        # Guards are block-scoped: a multi-line `when:` may carry the
        # `is defined` on a different line than the dereference.
        guarded = re.search(
            rf"\b{re.escape(reg)}(\.\w+)*\s+is\s+(not\s+)?(defined|skipped)\b", b
        ) or re.search(rf"\b{re.escape(reg)}(\.\w+)*\s*\|\s*default\b", b)
        if guarded:
            continue
        for line in b.splitlines():
            for mm in re.finditer(rf"\b{re.escape(reg)}\.(stat|rc|content|stdout)\b", line):
                s = line.strip()
                if s.startswith("#") or "default(" in s:
                    continue
                print(f"{reg}.{mm.group(1)} -> {s[:100]}")
PY
)

echo "==> hostfw: sibling extra-allow entries reach the ruleset"
# The single hostfw owner must be able to admit sibling front doors (review
# finding: multi-instance hosts had no way to honor the single-owner
# contract). Render with the knob set and assert both rule shapes land.
pin_render_nft="$WORK/extra-allow"
mkdir -p "$pin_render_nft"
cat > "$WORK/extra-allow-vars.json" <<OVR
{
  "carlos_out": "$pin_render_nft",
  "carlos_obs_enabled": false,
  "carlos_service_uid": 990,
  "carlos_db_root_password": "test-root-pw",
  "carlos_encryption_secret_key": "dGVzdC1lbmNyeXB0aW9uLWtleS0zMi1ieXRlcy1iNjQhIQ==",
  "carlos_log_view_hash": "\$2b\$14\$renderhash",
  "carlos_log_view_allow": "192.168.20.0/24",
  "carlos_log_view_filter_enabled": true,
  "carlos_restic_password_effective": "render-restic-pw",
  "carlos_obs_http_password_effective": "render-obs-pw",
  "carlos_pin_encrypted_effective": "yes",
  "carlos_tomcat_keystore_password": "render-ks",
  "carlos_tomcat_truststore_password": "render-ts",
  "carlos_host_firewall_extra_allow": [{"ip": "192.0.2.11", "port": 443}]
}
OVR
ANSIBLE_ROLES_PATH="$ROOT/ansible/roles" \
    ansible-playbook -i localhost, -e "@$WORK/extra-allow-vars.json" \
    "$WORK/plays/render.yml" > /dev/null
if ! grep -q 'ip daddr 192.0.2.11 meta l4proto tcp ct original proto-dst 443 accept' \
        "$pin_render_nft/nat.nft"; then
    echo "FAIL: carlos_host_firewall_extra_allow did not render the conntrack-original allow"
    fail=1
fi
if ! grep -q 'ip daddr 192.0.2.11 tcp dport 443 accept' "$pin_render_nft/nat.nft"; then
    echo "FAIL: carlos_host_firewall_extra_allow did not render the direct-dport allow"
    fail=1
fi

echo "==> obs store auth: flags in specs, plaintext NEVER in specs"
# The stores + every client must carry auth wiring, and the credential must
# reach containers by NAME (podman secret) — a plaintext token in a 0644
# rendered pod spec is the exact leak the design forbids.
for want in "-httpAuth.username=" "-datasource.basicAuth.passwordFile="; do
    if ! grep -q -- "$want" "$WORK/render-on/carlos-obs.yaml"; then
        echo "FAIL: obs pod spec lacks $want (store auth unwired)"
        fail=1
    fi
done
if ! grep -q -- "-remoteWrite.basicAuth.passwordFile=" "$WORK/render-on/carlos-app.yaml"; then
    echo "FAIL: vmagent lacks -remoteWrite.basicAuth.passwordFile (401s on remote-write)"
    fail=1
fi
if ! grep -q "password_file: /etc/obs-auth/password" "$WORK/render-on/scrape.yml"; then
    echo "FAIL: the victorialogs scrape job lacks its basic_auth password_file"
    fail=1
fi
if grep -rl "render-obs-pw" "$WORK/render-on/carlos-obs.yaml" "$WORK/render-on/carlos-app.yaml" \
        "$WORK/render-on/scrape.yml" >/dev/null 2>&1; then
    echo "FAIL: the obs credential PLAINTEXT leaked into a 0644 rendered spec"
    fail=1
fi
if ! grep -q 'auth.password = "render-obs-pw"' "$WORK/render-on/journald-collector.toml"; then
    echo "FAIL: the vector sink lacks its inline store credential (0600 render)"
    fail=1
fi
if ! grep -q "header_up Authorization" "$WORK/render-on/Caddyfile"; then
    echo "FAIL: the Caddyfile logview routes lack the upstream store credential"
    fail=1
fi

echo "==> PHI: redaction covers ALL streams; PIN encryption derived"
# Redaction must no longer be waf-only (finding 30): the transform applies to
# every stream, plus demographic_no query-param masking.
if grep -q 'starts_with(to_string(.stream)' "$WORK/render-on/journald-collector.toml"; then
    echo "FAIL: log redaction is still scoped to waf-* streams only"
    fail=1
fi
if ! grep -q 'demographic_no' "$WORK/render-on/journald-collector.toml"; then
    echo "FAIL: no demographic_no query-param masking in the collector redaction"
    fail=1
fi
# The template honors the derived PIN-encryption value (finding 32; the
# task-level fresh-vs-existing derivation is exercised by the full --check
# run, which renders with the datadir stat in place).
if ! grep -q '^IS_PIN_ENCRYPTED=yes' "$WORK/render-on/carlos.properties"; then
    echo "FAIL: carlos.properties did not honor carlos_pin_encrypted_effective"
    fail=1
fi

echo "==> PIN encryption: the REAL derivation chain (M1 + pass-17 H6)"
# The render play above injects carlos_pin_encrypted_effective directly and so
# BYPASSES the derivation in tasks/instance.yml. Two regressions live here:
#   M1: carlos_pin_encrypted defaults to "" (DEFINED, empty) in
#       defaults/main.yml and single-arg Jinja default() only fires on
#       undefined, so IS_PIN_ENCRYPTED= rendered BLANK.
#   pass-17 H6: the derivation then produced 'yes' for a FRESH datadir, but
#       provisioning runs BEFORE the schema load and the Flyway seed inserts
#       the bootstrap admin with a CLEARTEXT pin — the login path encrypts the
#       SUBMITTED pin before comparing, so the seeded account could never log
#       in (verified live). Cleartext is the correct default for BOTH cases.
# This play runs the same effective-var expression as instance.yml (keep in
# lockstep with the "Render carlos.properties" task).
pin_play="$WORK/plays/pin-derive.yml"
cat > "$pin_play" <<'EOF'
- hosts: localhost
  connection: local
  gather_facts: false
  vars_files:
    - "{{ playbook_dir }}/../roles/carlos_podman/defaults/main.yml"
    - "{{ playbook_dir }}/../roles/carlos_podman/vars/main.yml"
  tasks:
    - name: Detect an initialized MariaDB datadir (same probe as instance.yml)
      stat:
        path: "{{ carlos_data_dir }}/{{ carlos_datadir_signature }}"
      register: _pin_datadir
    - name: Render carlos.properties through the real derivation
      template:
        src: "{{ playbook_dir }}/../roles/carlos_podman/templates/carlos.properties.j2"
        dest: "{{ carlos_out }}/carlos.properties"
        mode: "0600"
      vars:
        # lockstep with tasks/instance.yml (Render carlos.properties)
        carlos_pin_encrypted_effective: "{{ carlos_pin_encrypted | default('no', true) }}"
EOF
pin_render() {  # pin_render <outdir> <emr_home> [extra -e args...]
    local out="$1" home="$2"; shift 2
    mkdir -p "$out"
    cat > "$WORK/pin-vars.json" <<OVR
{
  "carlos_out": "$out",
  "carlos_emr_home": "$home",
  "carlos_db_root_password": "test-root-pw",
  "carlos_encryption_secret_key": "dGVzdC1lbmNyeXB0aW9uLWtleS0zMi1ieXRlcy1iNjQhIQ==",
  "carlos_tomcat_keystore_password": "render-ks",
  "carlos_tomcat_truststore_password": "render-ts"
}
OVR
    ANSIBLE_ROLES_PATH="$ROOT/ansible/roles" \
        ansible-playbook -i localhost, -e "@$WORK/pin-vars.json" "$@" "$pin_play" \
        > /dev/null
}
# pass-17 H6: a FRESH datadir must render cleartext — it is the format the
# Flyway seed writes for the only account that exists at first login.
pin_render "$WORK/pin-fresh" "$WORK/pin-fresh/emr"
if ! grep -q '^IS_PIN_ENCRYPTED=no' "$WORK/pin-fresh/carlos.properties"; then
    echo "FAIL: a fresh datadir must render IS_PIN_ENCRYPTED=no — 'yes' makes the \
seeded bootstrap account unable to log in (got: \
$(grep '^IS_PIN_ENCRYPTED' "$WORK/pin-fresh/carlos.properties" || echo MISSING))"
    fail=1
fi
mkdir -p "$WORK/pin-existing/emr/data/mariadb-mnt/mysql"
pin_render "$WORK/pin-existing" "$WORK/pin-existing/emr"
if ! grep -q '^IS_PIN_ENCRYPTED=no' "$WORK/pin-existing/carlos.properties"; then
    echo "FAIL: pre-existing datadir must render IS_PIN_ENCRYPTED=no (compat)"
    fail=1
fi
# The M1 regression itself: an explicit-empty override (and the shipped
# default IS the empty string) must still resolve, never render a blank value.
pin_render "$WORK/pin-empty" "$WORK/pin-empty/emr" -e carlos_pin_encrypted=
if grep -q '^IS_PIN_ENCRYPTED=$' "$WORK/pin-empty/carlos.properties" || \
   ! grep -q '^IS_PIN_ENCRYPTED=no' "$WORK/pin-empty/carlos.properties"; then
    echo "FAIL: empty carlos_pin_encrypted rendered a blank/unresolved value \
(cleartext-PIN regression, finding M1)"
    fail=1
fi
# An explicit opt-in must still be honored verbatim.
pin_render "$WORK/pin-yes" "$WORK/pin-yes/emr" -e carlos_pin_encrypted=yes
if ! grep -q '^IS_PIN_ENCRYPTED=yes' "$WORK/pin-yes/carlos.properties"; then
    echo "FAIL: an explicit carlos_pin_encrypted=yes did not reach carlos.properties"
    fail=1
fi

echo "==> clinical/data knobs: opt-in with upstream defaults preserved"
# Finding C24/C27: carlos_rx_allergy_checking and carlos_jdbc_zero_date are
# opt-in knobs — the rendered defaults must keep the upstream values, and a
# host_vars override must actually reach the file.
if ! grep -q '^RX_ALLERGY_CHECKING=no' "$WORK/pin-fresh/carlos.properties"; then
    echo "FAIL: RX_ALLERGY_CHECKING default drifted from the upstream 'no'"
    fail=1
fi
if ! grep -q 'zeroDateTimeBehavior=round&' "$WORK/pin-fresh/carlos.properties"; then
    echo "FAIL: zeroDateTimeBehavior default drifted from the upstream 'round'"
    fail=1
fi
pin_render "$WORK/pin-knobs" "$WORK/pin-knobs/emr" \
    -e carlos_rx_allergy_checking=yes -e carlos_jdbc_zero_date=convertToNull
if ! grep -q '^RX_ALLERGY_CHECKING=yes' "$WORK/pin-knobs/carlos.properties"; then
    echo "FAIL: carlos_rx_allergy_checking=yes did not reach carlos.properties"
    fail=1
fi
if ! grep -q 'zeroDateTimeBehavior=convertToNull&' "$WORK/pin-knobs/carlos.properties"; then
    echo "FAIL: carlos_jdbc_zero_date=convertToNull did not reach the JDBC URL"
    fail=1
fi

echo "==> vmalert rules: aggregated ingestion alert + memory/load coverage"
# LogIngestionStalled must aggregate: VictoriaLogs exports the counter per
# ingestion protocol and only jsonline is used, so an unaggregated == 0 fires
# forever on the unused-path series (alert-fatigue regression guard).
if ! grep -q 'sum(rate(vl_rows_ingested_total' "$WORK/render-on/vmalert-rules.yml"; then
    echo "FAIL: LogIngestionStalled is not sum()-aggregated (fires per-series forever)"
    fail=1
fi
for rule in MemoryLowHost LoadHigh; do
    if ! grep -q "alert: $rule" "$WORK/render-on/vmalert-rules.yml"; then
        echo "FAIL: vmalert rules are missing $rule (pre-OOM/saturation lead time)"
        fail=1
    fi
done

echo "==> obs toggle round trip (pod spec content flips with the profile)"
# Match the CONTAINER entries (the vmagent-data volume is deliberately
# unconditional — db-init mounts and chowns it in both profiles).
if grep -qE '^\s+- name: "?vmagent"?\s*$' "$WORK/render-off/carlos-app.yaml"; then
    echo "FAIL: obs-disabled app pod still renders the vmagent container"
    fail=1
fi
if ! grep -qE '^\s+- name: "?vmagent"?\s*$' "$WORK/render-on/carlos-app.yaml"; then
    echo "FAIL: obs-enabled app pod is missing the vmagent container"
    fail=1
fi
if ! grep -qE '^\s+- name: "?vmalert"?\s*$' "$WORK/render-on/carlos-obs.yaml"; then
    echo "FAIL: obs pod is missing the vmalert container"
    fail=1
fi

echo "==> drugref carries the MariaDB Hibernate dialect flags (pass-17 H4)"
# DrugRef sets no hibernate.dialect and bundles mysql-connector-j 9.x, whose
# getSQLKeywords() selects INFORMATION_SCHEMA.KEYWORDS.RESERVED — a column
# MariaDB does not have. Without an explicit dialect the entityManagerFactory
# bean fails, /drugref2 404s forever, and the probes below (correctly) never
# green, so `carlos-ctl play` can never succeed. Both the pod spec (which
# overrides CATALINA_OPTS wholesale) and the image default must carry them.
for _f in "$WORK/render-on/carlos-app.yaml" "$ROOT/Containerfile.drugref"; do
    if ! grep -q 'hibernate.dialect=org.hibernate.dialect.MariaDBDialect' "$_f"; then
        echo "FAIL: $(basename "$_f") does not set -Dhibernate.dialect for drugref —" \
             "the /drugref2 context cannot start against MariaDB"
        fail=1
    fi
    if ! grep -q 'hibernate.boot.allow_jdbc_metadata_access=false' "$_f"; then
        echo "FAIL: $(basename "$_f") does not disable Hibernate JDBC metadata access" \
             "for drugref (the KEYWORDS.RESERVED query fails on MariaDB)"
        fail=1
    fi
done

echo "==> app pod: drugref probe rejects 404, carlos waits for the db (S7, S14)"
# S7: a drugref WAR that fails to deploy 404s forever — the probe must NOT
# accept 4xx, or wait_app_ready greenlights a deploy with drug-interaction
# checking silently down.
if grep -q '\[01\] \[234\]' "$WORK/render-on/carlos-app.yaml"; then
    echo "FAIL: a probe in carlos-app.yaml still accepts 4xx as healthy"
    fail=1
fi
# First-boot grace moved to a drugref startupProbe: the probe command must
# appear twice (startup + liveness), both 2xx/3xx-only.
drugref_probes=$(grep -c "GET /drugref2/" "$WORK/render-on/carlos-app.yaml" || true)
if [ "$drugref_probes" -ne 2 ]; then
    echo "FAIL: expected the drugref HTTP probe in BOTH startupProbe and" \
         "livenessProbe (found $drugref_probes)"
    fail=1
fi
# S14 / P3: kube play has no in-pod ordering, so the carlos command must carry
# the bounded wait-for-db loop (an initContainer would deadlock — see template).
# P3 upgraded it to wait for the `oscar` DATABASE (not just TCP), reading creds
# off-argv via MYSQL_PWD.
if ! grep -q "mariadb -u.*oscar -e 'SELECT 1'" "$WORK/render-on/carlos-app.yaml"; then
    echo "FAIL: the carlos container no longer waits for the oscar DB before Tomcat"
    fail=1
fi
if ! grep -q 'MYSQL_PWD' "$WORK/render-on/carlos-app.yaml"; then
    echo "FAIL: the carlos wait-for-db must pass the db password off-argv (MYSQL_PWD)"
    fail=1
fi
# Seventh pass: the properties value is java-properties-ESCAPED (\ -> \\);
# the wait loop must halve doubled backslashes or a backslash-bearing
# password auth-fails and stalls EVERY pod start the full 600s (verified
# live against a deployed pod).
if ! grep -qF "sed 's/" "$WORK/render-on/carlos-app.yaml"; then
    echo "FAIL: the carlos wait-for-db must unescape the properties-escaped" \
         "db_password (backslash halving sed) before using it as MYSQL_PWD"
    fail=1
fi
if grep -q "db -e '.*db_password" "$WORK/render-on/carlos-app.yaml"; then
    echo "FAIL: the db password must not ride the carlos command argv"
    fail=1
fi
# Pass-19: DrugRef builds its Hibernate SessionFactory at CONTEXT START and
# never retries, so a `drugref2` database that is missing (a fresh install
# loads it after `play`) or a MariaDB not yet accepting connections (a reboot
# race) kills /drugref2 PERMANENTLY — Tomcat then serves 404 forever, the
# 404-rejecting probes above never green, and `carlos-ctl play` fails its
# readiness gate with no .deployed marker and no timers. Measured live. The
# drugref container therefore carries the SAME bounded wait-for-db the carlos
# container does, with the same off-argv credential and backslash-halving.
if ! grep -q "mariadb -u.*drugref2 -e 'SELECT 1'" "$WORK/render-on/carlos-app.yaml"; then
    echo "FAIL: the drugref container no longer waits for the drugref2 DB before Tomcat"
    fail=1
fi
if ! grep -q "P=/run/drugref-config/drugref2.properties" "$WORK/render-on/carlos-app.yaml"; then
    echo "FAIL: the drugref wait-for-db must read the ASSEMBLED properties" \
         "(/run/drugref-config), not the read-only mounted base"
    fail=1
fi
# The image has to ship the client that loop calls, or every pod start burns
# the full 600s wait and then starts a context-dead Tomcat anyway.
if ! grep -q 'mariadb-client-core' "$ROOT/Containerfile.drugref"; then
    echo "FAIL: Containerfile.drugref must install mariadb-client-core for the" \
         "pod's wait-for-db loop"
    fail=1
fi
if ! grep -q 'exec catalina.sh run' "$WORK/render-on/carlos-app.yaml"; then
    echo "FAIL: the carlos wait-for-db wrapper must always exec catalina"
    fail=1
fi

echo "==> every rendered SIDECAR config parses in its own format (pass-17 H3/H5)"
# The pod specs were parse-checked below from the start; the configs the pods
# actually READ were not — and two of them shipped broken for months:
#   * vmagent's scrape.yml was INVALID YAML because a 6-space-indented Jinja
#     comment left its indentation on the following `username:` line (jinja
#     removes the comment TEXT, ansible's trim_blocks eats the newline after
#     it). vmagent hard-failed at startup; all metrics and every vmalert rule
#     were down on every default install.
#   * vector's journald-collector.toml carried a literal dollar-VAR example
#     INSIDE A COMMENT; vector env-interpolates the raw file before parsing it,
#     so it hard-failed config load and the PHI log collector crash-looped.
# Parse each in its real format, and reject any single (un-doubled) dollar
# sigil in the vector config — the interpolation pass sees comments too.
if ! python3 - "$WORK/render-on" <<'PY'
import pathlib, re, sys, tomllib, yaml
fail = 0
# The render harness flattens every template to <outdir>/<basename>.
d = pathlib.Path(sys.argv[1])
for rel in ("scrape.yml", "vmalert-rules.yml"):
    f = d / rel
    if not f.is_file():
        print(f"FAIL: {rel} was not rendered")
        fail = 1
        continue
    try:
        yaml.safe_load(f.read_text())
    except Exception as e:
        print(f"FAIL: {f} is not valid YAML: {e}")
        fail = 1
vec = d / "journald-collector.toml"
if not vec.is_file():
    print("FAIL: journald-collector.toml was not rendered")
    fail = 1
else:
    try:
        tomllib.loads(vec.read_text())
    except Exception as e:
        print(f"FAIL: {vec} is not valid TOML: {e}")
        fail = 1
    # vector interpolates $NAME and ${...} over the RAW text, comments too.
    for n, line in enumerate(vec.read_text().splitlines(), 1):
        if re.search(r"(?<!\$)\$(?!\$)[A-Za-z_{]", line):
            print(f"FAIL: {vec}:{n} carries a single '$' vector would interpolate "
                  f"(double it): {line.strip()[:90]}")
            fail = 1
sys.exit(fail)
PY
then
    fail=1
fi

echo "==> rendered pod specs parse as YAML"
# `if !` so a parse failure marks fail=1 and the remaining gates still run —
# a bare command here would abort the whole script under set -e before the
# lockstep check and the FAILED summary (review finding).
if ! python3 - "$WORK/render-on" "$WORK/render-off" <<'PY'
import sys, yaml, pathlib
fail = 0
for d in sys.argv[1:]:
    for f in pathlib.Path(d).glob("carlos-*.yaml"):
        try:
            list(yaml.safe_load_all(f.read_text()))
        except Exception as e:
            print(f"FAIL: {f}: {e}")
            fail = 1
sys.exit(fail)
PY
then
    fail=1
fi

echo "==> render -> CLI lockstep: the CLI reads every key the role writes"
# The hermetic CLI suite hand-writes carlos-app.env in mk_home, which can
# silently DRIFT from what the role's carlos-app.env.j2 actually renders (a new
# role-written key the CLI does not know, a renamed key). Feed the REAL rendered
# env to the CLI's Settings loader: the loader warns on any key it does not
# read, so a drifted/renamed key surfaces here instead of in production.
lockstep_home="$WORK/lockstep-home"
mkdir -p "$lockstep_home/container"
cp "$WORK/render-on/carlos-app.env" "$lockstep_home/container/carlos-app.env"
lock_out="$(EMR_HOME="$lockstep_home" \
    ENV_FILE="$lockstep_home/container/carlos-app.env" \
    PYTHONPATH="$ROOT" python3 -m carlos_ctl.cli version 2>&1 || true)"
if grep -q "does not read" <<<"$lock_out"; then
    echo "FAIL: the role's carlos-app.env carries a key carlos-ctl does not read —"
    echo "      render/CLI lockstep is broken (register it in config._DEFAULTS/"
    echo "      _EXTRA_KNOWN_KEYS or fix the template):"
    grep "does not read" <<<"$lock_out"
    fail=1
fi

if [[ "$fail" == 0 ]]; then
    echo "==> ansible checks OK"
else
    echo "==> ansible checks FAILED"
    exit 1
fi
