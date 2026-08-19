#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
#
# scripts/validation/run-validation.sh — one-shot orchestrator for the
# intensive carlos-ctl validation harness (ctl-validation.sh).
#
# What it does, in order:
#   1. builds a scratch EMR home (build context + env file) under VAL_HOME
#   2. generates a throwaway CA + api.github.com server cert, installs the
#      CA into the SYSTEM trust store, and points api.github.com at
#      127.0.0.1 via /etc/hosts
#   3. starts mock-github-api.py on 127.0.0.1:443 (frozen snapshot of real
#      release data; WAR assets still download from the real github.com)
#   4. runs ctl-validation.sh (real podman builds included — several GB of
#      downloads on the first run)
#   5. tears everything down again (mock, hosts entry, CA) — VAL_HOME is
#      kept for inspection
#
# Because step 2 modifies /etc/hosts and the system trust store, and the
# harness rebuilds the localhost/carlos-app[:latest] image tags, this MUST
# only be run on a disposable machine or dev VM, never on a production EMR
# host. It refuses to start without --yes for exactly that reason.
#
# Usage:  sudo scripts/validation/run-validation.sh --yes
#   VAL_HOME=/path   scratch dir override (default: mktemp under /tmp)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$ROOT/scripts/validation"

if [ "${1:-}" != "--yes" ]; then
    sed -n '5,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    echo "Refusing to run without --yes."
    exit 2
fi
[ "$(id -u)" = 0 ] || { echo "FATAL: must run as root (port 443, trust store, /etc/hosts)" >&2; exit 2; }
for cmd in podman python3 openssl curl; do
    command -v "$cmd" >/dev/null || { echo "FATAL: $cmd not found" >&2; exit 2; }
done

VAL_HOME="${VAL_HOME:-$(mktemp -d /tmp/carlos-validation.XXXXXX)}"
mkdir -p "$VAL_HOME"
MOCK="$VAL_HOME/mock"
H="$VAL_HOME/emr"
echo "== scratch home: $VAL_HOME"

# ---- 1. scratch EMR home ---------------------------------------------------
mkdir -p "$H/build/conf" "$H/container"
cp "$ROOT/Containerfile" "$ROOT/Containerfile.drugref" "$H/build/"
cp -r "$ROOT/conf/tomcat" "$ROOT/conf/drugref" "$H/build/conf/"
# Optional corporate/proxy CA for in-build downloads (same mechanism the
# deployment uses); empty placeholder otherwise.
if [ -n "${CARLOS_EXTRA_CA_BUNDLE:-}" ] && [ -f "${CARLOS_EXTRA_CA_BUNDLE:-}" ]; then
    cp "$CARLOS_EXTRA_CA_BUNDLE" "$H/build/.extra-ca-bundle.crt"
else
    : > "$H/build/.extra-ca-bundle.crt"
fi
cat > "$H/container/carlos-app.env" <<EOF
EMR_HOME=$H
INSTANCE=carlosval
SERVICE_USER=root
CARLOS_IMAGE=localhost/carlos-app:latest
DRUGREF_IMAGE=localhost/carlos-drugref:latest
CARLOS_REF=auto
CARLOS_ARTIFACT=auto
CARLOS_SOURCE_BRANCH=main
DRUGREF_REF=auto
DRUGREF_ARTIFACT=auto
DRUGREF_SOURCE_BRANCH=master
EOF

# ---- 2. throwaway CA + hosts redirect --------------------------------------
mkdir -p "$MOCK"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=carlos-validation-ca" \
    -keyout "$MOCK/ca.key" -out "$MOCK/ca.crt" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=api.github.com" \
    -keyout "$MOCK/api.key" -out "$MOCK/api.csr" 2>/dev/null
printf 'subjectAltName=DNS:api.github.com\n' > "$MOCK/san.ext"
openssl x509 -req -in "$MOCK/api.csr" -CA "$MOCK/ca.crt" -CAkey "$MOCK/ca.key" \
    -CAcreateserial -days 2 -extfile "$MOCK/san.ext" -out "$MOCK/api.crt" 2>/dev/null

CA_INSTALLED=""
install_ca() {
    if [ -d /usr/local/share/ca-certificates ] && command -v update-ca-certificates >/dev/null; then
        cp "$MOCK/ca.crt" /usr/local/share/ca-certificates/carlos-validation-ca.crt
        update-ca-certificates >/dev/null
        CA_INSTALLED=debian
    elif [ -d /etc/pki/ca-trust/source/anchors ] && command -v update-ca-trust >/dev/null; then
        cp "$MOCK/ca.crt" /etc/pki/ca-trust/source/anchors/carlos-validation-ca.crt
        update-ca-trust
        CA_INSTALLED=rhel
    else
        echo "FATAL: no known system trust store (update-ca-certificates / update-ca-trust)" >&2
        exit 2
    fi
}

HOSTS_ADDED=""
MOCK_PID=""
teardown() {
    set +e
    [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null
    if [ -n "$HOSTS_ADDED" ]; then
        sed -i '/^127\.0\.0\.1 api\.github\.com # carlos-validation$/d' /etc/hosts
    fi
    case "$CA_INSTALLED" in
        debian) rm -f /usr/local/share/ca-certificates/carlos-validation-ca.crt
                update-ca-certificates >/dev/null 2>&1 ;;
        rhel)   rm -f /etc/pki/ca-trust/source/anchors/carlos-validation-ca.crt
                update-ca-trust 2>/dev/null ;;
    esac
    echo "== teardown complete (scratch home kept at $VAL_HOME)"
}
trap teardown EXIT

if grep -qE '^[0-9.]+ +api\.github\.com' /etc/hosts; then
    echo "FATAL: /etc/hosts already redirects api.github.com — refusing to stack" >&2
    exit 2
fi
install_ca
echo '127.0.0.1 api.github.com # carlos-validation' >> /etc/hosts
HOSTS_ADDED=1

# ---- 3. mock server --------------------------------------------------------
echo full > "$MOCK/mode"
MOCK_MODE_FILE="$MOCK/mode" MOCK_CERT="$MOCK/api.crt" MOCK_KEY="$MOCK/api.key" \
    python3 "$HERE/mock-github-api.py" > "$MOCK/server.log" 2>&1 &
MOCK_PID=$!
for _ in $(seq 20); do
    NO_PROXY=api.github.com no_proxy=api.github.com \
        curl -fsS --max-time 3 "https://api.github.com/repos/carlos-emr/carlos/releases?per_page=1" \
        >/dev/null 2>&1 && break
    kill -0 "$MOCK_PID" 2>/dev/null || { echo "FATAL: mock server died:" >&2; cat "$MOCK/server.log" >&2; exit 2; }
    sleep 0.5
done
echo "== mock api.github.com is up (pid $MOCK_PID)"

# ---- 4. the harness --------------------------------------------------------
rc=0
VAL_HOME="$VAL_HOME" MOCK_MODE_FILE="$MOCK/mode" bash "$HERE/ctl-validation.sh" || rc=$?
exit $rc
