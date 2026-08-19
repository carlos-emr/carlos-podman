#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
# Hermetic e2e suite for the carlos-ctl Python CLI.
#
#   tests/run-tests.sh
#
# No root, no podman, no systemd, no TPM, no sops/age required: the recording
# stubs in tests/stubs/ replace every external binary, and the CARLOS_*_DIR
# overrides redirect every system write into a throwaway work directory.
# Nothing outside that directory is touched.
#
# The suite fabricates an ANSIBLE-RENDERED instance home (the playbook's
# output contract) and drives the CLI against it — asserting the go-live
# gates, the data-plane fail-closed guards, the secrets flows, and the
# off-argv credential discipline (stubs record forwarded-env values so a
# secret reaching a container without ever being an argv token is provable).
#
# NOT covered here (by design): the Ansible role's own rendering/idempotency
# (tests/ansible-checks.sh), pure-logic behaviors (pytest, tests/unit/), and
# the restore drill's binlog-replay leg (needs real podman/mariadb — run
# `carlos-ctl backup verify` on a live host after changing it).
set -uo pipefail

# Deterministic stdin: stub `podman exec -i` cats inherited stdin when it is
# not a tty — under a runner whose stdin is an open pipe that never EOFs the
# whole suite would hang on the first non-piped exec. /dev/null EOFs at once,
# and the interactive-refusal tests already model "non-interactive" anyway.
exec </dev/null

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/carlos-ctl-tests.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

export PATH="$ROOT/tests/stubs:$PATH"
export PYTHONPATH="$ROOT"
export STUBLOG="$WORK/stub.log"
export CARLOS_CREDSTORE_DIR="$WORK/credstore"
export CARLOS_SYSTEMD_DIR="$WORK/systemd"
export CARLOS_QUADLET_DIR="$WORK/quadlet"
export CARLOS_INSTANCE_REGISTRY_DIR="$WORK/registry"
export CARLOS_JOURNAL_DIR="$WORK/journal"
# Settings.systemd_runtime_dir — the sd_booted(3) probe behind
# Runner.systemd_running(). Point it at an EXISTING scratch dir so the default
# model here is "systemd works" (the systemctl STUB answers every call), which
# is what all the non-fallback cases below assume. The no-systemd model drops
# systemctl from PATH; the not-booted model (further down) instead points this
# knob at a path that does not exist — that is the only difference between a
# host whose systemctl works and one where the binary is present but systemd
# never booted (containers, WSL, chroots).
export CARLOS_SYSTEMD_RUNTIME_DIR="$WORK/systemd-runtime"
# Secrets /run staging (rekey/seal tmpfiles) — without this a ROOT suite run
# (CI runs under sudo) writes into the host's real /run (pass-8 M2).
export CARLOS_RUN_DIR="$WORK/run"
# Settings.run_secrets_dir — the ONE host knob this suite still left at its
# default, and `cmd_uninstall` rmtree's it for whatever INSTANCE the Settings
# under test carries: `carlos`, the same default name a real deployment uses.
# Measured live (pass 17): one `tests/run-tests.sh` as root DELETED a running
# instance's /run/carlos-emr — its decrypted sealed-credential fragments and
# the app pod's `app-secrets` hostPath source — while reporting "310 passed".
# The next `carlos-ctl play` then died with
# `failed to create volume "app-secrets": mkdir /run/carlos-emr: permission
# denied` (rootless podman cannot recreate a dir under root's /run), and on a
# SEALED install the app fails its __SEALED__ guard at the next restart.
# Pass-15 H2 fixed exactly this class for tests/unit/conftest.py; this is the
# same leak in the sibling suite. The static coverage gate below keeps the two
# lists from drifting again.
export CARLOS_RUN_SECRETS_DIR="$WORK/run-secrets"
# Same reason: uninstall unlinks <instance>-emr.conf from here. Individual
# tests still override it to assert the removal through the override path.
export CARLOS_TMPFILES_DIR="$WORK/tmpfiles.d-global"
# The suite acknowledges journal-only alerting + no heartbeat globally; the
# gate tests override with explicit env.
export ALERT_JOURNAL_ONLY=1
export CARLOS_NO_HEARTBEAT=1
# Hermetic homes hold no real datadir; the empty-datadir tests override.
export CARLOS_ACCEPT_EMPTY_DATADIR=1
# Fail-loud liveness by default; boot-grace tests override.
export BOOT_GRACE_SECONDS=0
export LOG_VIEW_ALLOW_CIDR=rfc1918
# Local restic repo is the hermetic default — accept the DR posture globally.
export CARLOS_ACCEPT_LOCAL_REPO=1
# Rootless engine: use THIS user as the service user so uid resolution works.
SERVICE_USER="$(id -un)"
export SERVICE_USER
# Snapshot the REAL host paths an instance named `carlos` owns, BEFORE any CLI
# invocation, so the containment gate at the end can prove the suite neither
# created nor removed them (pass-17 H8).
mkdir -p "$WORK/host-canary"
for _real in /run/carlos-emr /etc/tmpfiles.d/carlos-emr.conf \
             /etc/carlos-podman/instances/carlos.conf; do
    [ -e "$_real" ] && : > "$WORK/host-canary/$(printf '%s' "$_real" | tr / _)"
done
mkdir -p "$CARLOS_RUN_SECRETS_DIR" "$CARLOS_TMPFILES_DIR" \
         "$CARLOS_CREDSTORE_DIR" "$CARLOS_SYSTEMD_DIR" "$CARLOS_QUADLET_DIR" \
         "$CARLOS_INSTANCE_REGISTRY_DIR" "$CARLOS_JOURNAL_DIR" "$CARLOS_RUN_DIR" \
         "$CARLOS_SYSTEMD_RUNTIME_DIR"

PASS=0 FAIL=0
ok()   { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
assert() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
# refute: passes only on a DELIBERATE nonzero exit. An unhandled Python
# traceback also exits nonzero, so exit code alone would count a crash as a
# successful refusal — grep the captured output and fail the test on one.
refute() {
    local d="$1"; shift
    local out rc
    out="$("$@" 2>&1)"; rc=$?
    if [[ $rc -eq 0 ]]; then bad "$d"
    elif grep -q "Traceback (most recent call last)" <<<"$out"; then
        bad "$d (CRASHED with a traceback, not a deliberate refusal)"
    else ok "$d"; fi
}

ctl() {  # ctl <home> <args...> — run the CLI against an instance home
    local home="$1"; shift
    EMR_HOME="$home" python3 -m carlos_ctl.cli "$@"
}
# ctle <home> <ENV=val ...> -- <args...> — like ctl with per-run env overrides.
ctle() {
    local home="$1"; shift
    local -a envs=()
    while [[ "$1" != "--" ]]; do envs+=("$1"); shift; done
    shift
    env "${envs[@]}" EMR_HOME="$home" PYTHONPATH="$ROOT" python3 -m carlos_ctl.cli "$@"
}

# A real self-signed cert so the play/monitor expiry checks exercise their
# healthy branch (openssl is real — the CLI only ever READS certs with it).
make_cert() {
    openssl req -x509 -newkey rsa:2048 -keyout "$1/privkey.pem" \
        -out "$1/fullchain.pem" -days 365 -nodes -subj "/CN=test" >/dev/null 2>&1
}

# Fabricate what the Ansible role renders: THE output contract the CLI
# consumes. Keep in lockstep with roles/carlos_podman/tasks/instance.yml.
mk_home() {  # mk_home <dir> [instance]
    local home="$1" inst="${2:-carlos}"
    mkdir -p "$home/container/conf"/{carlos,drugref,mariadb,tomcat,waf/certs,vector,vmagent,vmalert,caddy,restic,metrics,secrets} \
             "$home/container/guard" \
             "$home/data"/{mariadb-mnt,mariadb-binlog,OscarDocument} \
             "$home/backup" "$home/logs" "$home/run/db-socket" "$home/build"
    cat > "$home/container/carlos-app.env" <<EOF
EMR_HOME=$home
INSTANCE=$inst
SERVICE_USER=$SERVICE_USER
BIND_IP=192.168.20.250
SERVER_NAME=emr.example.ca
OBS_ENABLED=1
HOSTFW_ENABLED=0
OBS_HTTP_USER=obs
CARLOS_DB_ROOT_PASSWORD=test-root-pw
CARLOS_TLS_MODE=manual
CARLOS_REF=auto
CARLOS_ARTIFACT=auto
CARLOS_SOURCE_BRANCH=main
DRUGREF_REF=auto
DRUGREF_ARTIFACT=auto
DRUGREF_SOURCE_BRANCH=master
EOF
    chmod 0600 "$home/container/carlos-app.env"
    printf 'db_username=carlos\ndb_password=app-pw\n' > "$home/container/conf/carlos/carlos.properties"
    printf 'db_user=drugref\ndb_password=drugref-pw\n' > "$home/container/conf/drugref/drugref2.properties"
    printf '[mysqld]\nbind_address = 127.0.0.1\nlog_bin = /var/lib/mysql-binlog/binlog\n' \
        > "$home/container/conf/mariadb/zz-carlos.cnf"
    printf '<Context/>\n' > "$home/container/conf/tomcat/context.xml"
    printf '# vector\nauth.password = "obs-pw"\n' \
        > "$home/container/conf/vector/journald-collector.toml"
    printf '# scrape\n' > "$home/container/conf/vmagent/scrape.yml"
    printf 'groups: []\n' > "$home/container/conf/vmalert/rules.yml"
    printf ':9443 {\n    basic_auth {\n        logview $2b$14$stubhash\n    }\n    header_up Authorization "Basic b2JzOm9icy1wdw=="\n}\n' \
        > "$home/container/conf/caddy/Caddyfile"
    # The obs-store basic-auth credential the playbook provisions (root-only).
    mkdir -p "$home/secrets-private"
    printf 'obs-pw\n' > "$home/secrets-private/obs-http-password"
    printf '[client]\nuser = exporter\npassword = __UNPROVISIONED__\n' \
        > "$home/container/conf/metrics/exporter.my.cnf"
    cat > "$home/container/conf/restic/restic.env" <<EOF
RESTIC_REPOSITORY=$home/backup/restic-repo
RESTIC_PASSWORD=restic-pw
AWS_EXTRA=keepme
EOF
    chmod 0600 "$home/container/conf/restic/restic.env"
    printf 'BACKUP_DB_USER=backup\nBACKUP_DB_PASSWORD=backup-pw\n' \
        > "$home/container/conf/restic/backup-db.env"
    make_cert "$home/container/conf/waf/certs"
    for pod in "$inst-app" "$inst-obs" "$inst-waf"; do
        printf 'apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - image: "docker.io/library/x:1@sha256:aa"\n' \
            > "$home/container/$pod.yaml"
    done
    touch "$CARLOS_QUADLET_DIR/$inst.kube"
    # The playbook installs all five schedule timers; play now verifies each
    # one starts (a missing timer = a schedule that silently never fires and
    # a nonzero play), so the fabricated home must carry them.
    for t in backup binlog docs backup-verify monitor; do
        touch "$CARLOS_SYSTEMD_DIR/$inst-$t.timer"
    done
    printf 'x\n' > "$home/data/mariadb-binlog/binlog.000001"
    printf 'x\n' > "$home/data/mariadb-binlog/binlog.000002"
    printf './binlog.000001\n./binlog.000002\n' > "$home/data/mariadb-binlog/binlog.index"
    printf 'doc\n' > "$home/data/OscarDocument/doc1.pdf"
    cat > "$CARLOS_INSTANCE_REGISTRY_DIR/$inst.conf" <<EOF
INSTANCE=$inst
EMR_HOME=$home
SERVICE_USER=$SERVICE_USER
BIND_IP=192.168.20.250
HTTPS_PORT=443
HTTPS_PUBLISH_PORT=8443
LOG_VIEW_PORT=9443
VICTORIALOGS_PORT=9428
VICTORIAMETRICS_PORT=8428
PMA_PORT=9444
EOF
}

env_set() {  # env_set <home> <KEY> <VALUE> — upsert into the fabricated env file
    local f="$1/container/carlos-app.env"
    grep -v "^$2=" "$f" > "$f.n" || true
    printf '%s=%s\n' "$2" "$3" >> "$f.n"
    mv "$f.n" "$f"
}

mark() { wc -l < "$STUBLOG" 2>/dev/null || echo 0; }
log_since() {  # log_since <line> <grep-args...>
    local n="$1"; shift
    tail -n +"$((n + 1))" "$STUBLOG" | grep -q "$@"
}

: > "$STUBLOG"

# ============================ play: go-live gates =================================
H="$WORK/h-play"; mk_home "$H"

m=$(mark)
assert "play succeeds on a fully-rendered home" ctl "$H" play
assert "play restarted the obs pod unit"  log_since "$m" "restart carlos-obs.service"
assert "play restarted the app pod unit"  log_since "$m" "restart carlos.service"
assert "play restarted the waf pod unit"  log_since "$m" "restart carlos-waf.service"
assert "play wrote the go-live marker" test -f "$H/container/.deployed"
assert "play armed the guard marker" test -f "$H/container/guard/deployed"
assert "play seeded the full-backup stamp" test -f "$H/backup/.last-full-ok"
assert "play seeded the binlog stamp" test -f "$H/backup/.last-binlog-ok"
assert "play seeded the restore-drill stamp" test -f "$H/backup/.last-verify-ok"

# Pre-cutover smoke: an image that cannot start a trivial process must be
# refused BEFORE --replace destroys the serving pods.
refute "play refuses cutover onto an image that cannot start (smoke gate)" \
    ctle "$H" STUB_SMOKE_FAIL=1 -- play

refute "play exits nonzero when the app never turns healthy (readiness gate)" \
    ctle "$H" STUB_HEALTH=starting READY_WAIT_SECONDS=0 -- play
refute "an EMPTY health status with a CONFIGURED healthcheck keeps polling (no false-green)" \
    ctle "$H" STUB_HEALTH= STUB_HEALTHCHECK_CONFIGURED=configured READY_WAIT_SECONDS=0 -- play
assert "an empty status with NO configured healthcheck passes the gate" \
    ctle "$H" STUB_HEALTH= -- play

refute "play refuses go-live without an alert channel" ctle "$H" ALERT_JOURNAL_ONLY= -- play
refute "play refuses go-live without a heartbeat ack"  ctle "$H" CARLOS_NO_HEARTBEAT= -- play
assert "play accepts a configured HEARTBEAT_URL" \
    ctle "$H" CARLOS_NO_HEARTBEAT= HEARTBEAT_URL=https://hc/ping -- play

# First-go-live DR-posture gate: a local-only restic repo dies with the host
# it protects. The suite ACKs it globally (CARLOS_ACCEPT_LOCAL_REPO=1); an
# UNACKED first go-live must refuse, an offsite repo must pass.
HDR="$WORK/h-dr-gate"; mk_home "$HDR"
refute "play refuses FIRST go-live on a local-only restic repo (no ack)" \
    ctle "$HDR" CARLOS_ACCEPT_LOCAL_REPO= -- play
sed -i 's|^RESTIC_REPOSITORY=.*|RESTIC_REPOSITORY=s3:https://backup.example/carlos|' \
    "$HDR/container/conf/restic/restic.env"
assert "play accepts first go-live with an OFFSITE repository" \
    ctle "$HDR" CARLOS_ACCEPT_LOCAL_REPO= -- play
assert "an already-deployed instance is never blocked by the DR gate" \
    bash -c "sed -i 's|^RESTIC_REPOSITORY=.*|RESTIC_REPOSITORY=$HDR/backup/restic-repo|' \
        '$HDR/container/conf/restic/restic.env' && cd '$ROOT' && \
        EMR_HOME='$HDR' CARLOS_ACCEPT_LOCAL_REPO= python3 -m carlos_ctl.cli play"

# `down --disable` disables the five timers and tells the operator `play`
# reverses it. play must therefore ENABLE them (not just start them) — a
# start-only play honored the promise only until the next reboot, after which
# every timer (including the monitor that would flag the stale backups)
# silently stayed dead forever.
m=$(mark)
assert "down --disable stops the stack and disables the timers" \
    ctl "$H" down --disable
assert "down --disable recorded the timer disable" \
    log_since "$m" "systemctl disable carlos-backup.timer"
m=$(mark)
assert "play after down --disable brings the stack back" ctl "$H" play
for t in backup binlog docs backup-verify monitor; do
    assert "play re-ENABLED carlos-$t.timer (survives the next reboot)" \
        log_since "$m" "systemctl enable carlos-$t.timer"
    assert "play re-STARTED carlos-$t.timer" \
        log_since "$m" "systemctl start carlos-$t.timer"
done

H2="$WORK/h-bind"; mk_home "$H2"
env_set "$H2" BIND_IP 0.0.0.0
refute "play refuses BIND_IP=0.0.0.0 (nft daddr gate would be a no-op)" ctl "$H2" play
assert "play accepts 0.0.0.0 with the explicit ack" ctle "$H2" CARLOS_ALLOW_ANY_BIND=1 -- play

H3="$WORK/h-cidr"; mk_home "$H3"
refute "play refuses a malformed LOG_VIEW_ALLOW_CIDR (fail-closed nft input)" \
    ctle "$H3" LOG_VIEW_ALLOW_CIDR=bogus -- play

H4="$WORK/h-ports"; mk_home "$H4"
env_set "$H4" HTTPS_PORT 8443
refute "play refuses HTTPS_PORT == HTTPS_PUBLISH_PORT (nft redirect no-op)" ctl "$H4" play

H5="$WORK/h-token"; mk_home "$H5"
printf 'image: @CARLOS_IMAGE@\n' > "$H5/container/carlos-app.yaml"
refute "play refuses a stray @TOKEN@ in a rendered pod spec" ctl "$H5" play
printf 'image: {{ carlos_image }}\n' > "$H5/container/carlos-app.yaml"
refute "play refuses un-rendered Jinja markers in a rendered pod spec" ctl "$H5" play

H6="$WORK/h-certs"; mk_home "$H6"
rm "$H6/container/conf/waf/certs/fullchain.pem"
refute "play refuses without TLS material (waf-init would crash-loop)" ctl "$H6" play

H7="$WORK/h-datadir"; mk_home "$H7"
touch "$H7/container/.deployed"
refute "play refuses a DEPLOYED instance whose datadir lost its mysql/ signature" \
    ctle "$H7" CARLOS_ACCEPT_EMPTY_DATADIR= -- play
mkdir -p "$H7/data/mariadb-mnt/mysql"
assert "play proceeds once the datadir signature is present" \
    ctle "$H7" CARLOS_ACCEPT_EMPTY_DATADIR= -- play
assert "accept-empty marker cleared when the override is off" \
    test ! -e "$H7/container/guard/accept-empty-datadir"
# Seventh pass: the acceptance is ONE play's worth — once the accepting play
# ends with an initialized datadir, the marker is consumed, so it cannot
# pre-accept a future unmounted/wiped data volume at reboot.
assert "an accepting play succeeds on an initialized datadir" \
    ctle "$H7" CARLOS_ACCEPT_EMPTY_DATADIR=1 -- play
refute "the acceptance is CONSUMED by the successful play (no standing marker)" \
    test -e "$H7/container/guard/accept-empty-datadir"

H8="$WORK/h-dbroot"; mk_home "$H8"
printf 'db_username=root\ndb_password=x\n' > "$H8/container/conf/carlos/carlos.properties"
env_set "$H8" CARLOS_DB_ROOT_PASSWORD ""
refute "play refuses db_username=root with no root password (silent root deploy)" ctl "$H8" play
assert "play allows root with the explicit one-shot override" \
    ctle "$H8" CARLOS_ALLOW_DB_ROOT=1 CARLOS_SKIP_AUTO_DB_USERS=1 -- play

H9="$WORK/h-exposed"; mk_home "$H9"
printf '[mysqld]\nbind_address = 0.0.0.0\n' > "$H9/container/conf/mariadb/zz-carlos.cnf"
refute "play refuses a non-loopback MariaDB bind_address (WAF could reach 3306)" ctl "$H9" play
assert "play deploys an exposed db only with the explicit override" \
    ctle "$H9" CARLOS_ALLOW_DB_EXPOSED=1 -- play

H10="$WORK/h-busy"; mk_home "$H10"
refute "play refuses a host port held by a foreign listener" \
    ctle "$H10" STUB_PORT_BOUND=8443 -- play
assert "port preflight bypass works" \
    ctle "$H10" STUB_PORT_BOUND=8443 CARLOS_SKIP_PORT_PREFLIGHT=1 -- play

# ============================ logs convenience verb ===============================
HLOG="$WORK/h-logs"; mk_home "$HLOG"
m=$(mark)
assert "logs tails the carlos container by default" ctl "$HLOG" logs
assert "logs resolved the default short name" \
    log_since "$m" -- "logs --tail 200 carlos-app-carlos"
m=$(mark)
assert "logs accepts the db short name" ctl "$HLOG" logs db
assert "logs resolved the db container" log_since "$m" -- "logs --tail 200 carlos-app-db"
refute "logs rejects unknown flags" ctl "$HLOG" logs --bogus

# ============================ build / rollback ====================================
HBD="$WORK/h-build"; mk_home "$HBD"
touch "$HBD/build/Containerfile" "$HBD/build/Containerfile.drugref"
m=$(mark)
assert "build succeeds (build-then-promote both images)" ctl "$HBD" build
assert "build promoted :latest for carlos" \
    log_since "$m" "tag localhost/carlos-app:build-.* localhost/carlos-app:latest"
assert "build promoted :latest for drugref" \
    log_since "$m" "tag localhost/carlos-drugref:build-.* localhost/carlos-drugref:latest"
assert "build recorded the dev build mode" \
    grep -qx dev "$HBD/build/.build-mode"
# G3: CARLOS_EXTRA_CA_BUNDLE stages a PEM into the build context and restores
# the empty placeholder afterward. (No podman argv changes — the mechanism is
# a context file the Containerfiles COPY, not a --build-arg — so we assert the
# lifecycle on disk, not the argv.)
printf -- '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n' > "$WORK/proxy-ca.pem"
assert "build with CARLOS_EXTRA_CA_BUNDLE succeeds" \
    ctle "$HBD" CARLOS_EXTRA_CA_BUNDLE="$WORK/proxy-ca.pem" -- build
assert "the staged CA bundle is restored to the empty placeholder after the build" \
    bash -c "test -f '$HBD/build/.extra-ca-bundle.crt' && ! test -s '$HBD/build/.extra-ca-bundle.crt'"
refute "a failed :previous retag ABORTS before promotion (rollback target preserved)" \
    ctle "$HBD" STUB_TAG_FAIL=1 -- build
# pass-15 H1: a subuid/subgid grant narrower than container id 65534 leaves
# the mysqld-exporter uid (and apt inside the image builds) outside the
# userns map. The role skips its grant whenever ANY line exists, so the width
# goes unchecked — and podman maps from the FIRST grant only, so an appended
# second range does not help. `build` must say so at second 1, not at minute
# 40 with apt's opaque "setgroups (22: Invalid argument)".
mkdir -p "$WORK/subid-narrow"
printf '%s:165536:34464\n%s:200000:65536\n' "$SERVICE_USER" "$SERVICE_USER" \
    > "$WORK/subid-narrow/subuid"
cp "$WORK/subid-narrow/subuid" "$WORK/subid-narrow/subgid"
assert "build WARNS on a subuid grant too narrow for container id 65534" \
    bash -c "cd '$ROOT' && CARLOS_SUBID_DIR='$WORK/subid-narrow' EMR_HOME='$HBD' \
        python3 -m carlos_ctl.cli build 2>&1 | grep -q 'maps only 34464 subuids'"
assert "the narrow-grant warning says WIDEN (an appended range does not help)" \
    bash -c "cd '$ROOT' && CARLOS_SUBID_DIR='$WORK/subid-narrow' EMR_HOME='$HBD' \
        python3 -m carlos_ctl.cli build 2>&1 | grep -q 'WIDEN THE EXISTING GRANT'"
mkdir -p "$WORK/subid-wide"
printf '%s:165536:65536\n' "$SERVICE_USER" > "$WORK/subid-wide/subuid"
cp "$WORK/subid-wide/subuid" "$WORK/subid-wide/subgid"
refute "a full-width grant produces no subid warning" \
    bash -c "cd '$ROOT' && CARLOS_SUBID_DIR='$WORK/subid-wide' EMR_HOME='$HBD' \
        python3 -m carlos_ctl.cli build 2>&1 | grep -q 'sub-ids\|subuids\|subgids'"
# Manual moving refs written into the env FILE (it wins over process env):
# under the auto default this home would resolve pinned WAR releases, which
# legitimately SATISFY release mode — the refusal under test is specifically
# a manual moving-branch source ref.
HRELREF="$WORK/h-relref"; mk_home "$HRELREF"
touch "$HRELREF/build/Containerfile" "$HRELREF/build/Containerfile.drugref"
printf 'CARLOS_REF=develop\nDRUGREF_REF=master\n' >> "$HRELREF/container/carlos-app.env"
refute "release mode refuses a moving (non-40-hex) source ref" \
    ctle "$HRELREF" CARLOS_BUILD_MODE=release -- build
assert "rollback retags both images and re-plays" ctl "$HBD" rollback
refute "rollback refuses when drugref :previous is missing (lockstep guard)" \
    ctle "$HBD" STUB_NO_DRUGREF_PREV=1 -- rollback

# ================= source selection (release-first + sticky pin) =================
# carlos_ctl.source: CARLOS_REF=auto resolves the newest GitHub release on the
# FIRST build (WAR artifact preferred), pins it in build/.source-pin, and every
# later build is OFFLINE on that pin — no drift without operator intervention.
# The curl stub answers api.github.com deterministically (STUB_GH_*).
HSRC="$WORK/h-source"; mk_home "$HSRC"
touch "$HSRC/build/Containerfile" "$HSRC/build/Containerfile.drugref"
m=$(mark)
assert "first auto build resolves the newest release and pins it" ctl "$HSRC" build
assert "the resolve queried the GitHub releases API" \
    log_since "$m" "api.github.com/repos/carlos-emr/carlos/releases"
assert "the source pin was persisted" test -s "$HSRC/build/.source-pin"
assert "the pinned release COMMIT drives CARLOS_REF (never the mutable tag)" \
    log_since "$m" "CARLOS_REF=1111111111111111111111111111111111111111"
assert "the published WAR selects the download stage" \
    log_since "$m" "CARLOS_WAR_STAGE=download"
assert "the WAR sha256 rides along for the in-image verification" \
    log_since "$m" "CARLOS_WAR_SHA256=dddddddddddddddddddddddddddddddd"
# DrugRef rides the SAME contract under its own keys and pin.
assert "the DrugRef source pin was persisted" test -s "$HSRC/build/.source-pin.drugref"
assert "the pinned DrugRef release COMMIT drives DRUGREF_REF" \
    log_since "$m" "DRUGREF_REF=3333333333333333333333333333333333333333"
assert "the DrugRef published WAR selects its download stage" \
    log_since "$m" "DRUGREF_WAR_STAGE=download"
assert "the DrugRef WAR sha256 rides along" \
    log_since "$m" "DRUGREF_WAR_SHA256=ffffffffffffffffffffffffffffffff"
m=$(mark)
assert "a PINNED build works with the GitHub API down (sticky = offline)" \
    ctle "$HSRC" STUB_GH_DOWN=1 -- build
refute "the pinned build made no GitHub API call" \
    bash -c "tail -n +$((m + 1)) '$STUBLOG' | grep -q api.github.com"
assert "source show prints the pinned CARLOS release" \
    bash -c "cd '$ROOT' && EMR_HOME='$HSRC' python3 -m carlos_ctl.cli source | grep -q 2026.08.0"
assert "source show prints the pinned DrugRef release" \
    bash -c "cd '$ROOT' && EMR_HOME='$HSRC' python3 -m carlos_ctl.cli source | grep -q v1.0.0rc2"
rm -f "$HSRC/build/.source-pin"
refute "an UNPINNED auto build refuses when the API is down" \
    ctle "$HSRC" STUB_GH_DOWN=1 -- build
assert "the refusal points at 'source set' (the offline escape hatch)" \
    bash -c "cd '$ROOT' && STUB_GH_DOWN=1 EMR_HOME='$HSRC' \
        python3 -m carlos_ctl.cli build 2>&1 | grep -q 'source set'"
assert "source set <sha> pins offline" \
    ctle "$HSRC" STUB_GH_DOWN=1 -- source set 2222222222222222222222222222222222222222
m=$(mark)
assert "the manual sha pin drives the next build" ctl "$HSRC" build
assert "the sha pin becomes CARLOS_REF" \
    log_since "$m" "CARLOS_REF=2222222222222222222222222222222222222222"
refute "a bare-commit pin compiles from source (no WAR stage)" \
    bash -c "tail -n +$((m + 1)) '$STUBLOG' | grep -q CARLOS_WAR_STAGE=download"
assert "source update re-resolves to the newest release" ctl "$HSRC" source update
assert "the pin moved back to the release" grep -q 2026.08.0 "$HSRC/build/.source-pin"
assert "a no-release repo falls back to the branch HEAD sha" \
    bash -c "cd '$ROOT' && STUB_GH_RELEASES=none EMR_HOME='$HSRC' \
        python3 -m carlos_ctl.cli source update >/dev/null 2>&1 \
        && grep -q '\"kind\": \"branch\"' '$HSRC/build/.source-pin'"
# DrugRef manual/sticky flows: set --drugref targets the DrugRef pin only,
# and its no-release fallback honors DRUGREF_SOURCE_BRANCH (master).
assert "source set --drugref <sha> pins DrugRef offline" \
    ctle "$HSRC" STUB_GH_DOWN=1 -- source set --drugref 4444444444444444444444444444444444444444
m=$(mark)
assert "the manual DrugRef pin drives the next build" ctl "$HSRC" build
assert "the DrugRef sha pin becomes DRUGREF_REF" \
    log_since "$m" "DRUGREF_REF=4444444444444444444444444444444444444444"
refute "a bare-commit DrugRef pin compiles from source (no WAR stage)" \
    bash -c "tail -n +$((m + 1)) '$STUBLOG' | grep -q DRUGREF_WAR_STAGE=download"
assert "a no-release DrugRef repo falls back to its master branch HEAD" \
    bash -c "cd '$ROOT' && STUB_GH_DR_RELEASES=none EMR_HOME='$HSRC' \
        python3 -m carlos_ctl.cli source update >/dev/null 2>&1 \
        && grep -q '\"branch\": \"master\"' '$HSRC/build/.source-pin.drugref'"
# Prerelease-only repo — TODAY's live carlos-emr/carlos state (one prerelease,
# 2026.08.0-alpha1, shipping a WAR): the fresh-install path must resolve it,
# pin it, and build from its WAR end to end.
HPRE="$WORK/h-source-pre"; mk_home "$HPRE"
touch "$HPRE/build/Containerfile" "$HPRE/build/Containerfile.drugref"
m=$(mark)
assert "a prerelease-only repo resolves the prerelease on first build" \
    ctle "$HPRE" STUB_GH_RELEASES=prerelease-only -- build
assert "the prerelease tag is pinned" grep -q 2026.08.0-alpha1 "$HPRE/build/.source-pin"
assert "the prerelease's WAR selects the download stage" \
    log_since "$m" "CARLOS_WAR_STAGE=download"

assert "source clear removes the pins" ctl "$HSRC" source clear
assert "both pin files are gone" \
    bash -c "! test -e '$HSRC/build/.source-pin' && ! test -e '$HSRC/build/.source-pin.drugref'"
refute "source rejects unknown sub-verbs" ctl "$HSRC" source frobnicate

# Prebuilt-image artifact (<APP>_ARTIFACT=image, OPT-IN): the pin records the
# registry digest at resolve time; `build` then PULLS by that digest (never
# builds, never trusts a tag) and promotes through the same
# :build-<stamp>/:previous/:latest machinery — mixed war/image pairs included.
HIMG="$WORK/h-image"; mk_home "$HIMG"
touch "$HIMG/build/Containerfile" "$HIMG/build/Containerfile.drugref"
printf 'CARLOS_ARTIFACT=image\nDRUGREF_ARTIFACT=image\n' >> "$HIMG/container/carlos-app.env"
m=$(mark)
assert "an image-artifact build resolves, pins the digest, pulls and promotes" \
    ctl "$HIMG" build
assert "the pin records the registry digest" \
    grep -q '"image_digest": "sha256:eeee' "$HIMG/build/.source-pin"
assert "the image is pulled BY DIGEST (never by mutable tag)" \
    log_since "$m" "pull ghcr.io/carlos-emr/carlos-app@sha256:eeee"
assert "the DrugRef image is pulled by digest too" \
    log_since "$m" "pull ghcr.io/carlos-emr/carlos-drugref@sha256:eeee"
refute "an image-mode build never runs podman build" \
    bash -c "tail -n +$((m + 1)) '$STUBLOG' | grep -q 'podman build'"
assert "the pulled image is promoted to :latest via :build-<stamp>" \
    log_since "$m" "localhost/carlos-app:latest"
m=$(mark)
assert "a PINNED image build works fully offline (API and registry down)" \
    ctle "$HIMG" STUB_GH_DOWN=1 STUB_GHCR_DOWN=1 -- build
refute "the pinned image build touched no API or registry endpoint" \
    bash -c "tail -n +$((m + 1)) '$STUBLOG' | grep -Eq 'api.github.com|ghcr.io/(token|v2)'"
refute "a pull failure aborts BEFORE any tag moves" \
    ctle "$HIMG" STUB_PULL_FAIL=1 -- build
refute "the failed pull moved no :previous/:latest tag" \
    bash -c "tail -n 6 '$STUBLOG' | grep -q ':previous'"
assert "rollback works after an image-mode build" ctl "$HIMG" rollback
# Release published but its image not pushed yet: refuse with the
# publish-images guidance, never silently fall back to another artifact.
HIMG2="$WORK/h-image-missing"; mk_home "$HIMG2"
touch "$HIMG2/build/Containerfile" "$HIMG2/build/Containerfile.drugref"
printf 'CARLOS_ARTIFACT=image\n' >> "$HIMG2/container/carlos-app.env"
refute "a release without a published image refuses to pin" \
    ctle "$HIMG2" STUB_GHCR_MISSING=1 -- build
assert "the refusal names the Publish Images workflow" \
    bash -c "cd '$ROOT' && STUB_GHCR_MISSING=1 EMR_HOME='$HIMG2' \
        python3 -m carlos_ctl.cli build 2>&1 | grep -q 'Publish Images'"
refute "no half-pinned pair is left behind by the refusal" \
    test -e "$HIMG2/build/.source-pin"

# Rollback schema-compatibility guard: rolling the CODE back never reverses
# hand-applied SQL migrations. play records the live schema fingerprint,
# build pairs it with :previous, and rollback refuses on a mismatch unless
# explicitly accepted (db-unreachable = warn + proceed: the emergency verb
# must not be blocked by the outage it is fixing).
HSG="$WORK/h-schema-guard"; mk_home "$HSG"
touch "$HSG/build/Containerfile" "$HSG/build/Containerfile.drugref"
assert "play records the schema fingerprint baseline" \
    bash -c "cd '$ROOT' && EMR_HOME='$HSG' python3 -m carlos_ctl.cli play >/dev/null 2>&1 \
        && test -s '$HSG/build/.schema-fingerprint'"
assert "build pairs the baseline with the :previous images" \
    bash -c "cd '$ROOT' && EMR_HOME='$HSG' python3 -m carlos_ctl.cli build >/dev/null 2>&1 \
        && test -s '$HSG/build/.schema-fingerprint.previous'"
assert "rollback proceeds when the live schema matches the baseline" \
    ctl "$HSG" rollback
refute "rollback REFUSES a schema the :previous build never ran against" \
    ctle "$HSG" STUB_SCHEMA_FP='demographic	new_col	2	text' -- rollback
assert "the explicit flag accepts the schema mismatch" \
    ctle "$HSG" STUB_SCHEMA_FP='demographic	new_col	2	text' -- rollback --accept-schema-mismatch
assert "rollback proceeds (warn, not block) when the db is unreachable" \
    ctle "$HSG" STUB_SCHEMA_PROBE_FAIL=1 -- rollback

# ============================ check: live validation ==============================
# Drives the read-only check verb against a fabricated home with all core
# containers "running" (STUB_PS). The stores are stubbed unreachable so the
# exit code is nonzero — assertions pin the ISOLATION verdict lines, the
# contract that matters: TLS backend reachable, plaintext closed, DB and PHI
# log store unreachable from the internet-facing WAF pod.
HCHK="$WORK/h-check"; mk_home "$HCHK"
CHK_PS="carlos-app-db
carlos-app-drugref
carlos-app-carlos
carlos-waf-waf
carlos-app-mysqld-exporter
carlos-app-vmagent
carlos-obs-node-exporter
carlos-obs-victorialogs
carlos-obs-victoria-metrics
carlos-obs-logcollect
carlos-obs-logview
carlos-obs-vmalert"
CHK_OUT="$WORK/check.out"
ctle "$HCHK" STUB_PS="$CHK_PS" -- check > "$CHK_OUT" 2>&1
assert "check: waf reaches the TLS backend (app:8443)" \
    grep -q "ok   waf reaches carlos-app:8443" "$CHK_OUT"
assert "check: plaintext Tomcat 8080 is CLOSED cross-pod" \
    grep -q "ok   waf cannot reach carlos-app:8080" "$CHK_OUT"
assert "check: MariaDB isolated from the edge pod" \
    grep -q "ok   waf cannot reach carlos-app:3306" "$CHK_OUT"
assert "check: PHI log store isolated from the edge pod" \
    grep -q "ok   waf cannot reach carlos-obs:9428" "$CHK_OUT"
assert "check: waf runs non-root (podman top probe)" \
    grep -q "ok   waf runs non-root" "$CHK_OUT"
assert "check: least-privilege DB account reported" \
    grep -q "ok   app DB account is least-privilege" "$CHK_OUT"
# Negative direction: the non-root probe must actually FLAG a root WAF, not
# just print "ok" on the healthy path (a broken probe would pass CI silently).
CHK_ROOT="$WORK/check-root.out"
ctle "$HCHK" STUB_PS="$CHK_PS" STUB_TOP_ROOT=1 -- check > "$CHK_ROOT" 2>&1 || true
assert "check: DETECTS a root WAF process (STUB_TOP_ROOT)" \
    grep -q "has a ROOT process" "$CHK_ROOT"
assert "check: does NOT falsely report non-root when the WAF runs as root" \
    bash -c "! grep -q 'ok   waf runs non-root' '$CHK_ROOT'"

# Store auth (finding 33): the probes carry the credential OFF-ARGV (curl -K
# config), and check positively asserts a credential-less query is rejected.
CHK_AUTH="$WORK/check-auth.out"
m=$(mark)
ctle "$HCHK" STUB_PS="$CHK_PS" STUB_STORE_AUTH=1 -- check > "$CHK_AUTH" 2>&1 || true
assert "check: store probes present the obs credential via curl -K config" \
    log_since "$m" '^user = "obs:obs-pw"'
refute "check: the obs credential never appears as a curl argv token" \
    log_since "$m" '^curl .*obs-pw'
assert "check: store auth ENFORCED (credential-less query rejected)" \
    grep -q "ok   store auth enforced" "$CHK_AUTH"
# The enforcement probe must also DETECT a store that stopped enforcing —
# without STUB_STORE_AUTH the stub answers credential-less queries too.
CHK_NOAUTH="$WORK/check-noauth.out"
ctle "$HCHK" STUB_PS="$CHK_PS" -- check > "$CHK_NOAUTH" 2>&1 || true
assert "check: DETECTS an unenforced store (credential-less query answered)" \
    grep -q "store auth is not enforced" "$CHK_NOAUTH"

# --- obs profile off ---------------------------------------------------------------
HOBS="$WORK/h-noobs"; mk_home "$HOBS"
env_set "$HOBS" OBS_ENABLED 0
rm "$HOBS/container/carlos-obs.yaml" \
   "$HOBS/container/conf/vector/journald-collector.toml" \
   "$HOBS/container/conf/vmagent/scrape.yml" "$HOBS/container/conf/caddy/Caddyfile"
m=$(mark)
assert "play succeeds with the obs pod disabled (no obs artifacts required)" ctl "$HOBS" play
refute "obs-disabled play does not touch the obs pod unit" \
    log_since "$m" "restart carlos-obs.service"
assert "obs-disabled play still starts app + waf" \
    log_since "$m" "restart carlos-waf.service"

# ================================ guard ===========================================
HG="$WORK/h-guard"; mk_home "$HG"
assert "guard passes on a not-yet-deployed instance" \
    ctle "$HG" CARLOS_ACCEPT_EMPTY_DATADIR= -- guard
touch "$HG/container/.deployed"
refute "guard refuses a deployed instance with a wiped datadir" \
    ctle "$HG" CARLOS_ACCEPT_EMPTY_DATADIR= -- guard
mkdir -p "$HG/data/mariadb-mnt/mysql"
assert "guard passes once datadir/binlog/documents are present" \
    ctle "$HG" CARLOS_ACCEPT_EMPTY_DATADIR= -- guard

# =============================== db-users =========================================
HDU="$WORK/h-dbusers"; mk_home "$HDU"
printf 'db_username=root\ndb_password=x\n' > "$HDU/container/conf/carlos/carlos.properties"
m=$(mark)
assert "db-users provisions the least-privilege accounts" \
    ctle "$HDU" STUB_PS="carlos-app-db" -- db-users
assert "provisioning SQL ran off-argv (root pw forwarded by name)" \
    log_since "$m" "forwarded-env MYSQL_PWD=test-root-pw"
assert "provisioning grants the backup account WITHOUT PROCESS" \
    log_since "$m" "GRANT SELECT, SHOW VIEW, TRIGGER, EVENT, RELOAD, REPLICATION CLIENT"
assert "carlos.properties switched off root" \
    grep -q '^db_username=carlos$' "$HDU/container/conf/carlos/carlos.properties"
refute "the generated app password is not the placeholder" \
    grep -q '^db_password=x$' "$HDU/container/conf/carlos/carlos.properties"
assert "backup-db.env rewritten with the dedicated account" \
    grep -q '^BACKUP_DB_USER=backup$' "$HDU/container/conf/restic/backup-db.env"
assert "exporter.my.cnf rewritten off the placeholder" \
    bash -c "! grep -q __UNPROVISIONED__ '$HDU/container/conf/metrics/exporter.my.cnf'"

HDU2="$WORK/h-dbusers-sqlfail"; mk_home "$HDU2"
printf 'db_username=root\ndb_password=x\n' > "$HDU2/container/conf/carlos/carlos.properties"
refute "db-users fails when the provisioning SQL fails" \
    ctle "$HDU2" STUB_PS="carlos-app-db" STUB_SQL_FAIL=1 -- db-users
assert "no credential FILE was touched on SQL failure" \
    grep -q '^db_username=root$' "$HDU2/container/conf/carlos/carlos.properties"

HDU3="$WORK/h-dbusers-reauth"; mk_home "$HDU3"
printf 'db_username=root\ndb_password=x\n' > "$HDU3/container/conf/carlos/carlos.properties"
refute "db-users fails when the new credentials do not re-authenticate" \
    ctle "$HDU3" STUB_PS="carlos-app-db" STUB_REAUTH_FAIL=1 -- db-users
assert "re-auth failure left the previous passwords in place" \
    grep -q '^db_password=x$' "$HDU3/container/conf/carlos/carlos.properties"

# ============================ db-backup argument contract ===========================
# db-backup writes a PLAINTEXT-PHI physical copy of the datadir into a
# directory named from argv. Pass 14: it read args[0] and DROPPED the rest,
# and the name regex accepts a leading dash — so `db-backup --help` took a
# real multi-GB snapshot into a directory called `--help` (verified live)
# instead of printing usage. Silently-dropped arguments on a verb that writes
# PHI to disk are the same class as the CLI's no-argument-verb guard.
HDB="$WORK/h-dbbackup"; mk_home "$HDB"
refute "db-backup refuses a flag-shaped name instead of snapshotting into it" \
    ctle "$HDB" STUB_PS="carlos-app-db" -- db-backup --help
refute "db-backup refuses a short flag-shaped name" \
    ctle "$HDB" STUB_PS="carlos-app-db" -- db-backup -h
refute "db-backup refuses extra arguments instead of dropping them" \
    ctle "$HDB" STUB_PS="carlos-app-db" -- db-backup nightly --compress
assert "no snapshot directory was created by any refused invocation" \
    bash -c "test -z \"\$(ls -A '$HDB/backup/mariadb-hot' 2>/dev/null)\""
# A plain name still runs (the stub podman's mariadb-backup is a no-op, so
# only the ARGUMENT gate is under test here — the host dir is a bind mount
# the real container writes into).
assert "a plain name still reaches the snapshot path" \
    ctle "$HDB" STUB_PS="carlos-app-db" -- db-backup pre-upgrade.1

# ========================= backup sub-verb argument contract ========================
# The SAME class one verb over. `backup` advertises --dry-run/--snapshot=/
# --stop-datetime= on its usage line, but only `restore` ever parsed them:
# every other mode read args[0] and dropped the rest, so `backup full
# --dry-run` silently ran the REAL nightly tier (multi-GB plaintext-PHI dump
# staged, restic snapshot committed, retention advanced) instead of the
# preview the flag names. Verified live: `backup status --dry-run --bogus
# extra` exited 0 with all three arguments discarded, while the sibling
# `db-backup --dry-run` refused the identical flag.
HBM="$WORK/h-backupmode"; mk_home "$HBM"
for _mode in full binlogs docs verify status; do
    refute "backup $_mode refuses a trailing --dry-run instead of dropping it" \
        ctle "$HBM" -- backup "$_mode" --dry-run
done
refute "backup full refuses several dropped arguments" \
    ctle "$HBM" -- backup full --dry-run --bogus extra
# The refusal must beat the repo lock and the credential lookup: this home has
# no restic.env, so a late guard would report the credential error instead.
BM_OUT="$WORK/backup-mode.out"
ctle "$HBM" -- backup full --dry-run >"$BM_OUT" 2>&1 || true
assert "the refusal names the dropped arguments" \
    grep -q -- '--dry-run' "$BM_OUT"
assert "the refusal points at the one mode that does take flags" \
    grep -q "backup restore" "$BM_OUT"
assert "the refusal beat the credential lookup (no restic error)" \
    grep -qv "no restic credentials" "$BM_OUT"
assert "no restic repository was initialized by a refused invocation" \
    test ! -d "$HBM/backup/restic-repo"
# restore KEEPS its flags, and the argument-less forms keep working.
ctle "$HBM" -- backup restore --dry-run >"$BM_OUT" 2>&1 || true
assert "backup restore still accepts its documented --dry-run" \
    grep -qv "takes no arguments" "$BM_OUT"
ctle "$HBM" -- backup status >"$BM_OUT" 2>&1 || true
assert "bare 'backup status' still runs" \
    grep -q "full db" "$BM_OUT"

# ============================ seal + secrets render =================================
HS="$WORK/h-seal"; mk_home "$HS"
printf 'db_username=carlos\ndb_password=sealme-pw\n' > "$HS/container/conf/carlos/carlos.properties"
m=$(mark)
assert "seal consolidates secrets into the bundle (no-TPM path)" \
    ctle "$HS" STUB_NO_TPM=1 CARLOS_SEAL_NO_TPM=1 AGE_ESCROW_CONFIRMED=1 -- seal
assert "bundle exists and is enveloped (not plaintext)" \
    grep -q 'SOPS_ENC\[' "$HS/container/conf/secrets/secrets.enc.yaml"
refute "raw db password is NOT greppable in the encrypted bundle" \
    grep -q 'sealme-pw' "$HS/container/conf/secrets/secrets.enc.yaml"
assert "carlos.properties keeps the __SEALED__ placeholder" \
    grep -q '^db_password=__SEALED__$' "$HS/container/conf/carlos/carlos.properties"
assert "plaintext restic.env was shredded after ingestion" \
    test ! -e "$HS/container/conf/restic/restic.env"
assert "secrets unit installed with the CLI render as ExecStart" \
    grep -q 'ExecStart=/usr/local/sbin/carlos-ctl secrets render' "$CARLOS_SYSTEMD_DIR/carlos-secrets.service"
assert "backup timers gained the age credential drop-in dir" \
    test -d "$CARLOS_SYSTEMD_DIR/carlos-backup.service.d"
assert "seal enabled + restarted the secrets unit" \
    log_since "$m" "systemctl enable carlos-secrets.service"

RUNSECRETS="$WORK/run-secrets"; mkdir -p "$RUNSECRETS"
assert "secrets render materializes the db fragment" \
    ctle "$HS" CARLOS_RUN_SECRETS_DIR="$RUNSECRETS" -- secrets render
assert "fragment carries the raw (re-escaped) password" \
    grep -q '^db_password=sealme-pw$' "$RUNSECRETS/carlos-db.properties"
refute "secrets render FAILS LOUD when the bundle cannot decrypt" \
    ctle "$HS" CARLOS_RUN_SECRETS_DIR="$RUNSECRETS" STUB_SOPS_DECRYPT_FAIL=1 -- secrets render

# ---- no-systemd host: seal must not silently strand the sealed credentials ----
# The README documents play/down falling back to plain `podman kube play` on a
# host with no systemd. `seal` ends by daemon-reload/enable/start-ing the
# secrets unit INSIDE `if have("systemctl")`, with no else — so on such a host
# it shredded the plaintext, left db_password=__SEALED__ in both properties
# files, rendered ZERO /run fragments and exited 0. Measured live (pass 20):
# the next `podman kube play` died with "init container … exited with code 1"
# (the pod's carlos-init __SEALED__ guard) and the EMR was down. A PATH with
# every stub EXCEPT systemctl is how this suite models that host.
#
# The model has to drop systemctl from the WHOLE PATH, not just from the stub
# dir. The first cut appended the host's own `/usr/bin:/bin`, so on any host
# that HAS systemd installed — every production target, every developer
# laptop, and the ubuntu-latest CI runner — `shutil.which("systemctl")` found
# /usr/bin/systemctl and `have("systemctl")` came back TRUE inside the very
# tests that exist to pin the no-systemd fallbacks. All seven assertions below
# (H2, M1, M2 of pass 20) then failed, and the fallback code they cover was
# never executed anywhere except a systemd-less sandbox. Worse, the systemd
# BRANCH ran instead: this suite runs under sudo in CI, so on a host that also
# has a real instance provisioned, `seal`'s daemon-reload / enable / restart
# reached the LIVE system manager and the live <instance>-secrets.service —
# the same host-containment breach class as pass-15 H2 and pass-17 H8.
#
# Build a sanitized system bin dir (symlinks to every real /usr/bin,/bin,
# /usr/sbin,/sbin entry EXCEPT systemctl) and assert, before the first case,
# that nothing on the model PATH resolves systemctl.
NOSD_PATH="$WORK/stubs-no-systemctl"
NOSD_SYSBIN="$WORK/sysbin-no-systemctl"
mkdir -p "$NOSD_PATH" "$NOSD_SYSBIN"
for _s in "$ROOT"/tests/stubs/*; do
    [ "$(basename "$_s")" = systemctl ] || ln -sf "$_s" "$NOSD_PATH/"
done
for _d in /usr/bin /bin /usr/sbin /sbin; do
    [ -d "$_d" ] || continue
    for _f in "$_d"/*; do
        _b="$(basename "$_f")"
        [ "$_b" = systemctl ] && continue
        [ -e "$NOSD_SYSBIN/$_b" ] || ln -sf "$_f" "$NOSD_SYSBIN/$_b"
    done
done
NOSD_PATH="$NOSD_PATH:$NOSD_SYSBIN"
# Static gate on the MODEL itself: if a future edit re-admits a directory that
# carries systemctl, every no-systemd case below silently tests the systemd
# branch instead. Fail here, where the cause is named.
assert "the no-systemd model PATH really resolves NO systemctl" \
    bash -c "! PATH='$NOSD_PATH' command -v systemctl"
assert "the no-systemd model PATH still resolves the other stubs (podman)" \
    bash -c "PATH='$NOSD_PATH' command -v podman >/dev/null"
HNS="$WORK/h-seal-nosystemd"; mk_home "$HNS"
printf 'db_username=carlos\ndb_password=nosd-pw\n' > "$HNS/container/conf/carlos/carlos.properties"
NSRUN="$WORK/run-secrets-nosd"; mkdir -p "$NSRUN"
NSD_OUT="$WORK/seal-nosd.out"
env PATH="$NOSD_PATH" STUB_NO_TPM=1 CARLOS_SEAL_NO_TPM=1 \
    AGE_ESCROW_CONFIRMED=1 CARLOS_RUN_SECRETS_DIR="$NSRUN" EMR_HOME="$HNS" \
    PYTHONPATH="$ROOT" python3 -m carlos_ctl.cli seal >"$NSD_OUT" 2>&1
assert "no-systemd seal renders the credential fragments INLINE" \
    test -s "$NSRUN/carlos-db.properties"
assert "the inline-rendered fragment carries the real password" \
    grep -q '^db_password=nosd-pw$' "$NSRUN/carlos-db.properties"
assert "no-systemd seal names the standing boot requirement" \
    grep -q "carlos-ctl secrets render" "$NSD_OUT"

# ---- no-systemd play: the go-live markers must not be armed in silence ----
# start_instance_timers returned True without a word when systemctl is absent,
# so `play` wrote .deployed and exited 0 with NO backup / binlog / docs /
# restore-drill / monitor schedule and no boot guard — and neither `check`
# (its runtime-floor loop skips an absent tool) nor the monitor (its own
# missing-unit sweep returns early, and it is one of the jobs that never runs)
# could say so.
NSD_TIMERS="$WORK/timers-nosd.out"
env PATH="$NOSD_PATH" EMR_HOME="$HNS" PYTHONPATH="$ROOT" python3 - \
    >"$NSD_TIMERS" 2>&1 <<'PY'
from carlos_ctl.config import Settings
from carlos_ctl.lifecycle2 import start_instance_timers
from carlos_ctl.runner import Runner
print("returned", start_instance_timers(Runner(Settings())))
PY
assert "no-systemd play warns that NO schedule is armed" \
    grep -q "NO schedule is armed" "$NSD_TIMERS"
assert "the warning names the jobs that will never run" \
    grep -Eq "backup full.*backup binlogs|backup binlogs" "$NSD_TIMERS"
assert "it still returns True (the fallback deploy is a documented mode)" \
    grep -q "returned True" "$NSD_TIMERS"

# ---- systemctl PRESENT but systemd never booted -------------------------------
# The shape the three fallbacks above actually meet in the field. Debian/Ubuntu
# ship /usr/bin/systemctl inside container images, WSL distributions and
# chroots, so `have("systemctl")` is TRUE there while systemd is not PID 1 and
# every call exits nonzero with "System has not been booted with systemd as
# init system (PID 1). Can't operate." Keying the fallbacks on the BINARY meant
# none of them engaged: measured on such a host, `carlos-ctl seal` ingested both
# DB credentials, rewrote carlos.properties/drugref2.properties to __SEALED__,
# SHREDDED the plaintext restic.env, then died on `systemctl daemon-reload`
# with ZERO /run fragments rendered — the pass-20 H2 end state, plus advice
# ("fix the unit, journalctl -u …") that cannot be followed on that host and a
# re-run that fails identically. Runner.systemd_running() now adds sd_booted's
# own test (/run/systemd/system is a directory) on top of the PATH lookup.
#
# Model: the FULL stub PATH (systemctl stub included, so calls would SUCCEED if
# anything made them) with CARLOS_SYSTEMD_RUNTIME_DIR pointed at a path that
# does not exist. Every assertion below therefore proves the fallback fired
# because systemd is unusable, not because the tool was missing.
NOTBOOTED_RT="$WORK/no-such-systemd-runtime-dir"
rm -rf "$NOTBOOTED_RT"
HNB="$WORK/h-seal-notbooted"; mk_home "$HNB"
printf 'db_username=carlos\ndb_password=notbooted-pw\n' > "$HNB/container/conf/carlos/carlos.properties"
NBRUN="$WORK/run-secrets-notbooted"; mkdir -p "$NBRUN"
NB_OUT="$WORK/seal-notbooted.out"
env STUB_NO_TPM=1 CARLOS_SEAL_NO_TPM=1 AGE_ESCROW_CONFIRMED=1 \
    CARLOS_SYSTEMD_RUNTIME_DIR="$NOTBOOTED_RT" CARLOS_RUN_SECRETS_DIR="$NBRUN" \
    EMR_HOME="$HNB" PYTHONPATH="$ROOT" python3 -m carlos_ctl.cli seal \
    >"$NB_OUT" 2>&1
assert "systemctl-present-but-not-booted: seal renders the fragments INLINE" \
    test -s "$NBRUN/carlos-db.properties"
assert "the inline-rendered fragment carries the real password" \
    grep -q '^db_password=notbooted-pw$' "$NBRUN/carlos-db.properties"
assert "seal did NOT die on the unreachable daemon-reload" \
    bash -c "! grep -q 'daemon-reload failed' '$NB_OUT'"
NB_TIMERS="$WORK/timers-notbooted.out"
env CARLOS_SYSTEMD_RUNTIME_DIR="$NOTBOOTED_RT" EMR_HOME="$HNB" PYTHONPATH="$ROOT" \
    python3 - >"$NB_TIMERS" 2>&1 <<'PY'
from carlos_ctl.config import Settings
from carlos_ctl.lifecycle2 import start_instance_timers
from carlos_ctl.runner import Runner
print("returned", start_instance_timers(Runner(Settings())))
PY
assert "systemctl-present-but-not-booted: play warns that NO schedule is armed" \
    grep -q "NO schedule is armed" "$NB_TIMERS"
assert "it still returns True there too (documented fallback mode)" \
    grep -q "returned True" "$NB_TIMERS"
# rotate obs must reach the kube-play fallback so the STORES move to the new
# credential (pass-20 M2 was the same gap one host-shape over).
HNBO="$WORK/h-rot-obs-notbooted"; mk_home "$HNBO"
printf 'apiVersion: v1\nkind: Pod\nspec:\n  containers: []\n' > "$HNBO/container/carlos-obs.yaml"
m_nb_obs=$(mark)
env CARLOS_SYSTEMD_RUNTIME_DIR="$NOTBOOTED_RT" OBS_HTTP_NEW_PASSWORD=notbooted-obs-pw \
    STUB_PS="carlos-app-db" EMR_HOME="$HNBO" PYTHONPATH="$ROOT" \
    python3 -m carlos_ctl.cli rotate obs >/dev/null 2>&1
assert "systemctl-present-but-not-booted: rotate obs restarts the obs pod via kube play" \
    log_since "$m_nb_obs" "kube play --replace .*carlos-obs.yaml"

# ===================== rotate / secrets-render argument contract ====================
# The same silently-dropped-argument class as `db-backup` and `backup <tier>`
# above, one verb over. `rotate` only ever parsed args for its `db` sub-verb:
# db-root/log-view/obs/age-key/restic took the trailing tokens and DROPPED
# them, so `rotate age-key --dry-run` re-keyed the sealed-secrets master for
# real and `rotate restic --help` re-passworded the backup repository. The
# dispatch for `secrets` had the same prefix-match hole (`secrets render
# --dry-run` did the real render into the /run tmpfs).
HRA="$WORK/h-rot-args"; mk_home "$HRA"
for _sub in db-root log-view obs age-key restic; do
    refute "rotate $_sub refuses a trailing --dry-run instead of dropping it" \
        ctle "$HRA" STUB_PS="carlos-app-db" -- rotate "$_sub" --dry-run
done
RA_OUT="$WORK/rotate-args.out"
ctle "$HRA" STUB_PS="carlos-app-db" -- rotate age-key --dry-run >"$RA_OUT" 2>&1 || true
assert "the refusal names the dropped argument" grep -q -- '--dry-run' "$RA_OUT"
assert "the refusal points at the one sub-verb that takes a flag" \
    grep -q -- "rotate db" "$RA_OUT"
assert "the refusal beat the mutation (the age key is untouched)" \
    test ! -e "$HRA/secrets-private/age-key.txt.new"
# An unknown sub-verb still gets the usage line, not an argument complaint.
ctle "$HRA" -- rotate bogus --dry-run >"$RA_OUT" 2>&1 || true
assert "an unknown rotate sub-verb still prints the usage line" \
    grep -q "usage: carlos-ctl rotate" "$RA_OUT"
refute "secrets render refuses a trailing flag instead of rendering" \
    ctle "$HS" CARLOS_RUN_SECRETS_DIR="$RUNSECRETS" -- secrets render --dry-run

# ============================ rotate db-root ========================================
HR="$WORK/h-rotroot"; mk_home "$HR"
m=$(mark)
assert "rotate db-root changes the password" \
    ctle "$HR" STUB_PS="carlos-app-db" CARLOS_DB_NEW_ROOT_PASSWORD=new-root-pw -- rotate db-root
assert "ALTER USER ran with the OLD password off-argv" \
    log_since "$m" "forwarded-env MYSQL_PWD=test-root-pw"
assert "the podman secret was refreshed" log_since "$m" "secret rm carlos-db"
assert "env file now carries the NEW root password" \
    grep -q '^CARLOS_DB_ROOT_PASSWORD=new-root-pw$' "$HR/container/carlos-app.env"

# EMIT-EARLY (finding 20): a GENERATED root password must be surfaced the
# instant ALTER USER succeeds — before the secret refresh / env write — so a
# later failure can never strand a password known to nobody. (Non-tty run:
# emit_secret writes the drop-file; assert it appears and no earlier step
# gated it.)
HRE="$WORK/h-rotroot-emit"; mk_home "$HRE"
assert "a generated root password is emitted (drop-file) on rotate" \
    bash -c "cd '$ROOT' && EMR_HOME='$HRE' STUB_PS=carlos-app-db \
        python3 -m carlos_ctl.cli rotate db-root >/dev/null 2>&1 </dev/null && \
        test -s '$HRE/secrets-private/.new-mariadb-root-password'"

# ============================ rotate age-key =======================================
# The MASTER key: re-key the bundle, prove it decrypts with the NEW key
# before any swap, install the new key/recipient, force escrow re-confirm.
HAK="$WORK/h-rotage"; mk_home "$HAK"
printf 'db_username=carlos\ndb_password=akme-pw\n' > "$HAK/container/conf/carlos/carlos.properties"
ctle "$HAK" STUB_NO_TPM=1 CARLOS_SEAL_NO_TPM=1 AGE_ESCROW_CONFIRMED=1 -- seal >/dev/null 2>&1
m=$(mark)
assert "rotate age-key re-keys the bundle (no-TPM path)" \
    ctle "$HAK" STUB_NO_TPM=1 CARLOS_SEAL_NO_TPM=1 -- rotate age-key
assert "a new keypair was generated" log_since "$m" "age-keygen -o"
assert "the bundle was re-encrypted to the new recipient" \
    log_since "$m" 'sops-env SOPS_AGE_RECIPIENTS=age1stubrecipient'
assert "the escrow-confirmation marker was cleared (re-confirm the new key)" \
    test ! -e "$HAK/secrets-private/.age-escrow-confirmed"
# H1: the persist-before-swap staging leaves no half-installed key/pub sibling
# behind on a successful rotation (a lingering .new would be a live secret).
assert "no half-installed age-key staging sibling survives the rotation" \
    test ! -e "$HAK/secrets-private/age-key.txt.new"
assert "the bundle still decrypts after the re-key (secrets render works)" \
    ctle "$HAK" STUB_NO_TPM=1 CARLOS_RUN_SECRETS_DIR="$WORK/rs-age" -- secrets render

# .new-* credential drop-files are reaped by seal (finding 21).
HRP="$WORK/h-reap"; mk_home "$HRP"
mkdir -p "$HRP/secrets-private"
printf 'leftover-secret\n' > "$HRP/secrets-private/.new-something"
printf 'db_username=carlos\ndb_password=reapme\n' > "$HRP/container/conf/carlos/carlos.properties"
assert "seal reaps a leftover .new-* credential drop-file" \
    bash -c "cd '$ROOT' && EMR_HOME='$HRP' STUB_NO_TPM=1 CARLOS_SEAL_NO_TPM=1 \
        AGE_ESCROW_CONFIRMED=1 python3 -m carlos_ctl.cli seal >/dev/null 2>&1; \
        test ! -e '$HRP/secrets-private/.new-something'"

# ============================ rotate restic =========================================
HRS="$WORK/h-rotrestic"; mk_home "$HRS"
m=$(mark)
assert "rotate restic completes the strand-proof sequence" \
    ctle "$HRS" RESTIC_NEW_PASSWORD=new-restic-pw -- rotate restic
assert "key add ran" log_since "$m" " key add "
assert "old key removed only after the stored credential verified" \
    log_since "$m" " key remove deadbeef"
assert "restic.env holds the NEW password" \
    grep -q '^RESTIC_PASSWORD=new-restic-pw$' "$HRS/container/conf/restic/restic.env"
assert "extra offsite-backend vars survived the rewrite" \
    grep -q '^AWS_EXTRA=keepme$' "$HRS/container/conf/restic/restic.env"
assert "the NEW password was verified off-argv" \
    log_since "$m" "forwarded-env RESTIC_PASSWORD=new-restic-pw"

HRS2="$WORK/h-rotrestic-vfail"; mk_home "$HRS2"
m=$(mark)
refute "rotate restic aborts when the NEW password cannot open the repo" \
    ctle "$HRS2" RESTIC_NEW_PASSWORD=new-restic-pw STUB_RESTIC_VERIFY_FAIL=1 -- rotate restic
assert "verify-failure still PERSISTED the new password (both keys valid)" \
    grep -q '^RESTIC_PASSWORD=new-restic-pw$' "$HRS2/container/conf/restic/restic.env"
refute "verify-failure did NOT remove the old key" log_since "$m" " key remove deadbeef"

# ============================ TLS modes ===========================================
# selfsigned (the default) must yield a serving WAF with ZERO manual cert
# steps, while never clobbering an operator-placed pair; manual keeps the
# historical refusal; acme drives certbot one-shot issuance + install.
HTLS="$WORK/h-tls"; mk_home "$HTLS"
rm -f "$HTLS/container/conf/waf/certs/fullchain.pem" \
      "$HTLS/container/conf/waf/certs/privkey.pem"
refute "manual TLS mode still refuses play without certs" ctl "$HTLS" play
env_set "$HTLS" CARLOS_TLS_MODE selfsigned
assert "selfsigned mode GENERATES the pair and plays" ctl "$HTLS" play
assert "the generated cert is a real certificate" \
    openssl x509 -noout -in "$HTLS/container/conf/waf/certs/fullchain.pem"
TLS_SUM_BEFORE=$(sha256sum "$HTLS/container/conf/waf/certs/fullchain.pem" | cut -d' ' -f1)
assert "a second selfsigned play leaves the existing pair untouched" ctl "$HTLS" play
assert "operator/previous certs are never clobbered (content unchanged)" \
    test "$TLS_SUM_BEFORE" = "$(sha256sum "$HTLS/container/conf/waf/certs/fullchain.pem" | cut -d' ' -f1)"

refute "cert-renew refuses outside acme mode (selfsigned regenerates at play)" \
    ctl "$HTLS" cert-renew
env_set "$HTLS" CARLOS_TLS_MODE acme
refute "acme cert-renew refuses without a contact email" ctl "$HTLS" cert-renew
env_set "$HTLS" ACME_EMAIL ops@example.ca
refute "acme cert-renew fails LOUDLY when certbot yields no certificate" \
    ctl "$HTLS" cert-renew
m=$(mark)
assert "acme cert-renew issues and installs (stubbed certbot)" \
    ctle "$HTLS" STUB_CERTBOT_ISSUE=1 -- cert-renew
assert "the issued cert replaced the installed pair" \
    grep -q "STUB-CERT" "$HTLS/container/conf/waf/certs/fullchain.pem"
assert "certbot published the HTTP-01 listener on the publish port" \
    log_since "$m" -- "-p 192.168.20.250:8081:80"
assert "the waf pod restarted to serve the renewed cert" \
    log_since "$m" "restart carlos-waf.service"
assert "the obs pod restarted too (the log view shares the pair)" \
    log_since "$m" "restart carlos-obs.service"
assert "an unchanged cert is a quiet not-due no-op" \
    ctle "$HTLS" STUB_CERTBOT_ISSUE=1 -- cert-renew

# ============================ rotate obs ==========================================
# The obs-store credential rotation: canonical file -> podman secret ->
# surgical rewrites of the two inline holders -> restarts, all off-argv.
HRO="$WORK/h-rotate-obs"; mk_home "$HRO"
m=$(mark)
assert "rotate obs rotates the store credential" \
    ctle "$HRO" OBS_HTTP_NEW_PASSWORD=new-obs-pw -- rotate obs
assert "the canonical credential file holds the new value" \
    grep -qx new-obs-pw "$HRO/secrets-private/obs-http-password"
assert "the podman secret was recreated" log_since "$m" "secret rm carlos-obs-http"
assert "the vector sink credential was rewritten" \
    grep -q 'auth.password = "new-obs-pw"' "$HRO/container/conf/vector/journald-collector.toml"
assert "the Caddyfile upstream credential was rewritten" \
    grep -q "Basic $(printf 'obs:new-obs-pw' | base64)" "$HRO/container/conf/caddy/Caddyfile"
assert "the obs pod was restarted to pick up the new secret" \
    log_since "$m" "restart carlos-obs.service"
refute "the new credential never appeared as an argv token" \
    log_since "$m" '^podman .*new-obs-pw'
# No-systemd host: the app+waf half of this rotation already falls back to
# `kube play --replace` (dbops.restart_app_and_waf); the OBS half did not, so
# every CLIENT moved to the new credential while the STORES kept the old one
# and the verb still printed its success line — the whole metrics/log pipeline
# 401s until someone happens to run `play`.
HRO2="$WORK/h-rotate-obs-nosd"; mk_home "$HRO2"
m=$(mark)
env PATH="$NOSD_PATH" OBS_HTTP_NEW_PASSWORD=nosd-obs-pw \
    EMR_HOME="$HRO2" PYTHONPATH="$ROOT" python3 -m carlos_ctl.cli rotate obs \
    >/dev/null 2>&1
assert "no-systemd rotate obs restarts the obs pod via kube play" \
    log_since "$m" "kube play --replace .*carlos-obs.yaml"
refute "rotate obs refuses when store auth is not provisioned" \
    bash -c "rm '$HRO/secrets-private/obs-http-password'; cd '$ROOT' && \
        EMR_HOME='$HRO' python3 -m carlos_ctl.cli rotate obs"

# ================================ backup ===========================================
HB="$WORK/h-backup"; mk_home "$HB"
mkdir -p "$HB/backup/restic-repo/data"   # non-empty local repo
m=$(mark)
assert "backup binlogs ships the closed binlogs" ctl "$HB" backup binlogs
assert "the active binlog was flushed first" log_since "$m" "FLUSH BINARY LOGS"
assert "the active binlog is excluded from the ship" \
    log_since "$m" -- "--exclude /backup/binlog/binlog.000002"
assert "binlog freshness stamp advanced" test -f "$HB/backup/.last-binlog-ok"

rm -f "$HB/backup/.last-binlog-ok"
assert "boot-grace db failure is a quiet skip" \
    ctle "$HB" STUB_BINLOG_PROBE_FAIL=1 BOOT_GRACE_SECONDS=99999999 -- backup binlogs
refute "a boot-grace skip must NOT advance the freshness stamp" \
    test -f "$HB/backup/.last-binlog-ok"
refute "outside boot grace the same failure is ALERTABLE (nonzero)" \
    ctle "$HB" STUB_BINLOG_PROBE_FAIL=1 -- backup binlogs

# Runtime binlog LATCH (@@log_bin still reads 1 after MariaDB turns logging
# off mid-process — a full binlog volume or an ownership change is enough).
# Before this guard the 15-minute ship ran clean forever over a frozen chain
# and kept stamping .last-binlog-ok, so nothing ever noticed PITR was dead.
rm -f "$HB/backup/.last-binlog-ok"
refute "a binlog latched off at runtime makes the ship FAIL (not a clean no-op)" \
    ctle "$HB" STUB_BINLOG_CLOSED=1 -- backup binlogs
refute "the latched-off ship must NOT stamp binlog freshness (the monitor pages)" \
    test -f "$HB/backup/.last-binlog-ok"
refute "the latched-off ship never FLUSHes (it bails before mutating)" \
    log_since "$(mark)" "FLUSH BINARY LOGS"
refute "the nightly full REFUSES on a latched-off binlog" \
    ctle "$HB" STUB_BINLOG_CLOSED=1 -- backup full
refute "the latched-off full bails BEFORE burning the dump" \
    log_since "$(mark)" "mariadb-dump"
# A pre-11.4 server knows only SHOW MASTER STATUS: the fallback must keep the
# healthy path working rather than refusing every backup on an older DB_IMAGE.
assert "the pre-11.4 SHOW MASTER STATUS spelling still reports OPEN" \
    ctle "$HB" STUB_BINLOG_STATUS_UNSUPPORTED=1 -- backup binlogs
assert "the fallback path still advances the freshness stamp" \
    test -f "$HB/backup/.last-binlog-ok"

# Binlog chain identity: a rebuilt/DR-fresh server (new @@server_uuid, since
# the uuid persists in the datadir) must NOT ship its unrelated binlogs over
# the existing chain — they would mask it as the newest 'latest' snapshots.
assert "the first ship recorded the chain identity marker" \
    grep -q '^11111111-1111-1111-1111-111111111111$' "$HB/backup/.binlog-identity"
assert "the identity sidecar rides in the shipped binlog dir" \
    grep -q '^11111111-1111-1111-1111-111111111111$' \
        "$HB/data/mariadb-binlog/.carlos-server-identity"
# M9: the sidecar must be 0644 (root writes under umask 077) so the rootless
# restic container can read it into the snapshot — a 0600 file fails the ship.
assert "the identity sidecar is world-readable (0644, not umask 077)" \
    test "$(stat -c %a "$HB/data/mariadb-binlog/.carlos-server-identity")" = 644
refute "a ship from a DIFFERENT server identity is REFUSED (chain pollution)" \
    ctle "$HB" STUB_SERVER_UUID=22222222-2222-2222-2222-222222222222 -- backup binlogs
assert "the identity marker is untouched by the refusal" \
    grep -q '^11111111-' "$HB/backup/.binlog-identity"
assert "the explicit ack accepts the new chain identity (one-shot)" \
    ctle "$HB" STUB_SERVER_UUID=22222222-2222-2222-2222-222222222222 \
        CARLOS_ACCEPT_NEW_BINLOG_IDENTITY=1 -- backup binlogs
assert "the ack re-anchored the marker to the new identity" \
    grep -q '^22222222-' "$HB/backup/.binlog-identity"
assert "the original identity re-anchors with the same ack" \
    ctle "$HB" CARLOS_ACCEPT_NEW_BINLOG_IDENTITY=1 -- backup binlogs
refute "a third identity is refused against the re-anchored marker" \
    ctle "$HB" STUB_SERVER_UUID=33333333-3333-3333-3333-333333333333 -- backup binlogs
assert "an identity-unknown server (pre-10.11 probe failure) ships as legacy" \
    ctle "$HB" STUB_UUID_PROBE_FAIL=1 -- backup binlogs

HB2="$WORK/h-sentinel"; mk_home "$HB2"
printf '%s\n' "$HB2/backup/restic-repo" > "$HB2/backup/.restic-repo-initialized"
refute "backup refuses to re-init an empty repo over a recorded one (legacy sentinel read)" \
    ctle "$HB2" STUB_RESTIC_CAT_RC=10 -- backup binlogs
m=$(mark)
assert "CARLOS_INIT_REPO=1 is the explicit re-provision escape" \
    ctle "$HB2" STUB_RESTIC_CAT_RC=10 CARLOS_INIT_REPO=1 -- backup binlogs
assert "the escape actually ran restic init" log_since "$m" " init"
refute "an unreachable/bad-password repo is never re-inited" \
    ctle "$HB2" STUB_RESTIC_CAT_RC=1 -- backup binlogs

# Seventh pass: the sentinel lives OUTSIDE the backup volume (conf/restic) so
# an unmounted backup volume — which takes the in-repo-dir legacy sentinel
# with it — still refuses the silent fresh-repo re-init.
HB2B="$WORK/h-sentinel-offvol"; mk_home "$HB2B"
printf '%s\n' "$HB2B/backup/restic-repo" \
    > "$HB2B/container/conf/restic/.restic-repo-initialized"
refute "lost backup mount (no legacy sentinel) still refuses re-init via the conf-side sentinel" \
    ctle "$HB2B" STUB_RESTIC_CAT_RC=10 -- backup binlogs
m=$(mark)
assert "a healthy repo run writes the sentinel to the conf side" \
    ctle "$HB2B" STUB_RESTIC_CAT_RC=10 CARLOS_INIT_REPO=1 -- backup binlogs
assert "conf-side sentinel present after init" \
    test -f "$HB2B/container/conf/restic/.restic-repo-initialized"

HB3="$WORK/h-docs"; mk_home "$HB3"
mkdir -p "$HB3/backup/restic-repo/data"
rm "$HB3/data/OscarDocument/doc1.pdf"
assert "an empty docs store still snapshots (exit 0 — one hourly alert, not a page storm)" \
    ctl "$HB3" backup docs
refute "but the success stamp is WITHHELD for an empty store" \
    test -f "$HB3/backup/.last-docs-ok"
printf 'doc\n' > "$HB3/data/OscarDocument/doc1.pdf"
assert "a populated store stamps success" ctl "$HB3" backup docs
assert "docs stamp present" test -f "$HB3/backup/.last-docs-ok"

HB4="$WORK/h-full"; mk_home "$HB4"
mkdir -p "$HB4/backup/restic-repo/data"
m=$(mark)
assert "backup full completes (dump staged + verified, retention, check)" ctl "$HB4" backup full
assert "dump used --master-data=2 (PITR anchor)" log_since "$m" -- "--master-data=2"
assert "retention delegated to restic forget" log_since "$m" -- "forget --host carlos-emr --tag db"
assert "repository check ran" log_since "$m" " check"
assert "full stamp advanced" test -f "$HB4/backup/.last-full-ok"
assert "DR env copy staged" test -f "$HB4/container/carlos-app.env.dr"
refute "DR env copy carries NO credential-bearing keys" \
    grep -qE '(PASSWORD|PWD|WEBHOOK|URL)=' "$HB4/container/carlos-app.env.dr"
# Finding S10: the DR copy is an ALLOWLIST — a custom key with an
# unrecognizable name (a possible operator secret) must be dropped, not
# copied into the backup by a name-pattern miss.
env_set "$HB4" SMTP_AUTH "user:hunter2"
assert "full re-runs with a custom unknown key present" ctl "$HB4" backup full
refute "DR env copy drops UNKNOWN keys (possible operator secrets)" \
    grep -q 'SMTP_AUTH' "$HB4/container/carlos-app.env.dr"
assert "identity keys still ride in the DR copy" \
    grep -q '^SERVER_NAME=' "$HB4/container/carlos-app.env.dr"

refute "full refuses a footer-complete but CONTENT-EMPTY dump (content floor)" \
    ctle "$HB4" STUB_DUMP_EMPTY=1 -- backup full

refute "full refuses when non-InnoDB tables break the PITR contract" \
    ctle "$HB4" STUB_NONINNODB=1 -- backup full
assert "the reviewed-risk hatch lets the dump proceed" \
    ctle "$HB4" STUB_NONINNODB=1 CARLOS_ALLOW_NON_INNODB=1 -- backup full
# formRourke2009 has 1227 columns (> InnoDB's 1017 limit) so it can NEVER be
# converted — refusing over it would fire on every fresh ON/BC install for a
# condition with no remedy, training operators to set the blanket override
# (which would then also mask a table that COULD be converted).
assert "the KNOWN-unconvertible table alone does NOT refuse the dump" \
    ctle "$HB4" STUB_ROURKE_ARIA=1 -- backup full
ctle "$HB4" STUB_ROURKE_ARIA=1 -- backup full > "$WORK/rourke-audit.log" 2>&1 || true
assert "...it is still NAMED in the output, never silently accepted" \
    grep -q 'formRourke2009' "$WORK/rourke-audit.log"
assert "...and the accepted PITR loss window is stated, not just the table" \
    grep -q 'silently lose writes' "$WORK/rourke-audit.log"
refute "a MIXED result still refuses (the convertible table is what blocks)" \
    ctle "$HB4" STUB_NONINNODB=1 STUB_ROURKE_ARIA=1 -- backup full
refute "a FAILED engine audit is fail-closed too (not read as all-InnoDB)" \
    ctle "$HB4" STUB_ENGINE_PROBE_FAIL=1 -- backup full

# ============================ restore (guided PITR) =================================
HREST="$WORK/h-restore"; mk_home "$HREST"
mkdir -p "$HREST/backup/restic-repo/data"
assert "restore --dry-run prints the plan and changes nothing" \
    ctle "$HREST" STUB_PS="carlos-app-db" -- backup restore --dry-run
refute "restore refuses the live overwrite non-interactively without confirmation" \
    bash -c "cd '$ROOT' && STUB_PS=carlos-app-db EMR_HOME='$HREST' PYTHONPATH='$ROOT' \
        python3 -m carlos_ctl.cli backup restore < /dev/null"
refute "restore refuses a WRONG instance name in the confirmation" \
    bash -c "cd '$ROOT' && STUB_PS=carlos-app-db EMR_HOME='$HREST' PYTHONPATH='$ROOT' \
        CARLOS_RESTORE_CONFIRMED=notcarlos python3 -m carlos_ctl.cli backup restore < /dev/null"
# Restore-to-latest with an unusable/absent binlog chain must NOT silently
# fall back to base-dump-only — that loses every committed write after the
# dump. It refuses before touching the live db unless the loss is explicitly
# acknowledged (roll-forward data-loss guard).
refute "restore-to-latest REFUSES silent base-dump-only (roll-forward data-loss guard)" \
    ctle "$HREST" STUB_PS="carlos-app-db" CARLOS_RESTORE_CONFIRMED=carlos -- backup restore
m=$(mark)
assert "confirmed restore loads the dump when base-dump-only is acknowledged" \
    ctle "$HREST" STUB_PS="carlos-app-db" CARLOS_RESTORE_CONFIRMED=carlos \
        CARLOS_RESTORE_BASE_DUMP_ONLY=1 -- backup restore
assert "the live load ran as root off-argv" \
    log_since "$m" "forwarded-env MYSQL_PWD=test-root-pw"
assert "the legacy CARLOS_RESTORE_CONFIRMED=1 still works (deprecated)" \
    ctle "$HREST" STUB_PS="carlos-app-db" CARLOS_RESTORE_CONFIRMED=1 \
        CARLOS_RESTORE_BASE_DUMP_ONLY=1 -- backup restore

# PITR roll-forward on a DISASTER-RECOVERY rebuild: the runbook's `play` starts
# a FRESH MariaDB whose local binlog.000001 must NOT be shipped as the chain's
# 'latest' (the old bug: that masked the real chain and silently lost up to a
# day of writes). With the real chain fetched from the repo, the replay branch
# MUST run from the dump anchor (binlog.000007:1234) — proof the fresh local
# binlog did not pollute the selection.
HRDR="$WORK/h-restore-dr"; mk_home "$HRDR"
mkdir -p "$HRDR/backup/restic-repo/data"
: > "$HRDR/data/mariadb-binlog/binlog.000001"        # fresh post-`play` server
printf 'binlog.000001\n' > "$HRDR/data/mariadb-binlog/binlog.index"
m=$(mark)
assert "DR restore-to-latest rolls forward via the repo chain (no ack needed)" \
    ctle "$HRDR" STUB_PS="carlos-app-db" STUB_RESTORE_BINLOGS=1 \
        CARLOS_RESTORE_CONFIRMED=carlos -- backup restore
assert "DR restore replayed the repo chain from the dump anchor (pos 1234)" \
    log_since "$m" "mariadb-binlog --no-defaults --start-position=1234"
assert "the replay session disables binlogging (retry must never double-apply)" \
    log_since "$m" "mariadb-binlog.*sql_log_bin=0"
assert "the load drop-and-recreates the dumped schema (no merge over live)" \
    log_since "$m" 'DROP DATABASE IF EXISTS `oscar`'
refute "DR restore did NOT pre-ship the fresh local binlog.000001 (no pollution)" \
    log_since "$m" "backup /backup/binlog"

# Replay-side chain identity: a chain shipped by a DIFFERENT server than the
# dump's originating one must refuse BEFORE the destructive load; legacy
# (pre-identity) artifacts warn and proceed on sequence contiguity alone.
HRID="$WORK/h-restore-ident"; mk_home "$HRID"
mkdir -p "$HRID/backup/restic-repo/data"
refute "restore REFUSES a chain shipped by a different server" \
    ctle "$HRID" STUB_PS="carlos-app-db" STUB_RESTORE_BINLOGS=1 \
        STUB_CHAIN_UUID=99999999-9999-9999-9999-999999999999 \
        CARLOS_RESTORE_CONFIRMED=carlos -- backup restore
assert "the explicit ack accepts the identity mismatch" \
    ctle "$HRID" STUB_PS="carlos-app-db" STUB_RESTORE_BINLOGS=1 \
        STUB_CHAIN_UUID=99999999-9999-9999-9999-999999999999 \
        CARLOS_ACCEPT_BINLOG_IDENTITY_MISMATCH=1 \
        CARLOS_RESTORE_CONFIRMED=carlos -- backup restore
assert "pre-identity artifacts restore with the legacy warn (never hard-fail)" \
    ctle "$HRID" STUB_PS="carlos-app-db" STUB_RESTORE_BINLOGS=1 \
        STUB_DUMP_NO_UUID=1 STUB_CHAIN_NO_UUID=1 \
        CARLOS_RESTORE_CONFIRMED=carlos -- backup restore
assert "a completed restore re-anchored the ship-side identity marker" \
    grep -q '^11111111-' "$HRID/backup/.binlog-identity"

# --snapshot=<ID> PITR: the DB dump is fetched from the NAMED snapshot, but the
# binlog chain MUST still be fetched with 'restore latest --tag binlog' —
# restic only applies --host/--tag filters when resolving 'latest', so passing
# the dump's snapshot ID there restores the dump into the binlog scratch and
# misreports the anchor as pruned (the stub enforces this like real restic:
# a non-latest chain fetch materializes no chain, so the replay assert below
# fails if the code regresses).
HSNAP="$WORK/h-restore-snap"; mk_home "$HSNAP"
mkdir -p "$HSNAP/backup/restic-repo/data"
m=$(mark)
assert "--snapshot=<ID> restore still rolls forward via the repo chain" \
    ctle "$HSNAP" STUB_PS="carlos-app-db" STUB_RESTORE_BINLOGS=1 \
        CARLOS_RESTORE_CONFIRMED=carlos -- backup restore --snapshot=abc123def
assert "--snapshot restore fetched the DB dump from the NAMED snapshot" \
    log_since "$m" "dump abc123def --host carlos-emr --tag db"
assert "--snapshot restore fetched the binlog chain from 'latest' (not the ID)" \
    log_since "$m" "restore latest --host carlos-emr --tag binlog"
assert "--snapshot restore replayed the chain from the dump anchor" \
    log_since "$m" "mariadb-binlog --no-defaults --start-position=1234"

# ================================ monitor ==========================================
HM="$WORK/h-monitor"; mk_home "$HM"
env_set "$HM" OBS_ENABLED 0
env_set "$HM" HEARTBEAT_URL https://hb.example/ping
touch "$HM/backup/.last-full-ok" "$HM/backup/.last-binlog-ok" "$HM/backup/.last-docs-ok" \
      "$HM/backup/.last-verify-ok"
CORE_PS=$'carlos-app-db\ncarlos-app-carlos\ncarlos-app-drugref\ncarlos-waf-waf'
assert "monitor is green on a healthy obs-disabled instance" \
    ctle "$HM" STUB_PS="$CORE_PS" -- monitor
refute "monitor alerts when a core container is missing" \
    ctle "$HM" STUB_PS=$'carlos-app-db\ncarlos-app-carlos\ncarlos-waf-waf' -- monitor
rm "$HM/backup/.last-binlog-ok"
refute "monitor alerts on a missing backup stamp (never-ran must not read green)" \
    ctle "$HM" STUB_PS="$CORE_PS" -- monitor
touch "$HM/backup/.last-binlog-ok"
rm "$HM/backup/.last-verify-ok"
refute "monitor alerts on a missing restore-drill stamp (a stopped drill is a fault)" \
    ctle "$HM" STUB_PS="$CORE_PS" -- monitor
touch "$HM/backup/.last-verify-ok"
printf 'db_username=root\ndb_password=rootpw\n' > "$HM/container/conf/carlos/carlos.properties"
refute "monitor alerts when the app still connects to MariaDB as root" \
    ctle "$HM" STUB_PS="$CORE_PS" -- monitor
printf 'db_username=carlos\ndb_password=app-pw\n' > "$HM/container/conf/carlos/carlos.properties"
touch "$HM/container/.deployed"
rm -f "$HM/container/conf/waf/certs/fullchain.pem"
refute "monitor alerts when a deployed instance's TLS cert file has vanished" \
    ctle "$HM" STUB_PS="$CORE_PS" -- monitor
make_cert "$HM/container/conf/waf/certs"
# Recurring supply-chain nag: a DEPLOYED instance on dev-mode-built images
# (moving source ref, no checksum) must page until rebuilt in release mode
# or explicitly accepted — build/play's one-shot warnings scroll away.
# (STUB_FRONT_DOOR=302: a deployed instance is also front-door probed now.)
printf 'dev\n' > "$HM/build/.build-mode"
refute "monitor nags a deployed instance running DEV-MODE built images" \
    ctle "$HM" STUB_PS="$CORE_PS" STUB_FRONT_DOOR=302 -- monitor
assert "CARLOS_ACCEPT_UNPINNED_BUILD=1 silences the unpinned-build nag" \
    ctle "$HM" STUB_PS="$CORE_PS" STUB_FRONT_DOOR=302 CARLOS_ACCEPT_UNPINNED_BUILD=1 -- monitor
printf 'release\n' > "$HM/build/.build-mode"
assert "a release-mode build marker keeps the monitor green" \
    ctle "$HM" STUB_PS="$CORE_PS" STUB_FRONT_DOOR=302 -- monitor
rm -f "$HM/build/.build-mode"

# End-to-end front-door probe on a DEPLOYED instance: the exact silent-outage
# pair the review found — a WAF on a cached app-pod IP serving 502 with every
# container green, and a flushed DNAT that only external clients notice.
assert "monitor is green when the front door serves (redirect counts)" \
    ctle "$HM" STUB_PS="$CORE_PS" STUB_FRONT_DOOR=302 -- monitor
m=$(mark)
refute "monitor pages when the front door serves 502 (stale cached backend IP)" \
    ctle "$HM" STUB_PS="$CORE_PS" STUB_FRONT_DOOR=502 -- monitor
refute "monitor pages when NOTHING serves the front door" \
    ctle "$HM" STUB_PS="$CORE_PS" -- monitor
# A lingering break-glass pma container is an unexpected-PRESENT fault
# (finding 29): a dropped session left a panel onto the PHI DB serving.
refute "monitor pages when a break-glass pma container is lingering" \
    ctle "$HM" STUB_PS="$CORE_PS"$'\ncarlos-pma-ondemand' STUB_FRONT_DOOR=302 -- monitor
rm -f "$HM/container/.deployed"
assert "a NOT-deployed instance is not front-door probed (no false page)" \
    ctle "$HM" STUB_PS="$CORE_PS" -- monitor

HM2="$WORK/h-monitor-obs"; mk_home "$HM2"
env_set "$HM2" HEARTBEAT_URL https://hb.example/ping
touch "$HM2/backup/.last-full-ok" "$HM2/backup/.last-binlog-ok" "$HM2/backup/.last-docs-ok" \
      "$HM2/backup/.last-verify-ok"
OBS_PS="$CORE_PS"$'\ncarlos-app-mysqld-exporter\ncarlos-app-vmagent\ncarlos-obs-victorialogs\ncarlos-obs-victoria-metrics\ncarlos-obs-logcollect\ncarlos-obs-logview\ncarlos-obs-node-exporter\ncarlos-obs-vmalert'
refute "obs-enabled monitor treats an unreachable vmalert as a FAULT" \
    ctle "$HM2" STUB_PS="$OBS_PS" -- monitor
assert "backup status reads green with fresh stamps (credential-free)" \
    ctle "$HM2" -- backup status
# Obs container crash-loop detection (finding 28): the obs pod has no
# livenessProbes, so RestartCount is the only signal. A rising count on an
# obs container that is UP at sweep time must page.
mkdir -p "$HM2/monitor/restarts"
printf '0\n' > "$HM2/monitor/restarts/carlos-obs-vmalert"
refute "monitor detects a crash-looping obs container (rising RestartCount)" \
    ctle "$HM2" STUB_PS="$OBS_PS" STUB_RESTARTS=3 -- monitor
assert "the legacy single-field baseline upgraded to id+count+streak" \
    grep -q '^deadbeef 3 0$' "$HM2/monitor/restarts/carlos-obs-vmalert"

# Pod-recreation crash-loop detection (pass-8 N2): a recreated container
# returns at RestartCount=0, so the rising-count compare alone is blind to
# pod-level churn — the container Id tells recreation apart from
# restart-in-place. One recreation is a normal play/rebuild (silent);
# recreations on CONSECUTIVE sweeps page.
printf 'deadbeef 3 0\n' > "$HM2/monitor/restarts/carlos-obs-vmalert"
refute "monitor pages a same-id rising RestartCount from 3-field state" \
    ctle "$HM2" STUB_PS="$OBS_PS" STUB_RESTARTS=7 -- monitor
assert "the same-id baseline advanced with streak reset" \
    grep -q '^deadbeef 7 0$' "$HM2/monitor/restarts/carlos-obs-vmalert"
printf 'oldid11 2 0\n' > "$HM2/monitor/restarts/carlos-obs-vmalert"
refute "monitor still faults (dev topology) on ONE container recreation" \
    ctle "$HM2" STUB_PS="$OBS_PS" STUB_CTR_ID=newid22 STUB_RESTARTS=0 -- monitor
refute "one recreation (a normal play/rebuild) did NOT page recreate" \
    test -f "$HM2/monitor/state/container-recreated-carlos-obs-vmalert"
assert "the recreate streak advanced to 1 in the baseline" \
    grep -q '^newid22 0 1$' "$HM2/monitor/restarts/carlos-obs-vmalert"
refute "monitor run with a SECOND consecutive id flip" \
    ctle "$HM2" STUB_PS="$OBS_PS" STUB_CTR_ID=newid33 STUB_RESTARTS=0 -- monitor
assert "consecutive recreations paged (recreate stamp exists)" \
    test -f "$HM2/monitor/state/container-recreated-carlos-obs-vmalert"
assert "the recreate streak kept counting (not reset by the alert)" \
    grep -q '^newid33 0 2$' "$HM2/monitor/restarts/carlos-obs-vmalert"

# ============================ alert-test ============================================
HA="$WORK/h-alert"; mk_home "$HA"
assert "alert-test succeeds journal-only when acknowledged" ctl "$HA" alert-test
env_set "$HA" ALERT_WEBHOOK https://hooks.example/secret-cap
m=$(mark)
refute "alert-test FAILS when the configured webhook does not deliver" ctl "$HA" alert-test
assert "the capability URL travelled via curl -K - (never argv)" \
    log_since "$m" 'curl-config url = "https://hooks.example/secret-cap"'
refute "the capability URL never appeared as a curl argv token" \
    log_since "$m" '^curl .*hooks\.example/secret-cap'
assert "alert-test succeeds when the webhook delivers" \
    ctle "$HA" STUB_WEBHOOK_OK=1 -- alert-test

# OnFailure dedup (finding 26): the 15-min binlog/docs timers page through
# `carlos-ctl alert <unit>` on every failing run — a repo down overnight
# would fire ~32 identical pages. The first delivers; a second within the
# reminder window is journal-only (throttled).
HAD="$WORK/h-alert-dedup"; mk_home "$HAD"
env_set "$HAD" ALERT_WEBHOOK https://hooks.example/dedup-cap
m=$(mark)
assert "the first OnFailure page delivers" \
    ctle "$HAD" STUB_WEBHOOK_OK=1 -- alert carlos-binlog.service "repo down"
assert "the first page hit the webhook" \
    log_since "$m" 'curl-config url = "https://hooks.example/dedup-cap"'
# H2 regression: a monitor run BETWEEN the first page and the repeat must NOT
# wipe the alert throttle stamp (its recovery sweep once deleted onfailure-*
# stamps, un-throttling a still-failing unit on every 15-min pass).
env_set "$HAD" OBS_ENABLED 0
touch "$HAD/backup/.last-full-ok" "$HAD/backup/.last-binlog-ok" \
      "$HAD/backup/.last-docs-ok" "$HAD/backup/.last-verify-ok"
ctle "$HAD" STUB_PS=$'carlos-app-db\ncarlos-app-carlos\ncarlos-app-drugref\ncarlos-waf-waf' \
    -- monitor >/dev/null 2>&1 || true
m=$(mark)
assert "a repeat within the window is throttled (still exits 0), even after a monitor sweep" \
    ctle "$HAD" STUB_WEBHOOK_OK=1 -- alert carlos-binlog.service "repo down"
refute "the throttled repeat did NOT re-hit the webhook" \
    log_since "$m" 'curl-config url = "https://hooks.example/dedup-cap"'
m=$(mark)
assert "a DIFFERENT unit is not throttled by the first's state" \
    ctle "$HAD" STUB_WEBHOOK_OK=1 -- alert carlos-docs.service "docs down"
assert "the different unit delivered" \
    log_since "$m" 'curl-config url = "https://hooks.example/dedup-cap"'

# Alert-channel sidecar (root-only mirror OUTSIDE $EMR_HOME): with the env
# file carrying NO webhook, the mirror supplies it — the boot guard's page
# must survive an unmounted/blank EMR_HOME. Non-empty env-file values win.
HSC="$WORK/h-alert-sidecar"; mk_home "$HSC"
printf 'ALERT_WEBHOOK=https://hooks.example/sidecar-cap\n' \
    > "$CARLOS_INSTANCE_REGISTRY_DIR/carlos.alert.env"
m=$(mark)
assert "alert-test delivers via the sidecar webhook when the env file has none" \
    ctle "$HSC" STUB_WEBHOOK_OK=1 -- alert-test
assert "the sidecar capability URL travelled via curl -K - (never argv)" \
    log_since "$m" 'curl-config url = "https://hooks.example/sidecar-cap"'
env_set "$HSC" ALERT_WEBHOOK https://hooks.example/envfile-cap
m=$(mark)
assert "a non-empty env-file webhook WINS over the sidecar" \
    ctle "$HSC" STUB_WEBHOOK_OK=1 -- alert-test
assert "the env-file capability URL was the one used" \
    log_since "$m" 'curl-config url = "https://hooks.example/envfile-cap"'
refute "the sidecar value was not used when the env file has one" \
    log_since "$m" 'curl-config url = "https://hooks.example/sidecar-cap"'
# The unmounted-EMR_HOME simulation: no env file at all, sidecar still pages
# (this is the guard's OnFailure path when the data volume failed to mount).
m=$(mark)
assert "alert delivers via the sidecar with EMR_HOME entirely absent" \
    bash -c "cd '$ROOT' && EMR_HOME='$WORK/nonexistent-home' STUB_WEBHOOK_OK=1 \
        python3 -m carlos_ctl.cli alert test-unit 'volume gone'"
assert "the sidecar carried the guard page off-box despite the missing home" \
    log_since "$m" 'curl-config url = "https://hooks.example/sidecar-cap"'
rm -f "$CARLOS_INSTANCE_REGISTRY_DIR/carlos.alert.env"

# ============================ instances / uninstall =================================
# The single registry slot for 'carlos' now points at the most recent
# mk_home (h-alert) — assert that resolution, not a stale earlier home.
assert "instances lists the registered instance with its resolved home" \
    bash -c "cd '$ROOT' && python3 -m carlos_ctl.cli instances | grep -q h-alert"
STALE="$CARLOS_INSTANCE_REGISTRY_DIR/stale.conf"
printf 'INSTANCE=stale\nEMR_HOME=%s/gone\n' "$WORK" > "$STALE"
refute "instances --prune refuses non-interactively without --yes" \
    bash -c "cd '$ROOT' && python3 -m carlos_ctl.cli instances --prune </dev/null >/dev/null 2>&1"
test -e "$STALE" || { echo "FAIL: prune deleted stale entry without --yes"; exit 1; }
assert "instances --prune --yes drops entries whose EMR_HOME is gone" \
    bash -c "cd '$ROOT' && python3 -m carlos_ctl.cli instances --prune --yes >/dev/null && test ! -e '$STALE'"
refute "--instance fails closed on an unregistered name" \
    bash -c "cd '$ROOT' && python3 -m carlos_ctl.cli --instance ghost status"
# M1: --instance is authoritative — a stale EMR_HOME line in the selected
# instance's own env file must NOT redirect the target; the registry wins and
# the mismatch is warned.
HPIN="$WORK/h-pin"; mk_home "$HPIN" pintest
sed -i "s|^EMR_HOME=.*|EMR_HOME=/srv/wrong-home|" "$HPIN/container/carlos-app.env"
PIN_OUT="$(cd "$ROOT" && python3 -m carlos_ctl.cli --instance pintest status 2>&1 || true)"
assert "--instance warns when the env file re-points EMR_HOME" \
    bash -c "printf '%s' \"\$1\" | grep -q 'WINS'" _ "$PIN_OUT"
assert "--instance keeps the registry-resolved home, not the stale env-file one" \
    bash -c "printf '%s' \"\$1\" | grep -q '$HPIN' && ! printf '%s' \"\$1\" | grep -q 'target:.*wrong-home'" _ "$PIN_OUT"

HU="$WORK/h-uninstall"; mk_home "$HU" carlos
touch "$CARLOS_SYSTEMD_DIR/carlos-backup.timer" "$CARLOS_SYSTEMD_DIR/carlos-monitor.service"
printf 'ALERT_WEBHOOK=https://hooks.example/uninstall-cap\n' \
    > "$CARLOS_INSTANCE_REGISTRY_DIR/carlos.alert.env"
# tmpfiles.d removal uses the SAME overridable dir the role installs into —
# seed it here (a hermetic dir) and assert uninstall clears it through that
# one path, not a hardcoded /etc/tmpfiles.d literal.
TMPFILES_D="$WORK/tmpfiles.d"; mkdir -p "$TMPFILES_D"
touch "$TMPFILES_D/carlos-emr.conf"
refute "uninstall refuses non-interactively without both confirmations" \
    bash -c "cd '$ROOT' && CARLOS_UNINSTALL_CONFIRMED=1 EMR_HOME='$HU' PYTHONPATH='$ROOT' \
        python3 -m carlos_ctl.cli uninstall < /dev/null"
m_uninstall=$(mark)
assert "uninstall decommissions with the double confirmation" \
    ctle "$HU" CARLOS_UNINSTALL_CONFIRMED=1 CARLOS_UNINSTALL_INSTANCE=carlos \
        CARLOS_TMPFILES_DIR="$TMPFILES_D" -- uninstall
assert "uninstall removed the instance units" test ! -e "$CARLOS_SYSTEMD_DIR/carlos-backup.timer"
assert "uninstall removed the tmpfiles.d persistence via the override dir" \
    test ! -e "$TMPFILES_D/carlos-emr.conf"
assert "uninstall removed the registry claim" test ! -e "$CARLOS_INSTANCE_REGISTRY_DIR/carlos.conf"
assert "uninstall removed the alert-channel mirror" \
    test ! -e "$CARLOS_INSTANCE_REGISTRY_DIR/carlos.alert.env"
assert "uninstall PRESERVED the data tree (PHI is never auto-deleted)" \
    test -d "$HU/data/OscarDocument"
# Pass-19: BOTH instance-owned podman secrets. The role creates
# <instance>-obs-http (the obs-store basic-auth credential fronting 180 days
# of PHI-adjacent logs) alongside <instance>-db, but decommission only removed
# the db one — measured live: `podman secret ls` still listed carlos-obs-http
# after a clean uninstall, a credential left in the shared service user's
# store and mentioned in neither half of the confirmation banner.
assert "uninstall removed the db podman secret" \
    log_since "$m_uninstall" "secret rm carlos-db"
assert "uninstall removed the obs-http podman secret" \
    log_since "$m_uninstall" "secret rm carlos-obs-http"

# No-systemd host: the decommission must still COMPLETE. The quadlet block's
# `systemctl_user` daemon-reload was not have()-gated and its enclosing
# suppress(CtlError) does not catch FileNotFoundError, so on such a host the
# verb raised out of cli.py as a bare "unexpected FileNotFoundError:
# 'systemctl'" and ABORTED mid-decommission — measured live, leaving the
# front-door DNAT table, the host-global default-deny -hostfw table, both
# podman networks, the <instance>-db (MariaDB root) and <instance>-obs-http
# secrets, the decrypted /run fragments, the tmpfiles.d entry and the registry
# claim all in place.
HU2="$WORK/h-uninstall-nosd"; mk_home "$HU2" carlos
TMPFILES_D2="$WORK/tmpfiles.d-nosd"; mkdir -p "$TMPFILES_D2"
touch "$TMPFILES_D2/carlos-emr.conf"
printf 'x\n' > "$CARLOS_INSTANCE_REGISTRY_DIR/carlos.conf"
m_uninstall_nosd=$(mark)
NSD_UN="$WORK/uninstall-nosd.out"
env PATH="$NOSD_PATH" CARLOS_UNINSTALL_CONFIRMED=1 \
    CARLOS_UNINSTALL_INSTANCE=carlos CARLOS_TMPFILES_DIR="$TMPFILES_D2" \
    EMR_HOME="$HU2" PYTHONPATH="$ROOT" python3 -m carlos_ctl.cli uninstall \
    >"$NSD_UN" 2>&1
assert "no-systemd uninstall does not crash out of the decommission" \
    bash -c "! grep -q 'unexpected FileNotFoundError' '$NSD_UN'"
assert "no-systemd uninstall still reaches the registry claim" \
    test ! -e "$CARLOS_INSTANCE_REGISTRY_DIR/carlos.conf"
assert "no-systemd uninstall still reaches the tmpfiles.d persistence" \
    test ! -e "$TMPFILES_D2/carlos-emr.conf"
assert "no-systemd uninstall still removes the db podman secret" \
    log_since "$m_uninstall_nosd" "secret rm carlos-db"
assert "no-systemd uninstall still removes the obs-http podman secret" \
    log_since "$m_uninstall_nosd" "secret rm carlos-obs-http"
assert "no-systemd uninstall still PRESERVES the data tree" \
    test -d "$HU2/data/OscarDocument"

# ============================ dev-setup.sh render (M7) ==============================
# The QUICKSTART helper renders carlos.properties + the dev pod spec in-process
# (python3, secrets by ENV not argv) — charset-agnostic now, so a password with
# @ \ & " must render cleanly (the old sed path choked on @ and \).
DEVH="$WORK/h-devsetup"
CARLOS_DEV_DB_PASSWORD='p@ss\&w"rd' bash -c \
    "cd '$ROOT' && EMR_HOME='$DEVH' scripts/dev-setup.sh --emr-home '$DEVH'" >/dev/null 2>&1
assert "dev-setup renders with a @ \\ & \" password (charset-agnostic)" \
    test -f "$DEVH/container/conf/carlos/carlos.properties"
assert "the db password is properties-escaped (backslash doubled) in the render" \
    grep -qF 'db_password=p@ss\\&w"rd' "$DEVH/container/conf/carlos/carlos.properties"
assert "the required encryption key rendered non-blank" \
    grep -Eq '^encryption\.util\.secret\.key=.+' "$DEVH/container/conf/carlos/carlos.properties"
refute "no unrendered Jinja remains in the rendered properties" \
    grep -qE '\{\{|\{%' "$DEVH/container/conf/carlos/carlos.properties"
refute "no unrendered placeholder remains in the dev pod spec" \
    grep -qE '__EMR_HOME__|__DB_ROOT_HASH_B64__' "$DEVH/carlos-app-dev.yaml"
assert "both rendered files are mode 600 (carry the db password + key)" \
    bash -c "test \"\$(stat -c %a '$DEVH/container/conf/carlos/carlos.properties')\" = 600 \
             && test \"\$(stat -c %a '$DEVH/carlos-app-dev.yaml')\" = 600"

# ===================== host-path containment (pass-17 H8) ==========================
# EVERY host path Settings resolves must be redirected by THIS script before a
# root run (CI runs the suites under sudo) can act on it — `cmd_uninstall`
# rmtree's/unlinks several of them for whatever INSTANCE the Settings under
# test carries, which is `carlos`: the default name a real deployment also
# uses. tests/unit/conftest.py got this treatment in pass 15 and pins it with
# test_every_host_path_setting_is_redirected; this suite had been left one
# knob short (CARLOS_RUN_SECRETS_DIR) and DELETED a live instance's
# /run/carlos-emr while reporting all-green. Derive the knob list from
# config.py so a NEW host path cannot silently re-open the hole.
assert "every CARLOS_*_DIR knob config.py reads is redirected by this suite" \
    python3 - "$ROOT" <<'PYEOF'
import pathlib, re, sys

src = (pathlib.Path(sys.argv[1]) / "carlos_ctl" / "config.py").read_text()
# Settings resolves host paths as env.get("CARLOS_..._DIR", <default>).
knobs = set(re.findall(r'env\.get\(\s*"(CARLOS_[A-Z0-9_]*DIR)"', src))
import os
missing = sorted(k for k in knobs if not os.environ.get(k))
if missing:
    print("UNREDIRECTED host-path knob(s): " + ", ".join(missing), file=sys.stderr)
    sys.exit(1)
sys.exit(0)
PYEOF

# And the live proof: the REAL host paths an instance named `carlos` owns must
# be in exactly the state they were in when this suite started — created,
# deleted or left alone, all three must match. (Recorded into HOST_CANARY_*
# before the first CLI invocation, at the top of this script.)
for real in /run/carlos-emr /etc/tmpfiles.d/carlos-emr.conf \
            /etc/carlos-podman/instances/carlos.conf; do
    before="$WORK/host-canary/$(printf '%s' "$real" | tr / _)"
    assert "the suite left $real exactly as it found it" \
        bash -c "if [ -e '$before' ]; then test -e '$real'; else test ! -e '$real'; fi"
done

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" == 0 ]]
