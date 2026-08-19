#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
#
# scripts/validation/ctl-validation.sh — intensive real-usage validation of
# carlos-ctl's release-first source selection: live podman builds, real curl
# + TLS against a local mock of api.github.com (frozen snapshot of real
# release data; WAR assets still download from the REAL github.com), and an
# explicit no-silent-failure contract: every check asserts exit code AND
# output, and every expected failure must fail LOUDLY.
#
# Do not run this directly — scripts/validation/run-validation.sh performs
# the required setup (mock server, /etc/hosts, throwaway CA, EMR home) and
# tears it down again. This script only checks its prerequisites.
#
# Required environment (exported by run-validation.sh):
#   VAL_HOME        scratch directory for this run
#   MOCK_MODE_FILE  mode file consumed by mock-github-api.py
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
: "${VAL_HOME:?run via run-validation.sh (VAL_HOME not set)}"
: "${MOCK_MODE_FILE:?run via run-validation.sh (MOCK_MODE_FILE not set)}"
H="$VAL_HOME/emr"
export PYTHONPATH="$ROOT"
# In proxied environments the mock must be reached directly, not via the
# egress proxy. Harmless when no proxy is configured.
export NO_PROXY=api.github.com no_proxy=api.github.com

# Frozen live-repo facts served by mock-github-api.py. If you refresh the
# snapshot there, refresh these in the same commit.
CARLOS_SHA=6d4117daf97c9a7eb5f4c67921aa907bcf2dc5dc
DRUGREF_SHA=101063bbd13d3c767cc3c3daf5f64ac673d8d327
CARLOS_WAR_SHA=7f42d44061e1629b022e3ef9d69d8f4a96db23ec15dd252dc94baa15abfe19cc
DRUGREF_WAR_SHA=5b367e65f5c0c0262ea36a4662d9040818754bea307ffb70a0c81931a0aaf6fc

# Phase 2 removes and rebuilds localhost/carlos-app + carlos-drugref image
# tags. Refuse to trample a machine that is actually running the EMR.
if [ -z "${VAL_ALLOW_RUNNING:-}" ] && podman ps --format '{{.Names}}' | grep -q '^carlos-app'; then
    echo "FATAL: carlos-app containers are running on this host; this harness" >&2
    echo "rebuilds the localhost image tags. Stop them or set VAL_ALLOW_RUNNING=1." >&2
    exit 2
fi
if ! curl -fsS --max-time 5 "https://api.github.com/repos/carlos-emr/carlos/releases?per_page=1" >/dev/null 2>&1; then
    echo "FATAL: mock api.github.com is not answering — run via run-validation.sh" >&2
    exit 2
fi

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf 'ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$1"; }
ctl() { EMR_HOME="$H" python3 -m carlos_ctl.cli "$@"; }
# assert_run <desc> <expected-rc> <grep-pattern-in-combined-output> -- cmd...
assert_run() {
  local d="$1" want_rc="$2" pat="$3"; shift 3; shift  # drop --
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  if [ "$rc" -ne "$want_rc" ]; then bad "$d (rc=$rc want=$want_rc)"; echo "$out" | tail -5 | sed 's/^/       /'; return; fi
  if [ -n "$pat" ] && ! grep -qE "$pat" <<<"$out"; then bad "$d (missing /$pat/)"; echo "$out" | tail -5 | sed 's/^/       /'; return; fi
  if grep -q "Traceback (most recent call last)" <<<"$out"; then bad "$d (TRACEBACK leaked)"; return; fi
  ok "$d"
}
pin() { python3 -c "import json,sys; d=json.load(open('$H/build/.source-pin$1')); print(d[sys.argv[1]])" "$2"; }

# Env files for the misconfiguration checks, derived from the main env.
sed 's/^CARLOS_ARTIFACT=.*/CARLOS_ARTIFACT=war/'   "$H/container/carlos-app.env" > "$VAL_HOME/env-war-typo"
sed 's/^CARLOS_ARTIFACT=.*/CARLOS_ARTIFACT=bogus/' "$H/container/carlos-app.env" > "$VAL_HOME/env-enum-typo"

echo "=== Phase 1: source verb against real-data mock ==="
echo full > "$MOCK_MODE_FILE"
assert_run "help prints usage rc 0" 0 "APP LIFECYCLE" -- ctl help
assert_run "version prints rc 0" 0 "carlos-ctl " -- ctl version
assert_run "unknown verb refuses loudly" 1 "unknown command" -- ctl frobnicate
assert_run "bare source: no pins yet, says what next build does" 0 "no source pin recorded" -- ctl source
assert_run "source update resolves BOTH apps from releases" 0 "deploy with 'carlos-ctl rebuild'" -- ctl source update
[ "$(pin '' tag)" = "2026.08.0-alpha2" ] && ok "carlos pin: prerelease tag (mock snapshot of live repo)" || bad "carlos pin tag: $(pin '' tag)"
[ "$(pin '' commit)" = "$CARLOS_SHA" ] && ok "carlos pin: real release commit" || bad "carlos pin commit"
[ "$(pin '' war_sha256)" = "$CARLOS_WAR_SHA" ] && ok "carlos pin: real published WAR sha256" || bad "carlos pin war sha"
[ "$(pin '' artifact)" = "war" ] && ok "carlos pin: WAR artifact auto-selected" || bad "carlos artifact"
[ "$(pin .drugref tag)" = "v1.0.0rc2" ] && ok "drugref pin: stable release tag" || bad "drugref pin tag: $(pin .drugref tag)"
[ "$(pin .drugref war_sha256)" = "$DRUGREF_WAR_SHA" ] && ok "drugref pin: real WAR sha256 (fixed-name asset)" || bad "drugref war sha"
assert_run "source show prints both pins + offline note" 0 "no network" -- ctl source show
# True API unavailability: the mock 503s EVERY request in deny mode. Keep the
# exported NO_PROXY=api.github.com bypass so the request reaches the mock's
# 503 even in proxied environments (unsetting it would send the request to
# the proxy instead and test the wrong failure).
echo deny > "$MOCK_MODE_FILE"
assert_run "source show offline (API denied) still works" 0 "2026.08.0-alpha2" -- \
  env EMR_HOME="$H" python3 -m carlos_ctl.cli source
echo full > "$MOCK_MODE_FILE"
assert_run "set <tag> --artifact source keeps WAR data" 0 "source compile" -- ctl source set 2026.08.0-alpha2 --artifact source
[ "$(pin '' artifact)" = "source" ] && [ "$(pin '' war_sha256)" = "$CARLOS_WAR_SHA" ] \
  && ok "forced-source pin retained WAR url+sha (flip-back is offline)" || bad "war data lost on forced-source pin"
assert_run "set <tag> flips back to WAR without extra state" 0 "published WAR" -- ctl source set 2026.08.0-alpha2
assert_run "set --drugref master pins branch HEAD sha" 0 "branch master HEAD" -- ctl source set --drugref master
[ "$(pin .drugref ref)" = "$DRUGREF_SHA" ] && ok "drugref branch pin carries the commit sha" || bad "drugref branch pin sha"
assert_run "source update moves drugref back to its release" 0 "v1.0.0rc2" -- ctl source update
assert_run "set unknown tag with --artifact war refuses" 1 "not a release tag" -- ctl source set no-such-tag-xyz --artifact war
assert_run "set <sha> under ARTIFACT=war refuses at SET time" 1 "bare commit has no WAR" -- \
  env ENV_FILE="$VAL_HOME/env-war-typo" EMR_HOME="$H" python3 -m carlos_ctl.cli source set $CARLOS_SHA
assert_run "unrecognized artifact enum fails LOUDLY" 1 "not a recognized artifact" -- \
  env ENV_FILE="$VAL_HOME/env-enum-typo" EMR_HOME="$H" python3 -m carlos_ctl.cli source update
assert_run "source usage error on bad subverb" 1 "usage: carlos-ctl source" -- ctl source frobnicate

echo "=== Phase 1b: pin robustness ==="
cp "$H/build/.source-pin" "$VAL_HOME/good-pin.bak"
echo '{broken json' > "$H/build/.source-pin"
assert_run "corrupt pin: warned, show still works" 0 "unreadable as a source pin" -- ctl source show
rm "$H/build/.source-pin" && mkdir "$H/build/.source-pin"
assert_run "unreadable (dir) pin: warned, not silent" 0 "could not be read" -- ctl source show
rmdir "$H/build/.source-pin" && cp "$VAL_HOME/good-pin.bak" "$H/build/.source-pin"
python3 - <<PYEOF
import json
p='$H/build/.source-pin'; d=json.load(open(p)); d['ref']='develop'; json.dump(d, open(p,'w'))
PYEOF
assert_run "implausible pin (branch-name ref): warned + degraded" 0 "implausible" -- ctl source show
cp "$VAL_HOME/good-pin.bak" "$H/build/.source-pin"

echo "=== Phase 1c: mutating-verb lock ==="
# The holder signals via a marker file once it actually owns the lock, so the
# refusal check never races a slow interpreter start; killing the holder
# afterwards avoids waiting out its full sleep.
rm -f "$VAL_HOME/lock-held"
python3 - <<PYEOF &
import fcntl, pathlib, time
f=open('$H/.carlos-ctl.lock','a'); fcntl.flock(f, fcntl.LOCK_EX)
pathlib.Path('$VAL_HOME/lock-held').write_text('1')
time.sleep(30)
PYEOF
LOCKPID=$!
for _ in {1..100}; do [ -e "$VAL_HOME/lock-held" ] && break; sleep 0.1; done
[ -e "$VAL_HOME/lock-held" ] && ok "lock holder acquired the lock" || bad "lock holder never acquired the lock"
assert_run "source update refuses while another mutating verb holds the lock" 1 "already running" -- ctl source update
kill "$LOCKPID" 2>/dev/null; wait "$LOCKPID" 2>/dev/null
assert_run "lock released: update succeeds again" 0 "" -- ctl source update

echo "=== Phase 2: REAL builds through carlos-ctl (live podman) ==="
podman rmi -f localhost/carlos-app:latest localhost/carlos-drugref:latest \
  localhost/carlos-app:previous localhost/carlos-drugref:previous >/dev/null 2>&1
assert_run "full 'carlos-ctl build' from the WAR pins (both apps, real assets)" 0 \
  "Built :build-.* and :latest" -- env BUILD_STAMP=val-1 EMR_HOME="$H" python3 -m carlos_ctl.cli build
podman image exists localhost/carlos-app:latest && ok "carlos :latest promoted" || bad "carlos :latest missing"
podman image exists localhost/carlos-drugref:latest && ok "drugref :latest promoted" || bad "drugref :latest missing"
podman image exists localhost/carlos-app:build-val-1 && ok "immutable :build-val-1 tag exists" || bad ":build tag missing"
grep -qx dev "$H/build/.build-mode" && ok ".build-mode records dev" || bad ".build-mode wrong"
OUT=$(env BUILD_STAMP=val-1 EMR_HOME="$H" python3 -m carlos_ctl.cli source 2>&1)
grep -q "published WAR" <<<"$OUT" && ok "post-build source show agrees with what was built" || bad "post-build show"

# deny mode: a pinned rebuild that touched the API would hit the mock's 503
# (NO_PROXY bypass stays in place) and fail loudly here.
echo deny > "$MOCK_MODE_FILE"
assert_run "second build (API denied, --use-cache): sticky pins, no API" 0 "Built :build-.*" -- \
  env BUILD_STAMP=val-2 EMR_HOME="$H" python3 -m carlos_ctl.cli build --use-cache
echo full > "$MOCK_MODE_FILE"
podman image exists localhost/carlos-app:previous && ok ":previous rollback target rotated in" || bad ":previous missing"
assert_run "build usage error on unknown flag" 1 "usage: carlos-ctl build" -- ctl build --frobnicate

echo "=== Phase 2b: sha256 mismatch must fail LOUDLY and not promote ==="
GOOD_LATEST=$(podman image inspect --format '{{.Id}}' localhost/carlos-app:latest)
python3 - <<PYEOF
import json
p='$H/build/.source-pin'; d=json.load(open(p)); d['war_sha256']='e'*64; json.dump(d, open(p,'w'))
PYEOF
assert_run "tampered WAR sha256: build FAILS (in-image sha256sum -c)" 1 "build failed for" -- \
  env BUILD_STAMP=val-3 EMR_HOME="$H" python3 -m carlos_ctl.cli build --use-cache
NOW_LATEST=$(podman image inspect --format '{{.Id}}' localhost/carlos-app:latest)
[ "$GOOD_LATEST" = "$NOW_LATEST" ] && ok ":latest untouched after failed build (no partial promote)" || bad ":latest moved on failure!"
cp "$VAL_HOME/good-pin.bak" "$H/build/.source-pin"

echo "=== Phase 2c: mid-pair API failure leaves no half-pinned state ==="
rm -f "$H/build/.source-pin" "$H/build/.source-pin.drugref"
echo ratelimit-half > "$MOCK_MODE_FILE"
assert_run "carlos /commits 403 mid-resolve: build refuses with guidance" 1 "source set" -- \
  env EMR_HOME="$H" python3 -m carlos_ctl.cli build
[ ! -e "$H/build/.source-pin" ] && [ ! -e "$H/build/.source-pin.drugref" ] \
  && ok "no pin written on first-app failure" || bad "pin left behind on first-app failure"
# The sharper drill: CARLOS resolves FIRST and fully succeeds, then DrugRef's
# /commits 403s. A broken implementation that persisted CARLOS immediately
# after resolving it would leave a half-pinned pair here.
echo dr-ratelimit-half > "$MOCK_MODE_FILE"
assert_run "drugref 403 AFTER carlos resolved: build refuses" 1 "" -- \
  env EMR_HOME="$H" python3 -m carlos_ctl.cli build
[ ! -e "$H/build/.source-pin" ] && [ ! -e "$H/build/.source-pin.drugref" ] \
  && ok "carlos pin NOT persisted when the second app fails (atomic pair resolve)" \
  || bad "half-pinned state left behind after second-app failure"
echo full > "$MOCK_MODE_FILE"
assert_run "recovery: next build resolves and pins cleanly" 0 "pinned CARLOS source" -- \
  env BUILD_STAMP=val-4 EMR_HOME="$H" python3 -m carlos_ctl.cli build --use-cache

echo "=== Phase 2d: no-release fallback resolves main HEAD ==="
rm -f "$H/build/.source-pin"
echo norelease > "$MOCK_MODE_FILE"
assert_run "no releases: falls back to branch main HEAD (source compile) and says so" 0 \
  "falling back to branch main HEAD" -- ctl source update
[ "$(pin '' kind)" = "branch" ] && [ "$(pin '' ref)" = "$CARLOS_SHA" ] \
  && ok "branch fallback pinned main's commit sha" || bad "branch fallback pin wrong"
echo full > "$MOCK_MODE_FILE"
ctl source update >/dev/null 2>&1  # restore release pins for any later use

# Untag the per-run :build-val-* image tags so repeat runs don't accumulate
# them (the underlying layers stay shared with :latest / the build cache).
podman images --format '{{.Repository}}:{{.Tag}}' | \
  grep -E '^localhost/carlos-(app|drugref):build-val-' | \
  xargs -r podman rmi >/dev/null 2>&1
echo "== per-run :build-val-* tags removed"

echo
echo "=== RESULT: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
