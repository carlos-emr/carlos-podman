<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 CARLOS Contributors -->

# carlos-ctl real-usage validation harness

An intensive, **non-hermetic** validation suite for carlos-ctl's
release-first source selection (`carlos-ctl source` / `build`): it drives
the real CLI against real podman and real curl + TLS, asserting exit code
AND output on every check so nothing can fail silently. It complements —
does not replace — the hermetic suites (`tests/unit`, `tests/run-tests.sh`),
which remain the CI gate.

## How it works

- `run-validation.sh` — one-shot orchestrator. Sets up a scratch EMR home,
  generates a throwaway CA, redirects `api.github.com` to `127.0.0.1` via
  `/etc/hosts`, starts the mock API server, runs the harness, and tears all
  of that down again (the scratch home is kept for inspection).
- `mock-github-api.py` — local HTTPS stand-in for the two GitHub API
  endpoint families the resolver uses (`/releases`, `/commits/<ref>`),
  serving a **frozen snapshot of real captured release data** for
  `carlos-emr/carlos` and `carlos-emr/drugref2026`. Asset download URLs are
  the real `github.com` URLs, so WAR downloads still travel the real
  network. A mode file toggles failure scenarios live (`norelease`,
  `ratelimit-half`).
- `ctl-validation.sh` — the checks (~44), covering: every `source` subverb
  against the mock, sticky-pin persistence and offline builds, pin-file
  corruption/implausibility warnings, the mutating-verb lock, full real
  `carlos-ctl build` of both apps from pinned WARs, tampered-sha256 refusal
  without image promotion, atomic pair resolution under mid-pair API
  failure, and the no-release → branch-HEAD fallback.

The mock's snapshot and the harness's expected tags/commits/sha256 values
are pinned to each other (constants in both files) — refresh both in the
same commit if you ever re-capture live data.

## Running it

```bash
sudo scripts/validation/run-validation.sh --yes
```

Requirements: root, podman (rootful), python3, openssl, curl, network
access to `github.com` for the real WAR assets (several hundred MB on the
first run; later runs hit the build cache). `VAL_HOME=/path` overrides the
scratch directory. Behind a TLS-inspecting egress proxy, point
`CARLOS_EXTRA_CA_BUNDLE` at the proxy CA so in-build downloads verify.

## Warnings — read before running

- **Never run on a production EMR host.** The harness removes and rebuilds
  the `localhost/carlos-app` and `localhost/carlos-drugref` image tags
  (`:latest`, `:previous`, `:build-val-*`), and refuses to start while
  `carlos-app*` containers are running (override: `VAL_ALLOW_RUNNING=1`).
- The orchestrator temporarily **modifies `/etc/hosts` and the system
  trust store** (throwaway CA, removed on exit — including on failure, via
  an EXIT trap). Run it on a disposable machine or dev VM.
- `ctl-validation.sh` is not meant to be run directly; it checks for the
  orchestrator's setup and refuses without it.
