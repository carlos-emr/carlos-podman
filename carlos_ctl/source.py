# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""CARLOS source selection: which version builds, and from which artifact.

THE CONTRACT (README "Choosing the CARLOS version"):

- CARLOS_REF=auto (the default) resolves per policy — the newest
  NON-prerelease GitHub release of carlos-emr/carlos by publish time, else
  the newest prerelease, else the HEAD of CARLOS_SOURCE_BRANCH (the app
  repo's default branch, `develop` — the repo has no `main`) — and then
  PINS the answer in $EMR_HOME/build/.source-pin. Every later build reads
  the pin with ZERO network calls: the deployed version never drifts because
  upstream published something, only because an operator ran
  `carlos-ctl source update` (or `set`/`clear`).
- Any other CARLOS_REF value is a MANUAL pin with exactly the historical
  semantics: no API call, no pin file, source compile of that ref (unless
  CARLOS_ARTIFACT=war plus explicit CARLOS_WAR_URL/CARLOS_WAR_SHA256).
- CARLOS_ARTIFACT=auto prefers a release's published WAR asset
  (carlos-<tag>.war, sha256-verified in-image) and falls back to compiling
  that release's source; `war`/`source` force one side. The choice made
  under `auto` is persisted in the pin like the version is.

Pins record the release tag AND its commit SHA: tags are mutable refs, so
nothing downstream trusts one — source builds fetch archive/<sha>.tar.gz
(immutable) and WAR builds verify the pinned sha256. The pin file sits next
to .build-mode (the established CLI marker-file pattern); carlos-app.env
stays Ansible-rendered/operator-owned and is never written by the CLI.

All GitHub API traffic goes through Runner+curl (like every external probe
in this tree) so both test suites stub it at the one boundary; unauth API
quota is 60 req/h, which only `update`/`set`/the first resolve ever touch
(≤3 calls each — pinned builds are offline).
"""

from __future__ import annotations

import dataclasses
import json
import re
import time
from pathlib import Path
from typing import List, Optional, Tuple

from .runner import Runner
from .util import CtlError, log, warn

# Must match the Containerfile's ADD URL host/repo — the pin's refs and WAR
# URLs are only meaningful against this repo.
GH_REPO = "carlos-emr/carlos"
_API = f"https://api.github.com/repos/{GH_REPO}"

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")

_USAGE = (
    "usage: carlos-ctl source [show]\n"
    "       carlos-ctl source update\n"
    "       carlos-ctl source set <release-tag|branch|40-hex-sha> [--artifact war|source]\n"
    "       carlos-ctl source clear"
)


@dataclasses.dataclass
class SourcePin:
    """One resolved CARLOS source selection. `ref` is what CARLOS_REF becomes
    for a source build (always a 40-hex commit SHA for policy-resolved pins);
    `tag`/`branch` carry display/asset identity; `artifact` says whether the
    build downloads the published WAR or compiles the source tarball."""

    ref: str
    kind: str            # "release" | "prerelease" | "branch" | "manual"
    tag: str = ""        # release tag ("" for branch/manual pins)
    branch: str = ""     # branch name ("" unless kind == "branch")
    commit: str = ""     # 40-hex sha when known
    artifact: str = "source"   # "war" | "source"
    war_url: str = ""
    war_sha256: str = ""
    resolved_at: str = ""      # UTC ISO8601
    policy: str = "auto"       # "auto" | "manual" (how this pin was chosen)

    def describe(self) -> str:
        """One human line naming the pin — used by build logs and `source`."""
        what = {
            "release": f"release {self.tag}",
            "prerelease": f"prerelease {self.tag}",
            "branch": f"branch {self.branch} HEAD",
            "manual": f"ref {self.ref}",
        }.get(self.kind, f"ref {self.ref}")
        how = "published WAR" if self.artifact == "war" else "source compile"
        commit = f" @ {self.commit[:12]}" if self.commit else ""
        return f"{what}{commit} ({how})"


def pin_path(runner: Runner) -> Path:
    # Beside .build-mode/.schema-fingerprint: $EMR_HOME/build is the CLI's
    # instance-state home. Nothing in the pin is secret (public tags, SHAs,
    # release-asset URLs), so default 0644 root-owned is fine.
    return runner.settings.emr_home / "build" / ".source-pin"


def read_pin(runner: Runner) -> Optional[SourcePin]:
    """The persisted pin, or None. Corrupt/unreadable degrades to None with a
    warning — an auto build then re-resolves (or fails with guidance when
    offline); a half-written file must never crash every build verb."""
    path = pin_path(runner)
    try:
        raw = path.read_text()
    except OSError:
        return None
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("not a JSON object")
        pin = SourcePin(
            ref=str(data["ref"]),
            kind=str(data["kind"]),
            tag=str(data.get("tag", "")),
            branch=str(data.get("branch", "")),
            commit=str(data.get("commit", "")),
            artifact=str(data.get("artifact", "source")),
            war_url=str(data.get("war_url", "")),
            war_sha256=str(data.get("war_sha256", "")),
            resolved_at=str(data.get("resolved_at", "")),
            policy=str(data.get("policy", "auto")),
        )
    except (KeyError, ValueError, TypeError) as e:
        warn(
            f"{path} is unreadable as a source pin ({e}) — ignoring it; the next "
            f"auto build re-resolves (or 'carlos-ctl source set <ref>' pins manually)"
        )
        return None
    if not pin.ref or pin.artifact not in ("war", "source"):
        warn(
            f"{path} carries an incomplete source pin — ignoring it; the next auto "
            f"build re-resolves"
        )
        return None
    return pin


def write_pin(runner: Runner, pin: SourcePin, *, implicit: bool) -> None:
    """Persist the pin. An explicit `source update`/`set` write failing is a
    hard error (the operator asked for durability); the implicit first-build
    write only warns — the build itself already has its answer for this run,
    and refusing to build over a marker-file write would invert priorities."""
    path = pin_path(runner)
    payload = json.dumps({"v": 1, **dataclasses.asdict(pin)}, indent=2) + "\n"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload)
    except OSError as e:
        if not implicit:
            raise CtlError(f"could not write the source pin {path} ({e})") from None
        warn(
            f"could not persist the source pin {path} ({e}) — this build proceeds, "
            f"but the NEXT build will resolve again (and may pick a newer release)"
        )


# --- GitHub API ---------------------------------------------------------------


def _gh_json(runner: Runner, url: str, *, follow: bool = False) -> Optional[object]:
    """One API/asset GET → parsed JSON (or raw-text passthrough callers split
    themselves). None on any failure — network, HTTP error, rate limit, bad
    JSON — so callers can distinguish "unreachable" from "empty answer".
    -L only for asset content (release-asset downloads redirect to
    objects.githubusercontent.com); API endpoints answer directly."""
    argv = [
        "curl", "-fsS", "--max-time", "20",
        "-H", "Accept: application/vnd.github+json",
        "-H", "X-GitHub-Api-Version: 2022-11-28",
    ]
    if follow:
        argv.append("-L")
    out = runner.output([*argv, url], timeout=30)
    if not out:
        return None
    try:
        return json.loads(out)
    except ValueError:
        return None


def list_releases(runner: Runner) -> Optional[List[dict]]:
    """All non-draft releases, newest published first. None = API unreachable
    (distinct from [] = reachable, no releases). Drafts are invisible to
    consumers and carry no stable assets; a missing published_at sorts last
    (ISO-8601 strings order lexicographically, and '' loses every descending
    comparison)."""
    data = _gh_json(runner, f"{_API}/releases?per_page=100")
    if data is None or not isinstance(data, list):
        return None
    releases = [r for r in data if isinstance(r, dict) and not r.get("draft")]
    releases.sort(key=lambda r: str(r.get("published_at") or ""), reverse=True)
    return releases


def resolve_commit(runner: Runner, ref: str) -> str:
    """A ref's commit SHA via GET /commits/<ref> (peels annotated tags,
    resolves branch heads). '' on failure."""
    data = _gh_json(runner, f"{_API}/commits/{ref}")
    if isinstance(data, dict):
        sha = str(data.get("sha") or "")
        if _SHA40.match(sha):
            return sha
    return ""


def detect_war_asset(runner: Runner, release: dict, tag: str) -> Tuple[str, str]:
    """(download_url, sha256) of the release's published WAR, or ('', '').
    The asset naming convention is upstream's release workflow:
    carlos-<tag>.war plus a sibling carlos-<tag>.war.sha256. The sha comes
    from the API's own digest field when present (authoritative, no extra
    fetch); the .sha256 asset is the fallback for releases published before
    GitHub stamped digests."""
    assets = release.get("assets") or []
    war_name = f"carlos-{tag}.war"
    war_url = ""
    war_sha = ""
    sha_asset_url = ""
    for a in assets:
        if not isinstance(a, dict):
            continue
        if a.get("name") == war_name:
            war_url = str(a.get("browser_download_url") or "")
            digest = str(a.get("digest") or "")
            if digest.startswith("sha256:") and _SHA256_HEX.match(digest[7:]):
                war_sha = digest[7:]
        elif a.get("name") == f"{war_name}.sha256":
            sha_asset_url = str(a.get("browser_download_url") or "")
    if war_url and not war_sha and sha_asset_url:
        # The .sha256 file is `sha256sum` output: "<hex>  <filename>".
        out = runner.output([
            "curl", "-fsSL", "--max-time", "20", sha_asset_url,
        ], timeout=30)
        first = out.split()[0].lower() if out.split() else ""
        if _SHA256_HEX.match(first):
            war_sha = first
    return war_url, war_sha


# --- policy -------------------------------------------------------------------


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _offline_error() -> CtlError:
    return CtlError(
        f"cannot resolve the CARLOS version: the GitHub API "
        f"(api.github.com/repos/{GH_REPO}) is unreachable or rate-limited "
        f"(unauthenticated quota is 60 requests/hour) and no source pin exists. "
        f"Pin manually — 'carlos-ctl source set <release-tag|branch|40-hex-sha>' — "
        f"or set CARLOS_REF to a specific ref in host_vars (carlos_ref)"
    )


def _pin_release(runner: Runner, release: dict, *, policy: str) -> SourcePin:
    """Build a pin for one chosen release: resolve the tag to its commit
    (tags are mutable; the SHA is what source builds fetch) and detect the
    published WAR per the artifact policy."""
    s = runner.settings
    tag = str(release.get("tag_name") or "")
    kind = "prerelease" if release.get("prerelease") else "release"
    commit = resolve_commit(runner, tag)
    if not commit:
        # The releases list answered but /commits did not (partial outage or
        # a deleted tag). A release pin without its immutable commit cannot
        # honor the no-drift contract for source builds — fail with guidance
        # rather than silently pinning the mutable tag name.
        raise CtlError(
            f"resolved {kind} {tag} but could not resolve its commit SHA via the "
            f"GitHub API — retry, or pin explicitly with 'carlos-ctl source set'"
        )
    war_url, war_sha = detect_war_asset(runner, release, tag)
    artifact_cfg = s.get("CARLOS_ARTIFACT")
    if artifact_cfg == "war" or (artifact_cfg != "source" and war_url and war_sha):
        if not (war_url and war_sha):
            raise CtlError(
                f"CARLOS_ARTIFACT=war but {kind} {tag} publishes no verifiable WAR "
                f"asset (carlos-{tag}.war with a sha256) — use CARLOS_ARTIFACT=auto/"
                f"source, or pick a release that ships one"
            )
        artifact, url, sha = "war", war_url, war_sha
    else:
        if artifact_cfg != "source" and war_url and not war_sha:
            warn(
                f"{kind} {tag} publishes carlos-{tag}.war but no sha256 could be "
                f"determined — an unverifiable download is refused; compiling from "
                f"source instead"
            )
        elif artifact_cfg != "source" and not war_url:
            log(f"{kind} {tag} publishes no WAR asset — compiling from source")
        artifact, url, sha = "source", "", ""
    return SourcePin(
        ref=commit, kind=kind, tag=tag, commit=commit, artifact=artifact,
        war_url=url, war_sha256=sha, resolved_at=_now_iso(), policy=policy,
    )


def _pin_branch(runner: Runner, branch: str, *, policy: str) -> SourcePin:
    commit = resolve_commit(runner, branch)
    if not commit:
        raise CtlError(
            f"could not resolve branch '{branch}' HEAD via the GitHub API — check the "
            f"branch name (CARLOS_SOURCE_BRANCH) and connectivity, or pin a 40-hex "
            f"commit with 'carlos-ctl source set <sha>'"
        )
    if runner.settings.get("CARLOS_ARTIFACT") == "war":
        raise CtlError(
            "CARLOS_ARTIFACT=war cannot be satisfied from a branch (only releases "
            "publish WAR assets) — use CARLOS_ARTIFACT=auto/source"
        )
    return SourcePin(
        ref=commit, kind="branch", branch=branch, commit=commit, artifact="source",
        resolved_at=_now_iso(), policy=policy,
    )


def resolve_policy(runner: Runner) -> SourcePin:
    """The default resolution chain: newest non-prerelease release by publish
    time → newest prerelease → CARLOS_SOURCE_BRANCH HEAD. Raises CtlError with
    pin-manually guidance when the API is unreachable."""
    releases = list_releases(runner)
    if releases is None:
        raise _offline_error()
    stable = [r for r in releases if not r.get("prerelease")]
    if stable:
        return _pin_release(runner, stable[0], policy="auto")
    if releases:
        log(
            f"{GH_REPO} has no non-prerelease release yet — falling back to the "
            f"newest prerelease"
        )
        return _pin_release(runner, releases[0], policy="auto")
    branch = runner.settings.get("CARLOS_SOURCE_BRANCH")
    log(f"{GH_REPO} has no releases yet — falling back to branch {branch} HEAD")
    return _pin_branch(runner, branch, policy="auto")


# --- the build entry point ----------------------------------------------------


def _manual_pin(runner: Runner) -> SourcePin:
    """Manual mode (CARLOS_REF != auto): the historical semantics, verbatim —
    the configured ref builds from source, no network, no pin file. The one
    addition: CARLOS_ARTIFACT=war works here too when the operator supplies
    the URL+sha explicitly (the offline/air-gapped WAR channel)."""
    s = runner.settings
    ref = s.get("CARLOS_REF")
    artifact_cfg = s.get("CARLOS_ARTIFACT")
    if artifact_cfg == "war":
        url = s.get("CARLOS_WAR_URL")
        sha = s.get("CARLOS_WAR_SHA256").lower()
        if not url or not _SHA256_HEX.match(sha):
            raise CtlError(
                "CARLOS_ARTIFACT=war with a manual CARLOS_REF needs explicit "
                "CARLOS_WAR_URL and CARLOS_WAR_SHA256 (64-hex) — or use "
                "CARLOS_REF=auto / 'carlos-ctl source set <release-tag>' to have "
                "them resolved from the release"
            )
        return SourcePin(
            ref=ref, kind="manual", commit=ref if _SHA40.match(ref) else "",
            artifact="war", war_url=url, war_sha256=sha, policy="manual",
        )
    return SourcePin(
        ref=ref, kind="manual", commit=ref if _SHA40.match(ref) else "",
        artifact="source", policy="manual",
    )


def resolve_for_build(runner: Runner) -> SourcePin:
    """What `build` should build, resolved exactly once per selection:

    - manual CARLOS_REF → passthrough (no network, no pin);
    - auto + existing pin → the pin, offline (CARLOS_ARTIFACT=war/source may
      override the pinned artifact for THIS run without rewriting the pin);
    - auto + no pin → resolve per policy, PERSIST, return.
    """
    s = runner.settings
    if s.get("CARLOS_REF") != "auto":
        return _manual_pin(runner)
    pin = read_pin(runner)
    if pin is None:
        pin = resolve_policy(runner)
        write_pin(runner, pin, implicit=True)
        log(
            f"pinned CARLOS source: {pin.describe()} — future builds stay on this "
            f"until 'carlos-ctl source update' (or set/clear)"
        )
        return pin
    forced = s.get("CARLOS_ARTIFACT")
    if forced == "war" and pin.artifact != "war":
        if not (pin.war_url and pin.war_sha256):
            raise CtlError(
                f"CARLOS_ARTIFACT=war but the pinned {pin.describe()} has no "
                f"verifiable WAR asset — 'carlos-ctl source update' to re-resolve, "
                f"or CARLOS_ARTIFACT=auto/source"
            )
        pin = dataclasses.replace(pin, artifact="war")
    elif forced == "source" and pin.artifact != "source":
        # One-run override: the pin keeps its WAR data so flipping back is free.
        pin = dataclasses.replace(pin, artifact="source")
    return pin


# --- the `source` verb --------------------------------------------------------


def _print_pin(pin: Optional[SourcePin], runner: Runner) -> None:
    s = runner.settings
    ref_cfg = s.get("CARLOS_REF")
    if pin is None:
        log("no source pin recorded")
    else:
        log(f"pinned: {pin.describe()}")
        if pin.tag:
            print(f"    tag:         {pin.tag}")
        if pin.branch:
            print(f"    branch:      {pin.branch}")
        if pin.commit:
            print(f"    commit:      {pin.commit}")
        print(f"    artifact:    {pin.artifact}")
        if pin.war_url:
            print(f"    war url:     {pin.war_url}")
            print(f"    war sha256:  {pin.war_sha256}")
        if pin.resolved_at:
            print(f"    resolved at: {pin.resolved_at} ({pin.policy})")
        print(f"    pin file:    {pin_path(runner)}")
    if ref_cfg != "auto":
        warn(
            f"CARLOS_REF={ref_cfg} is set (manual mode) — the pin is ignored; builds "
            f"use that ref until carlos_ref/CARLOS_REF is 'auto'"
        )
    elif pin is None:
        log(
            "next build resolves the newest release (release > prerelease > "
            f"{s.get('CARLOS_SOURCE_BRANCH')} HEAD) and pins it"
        )
    else:
        log("next build uses the pin above (no network) — 'carlos-ctl source update' "
            "moves it to the newest release")


def cmd_source(runner: Runner, args: List[str]) -> int:
    """show / update / set / clear — see _USAGE. `show` is read-only; the
    writing sub-verbs run under the per-instance mutating lock (cli._gating)
    so a `source update` cannot interleave with a running build's resolve."""
    if not args or args == ["show"]:
        _print_pin(read_pin(runner), runner)
        return 0
    verb, rest = args[0], args[1:]
    if verb == "update":
        if rest:
            raise CtlError(_USAGE)
        old = read_pin(runner)
        pin = resolve_policy(runner)
        write_pin(runner, pin, implicit=False)
        if old is not None and (old.ref, old.artifact) != (pin.ref, pin.artifact):
            log(f"updated: {old.describe()} -> {pin.describe()}")
        elif old is not None:
            log(f"already current: {pin.describe()}")
        else:
            log(f"pinned: {pin.describe()}")
        log("deploy it with 'carlos-ctl rebuild'")
        return 0
    if verb == "clear":
        if rest:
            raise CtlError(_USAGE)
        path = pin_path(runner)
        try:
            path.unlink()
            log(f"cleared {path} — the next auto build re-resolves and re-pins")
        except FileNotFoundError:
            log("no pin to clear")
        except OSError as e:
            raise CtlError(f"could not remove {path} ({e})") from None
        return 0
    if verb == "set":
        spec = ""
        artifact = ""
        i = 0
        while i < len(rest):
            a = rest[i]
            if a == "--artifact":
                if i + 1 >= len(rest) or rest[i + 1] not in ("war", "source"):
                    raise CtlError(_USAGE)
                artifact = rest[i + 1]
                i += 2
            elif not a.startswith("-") and not spec:
                spec = a
                i += 1
            else:
                raise CtlError(_USAGE)
        if not spec:
            raise CtlError(_USAGE)
        pin = _resolve_set_spec(runner, spec, artifact)
        write_pin(runner, pin, implicit=False)
        log(f"pinned: {pin.describe()}")
        if runner.settings.get("CARLOS_REF") != "auto":
            warn(
                f"CARLOS_REF={runner.settings.get('CARLOS_REF')} is set (manual mode) "
                f"— this pin takes effect once carlos_ref/CARLOS_REF is 'auto'"
            )
        else:
            log("deploy it with 'carlos-ctl rebuild'")
        return 0
    raise CtlError(_USAGE)


def _resolve_set_spec(runner: Runner, spec: str, artifact: str) -> SourcePin:
    """`source set <spec>`: a 40-hex sha pins OFFLINE (kind=manual, source
    compile — there is no release to hang a WAR off); anything else asks the
    API — a matching release tag pins that release (WAR-first unless
    --artifact source), otherwise the spec is treated as a branch name."""
    s = runner.settings
    if _SHA40.match(spec):
        if artifact == "war":
            raise CtlError(
                "--artifact war needs a RELEASE tag (WAR assets hang off releases, "
                "not bare commits) — 'carlos-ctl source set <release-tag> --artifact war'"
            )
        return SourcePin(
            ref=spec, kind="manual", commit=spec, artifact="source",
            resolved_at=_now_iso(), policy="manual",
        )
    releases = list_releases(runner)
    if releases is None:
        raise CtlError(
            f"cannot look up '{spec}': the GitHub API is unreachable or rate-limited "
            f"— pin a 40-hex commit SHA instead ('carlos-ctl source set <sha>')"
        )
    match = next((r for r in releases if str(r.get("tag_name")) == spec), None)
    if match is not None:
        # Honor an explicit --artifact over the CARLOS_ARTIFACT setting for
        # this pin; _pin_release reads the setting, so stage the choice.
        if artifact:
            s._vals["CARLOS_ARTIFACT"] = artifact  # noqa: SLF001 — per-run, like rebuild --ref
        return _pin_release(runner, match, policy="manual")
    if artifact == "war":
        raise CtlError(
            f"'{spec}' is not a release tag of {GH_REPO}, and --artifact war needs a "
            f"release (branches publish no WAR assets)"
        )
    return _pin_branch(runner, spec, policy="manual")
