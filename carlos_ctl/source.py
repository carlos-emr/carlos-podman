# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Source selection for the two built apps (CARLOS and DrugRef): which
version builds, and from which artifact.

THE CONTRACT (README "Choosing the CARLOS and DrugRef versions") — identical
for both apps, each governed by its own key prefix (CARLOS_* / DRUGREF_*)
and its own pin:

- <APP>_REF=auto (the default) resolves per policy — the newest
  NON-prerelease GitHub release of the app's repo by publish time, else the
  newest prerelease, else the HEAD of <APP>_SOURCE_BRANCH (the repo's
  default branch: carlos-emr/carlos has `develop`, carlos-emr/drugref2026
  has `master`; neither has `main`) — and then PINS the answer in
  $EMR_HOME/build/ (.source-pin for CARLOS, .source-pin.drugref for
  DrugRef). Every later build reads the pin with ZERO network calls: the
  deployed version never drifts because upstream published something, only
  because an operator ran `carlos-ctl source update` (or `set`/`clear`).
- Any other <APP>_REF value is a MANUAL pin with exactly the historical
  semantics: no API call, no pin file, source compile of that ref — a
  branch name like `develop`/`master`, a tag, or a 40-hex SHA (unless
  <APP>_ARTIFACT=war plus explicit <APP>_WAR_URL/<APP>_WAR_SHA256).
- <APP>_ARTIFACT=auto prefers a release's published WAR asset
  (sha256-verified in-image) and falls back to compiling that release's
  source; `war`/`source` force one side. The choice made under `auto` is
  persisted in the pin. WAR asset naming differs per repo: CARLOS releases
  ship `carlos-<tag>.war`, DrugRef releases ship a fixed-name
  `drugref2.war` — each app lists its accepted names.

Pins record the release tag AND its commit SHA: tags are mutable refs, so
nothing downstream trusts one — source builds fetch archive/<sha>.tar.gz
(immutable) and WAR builds verify the pinned sha256. The pin files sit next
to .build-mode (the established CLI marker-file pattern); carlos-app.env
stays Ansible-rendered/operator-owned and is never written by the CLI.

All GitHub API traffic goes through Runner+curl (like every external probe
in this tree) so both test suites stub it at the one boundary; unauth API
quota is 60 req/h, which only `update`/`set`/the first resolve ever touch
(a handful of calls each — pinned builds are offline).
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

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")

_USAGE = (
    "usage: carlos-ctl source [show]\n"
    "       carlos-ctl source update\n"
    "       carlos-ctl source set [--drugref] <release-tag|branch|40-hex-sha> "
    "[--artifact war|source]\n"
    "       carlos-ctl source clear"
)


@dataclasses.dataclass(frozen=True)
class AppSource:
    """One built app's selection surface: its repo, the env-key prefix its
    knobs live under, its pin file, and the WAR asset names its release
    workflow publishes ({tag} is substituted; first present asset wins)."""

    label: str        # display name ("CARLOS" / "DrugRef")
    repo: str         # GitHub owner/name — must match the Containerfile ADD URL
    prefix: str       # env keys: <prefix>_REF/_ARTIFACT/_SOURCE_BRANCH/_WAR_URL/_WAR_SHA256
    pin_file: str     # marker filename under $EMR_HOME/build/
    war_names: Tuple[str, ...]


CARLOS = AppSource(
    label="CARLOS",
    repo="carlos-emr/carlos",
    prefix="CARLOS",
    pin_file=".source-pin",
    war_names=("carlos-{tag}.war",),
)
# DrugRef's release workflow uploads the WAR under its fixed build name
# (drugref2.war, e.g. release v1.0.0rc2); accept a tag-suffixed name too so
# a future workflow change does not silently demote releases to source.
DRUGREF = AppSource(
    label="DrugRef",
    repo="carlos-emr/drugref2026",
    prefix="DRUGREF",
    pin_file=".source-pin.drugref",
    war_names=("drugref2-{tag}.war", "drugref2.war"),
)
APPS: Tuple[AppSource, ...] = (CARLOS, DRUGREF)


@dataclasses.dataclass
class SourcePin:
    """One resolved source selection. `ref` is what <APP>_REF becomes for a
    source build (always a 40-hex commit SHA for policy-resolved pins);
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


def pin_path(runner: Runner, app: AppSource) -> Path:
    # Beside .build-mode/.schema-fingerprint: $EMR_HOME/build is the CLI's
    # instance-state home. Nothing in a pin is secret (public tags, SHAs,
    # release-asset URLs), so default 0644 root-owned is fine.
    return runner.settings.emr_home / "build" / app.pin_file


def read_pin(runner: Runner, app: AppSource) -> Optional[SourcePin]:
    """The persisted pin, or None. Corrupt/unreadable degrades to None with a
    warning — an auto build then re-resolves (or fails with guidance when
    offline); a half-written file must never crash every build verb."""
    path = pin_path(runner, app)
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
            f"auto build re-resolves (or 'carlos-ctl source set' pins manually)"
        )
        return None
    if not pin.ref or pin.artifact not in ("war", "source"):
        warn(
            f"{path} carries an incomplete source pin — ignoring it; the next auto "
            f"build re-resolves"
        )
        return None
    return pin


def write_pin(runner: Runner, app: AppSource, pin: SourcePin, *, implicit: bool) -> None:
    """Persist the pin. An explicit `source update`/`set` write failing is a
    hard error (the operator asked for durability); the implicit first-build
    write only warns — the build itself already has its answer for this run,
    and refusing to build over a marker-file write would invert priorities."""
    path = pin_path(runner, app)
    payload = json.dumps({"v": 1, **dataclasses.asdict(pin)}, indent=2) + "\n"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload)
    except OSError as e:
        if not implicit:
            raise CtlError(f"could not write the source pin {path} ({e})") from None
        warn(
            f"could not persist the {app.label} source pin {path} ({e}) — this build "
            f"proceeds, but the NEXT build will resolve again (and may pick a newer "
            f"release)"
        )


# --- GitHub API ---------------------------------------------------------------


def _gh_json(runner: Runner, url: str) -> Optional[object]:
    """One API GET → parsed JSON. None on any failure — network, HTTP error,
    rate limit, bad JSON — so callers can distinguish "unreachable" from "empty
    answer"."""
    out = runner.output([
        "curl", "-fsS", "--max-time", "20",
        "-H", "Accept: application/vnd.github+json",
        "-H", "X-GitHub-Api-Version: 2022-11-28",
        url,
    ], timeout=30)
    if not out:
        return None
    try:
        return json.loads(out)
    except ValueError:
        return None


def list_releases(runner: Runner, app: AppSource) -> Optional[List[dict]]:
    """All non-draft releases, newest published first. None = API unreachable
    (distinct from [] = reachable, no releases). Drafts are invisible to
    consumers and carry no stable assets; a missing published_at sorts last
    (ISO-8601 strings order lexicographically, and '' loses every descending
    comparison)."""
    data = _gh_json(runner, f"https://api.github.com/repos/{app.repo}/releases?per_page=100")
    if data is None or not isinstance(data, list):
        return None
    releases = [r for r in data if isinstance(r, dict) and not r.get("draft")]
    releases.sort(key=lambda r: str(r.get("published_at") or ""), reverse=True)
    return releases


def resolve_commit(runner: Runner, app: AppSource, ref: str) -> str:
    """A ref's commit SHA via GET /commits/<ref> (peels annotated tags,
    resolves branch heads). '' on failure."""
    data = _gh_json(runner, f"https://api.github.com/repos/{app.repo}/commits/{ref}")
    if isinstance(data, dict):
        sha = str(data.get("sha") or "")
        if _SHA40.match(sha):
            return sha
    return ""


def detect_war_asset(runner: Runner, app: AppSource, release: dict, tag: str) -> Tuple[str, str]:
    """(download_url, sha256) of the release's published WAR, or ('', '').
    The accepted asset names are the app's release-workflow convention
    (app.war_names; first present wins). The sha comes from the API's own
    digest field when present (authoritative, no extra fetch); a sibling
    <name>.sha256 asset is the fallback for releases published before GitHub
    stamped digests — fetched with -L because release-asset downloads
    redirect to objects.githubusercontent.com."""
    assets = release.get("assets") or []
    by_name = {}
    for a in assets:
        if isinstance(a, dict) and a.get("name"):
            by_name[str(a["name"])] = a
    for name_tpl in app.war_names:
        name = name_tpl.format(tag=tag)
        a = by_name.get(name)
        if a is None:
            continue
        war_url = str(a.get("browser_download_url") or "")
        digest = str(a.get("digest") or "")
        war_sha = ""
        if digest.startswith("sha256:") and _SHA256_HEX.match(digest[7:]):
            war_sha = digest[7:]
        if war_url and not war_sha:
            sha_a = by_name.get(f"{name}.sha256")
            sha_url = str(sha_a.get("browser_download_url") or "") if sha_a else ""
            if sha_url:
                # The .sha256 file is `sha256sum` output: "<hex>  <filename>".
                out = runner.output([
                    "curl", "-fsSL", "--max-time", "20", sha_url,
                ], timeout=30)
                first = out.split()[0].lower() if out.split() else ""
                if _SHA256_HEX.match(first):
                    war_sha = first
        return war_url, war_sha
    return "", ""


# --- policy -------------------------------------------------------------------


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _offline_error(app: AppSource) -> CtlError:
    return CtlError(
        f"cannot resolve the {app.label} version: the GitHub API "
        f"(api.github.com/repos/{app.repo}) is unreachable or rate-limited "
        f"(unauthenticated quota is 60 requests/hour) and no source pin exists. "
        f"Pin manually — 'carlos-ctl source set"
        f"{' --drugref' if app is DRUGREF else ''} <release-tag|branch|40-hex-sha>' — "
        f"or set a specific ref in host_vars "
        f"({'carlos_drugref_ref' if app is DRUGREF else 'carlos_ref'})"
    )


def _pin_release(runner: Runner, app: AppSource, release: dict, *, policy: str) -> SourcePin:
    """Build a pin for one chosen release: resolve the tag to its commit
    (tags are mutable; the SHA is what source builds fetch) and detect the
    published WAR per the artifact policy."""
    s = runner.settings
    tag = str(release.get("tag_name") or "")
    kind = "prerelease" if release.get("prerelease") else "release"
    commit = resolve_commit(runner, app, tag)
    if not commit:
        # The releases list answered but /commits did not (partial outage or
        # a deleted tag). A release pin without its immutable commit cannot
        # honor the no-drift contract for source builds — fail with guidance
        # rather than silently pinning the mutable tag name.
        raise CtlError(
            f"resolved {app.label} {kind} {tag} but could not resolve its commit SHA "
            f"via the GitHub API — retry, or pin explicitly with 'carlos-ctl source set'"
        )
    war_url, war_sha = detect_war_asset(runner, app, release, tag)
    artifact_cfg = s.get(f"{app.prefix}_ARTIFACT")
    if artifact_cfg == "war" or (artifact_cfg != "source" and war_url and war_sha):
        if not (war_url and war_sha):
            raise CtlError(
                f"{app.prefix}_ARTIFACT=war but {app.label} {kind} {tag} publishes no "
                f"verifiable WAR asset ({' / '.join(n.format(tag=tag) for n in app.war_names)} "
                f"with a sha256) — use {app.prefix}_ARTIFACT=auto/source, or pick a "
                f"release that ships one"
            )
        artifact, url, sha = "war", war_url, war_sha
    else:
        if artifact_cfg != "source" and war_url and not war_sha:
            warn(
                f"{app.label} {kind} {tag} publishes a WAR but no sha256 could be "
                f"determined — an unverifiable download is refused; compiling from "
                f"source instead"
            )
        elif artifact_cfg != "source" and not war_url:
            log(f"{app.label} {kind} {tag} publishes no WAR asset — compiling from source")
        artifact, url, sha = "source", "", ""
    return SourcePin(
        ref=commit, kind=kind, tag=tag, commit=commit, artifact=artifact,
        war_url=url, war_sha256=sha, resolved_at=_now_iso(), policy=policy,
    )


def _pin_branch(runner: Runner, app: AppSource, branch: str, *, policy: str) -> SourcePin:
    commit = resolve_commit(runner, app, branch)
    if not commit:
        raise CtlError(
            f"could not resolve {app.label} branch '{branch}' HEAD via the GitHub API "
            f"— check the branch name ({app.prefix}_SOURCE_BRANCH) and connectivity, "
            f"or pin a 40-hex commit with 'carlos-ctl source set'"
        )
    if runner.settings.get(f"{app.prefix}_ARTIFACT") == "war":
        raise CtlError(
            f"{app.prefix}_ARTIFACT=war cannot be satisfied from a branch (only "
            f"releases publish WAR assets) — use {app.prefix}_ARTIFACT=auto/source"
        )
    return SourcePin(
        ref=commit, kind="branch", branch=branch, commit=commit, artifact="source",
        resolved_at=_now_iso(), policy=policy,
    )


def resolve_policy(runner: Runner, app: AppSource) -> SourcePin:
    """The default resolution chain: newest non-prerelease release by publish
    time → newest prerelease → <APP>_SOURCE_BRANCH HEAD. Raises CtlError with
    pin-manually guidance when the API is unreachable."""
    releases = list_releases(runner, app)
    if releases is None:
        raise _offline_error(app)
    stable = [r for r in releases if not r.get("prerelease")]
    if stable:
        return _pin_release(runner, app, stable[0], policy="auto")
    if releases:
        log(
            f"{app.repo} has no non-prerelease release yet — falling back to the "
            f"newest prerelease"
        )
        return _pin_release(runner, app, releases[0], policy="auto")
    branch = runner.settings.get(f"{app.prefix}_SOURCE_BRANCH")
    log(f"{app.repo} has no releases yet — falling back to branch {branch} HEAD")
    return _pin_branch(runner, app, branch, policy="auto")


# --- the build entry point ----------------------------------------------------


def _manual_pin(runner: Runner, app: AppSource) -> SourcePin:
    """Manual mode (<APP>_REF != auto): the historical semantics, verbatim —
    the configured ref (branch/tag/sha, e.g. an operator tracking `develop`
    or `master` deliberately) builds from source, no network, no pin file.
    The one addition: <APP>_ARTIFACT=war works here too when the operator
    supplies the URL+sha explicitly (the offline/air-gapped WAR channel)."""
    s = runner.settings
    ref = s.get(f"{app.prefix}_REF")
    artifact_cfg = s.get(f"{app.prefix}_ARTIFACT")
    if artifact_cfg == "war":
        url = s.get(f"{app.prefix}_WAR_URL")
        sha = s.get(f"{app.prefix}_WAR_SHA256").lower()
        if not url or not _SHA256_HEX.match(sha):
            raise CtlError(
                f"{app.prefix}_ARTIFACT=war with a manual {app.prefix}_REF needs "
                f"explicit {app.prefix}_WAR_URL and {app.prefix}_WAR_SHA256 (64-hex) — "
                f"or use {app.prefix}_REF=auto / 'carlos-ctl source set' to have them "
                f"resolved from the release"
            )
        return SourcePin(
            ref=ref, kind="manual", commit=ref if _SHA40.match(ref) else "",
            artifact="war", war_url=url, war_sha256=sha, policy="manual",
        )
    return SourcePin(
        ref=ref, kind="manual", commit=ref if _SHA40.match(ref) else "",
        artifact="source", policy="manual",
    )


def resolve_for_build(runner: Runner, app: AppSource) -> SourcePin:
    """What `build` should build for one app, resolved exactly once per
    selection:

    - manual <APP>_REF → passthrough (no network, no pin);
    - auto + existing pin → the pin, offline (<APP>_ARTIFACT=war/source may
      override the pinned artifact for THIS run without rewriting the pin);
    - auto + no pin → resolve per policy, PERSIST, return.
    """
    s = runner.settings
    if s.get(f"{app.prefix}_REF") != "auto":
        return _manual_pin(runner, app)
    pin = read_pin(runner, app)
    if pin is None:
        pin = resolve_policy(runner, app)
        write_pin(runner, app, pin, implicit=True)
        log(
            f"pinned {app.label} source: {pin.describe()} — future builds stay on "
            f"this until 'carlos-ctl source update' (or set/clear)"
        )
        return pin
    forced = s.get(f"{app.prefix}_ARTIFACT")
    if forced == "war" and pin.artifact != "war":
        if not (pin.war_url and pin.war_sha256):
            raise CtlError(
                f"{app.prefix}_ARTIFACT=war but the pinned {app.label} "
                f"{pin.describe()} has no verifiable WAR asset — 'carlos-ctl source "
                f"update' to re-resolve, or {app.prefix}_ARTIFACT=auto/source"
            )
        pin = dataclasses.replace(pin, artifact="war")
    elif forced == "source" and pin.artifact != "source":
        # One-run override: the pin keeps its WAR data so flipping back is free.
        pin = dataclasses.replace(pin, artifact="source")
    return pin


# --- the `source` verb --------------------------------------------------------


def _manual_key(app: AppSource) -> str:
    return "carlos_drugref_ref" if app is DRUGREF else "carlos_ref"


def _print_app(runner: Runner, app: AppSource) -> None:
    s = runner.settings
    ref_cfg = s.get(f"{app.prefix}_REF")
    pin = read_pin(runner, app)
    if pin is None:
        log(f"{app.label}: no source pin recorded")
    else:
        log(f"{app.label}: {pin.describe()}")
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
        print(f"    pin file:    {pin_path(runner, app)}")
    if ref_cfg != "auto":
        warn(
            f"{app.prefix}_REF={ref_cfg} is set (manual mode) — the {app.label} pin "
            f"is ignored; builds use that ref until {_manual_key(app)}/"
            f"{app.prefix}_REF is 'auto'"
        )
    elif pin is None:
        log(
            f"next build resolves the newest {app.repo} release (release > "
            f"prerelease > {s.get(f'{app.prefix}_SOURCE_BRANCH')} HEAD) and pins it"
        )


def cmd_source(runner: Runner, args: List[str]) -> int:
    """show / update / set / clear — see _USAGE. `show` is read-only; the
    writing sub-verbs run under the per-instance mutating lock (cli._gating)
    so a `source update` cannot interleave with a running build's resolve."""
    if not args or args == ["show"]:
        for app in APPS:
            _print_app(runner, app)
        if all(
            runner.settings.get(f"{a.prefix}_REF") == "auto"
            and read_pin(runner, a) is not None
            for a in APPS
        ):
            log("next build uses the pins above (no network) — 'carlos-ctl source "
                "update' moves them to the newest releases")
        return 0
    verb, rest = args[0], args[1:]
    if verb == "update":
        if rest:
            raise CtlError(_USAGE)
        # Refresh every app still under auto policy; a manual <APP>_REF masks
        # its pin entirely, so re-resolving it would only mislead — say so
        # and leave it alone.
        for app in APPS:
            if runner.settings.get(f"{app.prefix}_REF") != "auto":
                warn(
                    f"{app.label}: {app.prefix}_REF="
                    f"{runner.settings.get(f'{app.prefix}_REF')} is a manual ref — "
                    f"skipping (set {_manual_key(app)} to 'auto' to manage it here)"
                )
                continue
            old = read_pin(runner, app)
            pin = resolve_policy(runner, app)
            write_pin(runner, app, pin, implicit=False)
            if old is not None and (old.ref, old.artifact) != (pin.ref, pin.artifact):
                log(f"{app.label} updated: {old.describe()} -> {pin.describe()}")
            elif old is not None:
                log(f"{app.label} already current: {pin.describe()}")
            else:
                log(f"{app.label} pinned: {pin.describe()}")
        log("deploy with 'carlos-ctl rebuild'")
        return 0
    if verb == "clear":
        if rest:
            raise CtlError(_USAGE)
        for app in APPS:
            path = pin_path(runner, app)
            try:
                path.unlink()
                log(f"cleared {path} — the next auto build re-resolves and re-pins")
            except FileNotFoundError:
                log(f"{app.label}: no pin to clear")
            except OSError as e:
                raise CtlError(f"could not remove {path} ({e})") from None
        return 0
    if verb == "set":
        target: AppSource = CARLOS
        spec = ""
        artifact = ""
        i = 0
        while i < len(rest):
            a = rest[i]
            if a == "--drugref":
                target = DRUGREF
                i += 1
            elif a == "--artifact":
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
        pin = _resolve_set_spec(runner, target, spec, artifact)
        write_pin(runner, target, pin, implicit=False)
        log(f"pinned {target.label}: {pin.describe()}")
        if runner.settings.get(f"{target.prefix}_REF") != "auto":
            warn(
                f"{target.prefix}_REF={runner.settings.get(f'{target.prefix}_REF')} is "
                f"set (manual mode) — this pin takes effect once {_manual_key(target)}/"
                f"{target.prefix}_REF is 'auto'"
            )
        else:
            log("deploy it with 'carlos-ctl rebuild'")
        return 0
    raise CtlError(_USAGE)


def _resolve_set_spec(runner: Runner, app: AppSource, spec: str, artifact: str) -> SourcePin:
    """`source set [--drugref] <spec>`: a 40-hex sha pins OFFLINE
    (kind=manual, source compile — there is no release to hang a WAR off);
    anything else asks the API — a matching release tag pins that release
    (WAR-first unless --artifact source), otherwise the spec is treated as a
    branch name (so `source set develop` / `source set --drugref master`
    pins that branch's CURRENT head, sticky until the next update/set)."""
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
    releases = list_releases(runner, app)
    if releases is None:
        raise CtlError(
            f"cannot look up '{spec}' for {app.label}: the GitHub API is unreachable "
            f"or rate-limited — pin a 40-hex commit SHA instead "
            f"('carlos-ctl source set{' --drugref' if app is DRUGREF else ''} <sha>')"
        )
    match = next((r for r in releases if str(r.get("tag_name")) == spec), None)
    if match is not None:
        # Honor an explicit --artifact over the <APP>_ARTIFACT setting for
        # this pin; _pin_release reads the setting, so stage the choice.
        if artifact:
            s._vals[f"{app.prefix}_ARTIFACT"] = artifact  # noqa: SLF001 — per-run, like rebuild --ref
        return _pin_release(runner, app, match, policy="manual")
    if artifact == "war":
        raise CtlError(
            f"'{spec}' is not a release tag of {app.repo}, and --artifact war needs a "
            f"release (branches publish no WAR assets)"
        )
    return _pin_branch(runner, app, spec, policy="manual")
