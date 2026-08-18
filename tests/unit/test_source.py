# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Unit tests for carlos_ctl.source: the release-first resolution policy, the
sticky pin, WAR-asset detection, and the `source` verb.

The stakes: `build` defaults to whatever this module resolves, so an ordering
bug deploys the wrong CARLOS version to a PHI instance, and a stickiness bug
makes deployed versions drift with upstream publishes — the exact failure the
pin exists to prevent."""

from __future__ import annotations

import json

import pytest

from carlos_ctl import source as source_mod
from carlos_ctl.source import (
    SourcePin,
    cmd_source,
    read_pin,
    resolve_for_build,
    resolve_policy,
    write_pin,
)
from carlos_ctl.util import CtlError

_SHA = "c" * 40
_WAR_SHA = "d" * 64


def _rel(tag, *, pre=False, draft=False, published="2026-08-18T19:22:53Z", assets=None):
    return {
        "tag_name": tag, "prerelease": pre, "draft": draft,
        "published_at": published, "assets": assets or [],
    }


def _war_assets(tag, *, digest=True, sha_asset=False):
    war = {
        "name": f"carlos-{tag}.war",
        "browser_download_url":
            f"https://github.com/carlos-emr/carlos/releases/download/{tag}/carlos-{tag}.war",
    }
    if digest:
        war["digest"] = f"sha256:{_WAR_SHA}"
    assets = [war]
    if sha_asset:
        assets.append({
            "name": f"carlos-{tag}.war.sha256",
            "browser_download_url":
                f"https://github.com/carlos-emr/carlos/releases/download/{tag}/"
                f"carlos-{tag}.war.sha256",
        })
    return assets


def _gh(r, releases, *, commit=_SHA):
    """Script the two GitHub API endpoints the resolver touches."""
    r.script(
        "api.github.com/repos/carlos-emr/carlos/releases?per_page=100",
        out=json.dumps(releases),
    )
    r.script(
        "api.github.com/repos/carlos-emr/carlos/commits/",
        out=json.dumps({"sha": commit}),
    )


def _api_calls(r):
    return [c for c in r.calls if any("api.github.com" in a for a in c)]


class TestResolutionPolicy:
    def test_newest_stable_release_wins_over_newer_prerelease(self, mk_runner) -> None:
        # Requirement 1: the most recent NON-prerelease by publish time is the
        # default even when a prerelease was published after it.
        r = mk_runner()
        _gh(r, [
            _rel("2026.09.0-alpha1", pre=True, published="2026-09-01T00:00:00Z"),
            _rel("2026.08.0", published="2026-08-18T00:00:00Z"),
            _rel("2026.07.0", published="2026-07-01T00:00:00Z"),
        ])
        pin = resolve_policy(r)
        assert (pin.kind, pin.tag) == ("release", "2026.08.0")
        assert pin.ref == _SHA and pin.commit == _SHA

    def test_stable_releases_ordered_by_published_at_not_list_order(self, mk_runner) -> None:
        r = mk_runner()
        _gh(r, [
            _rel("2026.07.0", published="2026-07-01T00:00:00Z"),
            _rel("2026.08.0", published="2026-08-18T00:00:00Z"),
        ])
        assert resolve_policy(r).tag == "2026.08.0"

    def test_draft_releases_are_invisible(self, mk_runner) -> None:
        r = mk_runner()
        _gh(r, [
            _rel("2026.09.0", draft=True, published="2026-09-01T00:00:00Z"),
            _rel("2026.08.0-alpha1", pre=True),
        ])
        pin = resolve_policy(r)
        assert (pin.kind, pin.tag) == ("prerelease", "2026.08.0-alpha1")

    def test_missing_published_at_sorts_last(self, mk_runner) -> None:
        r = mk_runner()
        _gh(r, [
            _rel("undated", published=None),
            _rel("2026.08.0", published="2026-08-18T00:00:00Z"),
        ])
        assert resolve_policy(r).tag == "2026.08.0"

    def test_prerelease_only_repo_picks_the_prerelease(self, mk_runner) -> None:
        # Requirement 2, and the live state of carlos-emr/carlos today: one
        # prerelease (2026.08.0-alpha1) with a published WAR.
        r = mk_runner()
        _gh(r, [_rel("2026.08.0-alpha1", pre=True,
                     assets=_war_assets("2026.08.0-alpha1"))])
        pin = resolve_policy(r)
        assert (pin.kind, pin.tag) == ("prerelease", "2026.08.0-alpha1")
        assert pin.artifact == "war"
        assert pin.war_sha256 == _WAR_SHA

    def test_no_releases_falls_back_to_branch_head_sha(self, mk_runner) -> None:
        # Requirement 3: no releases at all -> the app repo's default branch
        # HEAD, pinned as a SHA (never the moving branch name).
        r = mk_runner()
        _gh(r, [])
        pin = resolve_policy(r)
        assert (pin.kind, pin.branch) == ("branch", "develop")
        assert pin.ref == _SHA
        assert pin.artifact == "source"

    def test_branch_fallback_honors_carlos_source_branch(self, mk_runner) -> None:
        r = mk_runner("CARLOS_SOURCE_BRANCH=experimental\n")
        _gh(r, [])
        pin = resolve_policy(r)
        assert pin.branch == "experimental"
        assert any("commits/experimental" in a for c in r.calls for a in c)

    def test_unreachable_api_raises_with_pin_guidance(self, mk_runner) -> None:
        r = mk_runner()  # FakeRunner default: every curl fails -> offline
        with pytest.raises(CtlError, match="source set"):
            resolve_policy(r)

    def test_release_whose_commit_cannot_resolve_is_refused(self, mk_runner) -> None:
        # A pin without the immutable commit cannot honor the no-drift
        # contract for source builds — refuse rather than pin the mutable tag.
        r = mk_runner()
        r.script(
            "api.github.com/repos/carlos-emr/carlos/releases?per_page=100",
            out=json.dumps([_rel("2026.08.0")]),
        )
        with pytest.raises(CtlError, match="commit SHA"):
            resolve_policy(r)


class TestWarArtifactDetection:
    def test_war_with_api_digest_needs_no_extra_fetch(self, mk_runner) -> None:
        r = mk_runner()
        _gh(r, [_rel("2026.08.0", assets=_war_assets("2026.08.0"))])
        pin = resolve_policy(r)
        assert (pin.artifact, pin.war_sha256) == ("war", _WAR_SHA)
        assert pin.war_url.endswith("carlos-2026.08.0.war")
        assert not any(".war.sha256" in a for c in r.calls for a in c)

    def test_war_without_digest_reads_the_sha256_asset(self, mk_runner) -> None:
        r = mk_runner()
        _gh(r, [_rel("2026.08.0",
                     assets=_war_assets("2026.08.0", digest=False, sha_asset=True))])
        r.script(
            "carlos-2026.08.0.war.sha256",
            out=f"{_WAR_SHA}  carlos-2026.08.0.war\n",
        )
        pin = resolve_policy(r)
        assert (pin.artifact, pin.war_sha256) == ("war", _WAR_SHA)

    def test_war_with_no_determinable_sha_compiles_from_source(
        self, mk_runner, capsys
    ) -> None:
        # An unverifiable download must never be pinned.
        r = mk_runner()
        _gh(r, [_rel("2026.08.0", assets=_war_assets("2026.08.0", digest=False))])
        pin = resolve_policy(r)
        assert pin.artifact == "source"
        assert "unverifiable" in capsys.readouterr().err

    def test_release_without_war_asset_compiles_from_source(self, mk_runner) -> None:
        r = mk_runner()
        _gh(r, [_rel("2026.08.0")])
        pin = resolve_policy(r)
        assert (pin.artifact, pin.war_url) == ("source", "")

    def test_artifact_source_setting_skips_the_war(self, mk_runner) -> None:
        r = mk_runner("CARLOS_ARTIFACT=source\n")
        _gh(r, [_rel("2026.08.0", assets=_war_assets("2026.08.0"))])
        assert resolve_policy(r).artifact == "source"

    def test_artifact_war_setting_refuses_a_warless_release(self, mk_runner) -> None:
        r = mk_runner("CARLOS_ARTIFACT=war\n")
        _gh(r, [_rel("2026.08.0")])
        with pytest.raises(CtlError, match="CARLOS_ARTIFACT=war"):
            resolve_policy(r)

    def test_artifact_war_setting_refuses_the_branch_fallback(self, mk_runner) -> None:
        r = mk_runner("CARLOS_ARTIFACT=war\n")
        _gh(r, [])
        with pytest.raises(CtlError, match="branch"):
            resolve_policy(r)


class TestPinPersistence:
    def test_round_trip_preserves_every_field(self, mk_runner) -> None:
        r = mk_runner()
        pin = SourcePin(
            ref=_SHA, kind="release", tag="2026.08.0", commit=_SHA,
            artifact="war", war_url="https://example/x.war", war_sha256=_WAR_SHA,
            resolved_at="2026-08-18T00:00:00Z", policy="auto",
        )
        write_pin(r, pin, implicit=False)
        assert read_pin(r) == pin

    def test_corrupt_pin_degrades_to_none_with_warning(self, mk_runner, capsys) -> None:
        r = mk_runner()
        source_mod.pin_path(r).parent.mkdir(parents=True, exist_ok=True)
        source_mod.pin_path(r).write_text("{not json")
        assert read_pin(r) is None
        assert "re-resolves" in capsys.readouterr().err

    def test_incomplete_pin_degrades_to_none(self, mk_runner, capsys) -> None:
        r = mk_runner()
        source_mod.pin_path(r).parent.mkdir(parents=True, exist_ok=True)
        source_mod.pin_path(r).write_text(json.dumps({"ref": "", "kind": "release"}))
        assert read_pin(r) is None
        assert "incomplete" in capsys.readouterr().err

    def test_absent_pin_is_none(self, mk_runner) -> None:
        assert read_pin(mk_runner()) is None


class TestResolveForBuild:
    def test_first_auto_build_resolves_and_persists(self, mk_runner) -> None:
        r = mk_runner()
        _gh(r, [_rel("2026.08.0", assets=_war_assets("2026.08.0"))])
        pin = resolve_for_build(r)
        assert pin.tag == "2026.08.0"
        assert read_pin(r) == pin  # persisted for the next build

    def test_pinned_build_makes_zero_network_calls(self, mk_runner) -> None:
        # THE stickiness contract: with a pin, builds are offline and cannot
        # drift with upstream publishes.
        r = mk_runner()
        write_pin(r, SourcePin(ref=_SHA, kind="release", tag="2026.08.0",
                               commit=_SHA, artifact="source"), implicit=False)
        pin = resolve_for_build(r)
        assert pin.ref == _SHA
        assert _api_calls(r) == []

    def test_pin_survives_newer_upstream_release(self, mk_runner) -> None:
        r = mk_runner()
        write_pin(r, SourcePin(ref=_SHA, kind="release", tag="2026.08.0",
                               commit=_SHA, artifact="source"), implicit=False)
        _gh(r, [_rel("2026.99.0", published="2026-12-01T00:00:00Z")])
        assert resolve_for_build(r).tag == "2026.08.0"

    def test_offline_with_pin_builds_offline_without_pin_refuses(self, mk_runner) -> None:
        r = mk_runner()  # offline (no curl scripted)
        with pytest.raises(CtlError, match="source set"):
            resolve_for_build(r)
        write_pin(r, SourcePin(ref=_SHA, kind="manual", commit=_SHA,
                               artifact="source"), implicit=False)
        assert resolve_for_build(r).ref == _SHA

    def test_manual_ref_passes_through_with_zero_network(self, mk_runner) -> None:
        # Backward compat: env files carrying CARLOS_REF=develop keep the
        # historical semantics exactly — no API, no pin file.
        r = mk_runner("CARLOS_REF=develop\n")
        pin = resolve_for_build(r)
        assert (pin.kind, pin.ref, pin.artifact) == ("manual", "develop", "source")
        assert _api_calls(r) == []
        assert read_pin(r) is None

    def test_manual_ref_ignores_an_existing_pin(self, mk_runner) -> None:
        r = mk_runner("CARLOS_REF=" + "e" * 40 + "\n")
        write_pin(r, SourcePin(ref=_SHA, kind="release", tag="2026.08.0",
                               commit=_SHA, artifact="war",
                               war_url="https://x/x.war", war_sha256=_WAR_SHA),
                  implicit=False)
        assert resolve_for_build(r).ref == "e" * 40

    def test_manual_war_needs_explicit_url_and_sha(self, mk_runner) -> None:
        r = mk_runner("CARLOS_REF=develop\nCARLOS_ARTIFACT=war\n")
        with pytest.raises(CtlError, match="CARLOS_WAR_URL"):
            resolve_for_build(r)

    def test_manual_war_with_url_and_sha_is_honored(self, mk_runner) -> None:
        r = mk_runner(
            "CARLOS_REF=develop\nCARLOS_ARTIFACT=war\n"
            f"CARLOS_WAR_URL=https://example/carlos.war\nCARLOS_WAR_SHA256={_WAR_SHA}\n"
        )
        pin = resolve_for_build(r)
        assert (pin.artifact, pin.war_url, pin.war_sha256) == (
            "war", "https://example/carlos.war", _WAR_SHA,
        )

    def test_forced_source_overrides_a_war_pin_without_rewriting_it(self, mk_runner) -> None:
        r = mk_runner("CARLOS_ARTIFACT=source\n")
        stored = SourcePin(ref=_SHA, kind="release", tag="2026.08.0", commit=_SHA,
                           artifact="war", war_url="https://x/x.war",
                           war_sha256=_WAR_SHA)
        write_pin(r, stored, implicit=False)
        assert resolve_for_build(r).artifact == "source"
        assert read_pin(r) == stored  # the pin keeps its WAR data

    def test_forced_war_on_a_warless_pin_refuses(self, mk_runner) -> None:
        r = mk_runner("CARLOS_ARTIFACT=war\n")
        write_pin(r, SourcePin(ref=_SHA, kind="branch", branch="develop",
                               commit=_SHA, artifact="source"), implicit=False)
        with pytest.raises(CtlError, match="source update"):
            resolve_for_build(r)

    def test_forced_war_uses_the_pins_stored_war_data(self, mk_runner) -> None:
        r = mk_runner("CARLOS_ARTIFACT=war\n")
        write_pin(r, SourcePin(ref=_SHA, kind="release", tag="2026.08.0",
                               commit=_SHA, artifact="source",
                               war_url="https://x/x.war", war_sha256=_WAR_SHA),
                  implicit=False)
        pin = resolve_for_build(r)
        assert (pin.artifact, pin.war_url) == ("war", "https://x/x.war")


class TestCmdSource:
    def test_bare_and_show_report_without_touching_anything(self, mk_runner, capsys) -> None:
        r = mk_runner()
        assert cmd_source(r, []) == 0
        assert "no source pin" in capsys.readouterr().out
        assert cmd_source(r, ["show"]) == 0
        assert _api_calls(r) == []

    def test_show_prints_the_pin_details(self, mk_runner, capsys) -> None:
        r = mk_runner()
        write_pin(r, SourcePin(ref=_SHA, kind="release", tag="2026.08.0",
                               commit=_SHA, artifact="war",
                               war_url="https://x/x.war", war_sha256=_WAR_SHA,
                               resolved_at="2026-08-18T00:00:00Z"), implicit=False)
        assert cmd_source(r, []) == 0
        out = capsys.readouterr().out
        assert "2026.08.0" in out and _SHA in out and "war" in out

    def test_show_warns_when_a_manual_ref_masks_the_pin(self, mk_runner, capsys) -> None:
        r = mk_runner("CARLOS_REF=develop\n")
        assert cmd_source(r, []) == 0
        assert "manual mode" in capsys.readouterr().err

    def test_update_moves_the_pin_and_reports_the_change(self, mk_runner, capsys) -> None:
        r = mk_runner()
        write_pin(r, SourcePin(ref="e" * 40, kind="release", tag="2026.07.0",
                               commit="e" * 40, artifact="source"), implicit=False)
        _gh(r, [_rel("2026.08.0", assets=_war_assets("2026.08.0"))])
        assert cmd_source(r, ["update"]) == 0
        assert read_pin(r).tag == "2026.08.0"
        assert "->" in capsys.readouterr().out

    def test_update_offline_is_a_hard_error_keeping_the_pin(self, mk_runner) -> None:
        r = mk_runner()
        old = SourcePin(ref=_SHA, kind="release", tag="2026.08.0", commit=_SHA,
                        artifact="source")
        write_pin(r, old, implicit=False)
        with pytest.raises(CtlError):
            cmd_source(r, ["update"])
        assert read_pin(r) == old

    def test_set_sha_pins_offline(self, mk_runner) -> None:
        r = mk_runner()
        sha = "f" * 40
        assert cmd_source(r, ["set", sha]) == 0
        pin = read_pin(r)
        assert (pin.kind, pin.ref, pin.artifact, pin.policy) == (
            "manual", sha, "source", "manual",
        )
        assert _api_calls(r) == []

    def test_set_sha_refuses_artifact_war(self, mk_runner) -> None:
        with pytest.raises(CtlError, match="release"):
            cmd_source(mk_runner(), ["set", "f" * 40, "--artifact", "war"])

    def test_set_release_tag_pins_that_exact_release(self, mk_runner) -> None:
        r = mk_runner()
        _gh(r, [
            _rel("2026.08.0", assets=_war_assets("2026.08.0")),
            _rel("2026.07.0", published="2026-07-01T00:00:00Z"),
        ])
        assert cmd_source(r, ["set", "2026.07.0"]) == 0
        pin = read_pin(r)
        assert (pin.tag, pin.policy) == ("2026.07.0", "manual")

    def test_set_release_tag_artifact_source_forces_the_compile(self, mk_runner) -> None:
        r = mk_runner()
        _gh(r, [_rel("2026.08.0", assets=_war_assets("2026.08.0"))])
        assert cmd_source(r, ["set", "2026.08.0", "--artifact", "source"]) == 0
        assert read_pin(r).artifact == "source"

    def test_set_unknown_spec_is_treated_as_a_branch(self, mk_runner) -> None:
        r = mk_runner()
        _gh(r, [_rel("2026.08.0")])
        assert cmd_source(r, ["set", "feature-x"]) == 0
        pin = read_pin(r)
        assert (pin.kind, pin.branch, pin.ref) == ("branch", "feature-x", _SHA)

    def test_set_branch_refuses_artifact_war(self, mk_runner) -> None:
        r = mk_runner()
        _gh(r, [_rel("2026.08.0")])
        with pytest.raises(CtlError, match="release"):
            cmd_source(r, ["set", "feature-x", "--artifact", "war"])

    def test_clear_removes_the_pin_and_is_idempotent(self, mk_runner, capsys) -> None:
        r = mk_runner()
        write_pin(r, SourcePin(ref=_SHA, kind="manual", commit=_SHA,
                               artifact="source"), implicit=False)
        assert cmd_source(r, ["clear"]) == 0
        assert read_pin(r) is None
        assert cmd_source(r, ["clear"]) == 0
        assert "no pin to clear" in capsys.readouterr().out

    @pytest.mark.parametrize("args", [
        ["bogus"], ["update", "extra"], ["clear", "extra"], ["set"],
        ["set", "--artifact", "war"], ["set", "x", "--artifact", "tarball"],
        ["set", "x", "y"],
    ])
    def test_bad_arguments_print_usage(self, mk_runner, args) -> None:
        with pytest.raises(CtlError, match="usage"):
            cmd_source(mk_runner(), args)
