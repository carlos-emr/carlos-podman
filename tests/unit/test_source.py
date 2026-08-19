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
    CARLOS,
    DRUGREF,
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
        pin = resolve_policy(r, CARLOS)
        assert (pin.kind, pin.tag) == ("release", "2026.08.0")
        assert pin.ref == _SHA and pin.commit == _SHA

    def test_stable_releases_ordered_by_published_at_not_list_order(self, mk_runner) -> None:
        r = mk_runner()
        _gh(r, [
            _rel("2026.07.0", published="2026-07-01T00:00:00Z"),
            _rel("2026.08.0", published="2026-08-18T00:00:00Z"),
        ])
        assert resolve_policy(r, CARLOS).tag == "2026.08.0"

    def test_draft_releases_are_invisible(self, mk_runner) -> None:
        r = mk_runner()
        _gh(r, [
            _rel("2026.09.0", draft=True, published="2026-09-01T00:00:00Z"),
            _rel("2026.08.0-alpha1", pre=True),
        ])
        pin = resolve_policy(r, CARLOS)
        assert (pin.kind, pin.tag) == ("prerelease", "2026.08.0-alpha1")

    def test_missing_published_at_sorts_last(self, mk_runner) -> None:
        r = mk_runner()
        _gh(r, [
            _rel("undated", published=None),
            _rel("2026.08.0", published="2026-08-18T00:00:00Z"),
        ])
        assert resolve_policy(r, CARLOS).tag == "2026.08.0"

    def test_prerelease_only_repo_picks_the_prerelease(self, mk_runner) -> None:
        # Requirement 2, and the live state of carlos-emr/carlos today: one
        # prerelease (2026.08.0-alpha1) with a published WAR.
        r = mk_runner()
        _gh(r, [_rel("2026.08.0-alpha1", pre=True,
                     assets=_war_assets("2026.08.0-alpha1"))])
        pin = resolve_policy(r, CARLOS)
        assert (pin.kind, pin.tag) == ("prerelease", "2026.08.0-alpha1")
        assert pin.artifact == "war"
        assert pin.war_sha256 == _WAR_SHA

    def test_no_releases_falls_back_to_branch_head_sha(self, mk_runner) -> None:
        # Requirement 3: no releases at all -> main HEAD (the app repo's
        # stable/release branch), pinned as a SHA (never the moving name).
        r = mk_runner()
        _gh(r, [])
        pin = resolve_policy(r, CARLOS)
        assert (pin.kind, pin.branch) == ("branch", "main")
        assert pin.ref == _SHA
        assert pin.artifact == "source"

    def test_branch_fallback_honors_carlos_source_branch(self, mk_runner) -> None:
        r = mk_runner("CARLOS_SOURCE_BRANCH=experimental\n")
        _gh(r, [])
        pin = resolve_policy(r, CARLOS)
        assert pin.branch == "experimental"
        assert any("commits/experimental" in a for c in r.calls for a in c)

    def test_unreachable_api_raises_with_pin_guidance(self, mk_runner) -> None:
        r = mk_runner()  # FakeRunner default: every curl fails -> offline
        with pytest.raises(CtlError, match="source set"):
            resolve_policy(r, CARLOS)

    def test_release_whose_commit_cannot_resolve_is_refused(self, mk_runner) -> None:
        # A pin without the immutable commit cannot honor the no-drift
        # contract for source builds — refuse rather than pin the mutable tag.
        r = mk_runner()
        r.script(
            "api.github.com/repos/carlos-emr/carlos/releases?per_page=100",
            out=json.dumps([_rel("2026.08.0")]),
        )
        with pytest.raises(CtlError, match="commit SHA"):
            resolve_policy(r, CARLOS)


class TestWarArtifactDetection:
    def test_war_with_api_digest_needs_no_extra_fetch(self, mk_runner) -> None:
        r = mk_runner()
        _gh(r, [_rel("2026.08.0", assets=_war_assets("2026.08.0"))])
        pin = resolve_policy(r, CARLOS)
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
        pin = resolve_policy(r, CARLOS)
        assert (pin.artifact, pin.war_sha256) == ("war", _WAR_SHA)

    def test_war_with_no_determinable_sha_compiles_from_source(
        self, mk_runner, capsys
    ) -> None:
        # An unverifiable download must never be pinned.
        r = mk_runner()
        _gh(r, [_rel("2026.08.0", assets=_war_assets("2026.08.0", digest=False))])
        pin = resolve_policy(r, CARLOS)
        assert pin.artifact == "source"
        assert "unverifiable" in capsys.readouterr().err

    def test_release_without_war_asset_compiles_from_source(self, mk_runner) -> None:
        r = mk_runner()
        _gh(r, [_rel("2026.08.0")])
        pin = resolve_policy(r, CARLOS)
        assert (pin.artifact, pin.war_url) == ("source", "")

    def test_artifact_source_setting_skips_the_war(self, mk_runner) -> None:
        r = mk_runner("CARLOS_ARTIFACT=source\n")
        _gh(r, [_rel("2026.08.0", assets=_war_assets("2026.08.0"))])
        assert resolve_policy(r, CARLOS).artifact == "source"

    def test_artifact_war_setting_refuses_a_warless_release(self, mk_runner) -> None:
        r = mk_runner("CARLOS_ARTIFACT=war\n")
        _gh(r, [_rel("2026.08.0")])
        with pytest.raises(CtlError, match="CARLOS_ARTIFACT=war"):
            resolve_policy(r, CARLOS)

    def test_artifact_war_setting_refuses_the_branch_fallback(self, mk_runner) -> None:
        r = mk_runner("CARLOS_ARTIFACT=war\n")
        _gh(r, [])
        with pytest.raises(CtlError, match="branch"):
            resolve_policy(r, CARLOS)


class TestPinPersistence:
    def test_round_trip_preserves_every_field(self, mk_runner) -> None:
        r = mk_runner()
        pin = SourcePin(
            ref=_SHA, kind="release", tag="2026.08.0", commit=_SHA,
            artifact="war", war_url="https://example/x.war", war_sha256=_WAR_SHA,
            resolved_at="2026-08-18T00:00:00Z", policy="auto",
        )
        write_pin(r, CARLOS, pin, implicit=False)
        assert read_pin(r, CARLOS) == pin

    def test_corrupt_pin_degrades_to_none_with_warning(self, mk_runner, capsys) -> None:
        r = mk_runner()
        source_mod.pin_path(r, CARLOS).parent.mkdir(parents=True, exist_ok=True)
        source_mod.pin_path(r, CARLOS).write_text("{not json")
        assert read_pin(r, CARLOS) is None
        assert "re-resolves" in capsys.readouterr().err

    def test_incomplete_pin_degrades_to_none(self, mk_runner, capsys) -> None:
        r = mk_runner()
        source_mod.pin_path(r, CARLOS).parent.mkdir(parents=True, exist_ok=True)
        source_mod.pin_path(r, CARLOS).write_text(json.dumps({"ref": "", "kind": "release"}))
        assert read_pin(r, CARLOS) is None
        assert "incomplete" in capsys.readouterr().err

    def test_absent_pin_is_none(self, mk_runner) -> None:
        assert read_pin(mk_runner(), CARLOS) is None


class TestResolveForBuild:
    def test_first_auto_build_resolves_and_persists(self, mk_runner) -> None:
        r = mk_runner()
        _gh(r, [_rel("2026.08.0", assets=_war_assets("2026.08.0"))])
        pin = resolve_for_build(r, CARLOS)
        assert pin.tag == "2026.08.0"
        assert read_pin(r, CARLOS) == pin  # persisted for the next build

    def test_pinned_build_makes_zero_network_calls(self, mk_runner) -> None:
        # THE stickiness contract: with a pin, builds are offline and cannot
        # drift with upstream publishes.
        r = mk_runner()
        write_pin(r, CARLOS, SourcePin(ref=_SHA, kind="release", tag="2026.08.0",
                               commit=_SHA, artifact="source"), implicit=False)
        pin = resolve_for_build(r, CARLOS)
        assert pin.ref == _SHA
        assert _api_calls(r) == []

    def test_pin_survives_newer_upstream_release(self, mk_runner) -> None:
        r = mk_runner()
        write_pin(r, CARLOS, SourcePin(ref=_SHA, kind="release", tag="2026.08.0",
                               commit=_SHA, artifact="source"), implicit=False)
        _gh(r, [_rel("2026.99.0", published="2026-12-01T00:00:00Z")])
        assert resolve_for_build(r, CARLOS).tag == "2026.08.0"

    def test_offline_with_pin_builds_offline_without_pin_refuses(self, mk_runner) -> None:
        r = mk_runner()  # offline (no curl scripted)
        with pytest.raises(CtlError, match="source set"):
            resolve_for_build(r, CARLOS)
        write_pin(r, CARLOS, SourcePin(ref=_SHA, kind="manual", commit=_SHA,
                               artifact="source"), implicit=False)
        assert resolve_for_build(r, CARLOS).ref == _SHA

    def test_manual_ref_passes_through_with_zero_network(self, mk_runner) -> None:
        # Backward compat: env files carrying CARLOS_REF=develop keep the
        # historical semantics exactly — no API, no pin file.
        r = mk_runner("CARLOS_REF=develop\n")
        pin = resolve_for_build(r, CARLOS)
        assert (pin.kind, pin.ref, pin.artifact) == ("manual", "develop", "source")
        assert _api_calls(r) == []
        assert read_pin(r, CARLOS) is None

    def test_manual_ref_ignores_an_existing_pin(self, mk_runner) -> None:
        r = mk_runner("CARLOS_REF=" + "e" * 40 + "\n")
        write_pin(r, CARLOS, SourcePin(ref=_SHA, kind="release", tag="2026.08.0",
                               commit=_SHA, artifact="war",
                               war_url="https://x/x.war", war_sha256=_WAR_SHA),
                  implicit=False)
        assert resolve_for_build(r, CARLOS).ref == "e" * 40

    def test_manual_war_needs_explicit_url_and_sha(self, mk_runner) -> None:
        r = mk_runner("CARLOS_REF=develop\nCARLOS_ARTIFACT=war\n")
        with pytest.raises(CtlError, match="CARLOS_WAR_URL"):
            resolve_for_build(r, CARLOS)

    def test_manual_war_with_url_and_sha_is_honored(self, mk_runner) -> None:
        r = mk_runner(
            "CARLOS_REF=develop\nCARLOS_ARTIFACT=war\n"
            f"CARLOS_WAR_URL=https://example/carlos.war\nCARLOS_WAR_SHA256={_WAR_SHA}\n"
        )
        pin = resolve_for_build(r, CARLOS)
        assert (pin.artifact, pin.war_url, pin.war_sha256) == (
            "war", "https://example/carlos.war", _WAR_SHA,
        )

    def test_forced_source_overrides_a_war_pin_without_rewriting_it(self, mk_runner) -> None:
        r = mk_runner("CARLOS_ARTIFACT=source\n")
        stored = SourcePin(ref=_SHA, kind="release", tag="2026.08.0", commit=_SHA,
                           artifact="war", war_url="https://x/x.war",
                           war_sha256=_WAR_SHA)
        write_pin(r, CARLOS, stored, implicit=False)
        assert resolve_for_build(r, CARLOS).artifact == "source"
        assert read_pin(r, CARLOS) == stored  # the pin keeps its WAR data

    def test_forced_war_on_a_warless_pin_refuses(self, mk_runner) -> None:
        r = mk_runner("CARLOS_ARTIFACT=war\n")
        write_pin(r, CARLOS, SourcePin(ref=_SHA, kind="branch", branch="develop",
                               commit=_SHA, artifact="source"), implicit=False)
        with pytest.raises(CtlError, match="source update"):
            resolve_for_build(r, CARLOS)

    def test_forced_war_uses_the_pins_stored_war_data(self, mk_runner) -> None:
        r = mk_runner("CARLOS_ARTIFACT=war\n")
        write_pin(r, CARLOS, SourcePin(ref=_SHA, kind="release", tag="2026.08.0",
                               commit=_SHA, artifact="source",
                               war_url="https://x/x.war", war_sha256=_WAR_SHA),
                  implicit=False)
        pin = resolve_for_build(r, CARLOS)
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
        write_pin(r, CARLOS, SourcePin(ref=_SHA, kind="release", tag="2026.08.0",
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
        # DRUGREF_REF manual here: `update` refreshes every auto-managed app,
        # so an unscripted DrugRef API would otherwise fail the carlos update.
        r = mk_runner("DRUGREF_REF=master\n")
        write_pin(r, CARLOS, SourcePin(ref="e" * 40, kind="release", tag="2026.07.0",
                               commit="e" * 40, artifact="source"), implicit=False)
        _gh(r, [_rel("2026.08.0", assets=_war_assets("2026.08.0"))])
        assert cmd_source(r, ["update"]) == 0
        assert read_pin(r, CARLOS).tag == "2026.08.0"
        cap = capsys.readouterr()
        assert "->" in cap.out
        assert "manual ref — skipping" in cap.err  # the masked app is named, not updated

    def test_update_offline_is_a_hard_error_keeping_the_pin(self, mk_runner) -> None:
        r = mk_runner()
        old = SourcePin(ref=_SHA, kind="release", tag="2026.08.0", commit=_SHA,
                        artifact="source")
        write_pin(r, CARLOS, old, implicit=False)
        with pytest.raises(CtlError):
            cmd_source(r, ["update"])
        assert read_pin(r, CARLOS) == old

    def test_set_sha_pins_offline(self, mk_runner) -> None:
        r = mk_runner()
        sha = "f" * 40
        assert cmd_source(r, ["set", sha]) == 0
        pin = read_pin(r, CARLOS)
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
        pin = read_pin(r, CARLOS)
        assert (pin.tag, pin.policy) == ("2026.07.0", "manual")

    def test_set_release_tag_artifact_source_forces_the_compile(self, mk_runner) -> None:
        r = mk_runner()
        _gh(r, [_rel("2026.08.0", assets=_war_assets("2026.08.0"))])
        assert cmd_source(r, ["set", "2026.08.0", "--artifact", "source"]) == 0
        assert read_pin(r, CARLOS).artifact == "source"

    def test_set_unknown_spec_is_treated_as_a_branch(self, mk_runner) -> None:
        r = mk_runner()
        _gh(r, [_rel("2026.08.0")])
        assert cmd_source(r, ["set", "feature-x"]) == 0
        pin = read_pin(r, CARLOS)
        assert (pin.kind, pin.branch, pin.ref) == ("branch", "feature-x", _SHA)

    def test_set_branch_refuses_artifact_war(self, mk_runner) -> None:
        r = mk_runner()
        _gh(r, [_rel("2026.08.0")])
        with pytest.raises(CtlError, match="release"):
            cmd_source(r, ["set", "feature-x", "--artifact", "war"])

    def test_clear_removes_the_pin_and_is_idempotent(self, mk_runner, capsys) -> None:
        r = mk_runner()
        write_pin(r, CARLOS, SourcePin(ref=_SHA, kind="manual", commit=_SHA,
                               artifact="source"), implicit=False)
        assert cmd_source(r, ["clear"]) == 0
        assert read_pin(r, CARLOS) is None
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


def _dr_rel(tag, *, pre=False, published="2026-03-21T22:27:21Z", war=True, war_name=None):
    assets = []
    if war:
        assets.append({
            "name": war_name or "drugref2.war",
            "browser_download_url":
                f"https://github.com/carlos-emr/drugref2026/releases/download/{tag}/"
                f"{war_name or 'drugref2.war'}",
            "digest": f"sha256:{'f' * 64}",
        })
    return {"tag_name": tag, "prerelease": pre, "draft": False,
            "published_at": published, "assets": assets}


def _gh_dr(r, releases, *, commit="a" * 40):
    r.script(
        "api.github.com/repos/carlos-emr/drugref2026/releases?per_page=100",
        out=json.dumps(releases),
    )
    r.script(
        "api.github.com/repos/carlos-emr/drugref2026/commits/",
        out=json.dumps({"sha": commit}),
    )


class TestDrugRefSelection:
    """The same contract, DRUGREF_* keyed, with DrugRef's own repo, pin file,
    and WAR naming (a fixed-name drugref2.war on current releases — e.g. the
    live v1.0.0rc2)."""

    def test_policy_resolves_the_drugref_repo_not_carlos(self, mk_runner) -> None:
        r = mk_runner()
        _gh_dr(r, [_dr_rel("v1.0.0rc2")])
        pin = resolve_policy(r, DRUGREF)
        assert (pin.kind, pin.tag, pin.ref) == ("release", "v1.0.0rc2", "a" * 40)
        assert all("repos/carlos-emr/drugref2026" in a
                   for c in _api_calls(r) for a in c if "api.github.com" in a)

    def test_fixed_name_war_asset_is_detected(self, mk_runner) -> None:
        # DrugRef releases upload the WAR under its build name (drugref2.war),
        # not a tag-suffixed one.
        r = mk_runner()
        _gh_dr(r, [_dr_rel("v1.0.0rc2")])
        pin = resolve_policy(r, DRUGREF)
        assert pin.artifact == "war"
        assert pin.war_url.endswith("/drugref2.war")
        assert pin.war_sha256 == "f" * 64

    def test_tag_suffixed_war_asset_wins_when_present(self, mk_runner) -> None:
        r = mk_runner()
        _gh_dr(r, [_dr_rel("v2.0.0", war_name="drugref2-v2.0.0.war")])
        assert resolve_policy(r, DRUGREF).war_url.endswith("drugref2-v2.0.0.war")

    def test_branch_fallback_uses_drugref_source_branch(self, mk_runner) -> None:
        # drugref2026's default branch is master, independently configurable.
        r = mk_runner()
        _gh_dr(r, [])
        pin = resolve_policy(r, DRUGREF)
        assert (pin.kind, pin.branch) == ("branch", "master")
        r2 = mk_runner("DRUGREF_SOURCE_BRANCH=next\n")
        _gh_dr(r2, [])
        assert resolve_policy(r2, DRUGREF).branch == "next"

    def test_pins_are_isolated_per_app(self, mk_runner) -> None:
        r = mk_runner()
        write_pin(r, CARLOS, SourcePin(ref="c" * 40, kind="manual", commit="c" * 40,
                                       artifact="source"), implicit=False)
        assert read_pin(r, DRUGREF) is None
        write_pin(r, DRUGREF, SourcePin(ref="a" * 40, kind="manual", commit="a" * 40,
                                        artifact="source"), implicit=False)
        assert read_pin(r, CARLOS).ref == "c" * 40
        assert read_pin(r, DRUGREF).ref == "a" * 40
        assert source_mod.pin_path(r, CARLOS) != source_mod.pin_path(r, DRUGREF)

    def test_manual_drugref_branch_passes_through_offline(self, mk_runner) -> None:
        # The explicit user requirement: configuring master/develop (or any
        # branch) manually must keep working — historical semantics, no API.
        r = mk_runner("DRUGREF_REF=master\n")
        pin = resolve_for_build(r, DRUGREF)
        assert (pin.kind, pin.ref, pin.artifact) == ("manual", "master", "source")
        assert _api_calls(r) == []
        assert read_pin(r, DRUGREF) is None

    def test_manual_drugref_war_channel_uses_drugref_keys(self, mk_runner) -> None:
        r = mk_runner(
            "DRUGREF_REF=master\nDRUGREF_ARTIFACT=war\n"
            f"DRUGREF_WAR_URL=https://example/drugref2.war\nDRUGREF_WAR_SHA256={'f' * 64}\n"
        )
        pin = resolve_for_build(r, DRUGREF)
        assert (pin.artifact, pin.war_url) == ("war", "https://example/drugref2.war")
        r2 = mk_runner("DRUGREF_REF=master\nDRUGREF_ARTIFACT=war\n")
        with pytest.raises(CtlError, match="DRUGREF_WAR_URL"):
            resolve_for_build(r2, DRUGREF)

    def test_sticky_drugref_pin_builds_offline(self, mk_runner) -> None:
        r = mk_runner()
        write_pin(r, DRUGREF, SourcePin(ref="a" * 40, kind="release", tag="v1.0.0rc2",
                                        commit="a" * 40, artifact="war",
                                        war_url="https://x/drugref2.war",
                                        war_sha256="f" * 64), implicit=False)
        pin = resolve_for_build(r, DRUGREF)
        assert pin.tag == "v1.0.0rc2"
        assert _api_calls(r) == []

    def test_set_drugref_flag_targets_the_drugref_pin(self, mk_runner) -> None:
        r = mk_runner()
        sha = "b" * 40
        assert cmd_source(r, ["set", "--drugref", sha]) == 0
        assert read_pin(r, DRUGREF).ref == sha
        assert read_pin(r, CARLOS) is None

    def test_set_drugref_branch_pins_its_head(self, mk_runner) -> None:
        # `source set --drugref master` = "track master, sticky at today's
        # HEAD" — the manual-but-pinned middle ground the user asked for.
        r = mk_runner()
        _gh_dr(r, [_dr_rel("v1.0.0rc2")])
        assert cmd_source(r, ["set", "--drugref", "master"]) == 0
        pin = read_pin(r, DRUGREF)
        assert (pin.kind, pin.branch, pin.ref) == ("branch", "master", "a" * 40)

    def test_update_refreshes_both_apps(self, mk_runner) -> None:
        r = mk_runner()
        _gh(r, [_rel("2026.08.0", assets=_war_assets("2026.08.0"))])
        _gh_dr(r, [_dr_rel("v1.0.0rc2")])
        assert cmd_source(r, ["update"]) == 0
        assert read_pin(r, CARLOS).tag == "2026.08.0"
        assert read_pin(r, DRUGREF).tag == "v1.0.0rc2"

    def test_show_reports_both_apps(self, mk_runner, capsys) -> None:
        r = mk_runner()
        write_pin(r, CARLOS, SourcePin(ref="c" * 40, kind="release", tag="2026.08.0",
                                       commit="c" * 40, artifact="war",
                                       war_url="https://x/x.war", war_sha256="d" * 64),
                  implicit=False)
        assert cmd_source(r, []) == 0
        out = capsys.readouterr().out
        assert "2026.08.0" in out
        assert "DrugRef: no source pin" in out

    def test_clear_removes_both_pins(self, mk_runner) -> None:
        r = mk_runner()
        for app in (CARLOS, DRUGREF):
            write_pin(r, app, SourcePin(ref="c" * 40, kind="manual", commit="c" * 40,
                                        artifact="source"), implicit=False)
        assert cmd_source(r, ["clear"]) == 0
        assert read_pin(r, CARLOS) is None
        assert read_pin(r, DRUGREF) is None


class TestArtifactFlagReconciliation:
    """`source set --artifact` must win over <APP>_ARTIFACT on EVERY spec
    path, and a war demand that a bare commit cannot satisfy must refuse at
    set time — not write a pin that bricks every later build."""

    def test_set_branch_artifact_source_beats_a_war_setting(self, mk_runner) -> None:
        r = mk_runner("CARLOS_ARTIFACT=war\n")
        _gh(r, [_rel("2026.08.0", assets=_war_assets("2026.08.0"))])
        assert cmd_source(r, ["set", "develop", "--artifact", "source"]) == 0
        pin = read_pin(r, CARLOS)
        assert (pin.kind, pin.branch, pin.artifact) == ("branch", "develop", "source")

    def test_set_sha_refuses_when_the_setting_demands_war(self, mk_runner) -> None:
        r = mk_runner("CARLOS_ARTIFACT=war\n")
        with pytest.raises(CtlError, match="--artifact source"):
            cmd_source(r, ["set", "f" * 40])
        assert read_pin(r, CARLOS) is None  # nothing half-written

    def test_set_sha_artifact_source_overrides_the_war_setting_and_warns(
        self, mk_runner, capsys
    ) -> None:
        r = mk_runner("CARLOS_ARTIFACT=war\n")
        assert cmd_source(r, ["set", "f" * 40, "--artifact", "source"]) == 0
        assert read_pin(r, CARLOS).artifact == "source"
        # The persistent setting will still force war at build time and this
        # pin has no WAR — the operator must hear that NOW.
        assert "REFUSE" in capsys.readouterr().err

    def test_set_tag_artifact_source_keeps_the_war_data(self, mk_runner, capsys) -> None:
        # The one-run-override contract: flipping back to the WAR later must
        # not need the network, so a forced-source release pin keeps url+sha.
        r = mk_runner()
        _gh(r, [_rel("2026.08.0", assets=_war_assets("2026.08.0"))])
        assert cmd_source(r, ["set", "2026.08.0", "--artifact", "source"]) == 0
        pin = read_pin(r, CARLOS)
        assert pin.artifact == "source"
        assert pin.war_url.endswith("carlos-2026.08.0.war")
        assert pin.war_sha256 == _WAR_SHA


class TestArtifactEnumValidation:
    """<APP>_ARTIFACT is a closed enum — a typo must fail loudly, not silently
    select an artifact the operator did not choose."""

    @pytest.mark.parametrize("bad", ["Source", "WAR", "True", "1", "tarball"])
    def test_unrecognized_artifact_value_is_refused(self, mk_runner, bad) -> None:
        r = mk_runner(f"CARLOS_ARTIFACT={bad}\nCARLOS_REF=develop\n")
        with pytest.raises(CtlError, match="not a recognized artifact"):
            resolve_for_build(r, CARLOS)

    def test_the_three_valid_values_pass(self, mk_runner) -> None:
        for good in ("auto", "source"):
            r = mk_runner(f"CARLOS_ARTIFACT={good}\nCARLOS_REF=develop\n")
            assert resolve_for_build(r, CARLOS).artifact == "source"
        r = mk_runner(
            "CARLOS_ARTIFACT=war\nCARLOS_REF=develop\n"
            f"CARLOS_WAR_URL=https://x/x.war\nCARLOS_WAR_SHA256={_WAR_SHA}\n"
        )
        assert resolve_for_build(r, CARLOS).artifact == "war"


class TestPinPlausibilityValidation:
    """read_pin rejects pins write_pin cannot produce (corruption/hand edits)
    so a bad value degrades to a clean re-resolve, never a --build-arg like
    CARLOS_REF=None dying deep inside podman."""

    def _write_raw(self, r, **fields) -> None:
        import json as _json

        base = dict(v=1, ref=_SHA, kind="manual", tag="", branch="", commit=_SHA,
                    artifact="source", war_url="", war_sha256="",
                    resolved_at="", policy="manual")
        base.update(fields)
        path = source_mod.pin_path(r, CARLOS)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_json.dumps(base))

    @pytest.mark.parametrize("fields", [
        {"ref": None},                       # str(None) -> "None": not a sha
        {"ref": "develop"},                  # persisted pins are commit-pinned
        {"kind": "releaseX"},
        {"artifact": "war", "war_url": "", "war_sha256": ""},
        {"artifact": "war", "war_url": "https://x/x.war", "war_sha256": "short"},
    ])
    def test_implausible_pins_degrade_to_none(self, mk_runner, capsys, fields) -> None:
        r = mk_runner()
        self._write_raw(r, **fields)
        assert read_pin(r, CARLOS) is None
        assert "implausible" in capsys.readouterr().err

    def test_a_plausible_war_pin_still_reads(self, mk_runner) -> None:
        r = mk_runner()
        self._write_raw(r, artifact="war", war_url="https://x/x.war",
                        war_sha256=_WAR_SHA)
        assert read_pin(r, CARLOS).artifact == "war"


class TestShowReportsArtifactOverride:
    def test_forced_source_over_a_war_pin_is_reported(self, mk_runner, capsys) -> None:
        r = mk_runner("CARLOS_ARTIFACT=source\n")
        write_pin(r, CARLOS, SourcePin(ref=_SHA, kind="release", tag="2026.08.0",
                                       commit=_SHA, artifact="war",
                                       war_url="https://x/x.war",
                                       war_sha256=_WAR_SHA), implicit=False)
        assert cmd_source(r, ["show"]) == 0
        assert "overrides the pinned artifact" in capsys.readouterr().out

    def test_forced_war_over_a_warless_pin_warns_refusal(self, mk_runner, capsys) -> None:
        r = mk_runner("CARLOS_ARTIFACT=war\n")
        write_pin(r, CARLOS, SourcePin(ref=_SHA, kind="branch", branch="main",
                                       commit=_SHA, artifact="source"),
                  implicit=False)
        assert cmd_source(r, ["show"]) == 0
        assert "REFUSE" in capsys.readouterr().err


class TestUpdateAtomicityAndAllManual:
    def test_all_manual_update_says_nothing_to_update(self, mk_runner, capsys) -> None:
        r = mk_runner("CARLOS_REF=develop\nDRUGREF_REF=master\n")
        assert cmd_source(r, ["update"]) == 0
        cap = capsys.readouterr()
        assert "nothing to update" in cap.out
        assert "rebuild" not in cap.out  # no pointless redeploy suggestion

    def test_update_writes_nothing_when_the_second_app_fails(self, mk_runner) -> None:
        # CARLOS resolves fine; DrugRef's API is not scripted (offline) — the
        # CARLOS pin must NOT have moved (resolve-all-then-write-all).
        r = mk_runner()
        old = SourcePin(ref="e" * 40, kind="release", tag="2026.07.0",
                        commit="e" * 40, artifact="source")
        write_pin(r, CARLOS, old, implicit=False)
        _gh(r, [_rel("2026.08.0", assets=_war_assets("2026.08.0"))])
        with pytest.raises(CtlError):
            cmd_source(r, ["update"])
        assert read_pin(r, CARLOS) == old


class TestReleasePagination:
    """The releases endpoint orders by created_at with no sort parameter and
    pages at 100 — every page must be fetched before filtering/sorting, or an
    older tag falls off page 1 and `set` misreads it as a branch."""

    def _page(self, n, tags):
        return json.dumps([_rel(t, published=f"2026-01-{n:02d}T00:00:00Z") for t in tags])

    def test_all_pages_are_fetched_before_matching_a_tag(self, mk_runner) -> None:
        r = mk_runner()
        page1 = [f"v{i}" for i in range(100)]  # a full page forces page 2
        r.script(
            "api.github.com/repos/carlos-emr/carlos/releases?per_page=100&page=1",
            out=json.dumps([_rel(t, published="2026-02-01T00:00:00Z") for t in page1]),
        )
        r.script(
            "api.github.com/repos/carlos-emr/carlos/releases?per_page=100&page=2",
            out=json.dumps([_rel("old-tag", published="2025-01-01T00:00:00Z")]),
        )
        r.script(
            "api.github.com/repos/carlos-emr/carlos/commits/",
            out=json.dumps({"sha": _SHA}),
        )
        assert cmd_source(r, ["set", "old-tag"]) == 0
        pin = read_pin(r, CARLOS)
        assert (pin.kind, pin.tag) == ("release", "old-tag")  # NOT a branch

    def test_newest_by_published_at_can_live_on_a_later_page(self, mk_runner) -> None:
        # GitHub pages by created_at; the newest published_at is not
        # guaranteed on page 1.
        r = mk_runner()
        page1 = [_rel(f"v{i}", published="2026-01-01T00:00:00Z") for i in range(100)]
        r.script(
            "api.github.com/repos/carlos-emr/carlos/releases?per_page=100&page=1",
            out=json.dumps(page1),
        )
        r.script(
            "api.github.com/repos/carlos-emr/carlos/releases?per_page=100&page=2",
            out=json.dumps([_rel("republished", published="2026-06-01T00:00:00Z")]),
        )
        r.script(
            "api.github.com/repos/carlos-emr/carlos/commits/",
            out=json.dumps({"sha": _SHA}),
        )
        assert resolve_policy(r, CARLOS).tag == "republished"

    def test_a_failing_later_page_reads_as_unreachable(self, mk_runner) -> None:
        # A silently truncated list could mispick — "unreachable" is honest.
        r = mk_runner()
        r.script(
            "api.github.com/repos/carlos-emr/carlos/releases?per_page=100&page=1",
            out=json.dumps([_rel(f"v{i}") for i in range(100)]),
        )
        # page 2 unscripted -> curl fails
        with pytest.raises(CtlError, match="source set"):
            resolve_policy(r, CARLOS)


class TestPairAtomicResolution:
    def test_build_pair_resolve_writes_no_pin_when_the_second_app_fails(
        self, mk_runner
    ) -> None:
        # CARLOS resolves; DrugRef's API is down mid-pair — the CARLOS pin
        # must NOT be persisted (no half-pinned pair for a later build).
        r = mk_runner()
        _gh(r, [_rel("2026.08.0", assets=_war_assets("2026.08.0"))])
        with pytest.raises(CtlError):
            source_mod.resolve_pair_for_build(r)
        assert read_pin(r, CARLOS) is None
        assert read_pin(r, DRUGREF) is None

    def test_build_pair_resolve_persists_both_on_success(self, mk_runner) -> None:
        r = mk_runner()
        _gh(r, [_rel("2026.08.0", assets=_war_assets("2026.08.0"))])
        _gh_dr(r, [_dr_rel("v1.0.0rc2")])
        pin, dpin = source_mod.resolve_pair_for_build(r)
        assert read_pin(r, CARLOS) == pin
        assert read_pin(r, DRUGREF) == dpin

    def test_update_rolls_back_the_first_pin_when_a_later_write_fails(
        self, mk_runner, monkeypatch, capsys
    ) -> None:
        r = mk_runner()
        old_pin = SourcePin(ref="e" * 40, kind="release", tag="2026.07.0",
                            commit="e" * 40, artifact="source")
        write_pin(r, CARLOS, old_pin, implicit=False)
        _gh(r, [_rel("2026.08.0", assets=_war_assets("2026.08.0"))])
        _gh_dr(r, [_dr_rel("v1.0.0rc2")])

        real = source_mod.write_pin
        calls = {"n": 0}

        def failing_second_explicit(runner, app, pin, *, implicit):
            if not implicit:
                calls["n"] += 1
                if calls["n"] == 2:
                    raise CtlError("disk full")
            return real(runner, app, pin, implicit=implicit)

        monkeypatch.setattr(source_mod, "write_pin", failing_second_explicit)
        with pytest.raises(CtlError, match="disk full"):
            cmd_source(r, ["update"])
        # The CARLOS pin was restored to its previous state, not left moved.
        assert read_pin(r, CARLOS) == old_pin
        assert "rolled back" in capsys.readouterr().err


class TestUnreadablePinWarns:
    def test_an_existing_but_unreadable_pin_warns(self, mk_runner, capsys) -> None:
        # The docstring promises a warning: a PermissionError/IsADirectoryError
        # on an EXISTING pin silently re-resolving would be undetectable drift.
        r = mk_runner()
        path = source_mod.pin_path(r, CARLOS)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.mkdir()  # a directory -> read_text raises IsADirectoryError
        assert read_pin(r, CARLOS) is None
        assert "could not be read" in capsys.readouterr().err

    def test_an_absent_pin_stays_silent(self, mk_runner, capsys) -> None:
        assert read_pin(mk_runner(), CARLOS) is None
        assert capsys.readouterr().err == ""


_IMG_DIGEST = "sha256:" + "e" * 64


def _ghcr(r, *, tag=None, digest=_IMG_DIGEST, repo="carlos-emr/carlos-app"):
    """Script the ghcr endpoints resolve_image_digest touches, modelling the
    real registry's behavior: the unauthenticated manifest HEAD answers a 401
    Bearer challenge; the token realm grants an anonymous pull token; the
    authorized retry carries the digest header."""
    # Insertion order matters for the FakeRunner substring match: the
    # authorized retry's argv contains BOTH the bearer token and the manifest
    # URL, so the more specific script must come first.
    r.script(
        "Authorization: Bearer anon-token",
        out=f"HTTP/2 200\nDocker-Content-Digest: {digest}\ncontent-length: 3\n",
    )
    r.script("ghcr.io/token", out=json.dumps({"token": "anon-token"}))
    path = f"ghcr.io/v2/{repo}/manifests/" + (tag or "")
    r.script(path, out=(
        'HTTP/2 401\nWww-Authenticate: Bearer realm="https://ghcr.io/token",'
        f'service="ghcr.io",scope="repository:{repo}:pull"\n'
    ))


class TestImageArtifact:
    """<APP>_ARTIFACT=image: the opt-in prebuilt-image mode. The stakes: the
    digest recorded here is the ONLY integrity anchor of what a PHI host will
    run — a pin without it, or a silently wrong one, defeats the entire
    tag-for-humans/digest-for-trust model."""

    def test_image_pin_round_trips(self, mk_runner) -> None:
        r = mk_runner()
        pin = SourcePin(
            ref=_SHA, kind="prerelease", tag="2026.08.0-alpha2", commit=_SHA,
            artifact="image", image_ref="ghcr.io/carlos-emr/carlos-app:2026.08.0-alpha2",
            image_digest=_IMG_DIGEST,
        )
        write_pin(r, CARLOS, pin, implicit=False)
        got = read_pin(r, CARLOS)
        assert got is not None
        assert (got.artifact, got.image_ref, got.image_digest) == (
            "image", pin.image_ref, pin.image_digest)

    @pytest.mark.parametrize("bad", ["", "e" * 64, "sha256:" + "e" * 63, "sha256:xyz"])
    def test_image_pin_without_valid_digest_degrades(self, mk_runner, capsys, bad) -> None:
        # An image pin that cannot be pulled-by-digest must degrade to
        # re-resolve exactly like a WAR pin missing its sha256 — never crash,
        # never pull by mutable tag.
        r = mk_runner()
        write_pin(r, CARLOS, SourcePin(
            ref=_SHA, kind="release", tag="t", commit=_SHA, artifact="image",
            image_ref="ghcr.io/carlos-emr/carlos-app:t", image_digest=bad,
        ), implicit=False)
        assert read_pin(r, CARLOS) is None
        assert "implausible" in capsys.readouterr().err

    def test_resolve_image_digest_happy_path(self, mk_runner) -> None:
        r = mk_runner()
        _ghcr(r, tag="2026.08.0")
        got = source_mod.resolve_image_digest(
            r, "ghcr.io/carlos-emr/carlos-app", "2026.08.0")
        assert got == _IMG_DIGEST
        # Every manifest probe must be a HEAD (-I): the digest header is the
        # answer, the body is never needed. The first probe is deliberately
        # NOT -f (a 401 must still yield its challenge headers).
        head_calls = [c for c in r.calls if any("manifests" in a for a in c)]
        assert len(head_calls) == 2
        assert "-sSI" in head_calls[0] and "-fsSI" in head_calls[1]
        # The token came from the ADVERTISED realm, not a hardcoded endpoint.
        assert any("ghcr.io/token?service=ghcr.io" in a for c in r.calls for a in c)

    def test_resolve_image_digest_failures_return_empty(self, mk_runner) -> None:
        # Unreachable registry (nothing scripted -> empty curl output).
        r = mk_runner()
        assert source_mod.resolve_image_digest(r, "ghcr.io/x/y", "t") == ""
        # Token ok but manifest HEAD fails (404 -> curl -f rc 22, no output).
        r2 = mk_runner()
        r2.script("ghcr.io/token", out=json.dumps({"token": "anon"}))
        r2.script("ghcr.io/v2/x/y/manifests/t", rc=22, out="")
        assert source_mod.resolve_image_digest(r2, "ghcr.io/x/y", "t") == ""
        # Malformed digest header is refused, not propagated.
        r3 = mk_runner()
        r3.script("ghcr.io/token", out=json.dumps({"token": "anon"}))
        r3.script("ghcr.io/v2/x/y/manifests/t",
                  out="docker-content-digest: sha256:notahexdigest\n")
        assert source_mod.resolve_image_digest(r3, "ghcr.io/x/y", "t") == ""

    def test_resolve_image_digest_anonymous_registry_skips_the_token_dance(self, mk_runner) -> None:
        # A mirror that answers the unauthenticated HEAD outright needs no
        # token round-trip at all.
        r = mk_runner()
        r.script("mirror.internal/v2/x/y/manifests/t",
                 out=f"HTTP/2 200\ndocker-content-digest: {_IMG_DIGEST}\n")
        assert source_mod.resolve_image_digest(r, "mirror.internal/x/y", "t") == _IMG_DIGEST
        assert not any("token" in a for c in r.calls for a in c)

    def test_resolve_image_digest_follows_the_advertised_realm(self, mk_runner) -> None:
        # A non-ghcr mirror advertising its own bearer realm and answering
        # with access_token (both allowed by the distribution spec).
        r = mk_runner()
        r.script("Authorization: Bearer mirror-tok",
                 out=f"HTTP/2 200\ndocker-content-digest: {_IMG_DIGEST}\n")
        r.script("auth.mirror.internal/grant", out=json.dumps({"access_token": "mirror-tok"}))
        r.script("mirror.internal/v2/x/y/manifests/t", out=(
            'HTTP/2 401\nWWW-Authenticate: Bearer realm="https://auth.mirror.internal/grant",'
            'service="mirror.internal"\n'
        ))
        assert source_mod.resolve_image_digest(r, "mirror.internal/x/y", "t") == _IMG_DIGEST
        assert any("auth.mirror.internal/grant?service=mirror.internal" in a
                   for c in r.calls for a in c)

    def test_resolve_image_digest_refuses_a_plaintext_realm(self, mk_runner) -> None:
        r = mk_runner()
        r.script("mirror.internal/v2/x/y/manifests/t", out=(
            'HTTP/2 401\nWWW-Authenticate: Bearer realm="http://evil.example/token"\n'
        ))
        assert source_mod.resolve_image_digest(r, "mirror.internal/x/y", "t") == ""

    def test_image_repo_with_tag_or_digest_is_refused(self, mk_runner) -> None:
        for bad in ("ghcr.io/x/y:latest", "ghcr.io/x/y@sha256:" + "e" * 64, "",
                    "ghcr.io"):
            r = mk_runner(f"CARLOS_ARTIFACT=image\nCARLOS_IMAGE_REPO={bad}\n"
                          f"CARLOS_IMAGE_DIGEST={'e' * 64}\nCARLOS_REF=sometag\n")
            with pytest.raises(CtlError, match="bare registry repository"):
                resolve_for_build(r, CARLOS)

    def test_policy_resolve_under_image_records_digest_and_keeps_war(self, mk_runner) -> None:
        tag = "2026.08.0"
        r = mk_runner("CARLOS_ARTIFACT=image\n")
        _gh(r, [_rel(tag, assets=_war_assets(tag))])
        _ghcr(r, tag=tag)
        pin = resolve_policy(r, CARLOS)
        assert pin.artifact == "image"
        assert pin.image_ref == f"ghcr.io/carlos-emr/carlos-app:{tag}"
        assert pin.image_digest == _IMG_DIGEST
        # The WAR url+sha ride along so flipping <APP>_ARTIFACT back to
        # war/auto later stays offline (the forced-source contract's twin).
        assert pin.war_url and pin.war_sha256 == _WAR_SHA

    def test_missing_published_image_refuses_with_guidance(self, mk_runner) -> None:
        tag = "2026.08.0"
        r = mk_runner("CARLOS_ARTIFACT=image\n")
        _gh(r, [_rel(tag, assets=_war_assets(tag))])
        # ghcr endpoints not scripted -> no digest resolvable.
        with pytest.raises(CtlError, match="no published image .*Publish Images"):
            resolve_policy(r, CARLOS)

    def test_branch_fallback_refuses_image(self, mk_runner) -> None:
        r = mk_runner("CARLOS_ARTIFACT=image\n")
        _gh(r, [])
        with pytest.raises(CtlError, match="cannot be satisfied from a branch"):
            resolve_policy(r, CARLOS)

    def test_manual_ref_image_requires_explicit_digest(self, mk_runner) -> None:
        r = mk_runner("CARLOS_REF=2026.08.0\nCARLOS_ARTIFACT=image\n")
        with pytest.raises(CtlError, match="CARLOS_IMAGE_DIGEST"):
            resolve_for_build(r, CARLOS)

    def test_manual_ref_image_is_offline_and_normalizes_bare_hex(self, mk_runner) -> None:
        r = mk_runner(
            "CARLOS_REF=2026.08.0\nCARLOS_ARTIFACT=image\n"
            f"CARLOS_IMAGE_DIGEST={'e' * 64}\n"
        )
        pin = resolve_for_build(r, CARLOS)
        assert pin.artifact == "image" and pin.kind == "manual"
        assert pin.image_digest == _IMG_DIGEST
        assert pin.image_ref == "ghcr.io/carlos-emr/carlos-app:2026.08.0"
        assert not _api_calls(r)  # the air-gap channel never touches the network

    def test_forced_image_on_a_pin_without_digest_refuses(self, mk_runner) -> None:
        # A pin resolved before the flip carries no digest — the only honest
        # path is a re-resolve, said explicitly (never a tag pull).
        r = mk_runner("CARLOS_ARTIFACT=image\n")
        write_pin(r, CARLOS, SourcePin(
            ref=_SHA, kind="release", tag="2026.08.0", commit=_SHA, artifact="source",
        ), implicit=False)
        with pytest.raises(CtlError, match="carries no image digest.*source update"):
            resolve_for_build(r, CARLOS)

    def test_forced_image_on_a_pin_with_digest_overrides_for_the_run(self, mk_runner) -> None:
        r = mk_runner("CARLOS_ARTIFACT=image\n")
        write_pin(r, CARLOS, SourcePin(
            ref=_SHA, kind="release", tag="t", commit=_SHA, artifact="war",
            war_url="https://x/y.war", war_sha256=_WAR_SHA,
            image_ref="ghcr.io/carlos-emr/carlos-app:t", image_digest=_IMG_DIGEST,
        ), implicit=False)
        pin = resolve_for_build(r, CARLOS)
        assert pin.artifact == "image"
        assert not _api_calls(r)

    def test_source_set_release_with_artifact_image(self, mk_runner) -> None:
        tag = "2026.08.0"
        r = mk_runner()
        _gh(r, [_rel(tag, assets=_war_assets(tag))])
        _ghcr(r, tag=tag)
        assert cmd_source(r, ["set", tag, "--artifact", "image"]) == 0
        pin = read_pin(r, CARLOS)
        assert pin is not None and pin.artifact == "image"
        assert pin.image_digest == _IMG_DIGEST

    def test_source_set_sha_with_artifact_image_refuses(self, mk_runner) -> None:
        r = mk_runner()
        with pytest.raises(CtlError, match="prebuilt image"):
            cmd_source(r, ["set", "f" * 40, "--artifact", "image"])

    def test_source_set_branch_with_artifact_image_refuses(self, mk_runner) -> None:
        r = mk_runner()
        _gh(r, [])
        with pytest.raises(CtlError, match="--artifact image needs a release"):
            cmd_source(r, ["set", "develop", "--artifact", "image"])

    def test_show_warns_when_forced_image_lacks_a_digest(self, mk_runner, capsys) -> None:
        r = mk_runner("CARLOS_ARTIFACT=image\n")
        write_pin(r, CARLOS, SourcePin(
            ref=_SHA, kind="release", tag="t", commit=_SHA, artifact="source",
        ), implicit=False)
        assert cmd_source(r, ["show"]) == 0
        assert "builds will REFUSE" in capsys.readouterr().err
