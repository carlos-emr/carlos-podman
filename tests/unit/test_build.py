# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Unit tests for `carlos-ctl build`: supply-chain ref gating and the build
posture marker the monitor's unpinned-build nag reads (findings 5, 43)."""

from __future__ import annotations

import pytest

from carlos_ctl.build import cmd_build
from carlos_ctl.util import CtlError

_SHA = "a" * 40


def _seed_build_ctx(runner) -> None:
    d = runner.settings.emr_home / "build"
    d.mkdir(parents=True, exist_ok=True)
    (d / "Containerfile").write_text("FROM scratch\n")
    (d / "Containerfile.drugref").write_text("FROM scratch\n")


class TestNofileWarning:
    """G2: warn before a long build when the nofile hard limit is below the
    verified-working floor (the Maven build dies with 'Too many open files')."""

    def test_low_hard_limit_warns(self, mk_runner, capsys, monkeypatch) -> None:
        import carlos_ctl.build as build_mod

        r = mk_runner("CARLOS_REF=" + "a" * 40 + "\nDRUGREF_REF=" + "b" * 40 + "\n")
        _seed_build_ctx(r)
        monkeypatch.setattr(build_mod.resource, "getrlimit", lambda _: (1024, 1024))
        assert cmd_build(r, []) == 0
        assert "Too many open files" in capsys.readouterr().err

    def test_high_hard_limit_is_quiet(self, mk_runner, capsys, monkeypatch) -> None:
        import carlos_ctl.build as build_mod

        r = mk_runner("CARLOS_REF=" + "a" * 40 + "\nDRUGREF_REF=" + "b" * 40 + "\n")
        _seed_build_ctx(r)
        monkeypatch.setattr(build_mod.resource, "getrlimit", lambda _: (1024, 65536))
        assert cmd_build(r, []) == 0
        assert "Too many open files" not in capsys.readouterr().err

    def test_verified_floor_is_quiet_and_below_it_warns(self, mk_runner, capsys) -> None:
        """4096 is the verified floor for the forked-compiler Containerfile —
        quiet at the floor, warn below it."""
        r = mk_runner("CARLOS_REF=" + "a" * 40 + "\nDRUGREF_REF=" + "b" * 40 + "\n")
        _seed_build_ctx(r)
        r.script("runuser", out="4096\n")
        assert cmd_build(r, []) == 0
        assert "Too many open files" not in capsys.readouterr().err
        r2 = mk_runner("CARLOS_REF=" + "a" * 40 + "\nDRUGREF_REF=" + "b" * 40 + "\n")
        _seed_build_ctx(r2)
        r2.script("runuser", out="2048\n")
        assert cmd_build(r2, []) == 0
        assert "Too many open files" in capsys.readouterr().err


class TestNofileUlimitForwarding:
    """The build must pass --ulimit nofile explicitly (the QUICKSTART manual
    path always did): a 4096 limit was observed killing the Maven build, and
    relying on the engine default silently inherits whatever the service
    user's session happens to carry."""

    def test_ulimit_capped_at_service_user_hard_limit(self, mk_runner) -> None:
        r = mk_runner("CARLOS_REF=" + "a" * 40 + "\nDRUGREF_REF=" + "b" * 40 + "\n")
        _seed_build_ctx(r)
        r.script("runuser", out="4096\n")
        assert cmd_build(r, []) == 0
        assert r.called_with("--ulimit", "nofile=4096:4096")

    def test_ulimit_targets_65536_when_unlimited(self, mk_runner) -> None:
        r = mk_runner("CARLOS_REF=" + "a" * 40 + "\nDRUGREF_REF=" + "b" * 40 + "\n")
        _seed_build_ctx(r)
        r.script("runuser", out="unlimited\n")
        assert cmd_build(r, []) == 0
        assert r.called_with("--ulimit", "nofile=65536:65536")

    def test_ulimit_never_exceeds_the_target(self, mk_runner) -> None:
        r = mk_runner("CARLOS_REF=" + "a" * 40 + "\nDRUGREF_REF=" + "b" * 40 + "\n")
        _seed_build_ctx(r)
        r.script("runuser", out="1048576\n")
        assert cmd_build(r, []) == 0
        assert r.called_with("--ulimit", "nofile=65536:65536")


class TestExtraCaBundle:
    """G3: CARLOS_EXTRA_CA_BUNDLE stages a PEM into the build context for the
    build-stage trust store, then restores the neutral empty placeholder."""

    def _ctx_file(self, r):
        return r.settings.emr_home / "build" / ".extra-ca-bundle.crt"

    def test_bundle_staged_during_build_then_cleared(
        self, mk_runner, monkeypatch, tmp_path
    ) -> None:

        pem = tmp_path / "proxy-ca.pem"
        pem.write_text("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
        r = mk_runner(
            "CARLOS_REF=" + "a" * 40 + "\nDRUGREF_REF=" + "b" * 40 + "\n",
            {"CARLOS_EXTRA_CA_BUNDLE": str(pem)},
        )
        _seed_build_ctx(r)
        ctx = self._ctx_file(r)
        ctx.write_text("")  # placeholder present, as the role ships it

        seen = {}
        real = r.podman_user

        def spy(args, **kw):
            if list(args)[:1] == ["build"]:
                seen["content_at_build"] = ctx.read_text()
            return real(args, **kw)

        monkeypatch.setattr(r, "podman_user", spy)
        assert cmd_build(r, []) == 0
        # The bundle was present in the context at build time...
        assert "BEGIN CERTIFICATE" in seen.get("content_at_build", "")
        # ...and restored to the neutral empty state afterward.
        assert ctx.read_text() == ""

    def test_unreadable_bundle_refuses_before_any_build(
        self, mk_runner
    ) -> None:
        r = mk_runner(
            "CARLOS_REF=" + "a" * 40 + "\nDRUGREF_REF=" + "b" * 40 + "\n",
            {"CARLOS_EXTRA_CA_BUNDLE": "/no/such/ca.pem"},
        )
        _seed_build_ctx(r)
        with pytest.raises(CtlError, match="CARLOS_EXTRA_CA_BUNDLE"):
            cmd_build(r, [])
        assert not any(list(c)[:1] == ["build"] for c in r.calls)

    def test_unset_writes_empty_placeholder(self, mk_runner) -> None:
        r = mk_runner("CARLOS_REF=" + "a" * 40 + "\nDRUGREF_REF=" + "b" * 40 + "\n")
        _seed_build_ctx(r)
        assert cmd_build(r, []) == 0
        assert self._ctx_file(r).read_text() == ""


class TestBuild:
    def test_dev_build_records_dev_posture_and_warns(self, mk_runner, capsys) -> None:
        # A moving branch ref is allowed in dev mode but must warn AND leave a
        # 'dev' marker the monitor nag reads.
        r = mk_runner("CARLOS_REF=develop\nDRUGREF_REF=main\n")
        _seed_build_ctx(r)
        assert cmd_build(r, []) == 0
        assert "not a full commit SHA" in capsys.readouterr().err
        assert (r.settings.emr_home / "build" / ".build-mode").read_text().strip() == "dev"

    def test_release_build_records_release_posture(self, mk_runner) -> None:
        r = mk_runner(
            f"CARLOS_REF={_SHA}\nDRUGREF_REF={_SHA}\n"
            "CARLOS_SRC_SHA256=deadbeef\nDRUGREF_SRC_SHA256=deadbeef\n"
            "SOURCE_DATE_EPOCH=1751500000\n",
            {"CARLOS_BUILD_MODE": "release"},
        )
        _seed_build_ctx(r)
        assert cmd_build(r, []) == 0
        assert (r.settings.emr_home / "build" / ".build-mode").read_text().strip() == "release"

    def test_release_build_refuses_moving_ref(self, mk_runner) -> None:
        r = mk_runner(
            "CARLOS_REF=develop\nDRUGREF_REF=main\n",
            {"CARLOS_BUILD_MODE": "release"},
        )
        _seed_build_ctx(r)
        with pytest.raises(CtlError, match="not a full 40-hex commit"):
            cmd_build(r, [])

    def test_release_build_refuses_missing_source_checksum(self, mk_runner) -> None:
        r = mk_runner(
            f"CARLOS_REF={_SHA}\nDRUGREF_REF={_SHA}\n",
            {"CARLOS_BUILD_MODE": "release"},
        )
        _seed_build_ctx(r)
        with pytest.raises(CtlError, match="CARLOS_SRC_SHA256 is unset"):
            cmd_build(r, [])

    def test_missing_containerfile_refused(self, mk_runner) -> None:
        r = mk_runner(f"CARLOS_REF={_SHA}\nDRUGREF_REF={_SHA}\n")
        with pytest.raises(CtlError, match="no Containerfile"):
            cmd_build(r, [])

    def test_rejects_unknown_arg(self, mk_runner) -> None:
        r = mk_runner()
        with pytest.raises(CtlError, match="usage"):
            cmd_build(r, ["--frobnicate"])


class TestBuildSmokeAndEpoch:
    def test_smoke_runs_before_any_tag_moves(self, mk_runner) -> None:
        # C25: the WAR-presence smoke must precede :previous/:latest retags.
        r = mk_runner("CARLOS_REF=develop\nDRUGREF_REF=main\n")
        _seed_build_ctx(r)
        assert cmd_build(r, []) == 0
        smoke_i = next(i for i, c in enumerate(r.calls)
                       if "--entrypoint" in c and "/usr/bin/test" in c)
        tag_i = next(i for i, c in enumerate(r.calls) if "tag" in c[:2] or
                     (len(c) > 1 and c[1] == "tag"))
        assert smoke_i < tag_i
        assert any("/usr/local/tomcat/webapps/carlos/WEB-INF" in c for c in r.calls)
        assert any("/usr/local/tomcat/webapps/drugref2/WEB-INF" in c for c in r.calls)

    def test_failed_smoke_aborts_without_promoting(self, mk_runner) -> None:
        r = mk_runner("CARLOS_REF=develop\nDRUGREF_REF=main\n")
        _seed_build_ctx(r)
        r.script("podman", "run", rc=1)
        with pytest.raises(CtlError, match="post-build smoke FAILED"):
            cmd_build(r, [])
        assert not any(len(c) > 1 and c[1] == "tag" for c in r.calls)

    def test_release_requires_source_date_epoch(self, mk_runner) -> None:
        r = mk_runner(
            f"CARLOS_REF={_SHA}\nDRUGREF_REF={_SHA}\n"
            "CARLOS_SRC_SHA256=deadbeef\nDRUGREF_SRC_SHA256=deadbeef\n",
            {"CARLOS_BUILD_MODE": "release"},
        )
        _seed_build_ctx(r)
        with pytest.raises(CtlError, match="SOURCE_DATE_EPOCH is unset"):
            cmd_build(r, [])

    def test_epoch_forwarded_as_build_arg_when_set(self, mk_runner) -> None:
        r = mk_runner(
            "CARLOS_REF=develop\nDRUGREF_REF=main\nSOURCE_DATE_EPOCH=1751500000\n"
        )
        _seed_build_ctx(r)
        assert cmd_build(r, []) == 0
        assert any("SOURCE_DATE_EPOCH=1751500000" in " ".join(c) for c in r.calls)

    def test_epoch_omitted_when_unset(self, mk_runner) -> None:
        r = mk_runner("CARLOS_REF=develop\nDRUGREF_REF=main\n")
        _seed_build_ctx(r)
        assert cmd_build(r, []) == 0
        assert not any("SOURCE_DATE_EPOCH" in " ".join(c) for c in r.calls)


class TestBuildContextKnobs:
    """CARLOS_BUILD_DIR / CARLOS_EXTRA_CA_BUNDLE used to be read from
    os.environ ONLY, so setting them in carlos-app.env — the documented
    configuration surface — both warned "carlos-ctl does not read this key"
    and silently did nothing. On a host behind a TLS-inspecting proxy that
    meant the Maven fetch still died on PKIX, twenty minutes in."""

    def test_build_dir_is_read_from_the_env_file(self, mk_runner, tmp_path) -> None:
        from carlos_ctl.build import _build_dir

        ctx = tmp_path / "checkout"
        ctx.mkdir()
        r = mk_runner(f"CARLOS_BUILD_DIR={ctx}\n")
        assert _build_dir(r) == ctx

    def test_build_dir_still_reads_the_process_env(self, mk_runner, tmp_path) -> None:
        from carlos_ctl.build import _build_dir

        ctx = tmp_path / "checkout2"
        ctx.mkdir()
        r = mk_runner("", {"CARLOS_BUILD_DIR": str(ctx)})
        assert _build_dir(r) == ctx

    def test_env_file_knobs_are_registered_and_do_not_warn(self, mk_runner, capsys) -> None:
        from carlos_ctl.config import known_keys

        assert {"CARLOS_BUILD_DIR", "CARLOS_EXTRA_CA_BUNDLE"} <= known_keys()
        mk_runner("CARLOS_BUILD_DIR=/x\nCARLOS_EXTRA_CA_BUNDLE=/y.pem\n")
        assert "does not read" not in capsys.readouterr().err


class TestSourcePinIntegration:
    """`build` builds what carlos_ctl.source resolved: the sticky pin under
    CARLOS_REF=auto (offline once pinned), WAR-artifact stage selection, and
    the artifact-aware release gate."""

    def _pin(self, r, app=None, **kw) -> None:
        from carlos_ctl.source import CARLOS, SourcePin, write_pin

        defaults = dict(ref=_SHA, kind="release", tag="2026.08.0", commit=_SHA,
                        artifact="source")
        defaults.update(kw)
        write_pin(r, app or CARLOS, SourcePin(**defaults), implicit=False)

    def test_auto_build_uses_the_pinned_sha_offline(self, mk_runner) -> None:
        r = mk_runner(f"DRUGREF_REF={'b' * 40}\n")  # CARLOS_REF defaults to auto
        _seed_build_ctx(r)
        self._pin(r)
        assert cmd_build(r, []) == 0
        assert r.called_with(f"CARLOS_REF={_SHA}")
        assert not any("api.github.com" in a for c in r.calls for a in c)

    def test_auto_build_without_pin_refuses_offline_with_guidance(self, mk_runner) -> None:
        r = mk_runner(f"DRUGREF_REF={'b' * 40}\n")  # no pin, curl unscripted
        _seed_build_ctx(r)
        with pytest.raises(CtlError, match="source set"):
            cmd_build(r, [])
        assert not any(list(c)[:1] == ["build"] for c in r.calls)

    def test_war_pin_selects_the_download_stage(self, mk_runner) -> None:
        r = mk_runner(f"DRUGREF_REF={'b' * 40}\n")
        _seed_build_ctx(r)
        self._pin(r, artifact="war", war_url="https://x/carlos-2026.08.0.war",
                  war_sha256="d" * 64)
        assert cmd_build(r, []) == 0
        build = next(c for c in r.calls if "build" in c and "-f" in c)
        assert "CARLOS_WAR_URL=https://x/carlos-2026.08.0.war" in build
        assert f"CARLOS_WAR_SHA256={'d' * 64}" in build
        assert "CARLOS_WAR_STAGE=download" in build

    def test_source_pin_passes_no_war_args(self, mk_runner) -> None:
        # ARG defaults must keep selecting the compile stage — the manual
        # QUICKSTART recipe depends on it.
        r = mk_runner(f"DRUGREF_REF={'b' * 40}\n")
        _seed_build_ctx(r)
        self._pin(r)
        assert cmd_build(r, []) == 0
        assert not any("CARLOS_WAR" in a for c in r.calls for a in c)

    def test_war_pin_suppresses_the_moving_ref_warning(self, mk_runner, capsys) -> None:
        # A WAR build is sha256-verified in-image whatever CARLOS_REF says;
        # only the (unchanged, moving) DrugRef ref may warn here.
        r = mk_runner(
            f"CARLOS_REF=develop\nDRUGREF_REF={'b' * 40}\nCARLOS_ARTIFACT=war\n"
            f"CARLOS_WAR_URL=https://x/x.war\nCARLOS_WAR_SHA256={'d' * 64}\n"
        )
        _seed_build_ctx(r)
        assert cmd_build(r, []) == 0
        assert "CARLOS_REF=" not in capsys.readouterr().err

    def test_release_mode_war_pin_needs_no_src_sha256(self, mk_runner) -> None:
        # The published WAR's sha256 IS the content checksum for the CARLOS
        # image; the source-tarball checksum is a compile-only layer.
        r = mk_runner(
            f"DRUGREF_REF={_SHA}\nDRUGREF_SRC_SHA256=deadbeef\n"
            "SOURCE_DATE_EPOCH=1751500000\n",
            {"CARLOS_BUILD_MODE": "release"},
        )
        _seed_build_ctx(r)
        self._pin(r, artifact="war", war_url="https://x/x.war", war_sha256="d" * 64)
        assert cmd_build(r, []) == 0
        assert (r.settings.emr_home / "build" / ".build-mode").read_text().strip() == "release"

    def test_release_mode_refuses_a_war_pin_without_sha(self, mk_runner) -> None:
        r = mk_runner(
            f"DRUGREF_REF={_SHA}\nDRUGREF_SRC_SHA256=deadbeef\n"
            "SOURCE_DATE_EPOCH=1751500000\n",
            {"CARLOS_BUILD_MODE": "release"},
        )
        _seed_build_ctx(r)
        self._pin(r, artifact="war", war_url="https://x/x.war", war_sha256="")
        with pytest.raises(CtlError, match="no sha256"):
            cmd_build(r, [])

    def test_release_mode_source_pin_still_needs_src_sha256(self, mk_runner) -> None:
        r = mk_runner(
            f"DRUGREF_REF={_SHA}\nDRUGREF_SRC_SHA256=deadbeef\n"
            "SOURCE_DATE_EPOCH=1751500000\n",
            {"CARLOS_BUILD_MODE": "release"},
        )
        _seed_build_ctx(r)
        self._pin(r)  # artifact=source, sha-pinned ref
        with pytest.raises(CtlError, match="CARLOS_SRC_SHA256 is unset"):
            cmd_build(r, [])

    def test_drugref_war_pin_selects_its_download_stage(self, mk_runner) -> None:
        from carlos_ctl.source import DRUGREF

        r = mk_runner(f"CARLOS_REF={_SHA}\n")  # DRUGREF_REF defaults to auto
        _seed_build_ctx(r)
        self._pin(r, app=DRUGREF, tag="v1.0.0rc2",
                  artifact="war", war_url="https://x/drugref2.war",
                  war_sha256="f" * 64)
        assert cmd_build(r, []) == 0
        dr_build = next(c for c in r.calls
                        if "build" in c and "Containerfile.drugref" in " ".join(c))
        assert "DRUGREF_WAR_URL=https://x/drugref2.war" in dr_build
        assert f"DRUGREF_WAR_SHA256={'f' * 64}" in dr_build
        assert "DRUGREF_WAR_STAGE=download" in dr_build
        # The CARLOS build must not inherit DrugRef's WAR args (or vice versa).
        carlos_build = next(c for c in r.calls if "build" in c and "-f" in c
                            and str(c[c.index("-f") + 1]).endswith("/Containerfile"))
        assert not any("DRUGREF_WAR" in a for a in carlos_build)
        assert not any("CARLOS_WAR" in a for a in dr_build)

    def test_all_war_release_build_needs_no_source_date_epoch(self, mk_runner) -> None:
        # SOURCE_DATE_EPOCH pins COMPILE timestamps; an all-WAR release build
        # runs no compiler, so requiring it would demand a meaningless knob.
        from carlos_ctl.source import DRUGREF

        r = mk_runner("", {"CARLOS_BUILD_MODE": "release"})
        _seed_build_ctx(r)
        self._pin(r, artifact="war", war_url="https://x/x.war", war_sha256="d" * 64)
        self._pin(r, app=DRUGREF, tag="v1.0.0rc2", artifact="war",
                  war_url="https://x/drugref2.war", war_sha256="f" * 64)
        assert cmd_build(r, []) == 0
        assert (r.settings.emr_home / "build" / ".build-mode").read_text().strip() == "release"

    def test_release_mode_refuses_drugref_war_pin_without_sha(self, mk_runner) -> None:
        from carlos_ctl.source import DRUGREF

        r = mk_runner(
            f"CARLOS_REF={_SHA}\nCARLOS_SRC_SHA256=deadbeef\n"
            "SOURCE_DATE_EPOCH=1751500000\n",
            {"CARLOS_BUILD_MODE": "release"},
        )
        _seed_build_ctx(r)
        self._pin(r, app=DRUGREF, tag="v1.0.0rc2", artifact="war",
                  war_url="https://x/drugref2.war", war_sha256="")
        with pytest.raises(CtlError, match="DRUGREF WAR artifact has no sha256"):
            cmd_build(r, [])

    def test_containerfile_drugref_carries_the_war_stage_plumbing(self) -> None:
        from pathlib import Path

        text = Path(__file__).resolve().parents[2].joinpath(
            "Containerfile.drugref").read_text()
        assert "ARG DRUGREF_WAR_URL" in text
        assert "ARG DRUGREF_WAR_SHA256" in text
        assert "ARG DRUGREF_WAR_STAGE=build" in text
        assert "AS download" in text
        assert "FROM ${DRUGREF_WAR_STAGE} AS warsrc" in text
        assert "from=warsrc" in text and "from=build" not in text
        assert 'test -n "$DRUGREF_WAR_SHA256"' in text
        assert "sha256sum -c" in text

    def test_containerfile_carries_the_war_stage_plumbing(self) -> None:
        from pathlib import Path

        text = Path(__file__).resolve().parents[2].joinpath("Containerfile").read_text()
        assert "ARG CARLOS_WAR_URL" in text
        assert "ARG CARLOS_WAR_SHA256" in text
        assert "ARG CARLOS_WAR_STAGE=build" in text
        assert "AS download" in text
        # The alias stage is what makes the runtime mount switchable.
        assert "FROM ${CARLOS_WAR_STAGE} AS warsrc" in text
        assert "from=warsrc" in text and "from=build" not in text
        # The sha256 verification is MANDATORY in the download stage — an
        # unverified URL-fetched WAR must fail the build, not ship.
        assert 'test -n "$CARLOS_WAR_SHA256"' in text
        assert "sha256sum -c" in text


class TestBuildIdentityStamp:
    """The app pom rewrites carlos.properties' buildVersion from the Jenkins
    env vars JOB_NAME/BUILD_NUMBER via Ant's `<property environment="env"/>`.
    Ant leaves an UNSET property as its literal `${env.JOB_NAME}` text, so a
    container build (no Jenkins) baked
    `buildVersion=${env.JOB_NAME} ${env.BUILD_NUMBER}` into the WAR and CARLOS
    rendered that raw placeholder on the LOGIN page to every unauthenticated
    visitor (verified live 2026-08-02). The Containerfile sets both; the CLI
    passes the same stamp that names the image tag, so the running page
    identifies its image."""

    def test_build_passes_the_stamp_matching_the_image_tag(self, mk_runner) -> None:
        r = mk_runner(f"CARLOS_REF={_SHA}\nDRUGREF_REF={'b' * 40}\n",
                      {"BUILD_STAMP": "20260802-140155"})
        _seed_build_ctx(r)
        assert cmd_build(r, []) == 0
        builds = [c for c in r.calls if "build" in c and "-f" in c]
        assert builds, "no image build was issued"
        carlos_build = builds[0]
        assert "CARLOS_BUILD_STAMP=20260802-140155" in carlos_build
        # The stamp must be the SAME one that names the tag, or the login
        # page would advertise a build that no image tag corresponds to.
        tag = carlos_build[carlos_build.index("-t") + 1]
        assert tag.endswith(":build-20260802-140155")

    def test_containerfile_sets_both_jenkins_vars(self) -> None:
        from pathlib import Path

        text = Path(__file__).resolve().parents[2].joinpath("Containerfile").read_text()
        assert "ARG CARLOS_BUILD_STAMP" in text
        assert "JOB_NAME=" in text
        assert "BUILD_NUMBER=${CARLOS_BUILD_STAMP}" in text
        # The stamp must NOT be the commit SHA: buildVersion renders
        # pre-authentication, and the exact source revision is not something
        # to hand an anonymous visitor.
        assert "BUILD_NUMBER=${CARLOS_REF}" not in text
