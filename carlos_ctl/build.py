# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Image builds: build / rebuild / rollback.

Each build is tagged three ways:
  :latest      what `play` deploys (the CARLOS_IMAGE/DRUGREF_IMAGE default)
  :build-<ts>  an immutable, timestamped tag for traceability/history
  :previous    the build that :latest pointed at BEFORE this one — the
               one-command rollback target (`carlos-ctl rollback`)

The build context (Containerfile, Containerfile.drugref) is installed by the
Ansible role to $EMR_HOME/build — the bash used its own checkout dir, but the
Python CLI is installed system-wide and must not depend on where the repo
happens to be. CARLOS_BUILD_DIR overrides for tests/dev checkouts."""

from __future__ import annotations

import contextlib
import re
import resource
import time
from pathlib import Path
from typing import List

from .runner import Runner
from .util import CtlError, log, warn

_SHA40 = re.compile(r"^[0-9a-f]{40}$")


def _build_dir(runner: Runner) -> Path:
    # Settings.get, not _env: the env FILE is the documented configuration
    # surface, and a process-env-only read made a carlos-app.env line
    # silently no-op (see config._EXTRA_KNOWN_KEYS). File wins over process
    # env, matching every other knob.
    override = runner.settings.get("CARLOS_BUILD_DIR")
    if override:
        # Absolute: the context path is an argv token for a `podman build` that
        # runs across the runuser boundary from a FIXED working directory (see
        # Runner's cross-user cwd pin), so a relative dev-checkout override
        # must be anchored in THIS process's cwd, not the child's.
        import os

        return Path(os.path.abspath(override))
    return runner.settings.emr_home / "build"


# The nofile ceiling requested for the in-build Maven/javac processes. 65536
# matches the QUICKSTART's manual `podman build --ulimit` invocation; the
# effective value is capped at the SERVICE USER's hard limit (rootless podman
# cannot grant more than the invoking user's own hard limit).
_NOFILE_TARGET = 65536
# Warn below this. 4096 is the floor VERIFIED with the current Containerfile
# (forked javac splits the compile's FD load across two processes; measured
# peak ~912 per JVM on the 2026-08-01 develop tree). The pre-fork in-process
# compile died at exactly 4096 — if the fork is ever removed, raise this.
_NOFILE_WARN_FLOOR = 4096


def _service_nofile_hard(runner: Runner) -> int:
    """The nofile HARD limit the build will actually run under: measured in a
    shell spawned across the same runuser boundary podman_user uses (the
    service user's limit, not this root process's). Falls back to this
    process's hard limit when the probe output is unusable."""
    out = runner.output([
        "runuser", "-u", runner.settings.service_user, "--", "sh", "-c", "ulimit -Hn",
    ]).strip()
    if out == "unlimited":
        return resource.RLIM_INFINITY
    try:
        return int(out)
    except ValueError:
        _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        return hard


def cmd_build(runner: Runner, args: List[str]) -> int:
    """[--use-cache]  Default --no-cache: `ADD <url>` caches on the URL string,
    so a cached same-ref build can silently ship a STALE source tarball for a
    moving branch ref; --use-cache opts back in for fast iteration on an
    immutable commit-SHA ref."""
    s = runner.settings
    cache_args = ["--no-cache"]
    if args == ["--use-cache"]:
        cache_args = []
    elif args and args != ["--no-cache"]:
        raise CtlError("usage: carlos-ctl build [--use-cache]")

    here = _build_dir(runner)
    if not (here / "Containerfile").is_file():
        raise CtlError(
            f"no Containerfile in {here} — the Ansible role installs the build context there "
            f"(re-run the provisioning playbook), or set CARLOS_BUILD_DIR to a repo checkout"
        )
    # The Maven build (and javac inside it) opens thousands of files; the
    # common 1024 nofile soft default dies with "Too many open files" ~20 min
    # in. The builds below pass --ulimit nofile explicitly (soft is raised to
    # the service user's hard limit, capped at the QUICKSTART's 65536), so
    # only a LOW HARD limit still bites — measured across the same runuser
    # boundary the build runs under. Warn, don't refuse: the measurement is
    # best-effort and a marginal build may still fit.
    nofile_hard = _service_nofile_hard(runner)
    if nofile_hard != resource.RLIM_INFINITY and nofile_hard < _NOFILE_WARN_FLOOR:
        warn(
            f"the service user's nofile hard limit is {nofile_hard} — the Maven build can "
            f"die with 'Too many open files' (4096 is the verified floor for the current "
            f"forked-compiler Containerfile; QUICKSTART recommends 65536). Raise it for "
            f"the service user (LimitNOFILE=, or /etc/security/limits.d) before a long build"
        )
    nofile_eff = (
        _NOFILE_TARGET if nofile_hard == resource.RLIM_INFINITY
        else min(_NOFILE_TARGET, nofile_hard)
    )
    ulimit_args = ["--ulimit", f"nofile={nofile_eff}:{nofile_eff}"]
    # Same class of check as the nofile floor above, and for the same reason:
    # a too-narrow subuid/subgid grant does not surface until apt drops to
    # uid 65534 in the RUNTIME stage — tens of minutes into the build, as
    # `setgroups (22: Invalid argument)`, which reads like an image bug. Say
    # it here, before the Maven fetch starts. (validate.subid_map_preflight
    # is also run by `play`; see its docstring.)
    from . import validate

    validate.subid_map_preflight(runner)
    # --format docker: podman builds OCI by default, and the OCI image spec
    # has no healthcheck field — so both Containerfiles' HEALTHCHECK was
    # DROPPED on every build ("HEALTHCHECK is not supported for OCI image
    # format and will be ignored", six lines buried in thousands of build-log
    # lines), and the shipped images carried none. Under `kube play` the pod
    # spec's own probes govern, but a standalone `podman run` of the image —
    # the case the Containerfile's HEALTHCHECK exists for, and what an
    # operator debugging a bad build reaches for — had no health signal at
    # all. Docker v2s2 keeps it; nothing else in this deployment depends on
    # the manifest type.
    format_args = ["--format", "docker"]
    stamp = s._env.get("BUILD_STAMP") or time.strftime("%Y%m%d-%H%M%S")  # noqa: SLF001
    carlos_image = s.get("CARLOS_IMAGE")
    drugref_image = s.get("DRUGREF_IMAGE")
    carlos_repo = carlos_image.rsplit(":", 1)[0]
    drugref_repo = drugref_image.rsplit(":", 1)[0]
    # WHICH versions to build, and from which artifacts: per app, the
    # historical manual <APP>_REF passthrough, or (<APP>_REF=auto, the
    # default) the sticky release-first pin — resolved via the GitHub API
    # exactly once, then read offline from $EMR_HOME/build/.source-pin[.
    # drugref]. See carlos_ctl/source.py.
    from . import source as source_mod

    pin = source_mod.resolve_for_build(runner, source_mod.CARLOS)
    dpin = source_mod.resolve_for_build(runner, source_mod.DRUGREF)
    carlos_ref = pin.ref
    drugref_ref = dpin.ref

    # Supply-chain gate. A branch name is a MOVING ref — the fetched tarball
    # has no checksum, so what gets built is whatever the branch points at
    # right now. DEV mode (default): warn only. RELEASE mode
    # (CARLOS_BUILD_MODE=release): HARD-FAIL unless every source is pinned to
    # a 40-hex commit SHA AND its content is checksummed AND the Maven
    # dependency-lock is enforced. For a WAR-artifact build (either app) the
    # published WAR's sha256 (verified in-image) IS that image's content
    # checksum, and the compile-only layers (source tarball sha256, the lock,
    # SOURCE_DATE_EPOCH) apply only to images that actually compile.
    build_dep_lock = "0"
    gated = (("CARLOS", pin), ("DRUGREF", dpin))
    if s.get("CARLOS_BUILD_MODE") == "release":
        build_dep_lock = "1"
        for prefix, p in gated:
            if p.artifact == "war":
                if not p.war_sha256:
                    raise CtlError(
                        f"CARLOS_BUILD_MODE=release: the {prefix} WAR artifact has no "
                        f"sha256 to verify — re-resolve ('carlos-ctl source update') "
                        f"or set {prefix}_WAR_SHA256"
                    )
                continue
            if not _SHA40.match(p.ref):
                raise CtlError(
                    f"CARLOS_BUILD_MODE=release: {prefix}_REF='{p.ref}' is not a full "
                    f"40-hex commit SHA — a release build must pin an immutable, "
                    f"auditable source ref"
                )
            if not s.get(f"{prefix}_SRC_SHA256"):
                raise CtlError(
                    f"CARLOS_BUILD_MODE=release: {prefix}_SRC_SHA256 is unset — supply "
                    f"the pinned tarball's sha256 (curl -sL <url> | sha256sum) so the "
                    f"in-image integrity check runs"
                )
        # The Containerfiles' SOURCE_DATE_EPOCH plumbing is inert unless a
        # value is actually passed — a release build claiming auditability
        # must pin its build timestamp too, or two "identical" release builds
        # diverge on embedded times. Compile-only: an all-WAR release build
        # runs no compiler, so there is no local timestamp to pin.
        if any(p.artifact != "war" for _, p in gated) and not s.get("SOURCE_DATE_EPOCH"):
            raise CtlError(
                "CARLOS_BUILD_MODE=release: SOURCE_DATE_EPOCH is unset — pin the build "
                "timestamp (e.g. the source commit's: git show -s --format=%ct <sha>) "
                "so release builds are time-reproducible"
            )
        # The dependency-lock profile exists in the CARLOS pom only, and only
        # matters when the CARLOS image actually compiles — say precisely
        # what is enforced rather than imply more.
        lock_note = (
            "Maven dependency-lock enforced (CARLOS compile; DrugRef has no lock profile)"
            if pin.artifact != "war"
            else "no local compile for CARLOS (published WAR verified by sha256)"
        )
        log(f"RELEASE build: every source commit-pinned and content-checksummed; {lock_note}")
    else:
        # A WAR-artifact build is sha256-verified in-image regardless of
        # mode, so only a SOURCE build with a moving ref deserves the nag
        # (auto pins are commit SHAs by construction and stay silent too).
        for prefix, p in gated:
            if p.artifact != "war" and not _SHA40.match(p.ref):
                warn(
                    f"{prefix}_REF='{p.ref}' is not a full commit SHA — the source fetch "
                    f"is a moving, unverifiable ref; pin a 40-hex commit and set "
                    f"CARLOS_BUILD_MODE=release for an audited build"
                )

    # Build-then-PROMOTE: both images build under :build-<stamp> only, and
    # :latest moves for BOTH after BOTH succeed — a drugref build failure
    # must not leave a mismatched carlos:latest(new)/drugref:latest(old)
    # pair for the next play to deploy.
    log(f"Building {carlos_repo}:build-{stamp} from carlos-emr/carlos {pin.describe()}")
    # CARLOS_SRC_SHA256/DRUGREF_SRC_SHA256 (empty by default) enable in-image
    # tarball integrity verification for audited release builds.
    # SOURCE_DATE_EPOCH is only forwarded when set — the Containerfile ARG
    # defaults to "" (unset semantics) and the CLI previously never passed it
    # at all, leaving the reproducibility plumbing permanently inert.
    epoch_args = (
        ["--build-arg", f"SOURCE_DATE_EPOCH={s.get('SOURCE_DATE_EPOCH')}"]
        if s.get("SOURCE_DATE_EPOCH") else []
    )
    # EXTRA_CA_BUNDLE hook: on a host behind a TLS-inspecting egress proxy, the
    # in-image Maven fetch must trust the proxy CA. The operator points
    # CARLOS_EXTRA_CA_BUNDLE at a PEM bundle; we stage it into the build context
    # so the Containerfiles' COPY .extra-ca-bundle.crt picks it up and imports
    # it into the BUILD-STAGE trust store only — never the runtime images, and
    # it does not weaken the digest-pinned base images (digests are verified
    # independently of transport trust). A committed 0-byte placeholder ships in
    # the repo/role so a fresh checkout's COPY never fails; we self-heal it and
    # always restore that neutral empty state after the builds.
    ca_ctx = here / ".extra-ca-bundle.crt"
    extra_ca = s.get("CARLOS_EXTRA_CA_BUNDLE")  # env file OR process env
    if extra_ca:
        try:
            content = Path(extra_ca).read_text()
        except OSError as e:
            raise CtlError(
                f"CARLOS_EXTRA_CA_BUNDLE={extra_ca} is not readable ({e}) — point it at a "
                f"readable PEM bundle, or unset it"
            ) from None
        if "BEGIN CERTIFICATE" not in content:
            raise CtlError(
                f"CARLOS_EXTRA_CA_BUNDLE={extra_ca} does not look like a PEM bundle (no "
                f"'BEGIN CERTIFICATE') — point it at a real CA bundle"
            )
        ca_ctx.write_text(content)  # CA certs are public material (0644 umask)
        log(f"staging {extra_ca} into the build context (build-stage trust only — "
            f"not baked into the runtime images)")
    else:
        ca_ctx.write_text("")  # self-heal: keep the placeholder present-but-empty
    # WAR-artifact builds select the Containerfiles' `download` stage (the
    # published, sha256-verified release WAR) instead of the Maven compile;
    # source builds pass nothing new so the ARG defaults keep selecting the
    # compile stage — the manual QUICKSTART `podman build` recipe unchanged.
    war_args = (
        [
            "--build-arg", f"CARLOS_WAR_URL={pin.war_url}",
            "--build-arg", f"CARLOS_WAR_SHA256={pin.war_sha256}",
            "--build-arg", "CARLOS_WAR_STAGE=download",
        ]
        if pin.artifact == "war" else []
    )
    drugref_war_args = (
        [
            "--build-arg", f"DRUGREF_WAR_URL={dpin.war_url}",
            "--build-arg", f"DRUGREF_WAR_SHA256={dpin.war_sha256}",
            "--build-arg", "DRUGREF_WAR_STAGE=download",
        ]
        if dpin.artifact == "war" else []
    )
    try:
        cp = runner.podman_user([
            "build", *cache_args, *format_args, *epoch_args, *ulimit_args,
            "--build-arg", f"CARLOS_REF={carlos_ref}",
            "--build-arg", f"CARLOS_SRC_SHA256={s.get('CARLOS_SRC_SHA256')}",
            "--build-arg", f"BUILD_DEP_LOCK={build_dep_lock}",
            *war_args,
            # Names the build in the app's own buildVersion string, which
            # CARLOS renders on the login page — same stamp as the image tag
            # below, so the running page identifies its image. See the
            # CARLOS_BUILD_STAMP block in the Containerfile.
            "--build-arg", f"CARLOS_BUILD_STAMP={stamp}",
            "-t", f"{carlos_repo}:build-{stamp}",
            "-f", str(here / "Containerfile"), str(here),
        ])
        if cp.returncode != 0:
            raise CtlError(f"build failed for {carlos_image}")
        log(f"Building {drugref_repo}:build-{stamp} from carlos-emr/drugref2026 "
            f"{dpin.describe()}")
        cp = runner.podman_user([
            "build", *cache_args, *format_args, *epoch_args, *ulimit_args,
            "--build-arg", f"DRUGREF_REF={drugref_ref}",
            "--build-arg", f"DRUGREF_SRC_SHA256={s.get('DRUGREF_SRC_SHA256')}",
            *drugref_war_args,
            "-t", f"{drugref_repo}:build-{stamp}",
            "-f", str(here / "Containerfile.drugref"), str(here),
        ])
        if cp.returncode != 0:
            raise CtlError(f"build failed for {drugref_image}")
    finally:
        # Never leave the operator CA staged in the context after the build.
        if extra_ca:
            ca_ctx.write_text("")
    # Post-build smoke BEFORE any tag moves: a bare `build`
    # used to promote :latest with nothing verifying the image even runs or
    # carries its exploded WAR — only `rebuild` (via play readiness) caught a
    # broken image, after the outage. One `podman run --entrypoint test`
    # proves both: the image executes a process AND the WAR tree is present.
    for smoke_ref, war in ((f"{carlos_repo}:build-{stamp}", "carlos"),
                           (f"{drugref_repo}:build-{stamp}", "drugref2")):
        if not runner.ok(runner.podman_user_argv([
            "run", "--rm", "--entrypoint", "/usr/bin/test", smoke_ref,
            "-d", f"/usr/local/tomcat/webapps/{war}/WEB-INF",
        ])):
            raise CtlError(
                f"post-build smoke FAILED for {smoke_ref} — the image does not run, or "
                f"/usr/local/tomcat/webapps/{war}/WEB-INF is missing (WAR not exploded). "
                f"NOT promoting; :previous and :latest are untouched for both apps."
            )
    # :previous is retagged HERE — after both builds succeeded, immediately
    # before :latest moves — so a FAILED build can never destroy the
    # last-good rollback target (retagging before the builds left :previous
    # pointing at the very build the operator may be trying to escape).
    # BOTH retags complete before EITHER promote runs: a failure in this
    # first loop aborts with :latest untouched for both apps; only a failed
    # promote (second loop) can leave a mismatch, and it says so.
    #
    # CAVEAT (rollback safety): this protects against a build that fails to
    # BUILD, NOT against a build that succeeds then fails to DEPLOY. If a
    # rebuild builds OK but `play` then fails readiness, :latest is the bad
    # build and :previous is still good — but a SECOND `rebuild` rotates
    # :previous:=bad and the good image survives only under its immutable
    # :build-<ts> tag. So after a failed deploy, run `carlos-ctl rollback`
    # BEFORE rebuilding again (the cmd_rebuild abort message says this).
    # Tracked for a proper last-good marker (would need a healthy-deploy stamp).
    for image, repo in ((carlos_image, carlos_repo), (drugref_image, drugref_repo)):
        if runner.ok(runner.podman_user_argv(["image", "exists", image])):
            if not runner.ok(runner.podman_user_argv(["tag", image, f"{repo}:previous"])):
                raise CtlError(
                    f"could not tag {repo}:previous (the rollback target) — NOT promoting "
                    f"this build; :latest is unchanged for both apps"
                )
    # Pair the schema baseline with :previous the same way the tag pairs with
    # the build: the schema the outgoing :latest last ran healthily against is
    # what a rollback TO these images must be compared with.
    fp_marker = s.emr_home / "build" / ".schema-fingerprint"
    if fp_marker.is_file():
        try:
            (s.emr_home / "build" / ".schema-fingerprint.previous").write_text(
                fp_marker.read_text()
            )
        except OSError:
            warn("could not record the :previous schema baseline — rollback's "
                 "schema guard will warn instead of verifying")
    for image, repo in ((carlos_image, carlos_repo), (drugref_image, drugref_repo)):
        if not runner.ok(runner.podman_user_argv(
            ["tag", f"{repo}:build-{stamp}", image]
        )):
            raise CtlError(
                f"could not promote {repo}:build-{stamp} to {image} — :latest may be "
                f"mismatched between the two apps; re-run the build"
            )
    # Record HOW :latest was built so `play` can surface a dev-mode image on
    # a production instance — the built image itself carries no reliable
    # marker of whether its source was pinned+checksummed.
    mode = "release" if s.get("CARLOS_BUILD_MODE") == "release" else "dev"
    try:
        mode_file = s.emr_home / "build" / ".build-mode"
        mode_file.parent.mkdir(parents=True, exist_ok=True)
        mode_file.write_text(mode + "\n")
    except OSError:
        warn("could not record the build mode — 'play' cannot flag dev-built images")
    log(
        f"Built :build-{stamp} and :latest. Previous build kept as :previous — "
        f"'carlos-ctl rollback' restores it, then 'carlos-ctl play'."
    )
    return 0


def cmd_rebuild(runner: Runner, args: List[str]) -> int:
    """THE app-lifecycle verb: (re)build the images and redeploy. DATA-SAFETY
    CONTRACT: touches container IMAGES and pod processes only — never
    $EMR_HOME/data, never credentials, never backups."""
    from . import lifecycle2

    s = runner.settings
    usage = (
        "usage: carlos-ctl rebuild [--ref <branch|tag|sha>] "
        "[--drugref-ref <branch|tag|sha>] [--pull]"
    )
    do_pull: List[str] = []
    ref_override = False
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--ref":
            if i + 1 >= len(args) or not args[i + 1]:
                raise CtlError(usage)
            # Per-run override, as the bash did: the value replaces CARLOS_REF
            # for THIS invocation only — a non-`auto` value takes the manual
            # path in source.resolve_for_build, so the sticky pin is neither
            # consulted nor rewritten (the next plain build returns to it).
            s._vals["CARLOS_REF"] = args[i + 1]  # noqa: SLF001
            ref_override = True
            i += 2
        elif a == "--drugref-ref":
            if i + 1 >= len(args) or not args[i + 1]:
                raise CtlError(usage)
            # One-shot like --ref: the DrugRef pin is neither consulted nor
            # rewritten for this run.
            s._vals["DRUGREF_REF"] = args[i + 1]  # noqa: SLF001
            ref_override = True
            i += 2
        elif a == "--pull":
            do_pull = ["--pull"]
            i += 1
        else:
            raise CtlError(usage)
    log("Rebuild: images only — the database, documents, and backups are not touched")
    cmd_build(runner, ["--no-cache"])
    # What was just built, for the messages below: after cmd_build the pin
    # exists (auto mode) or the manual ref passes straight through, so this
    # re-read is offline — and it never prints the raw `auto` sentinel.
    from . import source as source_mod

    built = source_mod.resolve_for_build(runner, source_mod.CARLOS).describe()
    dbuilt = source_mod.resolve_for_build(runner, source_mod.DRUGREF).describe()
    # play's readiness gate (wait_app_ready) makes rc nonzero when the app
    # never turns healthy — a failed rebuild must not report "redeployed".
    if lifecycle2.cmd_play(runner, do_pull) != 0:
        raise CtlError(
            f"rebuild deployed but the app did NOT come up healthy — the new build is "
            f"suspect. 'carlos-ctl rollback' restores the previous images "
            f"(carlos-emr/carlos {built} remains tagged :latest until then)."
        )
    log(
        f"Rebuilt carlos-emr/carlos {built} (drugref2026 {dbuilt}) "
        f"and redeployed — validate with 'carlos-ctl check' ('carlos-ctl rollback' restores "
        f"the previous build)"
        + (
            ". NOTE: --ref/--drugref-ref are one-shot — the next plain build returns "
            "to the pinned selection; 'carlos-ctl source set [--drugref] <ref>' makes "
            "it durable"
            if ref_override else ""
        )
    )
    return 0


def cmd_rollback(runner: Runner, args: List[str]) -> int:
    """Point :latest back at :previous for both app IMAGES, then re-play. One
    level deep (the last good build). Images ONLY — hand-applied SQL schema
    migrations (database/mysql/updates/) are NOT reversed by this verb; the
    schema guard below refuses a rollback onto a schema the :previous build
    never ran against unless the mismatch is explicitly accepted."""
    from . import dbops, lifecycle2

    s = runner.settings
    accept_mismatch = s.flag("CARLOS_ACCEPT_SCHEMA_MISMATCH")
    for a in args:
        if a == "--accept-schema-mismatch":
            accept_mismatch = True
        else:
            raise CtlError("usage: carlos-ctl rollback [--accept-schema-mismatch]")
    carlos_image = s.get("CARLOS_IMAGE")
    drugref_image = s.get("DRUGREF_IMAGE")
    carlos_repo = carlos_image.rsplit(":", 1)[0]
    drugref_repo = drugref_image.rsplit(":", 1)[0]
    # Schema-compatibility gate, BEFORE any retag. Three honest outcomes:
    # no baseline => warn+proceed (pre-upgrade install / first build); db
    # unreachable => warn+proceed (rollback is the emergency verb — it must
    # not be blocked by the very outage it is fixing); live != baseline =>
    # REFUSE without the explicit ack.
    baseline = ""
    with contextlib.suppress(OSError):
        baseline = (
            (s.emr_home / "build" / ".schema-fingerprint.previous")
            .read_text().strip()
        )
    if not baseline:
        warn(
            "no schema baseline is recorded for the :previous build (first build or "
            "pre-upgrade install) — cannot verify schema compatibility; proceeding"
        )
    else:
        live = dbops.schema_fingerprint(runner)
        if not live:
            warn(
                "the database is unreachable, so the schema-compatibility check could "
                "NOT run — if you applied SQL migrations since the previous build, the "
                "rolled-back code may not match the schema"
            )
        elif live != baseline and not accept_mismatch:
            raise CtlError(
                "the live oscar schema differs from what the :previous build last ran "
                "against — rolling back the CODE does not roll back SQL MIGRATIONS "
                "(database/mysql/updates/ are applied by hand and are not reversed by "
                "this verb). Reverse the migration first, or re-run with "
                "--accept-schema-mismatch (or CARLOS_ACCEPT_SCHEMA_MISMATCH=1) to "
                "deploy the old code against the new schema anyway."
            )
        elif live != baseline:
            warn(
                "schema mismatch ACCEPTED (--accept-schema-mismatch) — deploying the "
                "previous code against a schema it never ran with"
            )
    # Validate BOTH :previous images exist BEFORE retagging either — the two
    # must roll back in lockstep; a swallowed drugref failure would leave
    # carlos:previous running against drugref:latest, a version-mismatched
    # deploy. Refuse rather than half-do it.
    if not runner.ok(runner.podman_user_argv(["image", "exists", f"{carlos_repo}:previous"])):
        raise CtlError(
            f"no '{carlos_repo}:previous' image to roll back to — you need at least two "
            f"'carlos-ctl build' runs"
        )
    if not runner.ok(runner.podman_user_argv(["image", "exists", f"{drugref_repo}:previous"])):
        raise CtlError(
            f"no '{drugref_repo}:previous' image — refusing a MISMATCHED rollback (carlos "
            f"would roll back while drugref stayed current). Build both images "
            f"('carlos-ctl build'), or retag by hand."
        )
    log(f"Rolling back {carlos_repo} and {drugref_repo} to their :previous build")
    if not runner.ok(runner.podman_user_argv(["tag", f"{carlos_repo}:previous", carlos_image])):
        raise CtlError(
            f"could not retag {carlos_image} from :previous — aborting the rollback "
            f"(nothing changed)"
        )
    if not runner.ok(runner.podman_user_argv(["tag", f"{drugref_repo}:previous", drugref_image])):
        raise CtlError(
            f"could not retag {drugref_image} from :previous — {carlos_image} was retagged; "
            f"re-run 'carlos-ctl build' to restore a consistent pair"
        )
    # Honor play's readiness gate here too: an incident rollback whose
    # :previous ALSO fails to serve must not print success and stop the
    # investigation.
    if lifecycle2.cmd_play(runner, []) != 0:
        raise CtlError(
            "rolled the image tags back but the app did NOT come up healthy on the "
            ":previous build either — investigate the pod logs; the problem is likely "
            "not the image"
        )
    log(
        "Rolled back to the previous build (images only — hand-applied SQL migrations "
        "are untouched). Rebuild ('carlos-ctl build') to move forward again."
    )
    return 0
