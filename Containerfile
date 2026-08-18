# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
# CARLOS EMR application image: builds the WAR from source — or, in WAR mode
# (CARLOS_WAR_STAGE=download, see below), downloads a published release WAR —
# and packages it on Tomcat 11 / JDK 21 (the stack the carlos-emr/carlos
# devcontainer targets).
#
#   podman build --no-cache -t localhost/carlos-app:latest -f Containerfile .
#   (--no-cache matters: see REPRODUCIBILITY below — a cached ADD ships stale code)
#   podman build --build-arg CARLOS_REF=<branch-or-tag-or-SHA> ...
#
# REPRODUCIBILITY: the default `main` (the stable branch releases are cut
# from; pass CARLOS_REF=develop deliberately for the development branch) is
# still a moving branch — two clean builds
# weeks apart produce different images. For releases, pin a COMMIT SHA
# (--build-arg CARLOS_REF=<40-char-sha>; GitHub serves archive/<sha>.tar.gz and
# --strip-components=1 already handles the carlos-<sha>/ top dir). Because
# `ADD <url>` caches on the URL STRING, a plain rebuild of the SAME branch ref
# reuses the previously-fetched tarball and can silently ship stale code —
# `carlos-ctl build`/`rebuild` therefore pass --no-cache by default (and warn
# on non-SHA refs). The base images below are pinned tag@digest so a re-pushed
# tag can never change what a PHI image is built from — to bump, pick the new
# tag and re-resolve its multi-arch digest (skopeo inspect --format
# '{{.Digest}}' docker://<repo>:<tag>). Digests resolved 2026-07.
ARG CARLOS_REF=main
# WAR-artifact mode: when a GitHub release publishes a prebuilt WAR
# (carlos-<tag>.war), `carlos-ctl build` selects the `download` stage below
# instead of the Maven compile by passing CARLOS_WAR_STAGE=download plus the
# asset URL and its MANDATORY sha256. The defaults keep the historical
# compile-from-source behavior for every existing `podman build` invocation.
# Both engines skip stages the final stage does not reference (BuildKit
# always; buildah — podman's builder — since 1.24, well below this project's
# podman 4.9 floor), so a source build never fetches the WAR and a WAR build
# never pulls the Maven image or compiles.
ARG CARLOS_WAR_URL=""
ARG CARLOS_WAR_SHA256=""
ARG CARLOS_WAR_STAGE=build
# Reproducibility helpers (cosmetic): a fixed TZ keeps timestamp-sensitive
# build steps deterministic, and SOURCE_DATE_EPOCH is honored by tools that
# support it. Pass --build-arg SOURCE_DATE_EPOCH=<unix-ts> for a reproducible
# release build. Both are (re)declared INSIDE each stage: an ENV before the
# first FROM is a spec violation (docker/BuildKit hard-errors; buildah
# silently drops it into no stage), and a global ARG is only visible to FROM
# lines unless redeclared per stage.
ARG SOURCE_DATE_EPOCH=""

FROM docker.io/library/maven:3.9-eclipse-temurin-21@sha256:2b4496088e7b80ae10a8c9f74e574ea21380325a006ec684532ad6bad5bc7273 AS build
ARG CARLOS_REF
ARG SOURCE_DATE_EPOCH=""
# Exported as ENV so Maven/plugins that honor SOURCE_DATE_EPOCH see it; TZ
# pins timestamp-sensitive build steps. NOTE: an empty SOURCE_DATE_EPOCH is
# NOT ignored by every consumer (the Maven 3.9 archiver hard-fails on ''),
# so the mvn step below unsets it when no real epoch was passed.
ENV TZ=UTC \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
# Optional source-tarball integrity: for an AUDITED RELEASE build, pin
# CARLOS_REF to a full commit SHA and pass its tarball's sha256 as
# CARLOS_SRC_SHA256 (compute it with `curl -sL <url> | sha256sum`). When set,
# the fetched tarball is verified before use; empty (the default, for
# moving-ref dev builds) skips the check. See the README supply-chain note.
ARG CARLOS_SRC_SHA256=""
# BUILD_DEP_LOCK=1 enforces Maven's dependency-lock checksum check (drops the
# skip profile below); default 0 skips it for moving-ref dev builds. Plumbed by
# `carlos-ctl build` so a release build can enforce the lock WITHOUT hand-
# editing this file (it is forced on in CARLOS_BUILD_MODE=release).
ARG BUILD_DEP_LOCK=0
# EXTRA CA (build stage ONLY): for a host behind a TLS-inspecting egress proxy,
# `carlos-ctl build` stages the proxy CA bundle into the build context and this
# COPY picks it up; the guarded RUN adds it to the build-stage trust store
# (system + the JDK cacerts the Maven fetch uses) so the in-image dependency
# download succeeds. A committed 0-byte placeholder makes this inert by default
# (the RUN's `-s` guard skips an empty file). It never touches the runtime
# stage and does NOT weaken the digest-pinned base images — image digests are
# verified independently of transport trust. keytool imports only the FIRST
# cert of a multi-cert file, so split the bundle and import each block.
COPY .extra-ca-bundle.crt /usr/local/share/ca-certificates/carlos-extra-ca.crt
# The loop skips pieces without a certificate block (a corporate bundle's
# comment/Subject preamble splits into a cert-free first piece) and FAILS the
# build on any real import error: a `for` chain's exit status is the LAST
# iteration's, so an unguarded loop silently swallowed a corrupt cert
# mid-bundle and Maven failed 20 minutes later with a bare PKIX error (or
# succeeded trusting less than the operator staged).
RUN if [ -s /usr/local/share/ca-certificates/carlos-extra-ca.crt ]; then \
        update-ca-certificates \
        && csplit -z -f /tmp/ca- -b '%02d.crt' \
             /usr/local/share/ca-certificates/carlos-extra-ca.crt \
             '/BEGIN CERTIFICATE/' '{*}' \
        && for c in /tmp/ca-*.crt; do \
             grep -q 'BEGIN CERTIFICATE' "$c" || continue; \
             keytool -importcert -cacerts -storepass changeit -noprompt \
               -alias "carlos-extra-$(basename "$c" .crt)" -file "$c" || exit 1; \
           done \
        && rm -f /tmp/ca-*.crt; \
    else rm -f /usr/local/share/ca-certificates/carlos-extra-ca.crt; fi
ADD https://github.com/carlos-emr/carlos/archive/${CARLOS_REF}.tar.gz /tmp/carlos-src.tar.gz
RUN if [ -n "$CARLOS_SRC_SHA256" ]; then echo "$CARLOS_SRC_SHA256  /tmp/carlos-src.tar.gz" | sha256sum -c -; fi \
    && mkdir /src && tar -xzf /tmp/carlos-src.tar.gz -C /src --strip-components=1
WORKDIR /src
# (Compile mode only — the `download` stage below ships upstream's WAR as-is.)
# Tarball builds have no .git, but the app pom's buildnumber-maven-plugin
# (validate phase) runs `git log` with no revisionOnScmFailure fallback and
# hard-fails without one. Synthesize minimal git metadata; the real source
# ref is recorded in the commit message (upstream's buildNumber.properties
# is informational only — nothing consumes the revision beyond display).
RUN git init -q -b develop . \
    && git -c user.email=build@carlos-podman.invalid -c user.name="carlos-podman build" \
       commit -q --allow-empty -m "carlos-podman tarball build of carlos-emr/carlos@${CARLOS_REF}"
# Build identity for the app's own buildVersion string (compile mode only —
# a downloaded release WAR carries upstream CI's buildVersion, so a WAR-mode
# deploy shows the RELEASE's identity on the login page, not a local stamp).
# The app pom's
# antrun step does `<property environment="env"/>` and then rewrites
# carlos.properties with `${env.JOB_NAME}` / `${env.BUILD_NUMBER}` — Jenkins
# variables. Ant leaves an UNSET property as its literal `${env.JOB_NAME}`
# text, so a container build (no Jenkins) baked
# `buildVersion=${env.JOB_NAME} ${env.BUILD_NUMBER}` into the shipped WAR and
# CARLOS rendered that raw placeholder in the corner of the LOGIN page, to
# every unauthenticated visitor (verified live, 2026-08-02). Set them so the
# string resolves. BUILD_NUMBER carries the build stamp that also names the
# image tag (:build-<stamp>), so the deployed page identifies which image is
# running — deliberately NOT the commit SHA, which would hand an
# unauthenticated visitor the exact source revision; the stamp discloses no
# more than the buildDate already shown beside it.
ARG CARLOS_BUILD_STAMP=local
ENV JOB_NAME=carlos-podman \
    BUILD_NUMBER=${CARLOS_BUILD_STAMP}
# -Pskip-dependency-lock: upstream pom notes JitPack artifacts hash
# differently between fetches, which trips the dependency-lock check on clean
# builds — a false positive on a moving-ref build, which is the accepted site
# policy here. For an AUDITED release build, pin CARLOS_REF to a commit SHA
# (deterministic sources) AND set BUILD_DEP_LOCK=1 so the lock check runs
# against a fixed dependency set. See the supply-chain note in the README.
RUN --mount=type=cache,target=/root/.m2 \
    # An EMPTY-but-set SOURCE_DATE_EPOCH is NOT "unset semantics" for the
    # Maven 3.9 archiver — it parses it as project.build.outputTimestamp and
    # hard-fails on ''. Unset it unless a real epoch was passed via the ARG.
    if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then unset SOURCE_DATE_EPOCH; fi \
    && if [ "$BUILD_DEP_LOCK" = 1 ]; then LOCK_PROFILE=; else LOCK_PROFILE=-Pskip-dependency-lock; fi \
    # -Dmaven.compiler.fork=true, and no -T 1C: the in-process javac of this
    # single-module WAR holds the Maven JVM's jars AND the compile's file set
    # in ONE process — it blew past a 4096 nofile hard limit ("Too many open
    # files" ~20 min in, verified 2026-08-01), while -T 1C parallelizes
    # nothing on a single module. Forking javac splits the FD load across two
    # processes (measured peak ~912 per JVM) so the build fits common 4096
    # limits; the forked build is the configuration verified end-to-end
    # (deploy + Playwright). Keep --ulimit headroom anyway (see QUICKSTART).
    && mvn -B -DskipTests=true -Dcheckstyle.skip=true -Dmaven.compiler.fork=true $LOCK_PROFILE package \
    && cp target/carlos-*.war /carlos.war

# WAR download stage: the published release asset instead of the compile.
# Based on the SAME digest-pinned tomcat image as the runtime stage — no new
# pinned lineage to maintain, and a WAR build touches no other base image.
# `ADD <url>` is fetched by the BUILDER process on the host (host trust
# store), not inside this stage — so unlike the build stage's Maven fetch it
# needs no extra-CA import behind a TLS-inspecting proxy. The sha256 check is
# MANDATORY: a URL-fetched WAR is only trustworthy content-addressed
# (`carlos-ctl build` passes the sha from the pinned release; a manual build
# must pass CARLOS_WAR_SHA256 explicitly or this stage fails).
FROM docker.io/library/tomcat:11.0-jdk21-temurin@sha256:f29ace5eff7f2787a8ecc0ec79d61423e6129bcc8ee31eda9a8caa945796fb37 AS download
ARG CARLOS_WAR_URL
ARG CARLOS_WAR_SHA256
ADD ${CARLOS_WAR_URL} /carlos.war
RUN test -n "$CARLOS_WAR_SHA256" \
    && echo "$CARLOS_WAR_SHA256  /carlos.war" | sha256sum -c -

# Alias the selected WAR source so the runtime stage below mounts ONE fixed
# stage name whichever path produced /carlos.war.
FROM ${CARLOS_WAR_STAGE} AS warsrc

FROM docker.io/library/tomcat:11.0-jdk21-temurin@sha256:f29ace5eff7f2787a8ecc0ec79d61423e6129bcc8ee31eda9a8caa945796fb37
ENV TZ=UTC
# Drop the stock webapps; serve CARLOS at /carlos and redirect / there.
RUN rm -rf /usr/local/tomcat/webapps/* \
    && mkdir -p /usr/local/tomcat/webapps/ROOT \
    && printf '<%% response.sendRedirect("/carlos/"); %%>\n' > /usr/local/tomcat/webapps/ROOT/index.jsp
# Pre-explode the WAR at BUILD time, root-owned. Two things depend on this:
# (1) readOnlyRootFilesystem — Tomcat deploys the exploded dir without writing
# webapps/ at startup (unpackWARs never fires); (2) webshell resistance — the
# served tree is not writable by the runtime uid, so a compromised app cannot
# drop a JSP into /usr/local/tomcat/webapps/carlos/ and have Tomcat serve it.
# apt packages are intentionally NOT version-pinned: they are installed inside a
# digest-pinned base image (an integrity-pinned lineage), so pinning each package
# would add checksum-maintenance churn for no added supply-chain guarantee. See
# the README supply-chain note.
# The WAR is bind-mounted from the selected source stage (warsrc = compile or
# download, see CARLOS_WAR_STAGE above) rather than COPY'd: a COPY into
# /tmp creates a layer carrying the full WAR bytes that a later `rm` cannot
# remove from the image — roughly doubling the shipped payload next to the
# exploded tree. The mount leaves no layer behind.
RUN --mount=type=bind,from=warsrc,source=/carlos.war,target=/tmp/carlos.war \
    apt-get update \
    && apt-get install -y --no-install-recommends unzip \
    && mkdir /usr/local/tomcat/webapps/carlos \
    && cd /usr/local/tomcat/webapps/carlos \
    && unzip -q /tmp/carlos.war \
    && apt-get purge -y unzip && rm -rf /var/lib/apt/lists/* \
    # Pre-create Tomcat's configBase: the Host's createDirs (default on) tries
    # to mkdirs conf/Catalina/localhost at startup, which fails with a warning
    # on the read-only root every boot if the dir does not already exist.
    && mkdir -p /usr/local/tomcat/conf/Catalina/localhost
# Bake the hardened server.xml/context.xml INTO the image (defense-in-depth):
# the pod bind-mounts the same files from $EMR_HOME/container/conf/tomcat, but
# a standalone `podman run` of this image must not fall back to the stock
# Tomcat config — that one leaves the :8005 shutdown port open (any co-located
# process could stop the EMR with one TCP write) and sets no cookie SameSite.
COPY conf/tomcat/server.xml conf/tomcat/context.xml /usr/local/tomcat/conf/
# Fully non-root runtime (uid 10001). The `carlos-init` initContainer in the pod
# does the root-only setup (assemble the mode-0600 config into a tmpfs emptyDir,
# chown the writable mounts); this image just needs the user and tini. tini is
# wired as the image ENTRYPOINT below, so it is PID 1 for standalone runs AND
# under the pod spec alike: orphaned children of Runtime.exec
# (pdf/fax/ghostscript-type helpers CARLOS spawns) are reaped and SIGTERM is
# forwarded for graceful shutdown.
# USER 10001 (numeric) so the pod's runAsNonRoot admission check passes.
# NOTE: work/ and temp/ are deliberately NOT chowned — the pod runs this image
# with readOnlyRootFilesystem and mounts emptyDirs there (chowned by
# carlos-init); webapps/ stays root-owned read-only (see above).
RUN groupadd -g 10001 carlos \
    && useradd -u 10001 -g 10001 -d /home/carlos -m -s /usr/sbin/nologin carlos \
    # tini via apt: the base image is digest-pinned, so this install is inside
    # an integrity-pinned lineage — a curl'd static tini would add a second
    # fetch channel needing its own checksum maintenance.
    # mariadb-client-core provides the `mariadb` client for the pod's
    # wait-for-db loop ONLY: it polls the `oscar` database before starting
    # Tomcat, so a fresh install whose schema is loaded after `kube play` does
    # not hard-fail the webapp context on 'Unknown database'. The Ubuntu base's
    # `default-mysql-client` resolves to the Oracle mysql-client (no `mariadb`
    # binary), so pin the real MariaDB client here. The container still runs
    # non-root / read-only-root / drop-ALL.
    && apt-get update \
    && apt-get install -y --no-install-recommends tini mariadb-client-core \
    && rm -rf /var/lib/apt/lists/*
USER 10001
# Baseline JVM options so the image works standalone; the pod spec overrides
# CATALINA_OPTS with production heap sizes (and must keep these flags).
ENV CATALINA_OPTS="--add-opens java.base/java.net=ALL-UNNAMED -Djava.awt.headless=true -Dcarlos_override_properties=/home/carlos/carlos.properties"
# 8080 = plaintext (loopback-pinned by the baked server.xml); 8443 = the TLS
# connector the WAF actually proxies to.
EXPOSE 8080 8443
# Liveness for a STANDALONE `podman run` (the pod spec's livenessProbe takes
# precedence under kube play). bash /dev/tcp — the image ships bash and no
# curl/wget. A real HTTP status probe of /carlos/, not a bare port-open: a
# deadlocked or failed-deploy webapp keeps the socket accepting while serving
# nothing — that must read unhealthy.
# STANDALONE CAVEAT: the baked server.xml pins 8080 to container-loopback and
# 8443 needs the keystore the pod's tls-init generates — a bare
# `podman run -p 8080:8080` of this image is healthy per this probe (it runs
# in-container) yet unreachable from the host. Standalone debugging needs a
# mounted server.xml override (unpin the address) or a keystore at
# /run/tomcat-tls/keystore.p12.
HEALTHCHECK --interval=30s --timeout=10s --start-period=180s --retries=5 \
    CMD bash -c 'exec 3<>/dev/tcp/127.0.0.1/8080 \
        && printf "GET /carlos/ HTTP/1.0\r\nHost: localhost\r\n\r\n" >&3 \
        && head -1 <&3 | grep -qE "^HTTP/1\.[01] [23]"' || exit 1
# tini as PID 1 for EVERY invocation of this image — without the ENTRYPOINT,
# a bare CMD would make catalina.sh/the JVM PID 1 (no reaping, no signal
# forwarding) whenever the image runs outside the pod spec's explicit
# command override.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["catalina.sh", "run"]
