<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 CARLOS Contributors -->
# carlos-podman — CARLOS EMR under Podman

> **Status: pre-production.** carlos-podman is under active development and
> its interfaces and deployment procedures may change. A site considering
> production use must complete its own technical, security, privacy, backup,
> restore, and regulatory review before using the system with patient
> information. The repository includes a small sample deployment and the
> standard Ansible deployment for Ontario and British Columbia; a guided
> starting point is available in [QUICKSTART.md](QUICKSTART.md).

**License:** carlos-podman is distributed under the
[GNU Affero General Public License v3.0](LICENSE), SPDX identifier
`AGPL-3.0-only`, except for the compatible derived files listed in
[License](#license). Network use of a modified version may create source-code
provision obligations under the AGPL; obtain legal advice for your distribution
and deployment model when needed.

Deployment tooling for the [CARLOS EMR](https://github.com/carlos-emr/carlos),
the fork that succeeds the previous OpenO deployment — release-first by
default (the newest CARLOS/DrugRef GitHub releases, pinned; see
[Choosing the CARLOS and DrugRef versions](#choosing-the-carlos-and-drugref-versions)).
**Three pods**: a PHI runtime pod (`carlos-app`), an *optional* observability/admin
pod (`carlos-obs`, split out so app deploys never bounce the log/metric stores;
see [The observability pod is optional](#the-observability-pod-is-optional)),
and an edge pod (`carlos-waf`, split out so the internet-facing WAF shares no
network namespace with MariaDB — see
[WAF/DB network isolation](#wafdb-network-isolation)).

The deployment has two moving parts with a hard ownership boundary:

- **Provisioning is Ansible**: `ansible/site.yml` + the `carlos_podman` role
  render every config, install every unit, and enforce every cross-instance
  invariant. Drift handling *is* re-running the playbook
  (`--check --diff` is the dry-run).
- **Runtime is `carlos-ctl`**: a Python CLI (package `carlos_ctl/` in this
  repo) that the role installs to `/usr/local/sbin/carlos-ctl` — build, play,
  check, backup, monitor, seal, rotate, break-glass DB access. No pip on the
  host: the package is file-copied and its two dependencies (PyYAML, bcrypt)
  come from distro packages.

If you are coming from the 4,078-line bash `carlos-ctl`, read
[Migration from the bash carlos-ctl](#migration-from-the-bash-carlos-ctl) —
the verbs are the same, but `carlos-app.env` is now **playbook-owned**.

**`carlos-waf`** (the internet-facing edge; joins ONLY the `carlos-edge`
network; logs to the host journal via Podman's journald driver):

| Container | Image | Role |
| --- | --- | --- |
| `waf` | `owasp/modsecurity-crs` (nginx, ModSecurity v3) | TLS terminated on `BIND_IP:HTTPS_PUBLISH_PORT` (8443), published as user-facing `:443` by an nftables redirect; ModSecurity CRS; proxies to `carlos-app:8443` over TLS by pod-name DNS (in-pod self-signed keystore, regenerated each pod start). Certs staged into a tmpfs emptyDir by a root `waf-init` initContainer (the rootless `nginx` user cannot traverse the 0700 host certs dir). nginx is the CRS family with upstream read-only-rootfs support — the RO flip is documented in the WAF pod template for when upstream publishes those tags |

**`carlos-app`** (the PHI runtime; publishes NO host ports; logs to the host
journal via Podman's journald driver):

| Container | Image | Role |
| --- | --- | --- |
| `carlos` | `localhost/carlos-app` (built here) | CARLOS on Tomcat 11 / JDK 21, context path `/carlos` |
| `drugref` | `localhost/carlos-drugref` (built here) | DrugRef2026 drug/interaction lookups, Tomcat on `127.0.0.1:8180` |
| `db` | `mariadb` (official) | MariaDB, reuses the existing datadir; binds in-pod loopback only — host admin via the unix socket at `$EMR_HOME/run/db-socket` or `podman exec` |
| `mysqld-exporter` | `quay.io/prometheus/mysqld-exporter` | *obs-profile-gated* — MariaDB metrics on pod loopback `:9104` (least-priv `exporter` account; runs non-root); not rendered when `carlos_obs_enabled: false` |
| `vmagent` | `victoriametrics/vmagent` | *obs-profile-gated* — scrapes `mysqld-exporter` (pod loopback) + `node-exporter` and VictoriaLogs' self-metrics (obs pod, cross-pod), remote-writes to the obs pod's VictoriaMetrics; not rendered when `carlos_obs_enabled: false` |

**`carlos-obs`** (survives app restarts; everything on host loopback /
`BIND_IP`; the whole pod is provisioned only when `carlos_obs_enabled: true`,
the default):

| Container | Image | Role |
| --- | --- | --- |
| `node-exporter` | `prometheus/node-exporter` | host CPU/mem/net metrics on `:9100` (moved out of the PHI pod; scraped cross-pod by the app-pod vmagent) |
| `victorialogs` | `victoriametrics/victoria-logs` | log store + query API on host loopback `127.0.0.1:9428` |
| `victoria-metrics` | `victoriametrics/victoria-metrics` | metric store on host loopback `127.0.0.1:8428` |
| `vmalert` | `victoriametrics/vmalert` (v1.136.0, digest-pinned) | continuous evaluation of the metric-derived alert rules against the co-located VictoriaMetrics; HTTP API on host loopback `127.0.0.1:8880` (`VMALERT_PORT`); runs `-notifier.blackhole` — no Alertmanager, `carlos-ctl monitor` relays firing rules (see [Alerting](#alerting--health-monitoring)) |
| `logcollect` | `timberio/vector` | reads the host journal, ships app-pod logs to VictoriaLogs (disk-buffered, backfills after an outage) |
| `logview` | `caddy` (official) | authenticated HTTPS view on `BIND_IP:9443` (TLS + basic auth; read-only routes into BOTH the logs and metrics UIs) |

phpMyAdmin is launched **on demand** (`carlos-ctl pma`), not run as a standing
container — see the phpMyAdmin section.

Files:

- `carlos_ctl/` — the host runtime CLI, a Python package (stdlib + distro
  PyYAML/bcrypt). Installed by the Ansible role to
  `/usr/local/lib/carlos-ctl/` with a `/usr/local/sbin/carlos-ctl` shim — no
  pip, no PyPI, no network at deploy time. Lifecycle-grouped verbs:
  `build [--use-cache]` / `source <show|update|set|clear>` (which CARLOS +
  DrugRef versions and artifacts builds use — the release-first sticky pins,
  persisted at `$EMR_HOME/build/.source-pin` and `.source-pin.drugref`) /
  `rebuild` / `play` / `rollback [--accept-schema-mismatch]` /
  `down [--disable]` / `enable` (app lifecycle); `status` / `logs` / `check`
  / `backup <full|binlogs|docs|verify|status|restore>` / `monitor` /
  `alert-test` / `cert-renew` (operations); `db` /
  `db-migrate [--db <database>]` / `db-dump` / `db-backup` /
  `pma [--ttl <min>]` (break-glass); `db-users` / `seal` /
  `rotate <db|db-root|log-view|obs|age-key|restic>` (security);
  `--instance <name>` / `instances [--prune]` / `uninstall` / `setup`
  (multi-instance); the unit-driven verbs `guard`, `secrets render`, and
  `alert <unit> <msg>`; plus `help` and `version`
- `ansible/site.yml` — the provisioning playbook (one inventory host = ONE
  instance); `ansible/inventory.example` — starter inventory
- `ansible/roles/carlos_podman/` — the role: `defaults/main.yml` (the complete
  documented option list — every knob the old `carlos-app.env.example`
  carried, as `carlos_*` vars), `tasks/` (asserts → host → cli → instance →
  cleanup), `templates/` (all former `@TOKEN@` templates as Jinja2: the three
  pod specs, `carlos-app.env`, `carlos.properties`, `drugref2.properties`,
  `Caddyfile`, `restic.env`, `exporter.my.cnf`, vector/vmagent/vmalert
  configs, the nftables ruleset, the systemd units/timers, the Quadlet
  `.kube` units, the instance registry entry)
- `Containerfile` — multi-stage build: Maven-builds the CARLOS WAR from
  GitHub — or, when the pinned release publishes one, downloads the release's
  WAR asset instead (sha256-verified `download` stage, selected by
  `carlos-ctl build` via `CARLOS_WAR_STAGE=download`) — and bakes it into
  `tomcat:11.0-jdk21-temurin`
- `Containerfile.drugref` — same pattern for DrugRef2026 (`drugref2.war`),
  including the release-WAR `download` stage; mirrors the upstream
  devcontainer's drugref service
- `conf/` — the **verbatim, operator-owned** conf files (installed once by
  the role with `force: false`, never overwritten): `tomcat/server.xml`
  (Tomcat **11** — the old OpenO-era `server.xml` targets an older Tomcat),
  `tomcat/context.xml` (SameSite=Lax session cookie), `tomcat/logging.properties`
  (console-only JULI shared by both Tomcats), `drugref/server.xml` (connector
  on 8180, shutdown port disabled), `drugref/drugref2-context.xml` (baked
  into the DrugRef image), `mariadb/zz-carlos.cnf` (`innodb_page_size=32K`
  kept to match existing data; binlog + loopback bind), and the WAF tuning
  files `waf/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf` +
  `waf/nginx-headers.conf`
- `scripts/dev-setup.sh` — helper for the QUICKSTART dev walk-through:
  automates the instance directory layout, verbatim conf copies, and the
  `carlos.properties`/pod-spec renders (QUICKSTART step 3), password off-argv
- `tests/run-tests.sh` — the hermetic e2e suite for the CLI: no
  root/podman/systemd/TPM/sops needed — `tests/stubs/` provides recording
  fakes for Podman, systemctl, systemd-creds, sops, age, nft, ss, curl, …,
  and the `CARLOS_{CREDSTORE,SYSTEMD,QUADLET,INSTANCE_REGISTRY,JOURNAL}_DIR`
  overrides redirect every system write into a throwaway directory. It
  fabricates an Ansible-rendered instance home (the playbook's output
  contract) and drives the CLI against it
- `tests/unit/` — pytest unit tests for the pure-logic modules (config
  parsing, validation, the release-resolution policy and source pins, PITR
  anchor parsing, secrets round-trips, monitor)
- `tests/ansible-checks.sh` — role checks: syntax, ansible-lint, a full
  template render into a temp prefix (both obs profiles, token-free output),
  second-run idempotency, and the obs-toggle round trip
- `tests/db-migrate-integration.sh` — non-hermetic integration test proving
  the `db-migrate` collation contract against a REAL MariaDB 11.4+ server
  (root + podman + network; refuses to run beside a live deployment) — see
  [Tests](#tests)
- `scripts/validation/` — the non-hermetic real-usage validation harness
  (real podman, disposable hosts only; read `scripts/validation/README.md`
  before running)
- `Makefile` — `make check` = ruff + mypy + pytest + the e2e suite + the
  Ansible checks (dev-workstation targets; production installs never run
  make)
- `pyproject.toml` — dev toolchain config and workstation editable installs
  only (production hosts get the package file-copied by the role)
- [`QUICKSTART.md`](QUICKSTART.md) — guided walk-throughs (sample pod +
  standard deployment); [`docs/`](docs/README.md) — the docs index and
  development notes; `examples/` — the sample-deployment pod spec;
  [`LICENSE`](LICENSE) — AGPL-3.0-only (see [License](#license))

## Contents

- [Quick start](#quick-start)
  - [First login](#first-login)
- [Design rationale](#design-rationale)
- [Migration from the bash carlos-ctl](#migration-from-the-bash-carlos-ctl)
- [Running one or multiple instances](#running-one-or-multiple-instances)
- [carlos.properties (replaces oscar.properties)](#carlosproperties-replaces-oscarproperties)
- [Database: keeping your MariaDB data](#database-keeping-your-mariadb-data)
  - [Blank-datadir guard](#blank-datadir-guard)
  - [Schema](#schema)
- [What changed vs. the old openo-app pod](#what-changed-vs-the-old-openo-app-pod)
  - [Container privilege model](#container-privilege-model)
  - [Rootless engine](#rootless-engine)
  - [Least-privilege DB accounts](#least-privilege-db-accounts)
- [WAF/DB network isolation](#wafdb-network-isolation)
- [The observability pod is optional](#the-observability-pod-is-optional)
- [DrugRef](#drugref)
- [Logs & metrics](#logs--metrics)
  - [Logs](#logs)
  - [Metrics](#metrics)
  - [Viewing — the "slim SIEM"](#viewing--the-slim-siem)
- [WAF audit log & PHI](#waf-audit-log--phi)
- [Compliance risk register (accepted risks at a glance)](#compliance-risk-register-accepted-risks-at-a-glance)
- [Database admin from the host](#database-admin-from-the-host)
- [phpMyAdmin (on-demand database admin)](#phpmyadmin-on-demand-database-admin)
- [Secrets](#secrets)
  - [Single master (SOPS + age)](#single-master-sops--age)
  - [Sealing](#sealing)
  - [Portable disaster recovery](#portable-disaster-recovery)
  - [Rotating credentials](#rotating-credentials)
- [Opt-in hardening & data-integrity knobs](#opt-in-hardening--data-integrity-knobs)
- [Choosing the CARLOS and DrugRef versions](#choosing-the-carlos-and-drugref-versions)
  - [Prebuilt images (`<APP>_ARTIFACT=image`)](#prebuilt-images-app_artifactimage)
- [Updating](#updating)
  - [Upgrade considerations](#upgrade-considerations)
  - [Data-safety invariants](#data-safety-invariants)
- [Backups (restic)](#backups-restic)
  - [Guided point-in-time restore](#guided-point-in-time-restore)
  - [Disaster-recovery runbook (bare host → running EMR)](#disaster-recovery-runbook-bare-host--running-emr)
  - [Restore drill](#restore-drill)
  - [Native MariaDB physical backups (manual alternative)](#native-mariadb-physical-backups-manual-alternative)
- [Alerting & health monitoring](#alerting--health-monitoring)
  - [Validating a deployment (`carlos-ctl check`)](#validating-a-deployment-carlos-ctl-check)
  - [Alert → response runbook](#alert--response-runbook)
  - [Patching & rebooting the host](#patching--rebooting-the-host)
- [Troubleshooting](#troubleshooting)
  - [A container won't start](#a-container-wont-start)
- [Resource limits, JVM heap & health checks](#resource-limits-jvm-heap--health-checks)
  - [Liveness probes](#liveness-probes)
- [Supply chain & published images](#supply-chain--published-images)
  - [Release builds](#release-builds)
  - [Published prebuilt images (ghcr.io)](#published-prebuilt-images-ghcrio)
  - [TLS-inspecting egress proxy](#tls-inspecting-egress-proxy)
- [Tests](#tests)
- [Requirements](#requirements)
- [License](#license)

## Quick start

> [QUICKSTART.md](QUICKSTART.md) explains both available paths: a small
> sample-data pod for evaluation and the standard Ontario or British Columbia
> deployment. The steps below are the full Ansible workflow, including the WAF,
> backups, monitoring, and secret sealing.

Check the target host against [Requirements](#requirements) first (Podman ≥
4.9, cgroups v2, systemd, RAM sized to the pod limits, and friends).
Provisioning runs from a **control node** (your workstation or a management
host) with `ansible-core`, `passlib`, and `netaddr` installed plus the
`ansible.utils` collection:

```bash
pip install ansible-core passlib 'bcrypt<4.1' netaddr
ansible-galaxy collection install ansible.utils
```

(`passlib` bcrypt-hashes the log-view credential **on the control node** —
the plaintext never crosses to the target; `netaddr`/`ansible.utils` derive
the log-view firewall subnet from the target's interfaces. The `bcrypt<4.1`
pin is required: passlib 1.7.4 reads an attribute bcrypt removed in 4.1, so a
newer bcrypt makes `password_hash('bcrypt')` fail mid-play — an early role
assert catches this and points here.)

```bash
git clone <this repo> && cd carlos-podman
```

**1. Describe the instance.** Either run the guided wizard — it asks the
site questions (instance name, `EMR_HOME`, `BIND_IP`, server name, ports, DB
root password, billing province, TLS mode, timezone, alert email/heartbeat,
obs profile) and emits a starter host_vars file; it provisions nothing:

```bash
python3 -m carlos_ctl.cli setup        # writes ansible/host_vars/<instance>.yml
```

…or hand-write `ansible/host_vars/<instance>.yml` — every option, with its
default and rationale, is documented in
`ansible/roles/carlos_podman/defaults/main.yml`. Add the instance to your
inventory (see `ansible/inventory.example`: one line per instance).

**2. Vault the MariaDB root password.** `setup` writes it plaintext 0600
because it ran interactively — vault it before the file goes anywhere near a
repo:

```bash
ansible-vault encrypt_string --name carlos_db_root_password
```

…and paste the result over the plaintext line in host_vars.

**3. Provision.** Idempotent; re-run it forever. This is the old `init` +
`bootstrap` + `sync-conf` in one verb: host prep (service user, subuids,
linger, persistent journald), every rendered config/unit/quadlet, the Podman
networks + db secret, the nftables redirect, the instance registry entry,
and the installed `carlos-ctl` CLI:

```bash
sudo ansible-playbook -i inventory ansible/site.yml
```

**4. Front-door TLS.** The default mode is `selfsigned` (`carlos_tls_mode`):
provisioning and `play` generate a self-signed cert+key at
`$EMR_HOME/container/conf/waf/certs/{fullchain,privkey}.pem` automatically,
so the WAF starts with nothing to do here — browsers warn until you replace
it. Two alternatives (set `carlos_tls_mode` in host_vars):

- `manual`: place your own `{fullchain,privkey}.pem` at that path; `play`
  refuses to start without them.
- `acme`: Let's Encrypt via a certbot sidecar. After DNS for the server name
  points here, issue/renew with
  `sudo EMR_HOME=/usr/local/emr carlos-ctl cert-renew` (a daily renew timer
  is installed in acme mode). Needs `carlos_acme_email`.

`play` never clobbers an operator-placed cert; in selfsigned mode it only
(re)generates one that is missing or an expired self-issued pair.

**5. Build the CARLOS and DrugRef images.** The role installed the build
context to `$EMR_HOME/build/`. The first build resolves each app's newest
GitHub release (newest non-prerelease by publish time > newest prerelease >
its fallback-branch HEAD: `main` for CARLOS, `master` for DrugRef), prefers
the release's published WAR (sha256-verified — skips the long Maven
compile), and pins the choices in `$EMR_HOME/build/` (`.source-pin`,
`.source-pin.drugref`): later builds stay on those pins, offline, until
`carlos-ctl source update` moves them. `carlos-ctl source` shows what is
pinned; see
[Choosing the CARLOS and DrugRef versions](#choosing-the-carlos-and-drugref-versions).

```bash
sudo EMR_HOME=/usr/local/emr carlos-ctl build
```

**6. Start, then validate.** `play` provisions least-privilege DB accounts
by default (app, DrugRef, backup, metrics-exporter) and restarts the app off
the MariaDB root account (the playbook rendered `CARLOS_DB_ROOT_PASSWORD`
into `carlos-app.env` for this; `play` refuses to deploy an unprovisioned
app with no password available — `CARLOS_ALLOW_DB_ROOT=1` overrides once,
and `CARLOS_SKIP_AUTO_DB_USERS=1` defers provisioning to a later manual
`carlos-ctl db-users`). `play` also refuses go-live without an alert channel
(`ALERT_JOURNAL_ONLY=1` to accept journal-only) and without a
`HEARTBEAT_URL` dead-man's switch (`CARLOS_NO_HEARTBEAT=1` to accept the
blind spot). The first successful play starts the backup/monitor timers and
seeds their freshness stamps.

```bash
sudo EMR_HOME=/usr/local/emr carlos-ctl play
sudo EMR_HOME=/usr/local/emr carlos-ctl check
```

> **Fresh install — expect this first `play` to exit nonzero.** It starts
> the pods (which is what steps 7–8 need: the db must be running to load SQL
> into), then gates go-live on the app AND DrugRef actually serving. On a
> machine with no `oscar` and no `drugref2` database yet, neither can:
> CARLOS waits out its wait-for-db and deploys against a missing schema, and
> DrugRef's `/drugref2` context cannot start at all. So `play` reports "the
> app is not serving", writes no go-live markers and arms no timers —
> correct, not a failure of the install. Load the databases (steps 7–8),
> then re-run `play` (step 9); that run is the one that goes green and arms
> the schedule.

**7. Fresh install only — load the CARLOS schema** (no existing datadir;
after `play` so the db is running, before first login). Reusing an existing
OpenO/OSCAR datadir? Skip this — the app logs any missing migrations at
startup. MariaDB publishes no TCP port (the WAF/DB isolation boundary), so
any loader that drives a `mysql` client over TCP cannot reach this
deployment — use `carlos-ctl db-migrate`, which runs each migration file in
a client session pinned to the schema's collation:

```bash
sudo EMR_HOME=/usr/local/emr carlos-ctl db -e 'CREATE DATABASE IF NOT EXISTS oscar DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci'
```

…then apply the Flyway migration files from a
`github.com/carlos-emr/carlos` checkout in version order through one
`carlos-ctl db-migrate` invocation — the full current file list (Ontario and
BC variants) and the collation rationale live in [Schema](#schema).

**8. Fresh install only — create and load the drugref2 database** (the full
recipe is in the [DrugRef section](#drugref), including the mandatory InnoDB
conversion). It belongs here, before the go-live play: DrugRef's Spring
context builds its Hibernate session factory at startup and never retries,
so a container started against a missing `drugref2` serves 404 for the rest
of its life and `play` can never green.

**9. Fresh install only — re-run `play`.** With both databases loaded, this
is the run that turns green, writes the go-live markers and arms the
backup/monitor timers:

```bash
sudo EMR_HOME=/usr/local/emr carlos-ctl play
sudo EMR_HOME=/usr/local/emr carlos-ctl check
```

**10. Seal secrets** into the SOPS+age single-master bundle (TPM-protected
key at rest where available) and escrow the age private key AND the full
`restic.env` content off-host — those two are what recover everything,
including the backups; `seal` refuses until you confirm both:

```bash
sudo EMR_HOME=/usr/local/emr carlos-ctl seal
```

Then browse to `https://<SERVER_NAME>/` — the image redirects `/` to
`/carlos/`.

(`EMR_HOME=/usr/local/emr` is the default — the prefix is only needed for a
non-default home or a second instance; `carlos-ctl --instance <name> <verb>`
resolves it from the registry the playbook wrote.)

### First login

CARLOS ships **no default production credentials.** A fresh
schema load seeds the initial administrator account per upstream's database
setup (see `database/mysql/` in the app repo); create your own provider/admin
accounts through the Administration UI immediately and disable any seed
account. A datadir carried over from an existing OpenO/OSCAR install keeps its
existing logins.

Each pod runs as a systemd service via a Podman Quadlet unit, but under the
SERVICE_USER's **`systemd --user`** manager (not the system manager), because
the engine is rootless — `carlos-obs.service` (log/metric stores + collector +
vmalert + view; only when the obs profile is on), `carlos.service` (the app,
journald log driver, ordered after the obs pod), and `carlos-waf.service` (the
edge WAF, journald log driver, ordered after the app). The Quadlet `.kube`
files live under `/etc/containers/systemd/users/<uid>/` and the units are
wired `WantedBy=default.target`, so login lingering starts them at boot.
`carlos-ctl play` is `systemctl --user -M <SERVICE_USER>@ restart` of
obs → app → waf under the hood, `carlos-ctl down` stops them in reverse.
Inspect them with the same remote-user-manager flags, e.g.
`systemctl --user -M carlos@ status carlos.service`; pod lifecycle events are
in the **user** journal — `journalctl --user-unit carlos.service` when logged
in as the service user, or `journalctl _SYSTEMD_USER_UNIT=carlos.service` as
root. On hosts without systemd, `play`/`down` fall back to plain rootless
`podman kube play`/`kube down` (run via `runuser -u <SERVICE_USER>`; obs
first; the app pod on `carlos-net` + `carlos-edge` with `--log-driver
journald`; the waf pod on `carlos-edge` only). The backup/monitor timers, the
boot-time datadir guard, TPM secret-sealing, and the nftables redirect stay
**root** system units — root is retained for host operations only.

> **On a host with no systemd the fallback covers the PODS ONLY.** Nothing
> arms a schedule, so **you** must drive these from an external scheduler
> (cron/BusyBox crond), all with `EMR_HOME=<your home>`:
> `carlos-ctl backup full` nightly, `carlos-ctl backup binlogs` and
> `carlos-ctl backup docs` every 15 minutes, `carlos-ctl backup verify`
> weekly, `carlos-ctl monitor` every 15 minutes (the systemd timer cadence —
> it is the paging ceiling for metric-derived alerts), and `carlos-ctl
> guard` **before** the
> pods at boot. On a **sealed** instance also run `carlos-ctl secrets render`
> before the pods at every boot — the credential fragments live in tmpfs and
> the app refuses to start on the `__SEALED__` placeholder without them
> (`play` and `seal` render them inline for the run in front of you, but
> nothing recreates them across a reboot). `carlos-ctl play` and
> `carlos-ctl check` both print this reminder on such a host.
>
> "No systemd" here means **systemd is not usable**, not merely that the
> binary is missing. carlos-ctl applies sd_booted(3)'s own test —
> `/run/systemd/system` exists only while systemd is running as PID 1 — in
> addition to the PATH lookup, because Debian/Ubuntu ship `systemctl` inside
> container images, WSL distributions and chroots where systemd never
> booted and every call exits nonzero. Both shapes take the fallbacks above.

The playbook is idempotent, and its two file-ownership classes are the
contract to remember:

- **Playbook-owned** (re-rendered on every run — change host_vars, re-run):
  `carlos-app.env`, the three pod YAMLs, the systemd units/timers, the
  Quadlets, the nftables ruleset, the vector/vmagent/vmalert configs, the
  registry entry, the build context.
- **Operator-owned** (rendered once with `force: false`, then **never
  overwritten** — your edits survive every playbook run):
  `carlos.properties`, `drugref2.properties`, the `Caddyfile`, `restic.env`,
  `exporter.my.cnf`, the container `resolv.conf`, and every verbatim file
  under `conf/` (`zz-carlos.cnf`, `server.xml`, the WAF tuning files).

## Design rationale

**Why a Python CLI for the host runtime.** The bash `carlos-ctl` had grown to
4,078 lines of quoting discipline, hand-rolled JSON scraping, and one-shot
helper containers. The Python rewrite is **stdlib-first** (the only imports
beyond it are distro `python3-yaml` and `python3-bcrypt`), which buys three
things a PHI host actually cares about. First, *in-process* JSON/YAML/bcrypt:
the monitor parses vmalert's API and the backup parses restic's output
without `jq`, `rotate log-view` computes the Caddy bcrypt hash in-process
where the bash needed a one-shot caddy container fed the plaintext on stdin.
Second, **off-argv secrets by construction**: every credential travels by
environment *name* (`podman exec -e MYSQL_PWD`), stdin (`curl -K -` config
for webhook/heartbeat capability URLs, kube-play secret manifests), or
root-only files — a secret is never a `/proc/<pid>/cmdline` token, and the
config layer *parses* `carlos-app.env` instead of sourcing it (a hostile line
is inert data). Third, **testability**: the pure logic runs under pytest
(`tests/unit/`), and the process-spawning paths run under the same PATH-stub
harness the bash suite used (`tests/run-tests.sh`) — the recording stubs and
throwaway-directory overrides carried over intact, so the e2e contract
survived the rewrite. No pip on the host: the Ansible role file-copies the
package and installs a two-line shim.

**Why Ansible for provisioning.** The bash `init`/`bootstrap`/`sync-conf`
had become a hand-rolled configuration-management engine: `@TOKEN@` template
rendering, a shipped-file staleness manifest, an instance registry walked by
a collision checker. Idempotent templating, ownership semantics
(`force: false` = operator-owned), drift review (`--check --diff`), and
inventory are exactly what Ansible is, so the role replaces all of it with
less code and better guarantees. The **one-inventory-host-per-instance**
model makes cross-instance safety declarative: the playbook sees every
sibling instance's host_vars at once, so colliding ports, shared
`EMR_HOME`s, and prefix-overlapping instance names are **refused by assert
tasks before any mutation** — the old registry-walking checker's job, done
where the data already lives. The registry survives, but demoted to runtime
metadata: the role writes `/etc/carlos-podman/instances/<name>.conf`, and the
CLI only reads it (`--instance` resolution, `instances`).

**Why vmalert, and not Alertmanager.** The metric-derived health rules
(`mysql_up != 1`, scrape targets down, disk floor, log-ingestion staleness)
used to be re-derived by the shell monitor polling the VictoriaMetrics API
once an hour. vmalert evaluates them **continuously** (30 s interval, with
`for:` windows that absorb scrape blips) — but it deliberately notifies
nobody: it runs `-notifier.blackhole`, the upstream-supported evaluate-only
mode. `carlos-ctl monitor` polls vmalert's `/api/v1/alerts` and relays firing
rules through the alert path it already owns — journal, webhook, email,
heartbeat, per-condition re-remind throttling. An Alertmanager would be a
second stateful daemon with its own routing config, silence state, and HA
story, duplicating a dispatch pipeline that already exists; one less daemon
on a single-host PHI system wins. A monitor that finds vmalert unreachable
treats *that* as a firing alert — a dead alerting engine must not read as
"no alerts".

**Why sops/age stay exec'd binaries.** There is no maintained Python
implementation of the SOPS format worth trusting with the master secret path,
so the CLI execs `sops`/`age`/`age-keygen` exactly as the bash did. The
discipline is unchanged: plaintext never touches argv (bundle edits go
through a decrypt → re-encrypt round-trip in `/run` tmpfs rather than
`sops --set`, which would put the value on a world-visible command line), and
the age private key lives in a root-only directory outside the pod-mounted,
backed-up `container/` tree.

**One clinic per host stays the recommended fleet model** (unchanged — full
blast-radius isolation for a PHI system; see
[Running one or multiple instances](#running-one-or-multiple-instances)).
Ansible makes that model *cheaper*, not different: the same playbook run
provisions every host in the inventory, and per-clinic differences are one
host_vars file each.

**Why the observability pod is optional.** A solo-physician clinic gets real
value from the WAF, the backups, and the monitor — but VictoriaMetrics +
VictoriaLogs + vector + vmagent + vmalert + two exporters + an authenticated
log view is fleet-grade tooling with fleet-grade RAM cost (~6 GiB of
limits) and its own attack/maintenance surface. Proportionality is a
security posture too. The floor that is **always** present regardless of the
profile: Podman's journald log driver (every container's output lands in the
persistent host journal — `podman logs` / `journalctl`), and the monitor's
own store-independent liveness sweep. See
[The observability pod is optional](#the-observability-pod-is-optional).

## Migration from the bash carlos-ctl

The verbs and their contracts (arguments, refusal conditions, data-safety
invariants, exit codes) are preserved; what moved is *provisioning*.

| bash-era | now |
| --- | --- |
| `carlos-ctl init` (host prep) | `ansible-playbook -i inventory ansible/site.yml` (role `tasks/host.yml`) |
| `carlos-ctl bootstrap` (instance provisioning) | same playbook run (role `tasks/instance.yml`) |
| `carlos-ctl sync-conf [--apply]` | **gone** — drift handling is re-running the playbook; preview with `--check --diff`. Playbook-owned files are re-rendered every run; operator-owned files are never overwritten (merge shipped changes from `conf/` / the role templates yourself) |
| `carlos-ctl render` | **gone** — the playbook renders; `carlos-ctl play` *validates* the rendered artifacts (present, token-free, no stray Jinja markers, sane memory margins) before starting anything |
| `carlos-ctl setup` (wizard that wrote `carlos-app.env` + ran init/bootstrap) | still exists, retargeted: captures the site answers and **emits a starter `host_vars/<instance>.yml`** for the playbook — one source of truth, no second provisioning path. Refuses to clobber an existing file |
| the registry collision checker in `bootstrap`/`play` | cross-instance collision checking moved to the role's **assert tasks** (the playbook sees all siblings' host_vars); the registry is now *written by the role, read by the CLI*. `play` keeps the within-instance runtime checks Ansible can't do from vars: a foreign nft table claiming the front door, a foreign listener already holding a port |
| `carlos-backup.sh` | `carlos-ctl backup <full\|binlogs\|docs\|verify\|status\|restore>` |
| `carlos-monitor.sh` | `carlos-ctl monitor` |
| `carlos-alert.sh` | `carlos-ctl alert <unit> [detail]` / `carlos-ctl alert-test` |
| `carlos-secrets.sh` (boot-time sealed render) | `carlos-ctl secrets render` |
| `carlos-guard.sh` (boot-time datadir guard) | `carlos-ctl guard` |
| every other verb (`build [--use-cache]`, `rebuild`, `rollback [--accept-schema-mismatch]`, `play`, `down [--disable]`, `enable`, `status`, `logs`, `check`, `backup`, `monitor`, `alert-test`, `db`, `db-migrate [--db <database>]`, `db-dump`, `db-backup`, `pma [--ttl <min>]`, `db-users`, `seal`, `rotate <db\|db-root\|log-view\|restic\|obs\|age-key>`, `cert-renew` (acme mode), `instances [--prune [--yes]]`, `uninstall`, the `--instance` selector) | unchanged (`db-migrate` and `logs` are new since the bash CLI) |

The five installed helper shell scripts are gone entirely — their logic is CLI
subcommands, and the systemd units now `ExecStart` the CLI directly:

```text
<instance>-backup.service          ExecStart=/usr/local/sbin/carlos-ctl backup full
<instance>-binlog.service          ExecStart=/usr/local/sbin/carlos-ctl backup binlogs
<instance>-docs.service            ExecStart=/usr/local/sbin/carlos-ctl backup docs
<instance>-backup-verify.service   ExecStart=/usr/local/sbin/carlos-ctl backup verify
<instance>-monitor.service         ExecStart=/usr/local/sbin/carlos-ctl monitor
<instance>-alert@.service          ExecStart=/usr/local/sbin/carlos-ctl alert "%i"
<instance>-guard.service           ExecStart=/usr/local/sbin/carlos-ctl guard
<instance>-secrets.service         (installed by `carlos-ctl seal`) → carlos-ctl secrets render
```

The role's **cleanup task removes the old helper scripts**
(`carlos-{backup,alert,monitor,secrets,guard}.sh`) and the `sync-conf`
staleness manifest from upgraded hosts, so a leftover bash-era timer can never
call the old scripts against the new credential layout.

**THE behavioral change — `carlos-app.env` is playbook-owned now.** The old
flow was "edit `carlos-app.env`, run `carlos-ctl play`" (play re-rendered the
pod specs from it every time). The new flow is:

```text
edit host_vars/<instance>.yml  →  sudo ansible-playbook -i inventory ansible/site.yml  →  carlos-ctl play
```

The playbook re-renders `carlos-app.env` **and** the pod specs/units that
consume it on every run — a hand edit to `carlos-app.env` is overwritten by
the next playbook run, and the file's header says so. (`play` still *reads*
`carlos-app.env` on every invocation — it is the runtime contract between the
playbook and the CLI/units — it just no longer renders anything from it.)
Everything that was operator-owned stays operator-owned:
`carlos.properties` / `drugref2.properties` / `Caddyfile` / `restic.env` /
`exporter.my.cnf` / `zz-carlos.cnf` are rendered once and never overwritten —
edit those files directly, then `carlos-ctl play`.

**Upgrading an existing install — behavior that changed in this hardening
pass.** A single playbook re-run followed by `carlos-ctl play` applies all of
it; note these four:

- **Obs stores are now authenticated.** The re-run mints the per-instance
  credential and re-renders every consumer, and applies *idempotent* migrations
  to the operator-owned `Caddyfile` (adds the `Authorization` header the log
  view needs). The pod specs apply at the next start; `play` restarts obs → app
  → waf and vmagent disk-buffers across the seconds-wide 401 window, so there
  is no log loss. Set `carlos_obs_http_auth: false` to keep the old
  unauthenticated posture.
- **The host firewall defaults ON.** On a multi-instance host set
  `carlos_host_firewall_enabled: false` on every instance but one (it is
  host-global), and confirm `carlos_host_firewall_ssh_port` matches your sshd —
  the role asserts a valid port before applying the default-deny.
- **Front-door TLS defaults to `selfsigned`.** An install that relied on the
  old "place the cert or `play` refuses" behavior should set
  `carlos_tls_mode: manual` to KEEP that refusal — otherwise a missing cert is
  now auto-filled with a self-signed pair (operator-placed certs are never
  overwritten either way).
- **Operator-owned confs gained security lines** (drift-warned, never
  auto-applied): `Caddyfile` gets an access-`log` directive (truthful
  fail2ban recipe) and `nginx-headers.conf` gains `Cache-Control: no-store` for
  PHI pages. `carlos-ctl check` / the baseline drift warning flags these on an
  existing install so you can merge them by hand.

The documented option list moved with the ownership: the old
`carlos-app.env.example` is gone; the reference is now
`ansible/roles/carlos_podman/defaults/main.yml` (`@TOKEN@` →
`carlos_<token lowercased>`).

## Running one or multiple instances

An **instance** is one CARLOS deployment: the `carlos-app` pod, its
`carlos-obs` and `carlos-waf` pods, and their timers/secrets. Most sites run
exactly one. You can run several — for separate clinics or environments — and
the unit of definition is now the **inventory host**: one inventory line +
one `host_vars/<instance>.yml` per instance. Two instances on one machine are
two inventory hosts with the same `ansible_host`:

```ini
[carlos_instances]
carlos      ansible_host=emr1.example.ca
clinicb     ansible_host=emr1.example.ca    # second instance, same machine
clinicc     ansible_host=emr2.example.ca
```

**Concept.** `carlos_instance` (default `carlos`) names the group, and every
host-global identity derives from it: the pods (`$INSTANCE-app` /
`$INSTANCE-obs` / `$INSTANCE-waf`), the Podman networks (`$INSTANCE-net`,
`$INSTANCE-edge`), the db-root secret (`$INSTANCE-db`), every systemd unit
and timer (`$INSTANCE.service`, `$INSTANCE-backup.timer`,
`$INSTANCE-secrets.service`, …), the TPM credstore blobs, the
`/run/$INSTANCE-emr` tmpfs, and the log collector's journal filter (it ships
only `$INSTANCE-app-*` and `$INSTANCE-waf-*` container logs). The default
`carlos` reproduces the original names exactly, so single-instance installs
need change nothing. Instance names are lowercase `[a-z0-9-]`, and sibling
names may not prefix-overlap (`carlos` / `carlos-b` would cross-match the
`$INSTANCE-*` unit globs) — the role asserts both.

**One instance per host (the recommended fleet model).** For separate
clinics, run one instance per host/VM: one inventory host each, each with its
own `carlos_emr_home`, `carlos_bind_ip`, `carlos_server_name`. This is the
strongest posture for a PHI system — full blast-radius isolation (separate
kernel, disk, network, backups), no shared ports, and one clinic's incident
cannot touch another's.

**Multiple instances on one machine.** Give each a distinct
`carlos_instance`, a distinct `carlos_emr_home`, and offset the host ports
(loopback ports cannot be shared; the TLS ports can instead use a distinct
`carlos_bind_ip`). In `host_vars/clinicb.yml`:

```yaml
carlos_instance: clinicb
carlos_emr_home: /usr/local/emr-clinicb
carlos_bind_ip: 192.168.20.251       # or reuse the IP and offset the TLS ports
carlos_victorialogs_port: 19428
carlos_victoriametrics_port: 18428
carlos_vmalert_port: 18880
carlos_log_view_port: 19443
carlos_pma_port: 19444
# carlos_https_port: 10443           # user-facing TLS port; offset only if bind_ip is shared
# carlos_https_publish_port: 18443   # port the rootless WAF publishes; offset if bind_ip is shared
```

(`carlos-ctl setup` suggests a +10000 offset set automatically for any
non-default instance name.)

Each instance renders its own per-instance nftables table
(`ip <INSTANCE>-nat`) redirecting its `BIND_IP:HTTPS_PORT →
HTTPS_PUBLISH_PORT`, so two instances on the same `BIND_IP` must offset
**both** `HTTPS_PORT` and `HTTPS_PUBLISH_PORT` (a distinct `BIND_IP` avoids
the clash entirely). Instances may share the SERVICE_USER (one rootless
engine / image store) or each set its own `carlos_service_user`; a distinct
service user per instance gives each its own engine and full user-level
isolation.

**The port rule.** Each instance's WAF SSL entry is reachable on its own
user-facing `HTTPS_PORT` — **443 by default** for the first instance.
`HTTPS_PORT` may be a privileged port (443) because *root* installs the
nftables redirect; the ports the **rootless** engine actually binds
(`HTTPS_PUBLISH_PORT`, `LOG_VIEW_PORT`, and the loopback
`VICTORIALOGS_PORT` / `VICTORIAMETRICS_PORT` / `VMALERT_PORT` / `PMA_PORT`)
must be **≥ 1024**. Two coexistence patterns:

| Pattern | `carlos_bind_ip` | What to offset |
| --- | --- | --- |
| **Shared IP, offset ports** | same for all instances | **every** port — `HTTPS_PORT`, `HTTPS_PUBLISH_PORT`, `LOG_VIEW_PORT`, and the four loopback ports (all bind the same IP / 127.0.0.1) |
| **Per-instance IP** | one `bind_ip` per instance | only the **loopback** ports (`VICTORIALOGS`/`VICTORIAMETRICS`/`VMALERT`/`PMA`, always 127.0.0.1); each instance may keep 443/8443/9443 on its own IP |

**Collisions are refused, not warned — at playbook time.** The role's assert
tasks cross-check every sibling instance targeting the same machine (same
`ansible_host`): a shared `carlos_emr_home`, a colliding loopback port, a
colliding `BIND_IP` port set, a prefix-overlapping instance name, or a
rootless-published port `< 1024` **fails the play with a message naming the
conflict** — before any mutation. `carlos-ctl play` keeps the runtime slice
the playbook cannot know from vars: it refuses to start onto a host port a
*foreign process* already holds (`ss` preflight;
`CARLOS_SKIP_PORT_PREFLIGHT=1` bypasses) and refuses a front door another nft
table already redirects. There is **no arbitrary limit** on the number of
instances.

**Host-global operations are serialized.** When two instances are two
inventory hosts on one machine, Ansible provisions them in parallel — but the
truly host-global steps (creating the shared service user, allocating the
subuid/subgid range) are `throttle: 1` and the subuid write additionally holds
an `flock` on `/etc/subuid`, so two parallel runs cannot double-allocate a
range and break the rootless uid mapping. And the **host default-deny
firewall is host-global**: it installs a single `policy drop` input chain, so
only ONE instance per machine may set `carlos_host_firewall_enabled` (the
asserts refuse a second owner). Since it now defaults ON, set it to `false` on
every instance but one when several share a machine.

List everything allocated on the host before adding another instance:

```text
$ sudo carlos-ctl instances
INSTANCE     EMR_HOME                 BIND_IP          HTTPS→PUB     LOGVIEW  VLOGS  VMETR  PMA    STATUS
carlos       /usr/local/emr           192.168.20.250   443→8443      9443     9428   8428   9444   active
clinicb      /usr/local/emr-clinicb   192.168.20.250   10443→18443   19443    19428  18428  19444  active
clinicc      /usr/local/emr-clinicc   192.168.20.251   443→8443      9443     9428   8428   9444   inactive
```

(`clinicb` shares the IP with `carlos` and offsets its ports; `clinicc` takes
a second IP and keeps 443. `instances --prune` drops entries whose `EMR_HOME`
was removed out-of-band. The registry under
`/etc/carlos-podman/instances/*.conf` is written by the role, read by the
CLI.)

Then drive an instance by name — the `--instance` selector resolves its
`EMR_HOME` from the registry (fail-closed on an unregistered name), so a
mutating verb can never target whatever `EMR_HOME` happened to be in the
environment:

```bash
sudo carlos-ctl --instance clinicb build     # (or reuse the shared images)
sudo carlos-ctl --instance clinicb play
sudo carlos-ctl --instance clinicb check
```

(`sudo EMR_HOME=/usr/local/emr-clinicb carlos-ctl <verb>` still works.)
Mutating verbs take a per-instance lock (a second concurrent mutating verb
fails fast instead of interleaving) and print a `==> target:` banner naming
the resolved instance/home first — the #1 footgun on a multi-instance host is
mutating the wrong one.

Each instance installs its own `$INSTANCE-*` units/network/secret/credstore
alongside the others; `carlos-ctl status`, `down`, `rotate`, `seal`, `pma`,
and `backup` all act on the instance you point at. What instances still
**share** on the host: RAM (size the host for the *sum* of all instances'
memory limits), the persistent journal (each instance's collector filters to
its own app-/waf-pod prefixes, so logs never cross), and host-level node
metrics (each instance's `node-exporter` reports the same host — expected).
The container images (`carlos_image`, `carlos_db_image`, …) are shared by
default; a `build` in one instance updates the image all instances run, so
stage upgrades deliberately.

**Decommissioning an instance.** `sudo carlos-ctl --instance clinicb
uninstall` cleanly removes **only** that instance's host wiring — pods,
networks, db secret, `$INSTANCE-*` units/timers/quadlets, the nftables
redirect, the `/run` tmpfs, and its registry entry — freeing its ports and
`EMR_HOME` for reuse. (Remove it from the inventory too, or the next playbook
run re-provisions it.) It **preserves all data**: the MariaDB
datadir/binlogs, `OscarDocument`, the restic repo and hot backups,
`container/conf` (including TLS certs), and the TPM cred blobs (needed to
decrypt those backups). It prints exactly which directories to remove by hand
if you truly intend to destroy the data — nothing under `$EMR_HOME` is
deleted automatically. Because it touches PHI-adjacent infrastructure, it
requires **double confirmation**: type `yes`, then re-type the instance name
(non-interactively, set `CARLOS_UNINSTALL_CONFIRMED=1` and
`CARLOS_UNINSTALL_INSTANCE=<name>`).

## carlos.properties (replaces oscar.properties)

CARLOS locates its override properties file via the JVM flag
`-Dcarlos_override_properties=/run/carlos-config/carlos.properties` (set in
`CATALINA_OPTS` in the pod spec). Your editable base file

```text
$EMR_HOME/container/conf/carlos/carlos.properties
```

is read by the `carlos-init` initContainer, which assembles the effective
config (that base plus, if sealing is in use, the db-credential fragment)
into the `carlos-config` tmpfs `emptyDir` at
`/run/carlos-config/carlos.properties` and chowns it to the runtime user —
the app container then reads it read-only. The base lives at a plain,
editable host path instead of the old `oscar.properties` Podman secret (keep
it `chmod 600`). Defaults ship in the WAR
(`src/main/resources/carlos.properties`); the mounted file overrides them.

The playbook renders this file **once** (operator-owned — your edits are
never overwritten by a playbook re-run), pre-filling the site values from
host_vars: `billregion` (`carlos_billing_province`), the
`ws_endpoint_url_base` derived from the server name, `TESTING=no`, the db
credentials, the app encryption key (`carlos_encryption_secret_key` →
`encryption.util.secret.key` — **required**: current CARLOS develop refuses
first boot without a pre-provisioned key, because it would otherwise try to
generate one and persist it into this file, which the pod mounts read-only;
`carlos-ctl setup` generates it, or run `openssl rand -base64 32`; rotating
it orphans values already encrypted under the old key, so escrow it with the
other instance secrets; **known early-access limitation**: unlike
`db_password`, this key is not yet covered by `carlos-ctl seal` — it remains
in the mode-0600 base properties file on disk even after sealing),
`drugref_url`, and generated Tomcat keystore passwords (so the well-known
`changeit` never ships; inert until the Sharing Center is enabled).
Everything site-specific beyond that is a hand edit — Ontario
billing IDs (`clinic_no`/`clinic_view`/`dataCenterId`/`billcenter` are
OHIP-registration lookups set at billing time), PGP keys, module credentials
(`email.*`, `mcedt.*`, `hcv.*`, `OMD_HRM_*`). The clinic name/address live in
the app's database via the Administration UI — they belong in neither file.
After editing, restart with `carlos-ctl play`.

**Porting your old oscar.properties:** most keys kept their names (both files
descend from OSCAR), so copy your site-specific values — clinic info, billing
region, HL7 settings, integrations — into the rendered file. The rendered
file declares `db_username`/`db_password` exactly ONCE, near the top (the
upstream end-of-file duplicate was removed so `carlos-ctl seal`, which reads
the first occurrence, and the app, which honours the last, always agree) —
keep it that way when editing by hand: Java properties are last-one-wins, so
a re-added duplicate would silently win over the managed value.

Document paths changed name with the fork: the container path is now
`/var/lib/OscarDocument` (was `/var/lib/OpenoDocument`), and all
`DOCUMENT_DIR`-family properties in the rendered file already point there.
Your existing files are reused — the playbook renames the host directory
`data/OpenoDocument` → `data/OscarDocument` once (same filesystem, plain
`mv`). If your existing tree doesn't contain the `oscar/document/...`
subdirectories the template expects, adjust the `*_DIR` properties to match
what you actually have on disk.

## Database: keeping your MariaDB data

The pod mounts the same datadir as before (`$EMR_HOME/data/mariadb-mnt`) into
the **official** `mariadb` image instead of the old custom-built
`mc-demo-db`:

- `MARIADB_AUTO_UPGRADE=1` runs `mariadb-upgrade` automatically when the
  datadir was written by an older server. It never downgrades — pick a
  `carlos_db_image` version ≥ whatever wrote your datadir (check
  `data/mariadb-mnt/mysql_upgrade_info` for the version that last wrote it).
  The default is `mariadb:11.4` — the longest-supported current LTS (May
  2029; MariaDB moved to 3-year LTS windows after it, so 11.8 ends June 2028
  while 12.3 gains only a month over 11.4). Because the in-place upgrade
  never downgrades, stay on 11.4 unless your datadir already demands newer,
  and plan the next one-way hop (12.3+ LTS) once it has matured, before 11.4
  sunsets in 2029.
- `zz-carlos.cnf` keeps `innodb_page_size=32K` (baked into an existing
  datadir — must not change) and defaults the **server** charset to
  **utf8mb4** (`utf8mb4_general_ci`). Note the app-repo schema still creates
  utf8mb3 columns until it is converted — see the charset note under
  [Database admin from the host](#database-admin-from-the-host).
- The root password of an existing datadir is unchanged; the `carlos-db`
  secret (`MARIADB_ROOT_PASSWORD_HASH`) is only consulted when initializing
  an **empty** datadir. Give the playbook (`carlos_db_root_password`) the
  password your DB already uses so `carlos.properties` gets the right
  `db_password`.
- **Take a backup first** (`mariadb-dump` from the old pod, or a filesystem
  copy of `mariadb-mnt` while stopped). The upgrade is one-way.

### Blank-datadir guard

A deployed instance whose datadir suddenly holds no
`mysql/` system schema means the data volume is unmounted or wiped — and
MariaDB would silently initialize a **blank** database over the empty
mountpoint. Three layers refuse that, sharing one signature definition:
`carlos-ctl play` refuses before starting; the root
`<instance>-guard.service` (`carlos-ctl guard`) re-checks at every boot,
*before* the user manager starts the pod, and pages via `OnFailure=`; and the
in-pod `db-init` initContainer is the hard stop even if both are bypassed.
`CARLOS_ACCEPT_EMPTY_DATADIR=1` accepts a fresh datadir on purpose (first
installs need nothing — the guard only arms after the first successful
`play`).

### Schema

CARLOS's schema is now Flyway-managed upstream: a consolidated
`V1` genesis baseline plus sequential forward migrations under
`database/mysql/migration/{common,on,bc}/` (the legacy
`createdatabase_*.sh`/`oscarinit*.sql`/`oscardata.sql` build was retired —
see `docs/database-schema-management.md` in the app repo). The app's Flyway
boot gate defaults to `off` (schema managed out of band, exactly as before);
production can set `carlos.flyway.onBoot=validate` in the properties to
fail fast on a version mismatch. Coming from an OpenO build, review the
migration READMEs for the adoption/baseline step before pointing the app at
an existing datadir. For a fresh install, load the schema **after
`carlos-ctl play`** (the db must be running) and **before first login**.
(The database itself is named `oscar`, kept as-is for upstream
compatibility — that name appears only in the SQL and the `carlos-ctl db
oscar` target, never in user-facing text.) MariaDB publishes no TCP port in
this deployment (the WAF/DB isolation boundary), so apply the files with
`carlos-ctl db-migrate` in version order, common and province interleaved —
from a `github.com/carlos-emr/carlos` checkout (Ontario shown; for BC use
the `bc/` twins of V1.0.1/V1.0.2/V1.0.6 and drop the Ontario-only
V1.0.4/V1.0.11/V1.0.12):

```bash
sudo EMR_HOME=/usr/local/emr carlos-ctl db -e 'CREATE DATABASE IF NOT EXISTS oscar DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci'
cd database/mysql/migration
sudo EMR_HOME=/usr/local/emr carlos-ctl db-migrate \
    common/V1__baseline_schema.sql on/V1.0.1__on_schema.sql \
    on/V1.0.2__on_data.sql common/V1.0.3__performance_indexes.sql \
    on/V1.0.4__on_performance_indexes.sql \
    common/V1.0.5__restore_live_legacy_common_tables.sql \
    on/V1.0.6__restore_reporting_privilege.sql \
    common/V1.0.7__restore_phcp_diagnosis_groups.sql \
    common/V1.0.8__expand_appointment_type_location.sql \
    common/V1.0.9__remove_carlosdoc_schedule_group_denial.sql \
    common/V1.0.10__seed_default_measurement_groups.sql \
    on/V1.0.11__billing_filename_unique_indexes.sql \
    on/V1.0.12__portable_billing_filename_unique_indexes.sql \
    common/V1.0.13__fix_phcp_diagnosis_group_backfill_collation.sql
# Current through V1.0.13. New migrations continue the V1.0.N sequence —
# check database/mysql/migration/README.md upstream for the current list.
```

`db-migrate` exists because collation pinning must happen **in the same
client session** that executes the SQL. MariaDB 11.4+ images ship
`character_set_collations = utf8mb4=uca1400_ai_ci`, so an utf8mb4 client
session gives every bare `CAST(... AS CHAR)` the uca1400 collation, and a
collation-sensitive migration — upstream
`common/V1.0.7__restore_phcp_diagnosis_groups.sql` is the known case —
aborts with `ERROR 1267` (illegal mix of collations). `db-migrate` starts
the client with `--init-command='SET NAMES utf8mb4 COLLATE
utf8mb4_general_ci'`; a standalone `carlos-ctl db -e 'SET NAMES ...'`
beforehand is NOT equivalent, because each `carlos-ctl db` run is its own
client process and session settings die with it. The verb stays fail-fast
(no `--force` — continuing past an arbitrary SQL error would leave the
schema in an unknown partial state).

**Recovery from a V1.0.7 collation abort:** a database migrated through a
plain client session may have stopped at V1.0.7 with `ERROR 1267` — its DDL
applied, its backfill `INSERT`s not. CARLOS migrations are written
re-runnable (IF-NOT-EXISTS DDL, existence-guarded backfills), so rerun the
failed file and every not-yet-applied file after it through one
`db-migrate` invocation, listing them explicitly in version order per the
upstream migration README — for example (Ontario, through the collation
fix; check upstream for files added since):

```bash
sudo EMR_HOME=/usr/local/emr carlos-ctl db-migrate \
    common/V1.0.7__restore_phcp_diagnosis_groups.sql \
    common/V1.0.8__expand_appointment_type_location.sql \
    common/V1.0.9__remove_carlosdoc_schedule_group_denial.sql \
    common/V1.0.10__seed_default_measurement_groups.sql \
    on/V1.0.11__billing_filename_unique_indexes.sql \
    on/V1.0.12__portable_billing_filename_unique_indexes.sql \
    common/V1.0.13__fix_phcp_diagnosis_group_backfill_collation.sql
```

The pinned sessions apply the aborted backfills and continue; files that
already completed are guarded no-ops, so overshooting is safe. On a BC
database the recovery sequence is the `common/` files only
(V1.0.7–V1.0.10 and V1.0.13) — V1.0.11/V1.0.12 are Ontario-only.

## What changed vs. the old openo-app pod

| | openo-app (old) | carlos-app (new) |
| --- | --- | --- |
| App image | `localhost/open-o-mc-demo` + `/workspace` source and `.m2` mounts | WAR baked into `localhost/carlos-app` at build time; no source/Maven mounts |
| Runtime | older Tomcat / JVM with CMS GC flags | Tomcat 11, JDK 21, G1 GC (`-XX:+UseConcMarkSweepGC` etc. no longer exist and would abort the JVM) |
| Context path | `/oscar` | `/carlos` (`/` redirects) |
| Properties | `oscar.properties` secret → `/root/oscar.properties` | host file, assembled by an initContainer into a tmpfs `emptyDir` at `/run/carlos-config/carlos.properties` via `-Dcarlos_override_properties` |
| Documents | `/var/lib/OpenoDocument` | `/var/lib/OscarDocument` (host dir renamed once by the playbook) |
| DB image | custom `localhost/mc-demo-db` | official `mariadb` + mounted `zz-carlos.cnf`, auto-upgrade on first start |
| DB secret | `openo-mc-demo` | `carlos-db` (same `mariadb-root-password-hash` key) |
| DrugRef | not present (drug lookups unavailable) | in-pod `drugref` container on `127.0.0.1:8180`, same pattern as the upstream devcontainer |
| phpMyAdmin | container on `:8081` | on-demand only (`carlos-ctl pma`, loopback + SSH tunnel, connects over the db unix socket) |
| FaxWS | container on `:8082` | dropped |
| server.xml | old-Tomcat version | Tomcat 11 version in `conf/tomcat/`, adds `RemoteIpValve` for correct `https://` behavior behind the WAF |
| WAF | in the app pod's netns — loopback reach to Tomcat AND MariaDB | own `carlos-waf` pod on a dedicated edge network; **no network path to MariaDB** (see [WAF/DB network isolation](#wafdb-network-isolation)) |

For ad-hoc database work — shell, exports, imports — see
[Database admin from the host](#database-admin-from-the-host) (and the
break-glass/audit caveats at the end of the
[phpMyAdmin](#phpmyadmin-on-demand-database-admin) section).

### Container privilege model

Root is used only where function demands it,
and never with Podman's full default capability set. Every container carries
`allowPrivilegeEscalation: false` and `seccompProfile: RuntimeDefault`, and
every container except the WAF and the run-once initContainers runs on a
**read-only root filesystem** (`readOnlyRootFilesystem: true`; writable state
lives on mounts — the Tomcats get `work`/`temp` emptyDirs and a build-time
pre-exploded, root-owned `webapps/` tree, the db a disk-backed `/tmp`
emptyDir). These claims are declared in the pod-spec templates and enforced
by Podman; a violated assumption fails **loudly** at start (`EROFS` /
`Operation not permitted` in the container's journald stream), and
`carlos-ctl check` probes the *runtime behaviors* they exist for — the
isolation boundaries, the pipelines, the front door:

| Container | User | Capabilities | Why |
| --- | --- | --- | --- |
| carlos, drugref | 10001 non-root | drop ALL | no root entrypoint; `tini` PID 1 reaps `Runtime.exec` orphans |
| mysqld-exporter | 65534 non-root | drop ALL | reads its own 0600 cnf |
| vmagent | 10012 non-root | drop ALL | image default was root for no reason; buffer chowned by db-init |
| victorialogs / victoria-metrics | 10010 / 10011 non-root | drop ALL | image default was root for no reason; store dirs chowned by obs-init |
| vmalert | non-root, static binary | drop ALL | stateless — the rules file is a read-only mount, no root-fs writes |
| logview (caddy) | 10013 non-root | drop ALL | :9443 > 1024; XDG state on chowned tmpfs emptyDirs |
| node-exporter | 65534 (image default) | drop ALL | default collectors read world-readable /proc//sys; root-only per-process detail deliberately given up |
| logcollect (vector) | **container uid 0, zero caps** | drop ALL | under the rootless engine container uid 0 = the unprivileged SERVICE_USER; it reads the service user's `user-<uid>.journal` (where the user-manager pods' journald output lands) via journald's owner ACL — the root-owned system journal is unreadable and unneeded. Requires journald `SplitMode=uid` (the default) |
| db (mariadb) | 999 non-root (the image's mysql uid) | drop ALL | the image's documented `--user` mode: started non-root, the entrypoint never enters its root phase; db-init owns the datadir/binlog/socket/backup-target chowns. An existing datadir is already 999-owned from prior root-entrypoint starts, so migration is a no-op; a wrong-owner datadir now fails loudly instead of self-healing |
| waf (nginx/CRS) | `nginx` (image default, non-root) | drop ALL | CRS-4-era images run entirely unprivileged (hence the >1024 listeners on 18000/18080); the nginx uid is image-assigned so it is deliberately not pinned. Root fs stays writable until upstream publishes its `*-nginx-read-only` variants (see the note in the WAF pod template) |
| initContainers | root | CHOWN (+DAC_OVERRIDE safety) | the pattern that lets everything else be non-root: assemble 0600 config into tmpfs, chown writable mounts |

The root-only setup is done by per-app **initContainers** (`carlos-init`,
`drugref-init`, `db-init`, `obs-init`): they read the mode-0600 base
properties, assemble the effective config into a tmpfs `emptyDir` (chowned to
the app uid, which the app reads read-only), and chown the writable
hostPath/emptyDir mounts. Tomcat's `ErrorReportValve` leaks neither the
version nor stack traces. **One-time migrations** on first start after an
upgrade: `carlos-init` chowns `logs` + the `OscarDocument` store to 10001,
`obs-init` chowns the VictoriaLogs/VictoriaMetrics stores to their new
non-root uids, `db-init` chowns the vmagent buffer and guards the datadir at
uid 999 — all guarded, so later starts skip them; a large log store may take
a moment. (The datadir guard is normally a no-op: the image's own root
entrypoint kept it 999-owned before this deployment went non-root.)

### Rootless engine

"Rootless" has two senses. The per-container work above
narrows what a compromised container can do; the engine itself is also
rootless: the three pods run in a **dedicated service user's**
(`carlos_service_user`, default `carlos`) Podman engine as `systemd --user`
quadlet units. The playbook's host tasks create that account with
`/etc/subuid` + `/etc/subgid` ranges (so container uid 0 maps to an
unprivileged host subuid) and `loginctl enable-linger` (so its user manager
and pods start at boot with nobody logged in).

Its **home** (`carlos_service_user_home`, default `/var/opt/<user>`) is a
correctness setting, not cosmetics: it is the parent of Podman's graphroot
(`$HOME/.local/share/containers/storage`), and netavark reads its network
definitions from `<graphroot>/networks`. Podman's **rootless network
namespace mounts a fresh tmpfs over both `/run` and `/var/lib`**, so a home
under either prefix hides those definitions from inside the very namespace
that has to resolve them, and every named bridge network fails at container
start with `unable to find network with name or ID <net>: network not found`
— even though `podman network ls` on the host lists it. Since all three pods
sit on named bridge networks, `carlos-ctl play` then aborts on its first
`podman kube play` and the instance can never start. The role asserts the
home is outside those prefixes; `play` re-checks the live account. **An
instance provisioned before this default changed** (its account's home was
`/var/lib/<user>`) is relocated by the next playbook run — stop it first
(`carlos-ctl down`, plus killing any surviving Podman `pause`/`catatonit`
helpers), because `usermod` refuses to move a home while any process runs as
the account. `carlos-ctl` runs as root and
drives the engine through `runuser -u $SERVICE_USER -- … podman …`; pod
services are controlled with `systemctl --user -M $SERVICE_USER@ …`.

**Root is retained only for host operations**, because they genuinely need it
and are cleanly separable from the pods: the
backup/binlog/docs/verify/monitor timers and the boot-time datadir guard run
as root **system** units (so **TPM sealing** via root-only `systemd-creds` is
unchanged — the sealed db fragments are simply installed owned by the service
user for the rootless initContainers to read), the log collector reads the
host journal, and `$EMR_HOME` host prep + the nftables redirect (below) are
root actions in the playbook.

**End users still reach `:443`.** A rootless process cannot bind a privileged
port, so the WAF publishes `HTTPS_PUBLISH_PORT` (default 8443) and the
playbook installs a root **nftables** redirect
`BIND_IP:HTTPS_PORT → HTTPS_PUBLISH_PORT` (a per-instance
`ip <instance>-nat` table, re-applied at boot by `<instance>-nft.service`).
It has a `prerouting` chain for external clients and an `output` chain so
host-local checks (the monitor's served-cert probe) hit the WAF too. This
keeps the privileged-port floor at 1024 for every other process — nothing
else can squat 443–1023.

With this model, **no container runs a root entrypoint, and even container
"root" is an unprivileged host subuid** — the only uid-0 (in the container
namespace) processes are the initContainers (CHOWN-only, run-once) and the
vector log collector (uid 0 as file OWNER, zero capabilities). The TLS key,
which the unprivileged WAF and log-view containers must read, is staged by
their initContainers (`waf-init` / `obs-init`) from the 0700 host certs dir
into per-pod tmpfs `emptyDir`s — a rootless container cannot read a 0700 host
dir it does not own, so the copy-out replaces the earlier direct bind mount.

**Read-only root filesystems** are ON for every container except two
deliberate exceptions:

- **The WAF** — the **nginx** CRS variant (the family upstream builds
  read-only support for), but upstream currently *publishes no*
  `*-nginx-read-only` image tags (the read-only variants are documented and
  the Dockerfile supports them via `READ_ONLY_FS=true`, but the build-matrix
  entry is disabled as of 2026-07). Read-only is not a runtime flag on the
  plain image — its entrypoint writes generated config into `/etc/nginx` at
  startup. When the read-only tags ship, the flip is one pin + one flag —
  see the note in the WAF pod template
  (`ansible/roles/carlos_podman/templates/carlos-waf.yaml.j2`).
- **The initContainers** — run-once root helpers that write only to mounts.

What made the rest possible: the CARLOS/DrugRef WARs are **pre-exploded at
image build, root-owned** (Tomcat never writes `webapps/` at startup — and a
compromised app can no longer drop a JSP into the served tree), Tomcat
`work`/`temp` are per-start emptyDirs chowned by the initContainers, MariaDB
gets a disk-backed `/tmp` emptyDir for temp-table/filesort spill (disk, not
RAM tmpfs, so one big report can't eat the pod's memory limit), and Podman's
default `read_only_tmpfs` supplies `/tmp`/`/run`/`/var/tmp` everywhere else.

One hardening step stays deferred: trimming the CHOWN / DAC_OVERRIDE
safeties from the initContainer sets after a soak. As with the original
non-root refactor, everything here fails LOUDLY at `carlos-ctl play`/`check`
if an assumption is wrong — a missing capability, a read-only `EROFS` write,
or a wrong-owner datadir surfaces as `Operation not permitted` / `Permission
denied` in the container's journald stream, never silently. The db's
non-root paths to verify live: a normal start against the existing datadir,
an empty-datadir first init, and a `MARIADB_AUTO_UPGRADE` run — all as
uid 999.

### Least-privilege DB accounts

Blast-radius containment: after `play` (or `carlos-ctl
db-users`) the app connects to MariaDB as **`carlos`**, DrugRef as
**`drugref`**, each with privileges scoped to **its own schema only**
(`GRANT ALL ON oscar.*` / `drugref2.*`) — not root and not `*.*`. The metrics
exporter (`exporter`) and backup (`backup`) accounts are likewise
least-privilege. So an app-layer SQL injection or RCE cannot reach other
schemas, `GRANT`, or `FILE`; root is reserved for admin/migration. (The
`db_username=root` render-time default is a bootstrap value used only until
provisioning runs on the first `play`.)

## WAF/DB network isolation

The internet-facing `waf` container used to share the app pod's network
namespace, so a WAF-container compromise had direct TCP to MariaDB on
`127.0.0.1:3306`, bypassing the app tier. That gap is now **closed** by three
reinforcing changes:

- **The WAF runs in its own `carlos-waf` pod** and proxies to the app by
  pod-name DNS **over TLS** (`BACKEND=https://carlos-app:8443` with
  `PROXY_SSL=on`) — no shared netns, so no loopback reach to anything in the
  app pod, and no plaintext PHI on the cross-pod edge-network segment.
  Tomcat's 8443 connector serves a self-signed keystore generated fresh into
  a RAM tmpfs by the `tls-init` initContainer on every pod start; the
  plaintext 8080 connector is pinned to in-pod loopback (`address=
  "127.0.0.1"` in `server.xml`) so it is unreachable from the edge network.
  Residual (documented): the WAF does not *verify* the per-start self-signed
  cert (`proxy_ssl_verify off`; the CRS image template has no trusted-CA
  hook) — upstream authentication remains the edge network's membership
  boundary; the TLS hop adds passive-capture resistance, not upstream authn.
- **The waf pod joins ONLY a dedicated `carlos-edge` network** (the app pod
  joins both `carlos-net` and `carlos-edge`). Putting the WAF on `carlos-net`
  instead would hand the internet-facing container a network path to the obs
  pod's VictoriaLogs/VictoriaMetrics HTTP APIs — 180 days of PHI-correlated
  logs, guarded at that point only by the basic-auth credential. On the edge
  network the WAF can reach exactly one peer: the app pod.
- **MariaDB binds in-pod loopback** (`bind_address = 127.0.0.1` in
  `zz-carlos.cnf`), so `carlos-app:3306` is not reachable over the edge
  network either — or over any network. The old host-loopback
  `127.0.0.1:3306` publish is gone with it (DNAT cannot reach a loopback
  bind); host-side admin uses the db's **unix socket**, exposed at
  `$EMR_HOME/run/db-socket/mysqld.sock` (this is what `carlos-ctl pma` and a
  host `mariadb -S …` client use), or `podman exec`. DrugRef's `:8180` stays
  guarded by its built-in `127.0.0.1`-only valve.

Because `zz-carlos.cnf` is operator-owned (never overwritten), a
carried-over cnf without the loopback bind would silently reopen the gap —
so `carlos-ctl play` **refuses** to deploy unless the cnf carries a loopback
`bind_address` (`CARLOS_ALLOW_DB_EXPOSED=1` overrides, loudly), the playbook
prints an advisory when the line is missing, and `carlos-ctl check` probes
the boundary live from inside the waf container.

The login/session regression the old deferral warned about is handled in
`conf/tomcat/server.xml`: `RemoteIpValve` no longer pins
`internalProxies="127\.0\.0\.1"` — the attribute is omitted, which selects
Tomcat's default internal-proxy set (loopback + RFC1918 + CGNAT + link-local)
and therefore matches the WAF's dynamically-assigned pod-subnet address. That
trust is safe because neither Tomcat connector is published on a host
interface (`:8080` is loopback-pinned, `:8443` is pod-network-only) — the
only peers that can connect are pod-network members, all inside the trust
boundary. **Verify a live login after deploying this topology** (Secure
cookie present, redirects stay `https://`) — `carlos-ctl check` proves the
network paths (`waf → app:8443` reachable, `waf → app:8080` plaintext
refused, `waf → app:3306` refused, `waf → obs:9428` refused) and the front
door end to end, but cannot exercise the cookie flow.

## The observability pod is optional

`carlos_obs_enabled: true|false` in host_vars (default **true**) selects the
observability profile per instance:

**`true` (the default)** — the full pipeline this README describes: the
`carlos-obs` pod (VictoriaMetrics, VictoriaLogs, vector, vmalert,
node-exporter, the authenticated log view), plus `vmagent` and
`mysqld-exporter` in the app pod, plus the log-view nftables source filter.
`carlos-ctl monitor` delegates the metric-derived checks to vmalert and
relays its firing rules.

**`false`** — **journald-only logging**: no obs pod at all, and the app pod
drops `vmagent` + `mysqld-exporter`. Every container's stdout/stderr still
lands in the persistent host journal via Podman's journald log driver — read
with `podman logs <ctr>` or `journalctl` — there is simply no queryable
store, no metrics, no log view, no vmalert. `carlos-ctl monitor` runs its own
**direct container/DB liveness sweep** instead of polling vmalert (same
container-presence / unhealthy / crash-loop / DB-accepting-connections checks
— the sweep is deliberately store-independent either way), and keeps every
non-metric check (backups, TLS, disk, heap dumps, sealed-secrets health,
pod-unit states, heartbeat). `carlos-ctl check` skips the store/pipeline
checks and says so. Size `SystemMaxUse` in journald.conf as your only log
retention bound in this mode.

Why it's a knob: proportionality. The obs stack is ~6 GiB of memory limits
and its own maintenance surface — right for a multi-provider clinic that
wants the "slim SIEM", oversized for a solo practice. The safety-critical
paths (WAF, backups + PITR, the monitor's alerting, the dead-man heartbeat)
do not depend on it.

**Toggling — both directions, on a live instance.** The toggle is an ordinary
playbook re-run, never a special path (the role installs-when-true and
removes-when-false):

*Enable later (false → true):*

```bash
# 1. host_vars/<instance>.yml:  carlos_obs_enabled: true
sudo ansible-playbook -i inventory ansible/site.yml   # renders the obs pod spec,
                                                      # quadlet, vector/vmagent/vmalert
                                                      # configs, Caddyfile, exporter cnf
sudo carlos-ctl --instance <name> db-users            # provisions the least-priv
                                                      # `exporter` metrics account
sudo carlos-ctl --instance <name> play                # starts obs, re-plays the app pod
                                                      # (now carrying vmagent + exporter)
```

*Disable later (true → false):*

```bash
# 1. host_vars/<instance>.yml:  carlos_obs_enabled: false
sudo ansible-playbook -i inventory ansible/site.yml   # stops the obs pod, removes its
                                                      # quadlet/spec and the obs-only configs
sudo carlos-ctl --instance <name> play                # re-plays the app pod without
                                                      # vmagent/mysqld-exporter
```

**Disable preserves historical data on disk**: the metric and log stores
(`$EMR_HOME/metrics/victoria-metrics-data`,
`$EMR_HOME/logs/victoria-logs-data`, the vector buffer) are left in place —
re-enabling picks the history back up; delete them by hand only if you mean
to. The log-view password (Caddyfile) and exporter credentials likewise
survive a disable/enable round trip.

## DrugRef

Drug and interaction lookups run in the pod's `drugref` container, built by
`carlos-ctl build` from
[carlos-emr/drugref2026](https://github.com/carlos-emr/drugref2026), with the
version and artifact (WAR, source, or prebuilt image) selected exactly like
the CARLOS ones — see
[Choosing the CARLOS and DrugRef versions](#choosing-the-carlos-and-drugref-versions) — the
same source and layout the upstream devcontainer uses
(`.devcontainer/drugref/`). Wiring:

- `carlos.properties` sets
  `drugref_url=http://127.0.0.1:8180/drugref2/DrugrefService` (the upstream
  template's `http://drugref:8080/...` hostname only resolves on the
  devcontainer's bridge network, not in a pod).
- `conf/drugref/server.xml` moves DrugRef's Tomcat to port 8180 and disables
  its shutdown port, since it shares the network namespace with the CARLOS
  Tomcat (8080/8005). Port 8180 is not published by the pod, and a
  loopback-only `RemoteCIDRValve` additionally restricts clients to
  `127.0.0.1` — baked into the image as an **external** context descriptor
  (`conf/drugref/drugref2-context.xml` →
  `conf/Catalina/localhost/drugref2.xml`) rather than relying on the WAR's
  own `META-INF/context.xml`: that in-WAR valve uses a
  `${…:127.0.0.1/32,::1/128}` placeholder default that RemoteCIDRValve
  cannot parse (it splits `allow` on commas before property substitution —
  the upstream devcontainer overrides it for the same reason).
- The playbook renders `drugref2.properties` once (operator-owned) to
  `$EMR_HOME/container/conf/drugref/drugref2.properties` (read by the
  `drugref-init` initContainer and assembled into the `drugref-config` tmpfs
  `emptyDir`; the image bakes `/home/drugref/drugref2.properties ->
  /run/drugref-config/drugref2.properties`, which DrugRef resolves via
  `${user.home}/drugref2.properties`) with the same DB password as
  `carlos.properties`.

**Database (one-time):** DrugRef expects a `drugref2` database next to
`oscar` — the devcontainer seeds it from upstream's
`database/mysql/development-drugref.sql` plus the patch in
`database/mysql/drugref/`. An OpenO-era datadir won't have it. With the pod
running and the two SQL files from a CARLOS checkout at hand:

```bash
# The two SQL files live in the CARLOS app repo, NOT this one — clone it first
# (or adjust the paths to your existing checkout):
git clone https://github.com/carlos-emr/carlos && cd carlos
sudo carlos-ctl db -e 'CREATE DATABASE IF NOT EXISTS drugref2'
sudo carlos-ctl db drugref2 < database/mysql/development-drugref.sql
sudo carlos-ctl db drugref2 < database/mysql/drugref/2026-04-19-drugref-tc-atc-f.sql
```

(`carlos-ctl db` is the host DB-admin wrapper — see
[Database admin from the host](#database-admin-from-the-host). The piped
imports need `CARLOS_DB_ROOT_PASSWORD` in the env file — the playbook renders
it there.)

**Convert the loaded tables to InnoDB — otherwise every nightly backup
refuses.** Upstream's `development-drugref.sql` creates all 17 tables as
`ENGINE=Aria`, and a non-transactional table cannot take part in the
`--single-transaction` snapshot the point-in-time-recovery anchor depends on,
so `carlos-ctl backup full` refuses the dump by design (and `backup verify`
then has no `db` snapshot to drill). The stamps `play` seeded keep the monitor
quiet for the first `BACKUP_MAX_AGE_HOURS`, so this surfaces as a *failing*
backup rather than a *missing* one. Convert them right after the load:

```bash
sudo carlos-ctl db -N -B -e "SELECT CONCAT('ALTER TABLE \`drugref2\`.\`',table_name,'\` ENGINE=InnoDB;') \
  FROM information_schema.tables WHERE table_schema='drugref2' AND engine<>'InnoDB'" \
  | sudo carlos-ctl db drugref2
sudo carlos-ctl backup full     # now succeeds
```

(`oscar.formRourke2009` stays Aria — it has more columns than InnoDB's 1017
limit, and the audit recognizes it as a known, accepted exception.)

That dataset is the one upstream develops against; refresh or replace it
according to your drug-data source and licensing. To run without DrugRef,
remove the `drugref` container from the app-pod template
(`ansible/roles/carlos_podman/templates/carlos-app.yaml.j2`) and re-run the
playbook — lookups then fail gracefully, as they did in the OpenO pod.

**Upgrading an install rendered before DrugRef existed:** the properties
files are operator-owned (never overwritten), so a previously rendered
`carlos.properties` may still carry the old unresolvable
`drugref_url=http://drugref:8080/...`. Edit it to
`drugref_url=http://127.0.0.1:8180/drugref2/DrugrefService`, re-run the
playbook (adds the missing drugref conf), and `carlos-ctl play`.

## Logs & metrics

Nothing leaves the machine (logs contain PHI-correlating identifiers, so both
stores bind loopback only). Logging is **journald-based**, metrics are
**scraped**, and both stores live in the obs pod so they survive app
restarts. (This whole section describes `carlos_obs_enabled: true`, the
default; with the profile off, the journald floor below is the entire logging
story and there are no metrics — see
[The observability pod is optional](#the-observability-pod-is-optional).)

```text
carlos-waf pod (journald log driver)
  waf  ── stdout/stderr ──> HOST systemd journal
carlos-app pod (journald log driver)
  carlos / drugref / db  ── stdout/stderr ──> HOST systemd journal
  mysqld-exporter ────────scraped by── vmagent ──────────remote_write──┐
                                          │ (also scrapes node-exporter │ (buffered)
carlos-obs pod                            │  + victorialogs, below)     v
  node-exporter :9100  <──────────────────┘                    victoria-metrics
  logcollect (Vector: reads /var/log/journal) ──ship──> victorialogs   :8428
                                              (disk buffer, backfills)   ^
                                                          :9428          │ evaluates
       caddy :9443  ──basic_auth, read-only──>  vmui (logs) + vmui     vmalert :8880
                                                (metrics)              (rules; polled by
                                                                        carlos-ctl monitor)
```

### Logs

First stop: `carlos-ctl logs [carlos|db|drugref|waf|<container>]
[-f]` tails a container's logs without remembering pod-name prefixes or the
runuser boundary (it resolves the short names to `<instance>-app-carlos`
etc. and follows with `-f`). Underneath, the app and waf pods run with
Podman's `journald` log driver, so every container's stdout/stderr lands in
the host's persistent journal (`podman logs` still works). The obs pod's
single `logcollect` (Vector) tails
`/var/log/journal`, derives the `stream` from the container name (`carlos`,
`drugref`, `db`; the waf-pod container is split into `waf-access` /
`waf-error` by journal priority, exactly as before the pod split), and ships
to VictoriaLogs. It **checkpoints the journal cursor and disk-buffers with
end-to-end acknowledgements**: if VictoriaLogs is down the cursor holds and,
on recovery, every missed line is **backfilled** (bounded only by the
journal's `SystemMaxUse` retention). Everything each process prints is
captured — CARLOS's log4j2 console log, Tomcat/JULI, the access-log valve
(`%{ms}T` per-request ms), JVM GC lines (`-Xlog:gc*:stdout`), and MariaDB's
error log. The playbook enables persistent journald; size `SystemMaxUse`
(and the rate-limit caveat) per [Requirements](#requirements) to cover the
longest VictoriaLogs outage you want to backfill.

### Metrics

`node-exporter` (host — mounts host `/` **read-only** at
`/host/root` so `node_filesystem_*` reflects the host **root** filesystem
for the DiskLow rule; separately-mounted volumes still do not appear as
series, so the monitor's statvfs sweep remains the authoritative
all-volumes disk check. Runs as `nobody` with all caps dropped, so 0600
host secrets stay unreadable) and `mysqld-exporter`
(MariaDB, via the least-priv `exporter` account provisioned by
`play`/`db-users` — `PROCESS`/`REPLICATION CLIENT` + `SELECT` on
`performance_schema` only, no PHI table access) listen on pod loopback /
the obs pod; `vmagent` scrapes
them — plus VictoriaLogs' own `/metrics` (its `vl_rows_ingested_total`
counter feeds the log-ingestion-staleness alert rule) — and remote-writes to
VictoriaMetrics in the obs pod as `carlos-obs:8428`, buffering on disk if
the store is briefly down. Retention is `carlos_metrics_retention`. The two
pods share a `carlos-net` Podman network (created by the playbook) so
vmagent can reach the obs pod by name — a `127.0.0.1`-published port is not
reachable from another netns via the host gateway (Podman #28435), so
cross-pod traffic uses this network, not host loopback. There is
deliberately **no JVM/Tomcat metrics job**: heap/GC trending would need a
`jmx_exporter` javaagent baked into the app image; the OOM failure mode is
covered out-of-band (the monitor alerts on a `.hprof` heap dump under
`logs/`, and the liveness probe catches a dead webapp). `vmalert` (same
pod) continuously evaluates the alert rules in
`conf/vmalert/rules.yml` against the co-located store — see
[Alerting & health monitoring](#alerting--health-monitoring).

### Viewing — the "slim SIEM"

HTTPS, authenticated, no SSH: open
`https://<SERVER_NAME>:9443/select/vmui/` (logs) or
`https://<SERVER_NAME>:9443/vmui/` (metrics) and sign in with the log-view
user (the playbook generates the password and prints it **once** in the play
output — store it in your password manager; only its bcrypt hash is kept on
disk, and the hash is computed **on the control node** via passlib, so the
plaintext never crosses to the host; alternatively vault an explicit
`carlos_log_view_password`). Caddy terminates TLS with the same certificate
as the WAF and routes **read-only**: only the vmui UIs + query APIs reach the
stores — ingestion/admin endpoints (including VM's `/api/v1/write`) return
404. Filter logs by `stream` (`carlos`, `drugref`, `db`, `waf-access`,
`waf-error`), live tail; retention is `carlos_log_retention` (default 180d).

Security-review starter queries (LogsQL):

```text
_stream:{stream="carlos"} "Login!@#$"      # CARLOS login security events (blocked/inactive accounts)
_stream:{stream="waf-error"} ModSecurity   # WAF/CRS rule alerts
_stream:{stream="waf-access"} " 403 "      # requests blocked at the edge
_stream:{stream="db"} error                # database errors
```

Notes: basic auth has no lockout — the password is machine-generated (or
vaulted by you), auth failures are logged by Caddy
(`podman logs carlos-obs-logview`), and 9443 binds `BIND_IP`. **The playbook
firewalls it for you**: an nft input filter restricts the log-view port to
the subnet of the interface carrying `BIND_IP` (override with
`carlos_log_view_allow_cidr`; the literal `rfc1918` opts into the broad
private-ranges set; skipped entirely on a loopback `BIND_IP`). When the
subnet **cannot** be derived and no override is set, the playbook **fails
closed** — it refuses to leave the PHI-bearing log view reachable from
anywhere rather than guessing. The filter lives at the host input hook
because rootless port-forwarding can hide real client IPs from Caddy, and
the stock Caddy image has no rate-limit plugin. The raw stores stay on host
loopback (`127.0.0.1:9428` / `:8428`, vmalert on `:8880`); an SSH tunnel to
them remains the full-access/admin path.

**Still on `podman logs` only** (not shipped): the obs pod's own containers
(default log driver, so they never feed the collector — avoids a loop), e.g.
`runuser -u carlos -- podman logs carlos-obs-victorialogs` (rootless engine —
`podman` runs as the SERVICE_USER; drop the `runuser` prefix when already
logged in as that user).

**Diagnostics (artifacts, not streams)** in `$EMR_HOME/logs/carlos/`,
persisted across pod replacement: heap dump on OOM (`carlos-oom.hprof` —
large, delete after analysis), crash reports (`hs_err_*.log`), the WAR's
small self-rotating `csrf`/`waf` log4j2 files, and a continuous Java Flight
Recorder ring buffer (48 h / 256 MB, ~1% overhead, dumped on JVM exit). JFR
is the JVM-native answer to JavaMelody-style monitoring, without embedding a
monitoring webapp in a PHI system.

**PHI note:** both `.hprof` heap dumps and `.jfr` recordings are memory
images of a process handling patient data — treat them as PHI: restrict who
can read `$EMR_HOME/logs/carlos/`, and delete them once analysis is done. The
monitor **alerts on `.hprof`** (exceptional — an OOM occurred) but not on
`.jfr` (the recorder is always-on, so a `.jfr` is a normal artifact and
alerting on its presence would fire every run); disk growth from either is
caught by the free-space check.

```bash
# snapshot now, summarize, or open in JDK Mission Control
# (PID 1 is tini, not the JVM — resolve the java pid inside the container).
# The engine is rootless, so reach the container as the SERVICE_USER; from the
# host root shell prefix each call with `runuser -u carlos --` (or run them
# directly when logged in as the service user):
runuser -u carlos -- podman exec carlos-app-carlos sh -c 'jcmd $(pgrep -f java) JFR.dump name=carlos filename=/usr/local/tomcat/logs/now.jfr'
runuser -u carlos -- podman exec carlos-app-carlos jfr summary /usr/local/tomcat/logs/now.jfr
runuser -u carlos -- podman exec carlos-app-carlos sh -c 'jcmd $(pgrep -f java) GC.heap_info'
```

(The `VMSTAT_LOGGING_PERIOD` property that ships in the CARLOS defaults is
vestigial — no code reads it. JVM-side runtime stats come from the GC log
lines and JFR above, host-side from node-exporter.)

## WAF audit log & PHI

The WAF pod pins `MODSEC_RULE_ENGINE=On` (blocking is contractual, not left
to the image default), `MODSEC_AUDIT_ENGINE=RelevantOnly`, and
`MODSEC_AUDIT_LOG=/dev/stdout`, so ModSecurity (v3, JSON-formatted audit
records under the nginx image) writes its audit stream to the WAF container's
stdout; like the app-pod containers it is journald-collected and (obs profile
on) shipped to VictoriaLogs, where it lives out its `carlos_log_retention`
(default 180d) as a mutable, queryable store.

**Audit records are BODY-FREE by default.** `MODSEC_AUDIT_LOG_PARTS` defaults
to `ABFHKZ` — request/response headers plus the matched rules, which is
enough to triage a CRS false positive, and **no** request/response bodies
(parts `C`/`E`/`I`/`J`). Bodies are where PHI lands: medical forms routinely
trip CRS rules, and each such record would otherwise persist clinical
free-text and health-card numbers for the whole retention window. Restoring
full capture (`carlos_waf_audit_log_parts: ABCEFHIJKZ` in host_vars, then
playbook + play) is a **conscious HIPAA/PIPEDA decision** — prefer enabling
it temporarily while tuning rule exclusions, then reverting.

Even body-free, query strings and headers can carry PHI-correlating
identifiers (`demographic_no`, billing IDs) — and the WAF *access* log always
logs URLs. Two mitigations apply: the log collector **redacts 9+-digit runs**
(health-card numbers, phone numbers) AND masks `demographic_no=`-style query
parameters — applied to **every** stream (app/db/drugref, not just `waf-*`),
since PHI-correlating IDs surface across all of them — before anything
is persisted to VictoriaLogs (bare 5-6-digit IDs are left unmasked: too
collision-prone to redact without shredding legitimate log context), and the
whole pipeline sits behind the
basic_auth + TLS log-view gate (source-restricted at the host firewall — see
the log-view section) and never leaves the host. Note the **host journal
keeps the unredacted copy** of container stdout (the redaction is
collector-side): bound it with `SystemMaxUse` and treat membership in the
`systemd-journal` group as PHI access — see [Requirements](#requirements).
Treat the retention window and who can query the store as compliance
decisions: shorten `carlos_log_retention` if you do not need the full window,
and scope access to the log view accordingly. (With the obs profile **off**,
the journal is the only copy and `SystemMaxUse` is the retention decision.)

**Store access — two independent layers.** VictoriaLogs (`:9428`, holding
this audit stream) and VictoriaMetrics (`:8428`) are protected twice over.
The network boundary: their reach is exactly the host loopback plus
`carlos-net` peers — i.e. the app pod, which remote-writes metrics there —
while the internet-facing WAF pod joins only the edge network and has **no
route** to the stores (`carlos-ctl check` probes this from inside the waf
container and fails if it ever changes), and the only network-exposed read
path is the basic_auth+TLS log view. The credential: both stores require
HTTP basic auth (one regenerable per-instance credential that every client —
vmagent, vector, the scrape config, the log view, vmalert, `carlos-ctl` —
carries; `carlos-ctl rotate obs` re-mints it, and `check` proves a
credential-free store query is rejected). The residual risk — a compromised
app-pod container that can read its mounted store credential — is accepted
because that compromise already holds the app's DB credentials (full PHI),
which strictly dominate the log copy. `carlos_obs_http_auth: false` restores
the legacy unauthenticated posture for sites that need it (see
[Secrets](#secrets) and the obs pod template).

## Compliance risk register (accepted risks at a glance)

The postures below are deliberate defaults, each documented in depth in its
own section; this table exists so a privacy/security review (HIPAA/PIPEDA)
can find every accepted risk and every knob that changes it in one place.

| # | Accepted risk (default posture) | Where it is enforced/documented | Change it with |
|---|--------------------------------|----------------------------------|----------------|
| 1 | VictoriaLogs/VictoriaMetrics/vmalert are **basic-auth authenticated** (one regenerable per-instance credential; every client — vmagent, vector, scrape, the log view, carlos-ctl — carries it; `check` proves a credential-free store query is rejected 401). Still loopback + app-pod-only on `carlos-net`; the credential is the second layer | this section, obs pod template, [Secrets](#secrets) | `carlos_obs_http_auth: false` restores the legacy unauthenticated posture; `carlos-ctl rotate obs` re-mints the credential |
| 2 | The **host journal keeps the unredacted copy** of all container stdout (collector-side redaction only protects the shipped store) | this section, [Requirements](#requirements) | `carlos_journald_max_use` (size), `systemd-journal` group membership (access) |
| 3 | Shipped logs (incl. WAF access/audit streams) retained **180 days** behind one shared basic-auth credential | this section, log-view section | `carlos_log_retention`, `rotate log-view`, `carlos_log_view_allow_cidr` |
| 4 | WAF→Tomcat backend TLS is **encrypted but not verified** (self-signed per-start cert, `proxy_ssl_verify off`); upstream authn = edge-network membership | WAF/DB network isolation section, `server.xml`, waf pod template | none (image template has no trusted-CA hook) — accepted |
| 5 | The front-door DNAT is **IPv4-only**; an AAAA record on the host would bypass the redirect | nftables template header | bind AAAA off / IPv4-only front address |
| 6 | The default restic repository is **local-path** ("first tier"); a fire/ransomware event takes EMR + backups together | Backups section; the monitor nags (`restic-repo-local`); **first go-live is REFUSED** on a local repo | offsite `RESTIC_REPOSITORY` (s3:/rest:/sftp:/b2:), or `CARLOS_ACCEPT_LOCAL_REPO=1` to accept and silence |
| 7 | ModSecurity audit records are **body-free** (`ABFHKZ`) — full capture would persist clinical free-text on rule hits | WAF audit log & PHI (above) | `carlos_waf_audit_log_parts` (temporarily, while tuning) |
| 8 | The MariaDB **root password lives in root-only `carlos-app.env`** (0600) unless sealed; the sealed bundle is the DR copy | Secrets section | `carlos-ctl seal` (TPM-seal + shred) |
| 9 | PHI at rest is **not application-encrypted**: protection = 0700 service-user-owned trees + (recommended) LUKS under `$EMR_HOME` | Requirements; Backups (repo IS encrypted) | LUKS/dm-crypt at provisioning time |
| 10 | The **age escrow copy** of the secrets key lives wherever the operator stored it at seal time — its custody is out of the system's hands | Secrets / seal gate | your key-custody policy; `carlos-ctl rotate age-key` re-keys and forces re-escrow |
| 11 | The front-door cert defaults to **self-signed** (`carlos_tls_mode: selfsigned`) — browsers warn, and there is no chain of trust to a public CA | [Quick start](#quick-start) step 4; TLS-mode plumbing | `carlos_tls_mode: manual` (place your own) or `acme` (Let's Encrypt via certbot) |
| 12 | The host default-deny firewall is **ON by default** (`carlos_host_firewall_enabled`); it is **host-global**, so on a multi-instance host only ONE instance may own it (asserts refuse a second), and a wrong `carlos_host_firewall_ssh_port` would lock out SSH (an assert refuses a malformed one) | nftables template; asserts | `carlos_host_firewall_enabled: false` where an external firewall already fronts the host |
| 13 | **node-exporter** listens unauthenticated on the obs pod's `carlos-net` interface (`:9100`, no hostPort). Verified topology: vmagent (app pod) scrapes it cross-pod, so binding it to loopback would break the scrape; the WAF is proven OFF `carlos-net` by `check`, and the port is never host-published. Host CPU/mem/fs metrics only — no PHI | obs pod template; `check`'s waf-network probes | accepted; keep `carlos-net` membership tight (it already is) |
| 14 | **Maven dependency cache** (`--mount=type=cache`) survives `podman build --no-cache` — a dependency fetched in a prior build is reused without re-verification. For a fully pristine audited release, wipe the build cache volume first (`podman system prune --build-cache`, service user) so the dependency-lock check resolves a fresh tree | Containerfile comments; build docs | wipe the cache before a release build |
| 15 | **`tini`/`unzip` install unpinned** inside the digest-pinned base (same-distro-snapshot versions vary as the repo moves) and the images build with `-DskipTests` (upstream CI is the test authority; the post-build smoke + `rebuild` readiness gate the deploy path) | Containerfile comments | accepted — the digest-pinned base bounds the drift |
| 16 | **Manual `mariadb-hot` physical snapshots are never reaped** — retention is the operator's (the disk monitor and the reclaim order below are the backstop) | Native MariaDB physical backups section; disk-reclaim order | delete analysed snapshots by hand |

Review cadence suggestion: re-read this table (and re-run `carlos-ctl check`
+ `alert-test`) at every major upgrade and at least annually, and record the
site's decision for each row in your clinic's privacy documentation.

## Database admin from the host

MariaDB publishes no TCP port (see
[WAF/DB network isolation](#wafdb-network-isolation)), but day-to-day admin
from the host is a single command. Four paths, by use case:

> **Charset/sql_mode note (OSCAR lineage).** The **server** in
> `conf/mariadb/zz-carlos.cnf` is now **utf8mb4-ready**
> (`character-set-server = utf8mb4`, `collation-server = utf8mb4_general_ci`,
> `init-connect = 'SET NAMES utf8mb4'`) — the 4-byte-capable equivalent of the
> app's historical `utf8_general_ci`. Any charset-less table and any
> connection that doesn't override it now get full 4-byte Unicode (emoji,
> astral-plane code points in names/clinical text).
>
> **The remaining limiter is the app-repo schema**, not this cnf: the Flyway
> baseline under `database/mysql/migration/` carries forward the historical
> column definitions, so many tables and columns still declare
> utf8mb3/latin1 charsets inherited from the retired legacy build, and its
> MyISAM tables carry a 1000-byte index cap a utf8mb4 `varchar(255)` full
> index exceeds. So **columns created by that schema are still utf8mb3 until
> the app-side conversion is done** (per-table `CONVERT`, the
> `ALTER DATABASE` default, and a MyISAM index review — an app+schema
> project in `carlos-emr/carlos`). This cnf is deliberately utf8mb4-ready so
> the server is never the blocker.
>
> `sql_mode = ""` stays **permissive** (over-length/invalid values coerced,
> zero dates allowed) — the app relies on it; STRICT is a separate,
> app-affecting decision, intentionally left off.

| You want | Use |
| --- | --- |
| SQL shell, one-liners, imports | `carlos-ctl db` |
| a one-off export | `carlos-ctl db-dump` |
| a fast physical (hot) backup, e.g. before risky maintenance | `carlos-ctl db-backup` (see [Native MariaDB physical backups](#native-mariadb-physical-backups-manual-alternative)) |
| a GUI | `carlos-ctl pma` (next section) |
| a host-installed client / GUI over SSH | the unix socket at `$EMR_HOME/run/db-socket/mysqld.sock` |

**Recipes** (all as root on the host — the CLI is on PATH at
`/usr/local/sbin/carlos-ctl`):

```bash
# Interactive SQL shell (root@localhost inside the db container)
sudo carlos-ctl db

# One-liner query
sudo carlos-ctl db -e 'SELECT COUNT(*) FROM provider' oscar

# Export — a consistent dump (safe on the running db); ALWAYS redirect it
sudo carlos-ctl db-dump > /root/oscar-$(date +%F).sql        # dumps `oscar`
sudo carlos-ctl db-dump drugref2 > /root/drugref2.sql        # any database

# Import a dump / run a SQL file — stdin streams straight into the client,
# so compressed dumps import without an intermediate file
sudo carlos-ctl db oscar < oscar-2026-07-04.sql
zcat oscar-2026-07-04.sql.gz | sudo carlos-ctl db oscar

# Create a database
sudo carlos-ctl db -e 'CREATE DATABASE IF NOT EXISTS drugref2'

# Physical (hot) snapshot of the whole instance, restore-ready — e.g. before
# a schema migration; restores by file copy-back, no SQL replay
sudo carlos-ctl db-backup pre-migration-$(date +%F)

# Host-installed mariadb client (or a GUI over an SSH tunnel that supports
# sockets) — connects as <user>@localhost via the unix socket:
mariadb -S /usr/local/emr/run/db-socket/mysqld.sock -uroot -p oscar
```

**Password:** with `CARLOS_DB_ROOT_PASSWORD` present in
`$EMR_HOME/container/carlos-app.env` (the playbook renders it there, mode
600 — the same setting `play` uses for auto-provisioning), `carlos-ctl db`
never prompts and piped imports/exports just work — the password is forwarded
to the container by environment name, never as a process-list token. Without
it, `carlos-ctl db` prompts interactively (and `db-dump`/piped runs explain
what to set instead of hanging on an invisible prompt).

**PHI handling:** an export is **plaintext patient data** — write it to an
encrypted volume and delete it when done (`db-dump` also refuses to print to
the terminal). A manual dump is not a backup strategy: scheduled, encrypted,
point-in-time-capable backups are the restic tier under
[Backups](#backups-restic).

**Audit:** these paths (like phpMyAdmin below) run as the MariaDB account you
use and bypass the application's `UserActivityFilter` — see the break-glass
audit caveat at the end of the phpMyAdmin section.

## phpMyAdmin (on-demand database admin)

phpMyAdmin is **not** a standing container — a permanent PHP/Apache surface
isn't worth carrying for occasional break-glass admin. Launch it only when
you need it:

```bash
sudo carlos-ctl pma        # runs phpMyAdmin on 127.0.0.1:9444 for 120 min
                           # (--ttl <min> adjusts; --ttl 0 = until Ctrl-C)
```

Then reach it through an SSH tunnel and sign in with a MariaDB account:

```bash
ssh -L 9444:127.0.0.1:9444 <this-host>     # then open http://localhost:9444/
```

The MariaDB login is the auth (phpMyAdmin cookie auth, nothing stored); the
container binds the **host loopback only** and connects to the database over
its **unix socket** (`PMA_SOCKET`, via the `$EMR_HOME/run/db-socket` mount) —
MariaDB binds in-pod loopback with no published port, so the socket is the
only host-side path (see
[WAF/DB network isolation](#wafdb-network-isolation)); the container joins no
Podman network at all. Socket connections authenticate as `<user>@localhost`.
The socket file is world-connectable (MariaDB default) inside a root-owned
directory — the same any-local-user posture the old `127.0.0.1:3306` publish
had; account auth remains the control. Stopping the command removes the
container and its listener, and the default 120-minute TTL tears the session
down even if the terminal is lost (a dropped SSH tunnel can otherwise leave
the listener up; the monitor pages on a lingering pma container either way).

For quick, non-GUI work, prefer the CLI — see
[Database admin from the host](#database-admin-from-the-host):

```bash
sudo carlos-ctl db        # or raw: runuser -u carlos -- podman exec -it carlos-app-db mariadb -uroot -p oscar
```

On a PHI system this is **break-glass tooling**: whatever MariaDB account you
use defines what it can touch, and every query hits the production database —
use `root` only when a task requires it, and a `SELECT`-only user for
read-only poking. **Audit gap to close operationally:** these out-of-band
paths (pma, the `mariadb` CLI) and the log-view's own auth log are not
captured by the application's `UserActivityFilter`, and MariaDB's audit
plugin is off by default, so a break-glass read of patient data leaves no
durable trail. For HIPAA/PIPEDA, enable the MariaDB `server_audit` plugin (at
least for the admin accounts) writing to stdout→journald→VictoriaLogs, and
treat break-glass access as a logged, reviewed event.

## Secrets

### Single master (SOPS + age)

All reversible secrets are consolidated into
**one age-encrypted bundle** —
`$EMR_HOME/container/conf/secrets/secrets.enc.yaml` — encrypted with
[Mozilla **SOPS**](https://github.com/getsops/sops) to the instance's **age**
recipient. The age **private key** is the single master: it decrypts every
secret, it is what you **escrow off-host** for disaster recovery, and it is
protected **at rest** on the host by TPM-sealing it via `systemd-creds`
(`/etc/credstore.encrypted/<instance>-age.cred`) so pods still start
unattended at boot. On a host without a TPM, `seal` keeps the key as a 0600
root-only file — but it **refuses** to proceed until you set
`CARLOS_SEAL_NO_TPM=1`, explicitly accepting that at-rest protection then
rests on LUKS full-disk encryption (which the tooling cannot verify). The
playbook generates the age keypair at provisioning time (the private key
lives in the root-only `$EMR_HOME/secrets-private/`, deliberately **outside**
the pod-mounted, chown-swept, backed-up `container/` tree); until you run
`seal`, secrets are the plaintext mode-600 files below (each
machine-generated where possible, defined in exactly one place); `seal` folds
them into the bundle and leaves `__SEALED__` placeholders.

| Secret | Where (sealed) | Consumer |
| --- | --- | --- |
| **age master key** | `conf/secrets/age-recipient.pub` (public) + `<instance>-age.cred` (TPM-sealed private) / 0600 `$EMR_HOME/secrets-private/age-key.txt` (no-TPM, root-only, outside the backed-up `container/` tree) — **escrow the private key off-host** | `sops` at boot/backup |
| attended-recovery wrap (optional) | `$EMR_HOME/secrets-private/age-key.recovery.enc` — the SAME age key wrapped with an operator passphrase (openssl AES-256-CBC, PBKDF2 600k; ≥ 12 chars enforced; written by `seal` on TPM hosts, round-trip verified). Deliberately an offline-crackable artifact protected by passphrase strength + LUKS — the price of attended recovery. Delete the file to disable | any `carlos-ctl` verb needing the age key when the TPM unseal fails or the credstore blob is gone — automatically at the boot render (console prompt), or interactively on a root tty (e.g. `backup`/`rotate`) |
| app db credentials | bundle `carlos.*`; base `conf/carlos/carlos.properties` keeps `__SEALED__` | carlos container (via `/run` fragment) |
| drugref db credentials | bundle `drugref.*`; base keeps `__SEALED__` | drugref container (via `/run` fragment) |
| backup db credentials | bundle `backup_db.env` | `carlos-ctl backup` only |
| restic repo password / backend creds | bundle `restic.env` (whole env — extra offsite-backend vars kept) | `carlos-ctl backup` / restic container |
| metrics db credentials | `conf/metrics/exporter.my.cnf` (mirrored in bundle `exporter.password` for rotation); metrics-only account, no PHI access | mysqld-exporter (mounted ro; obs profile only) |
| db root password **hash** | Podman secret `carlos-db` (one-way hash — stays a Podman secret; created by the playbook, hash computed in-process, manifest over stdin) | db container, empty-datadir init only |
| log-view password | **bcrypt hash only** in `conf/caddy/Caddyfile` (one-way — plaintext shown once at provisioning, never stored; hashed on the control node) | logview container (mounted ro; obs profile only) |
| obs-store basic-auth credential | **NOT sealed** (regenerable — a playbook re-run mints a fresh one and re-renders every consumer). Canonical plaintext is the root-only `$EMR_HOME/secrets-private/obs-http-password` (0600, outside the pod-mounted/backed-up tree); reaches containers only by NAME via the `<instance>-obs-http` Podman secret, never in a 0644 pod spec | VictoriaLogs/VictoriaMetrics/vmalert + vmagent/vector/scrape clients + the log view + carlos-ctl; `carlos-ctl rotate obs` re-mints it |
| TLS private key | `conf/waf/certs/privkey.pem` (host file **0640**) | waf + logview. The host `certs` dir stays **0700**, which host users cannot traverse — but a rootless container also cannot traverse a 0700 mount it does not own, so the PEMs are **not** bind-mounted into the unprivileged listeners. Instead a root-run initContainer copies `fullchain.pem`+`privkey.pem` from the read-only host mount into a tmpfs `emptyDir` the listener mounts, key mode **0640** owned by the listener's uid: `obs-init` chowns to the pinned logview uid 10013, `waf-init` resolves the uid from the WAF image's own `/etc/passwd` (`nginx`, else `www-data` for an Apache-pinned image, else a warned 0644 fallback so an image bump can't kill the front door). The playbook clamps the host key to 0640 and enforces the 0700 dir mode |

Handling rules the tooling enforces: passwords are generated, never echoed to
the terminal except the deliberate show-once moments, never placed in argv
(`MYSQL_PWD` forwarded by environment *name* to db clients; webhook and
heartbeat capability URLs travel via `curl -K -` config on stdin;
`secrets_set` edits the bundle via a decrypt→re-encrypt round-trip in `/run`
tmpfs rather than `sops --set`, which would put the value on a world-visible
argv), never logged or shipped in log streams, and each container sees only
its own secret via a read-only `subPath` mount. `conf/secrets/` is pinned
root-owned (a service-user-writable bundle/recipient would be a
re-encryption-recipient injection vector — `seal` and `play` both re-pin it).
One deliberate residue: **`carlos-app.env` keeps `CARLOS_DB_ROOT_PASSWORD`**
(mode 0600, root-only, excluded from backups) even after `seal` — it is what
lets `play`'s auto-provisioning, `db-users`, and the break-glass `db` verbs
work unattended; protect it with LUKS like the rest of `$EMR_HOME`. (The
bundle also carries a copy as `carlos.db_root_password`, so a DR restore can
recover it.)

**Least-privilege database accounts** — `play` provisions them by default on
first deploy; run explicitly with:

```bash
sudo carlos-ctl db-users && sudo carlos-ctl play
```

This creates `carlos` (ALL on `oscar.*`), `drugref` (ALL on `drugref2.*`),
`backup` (global read/dump/binlog privileges only), and `exporter` (metrics —
`PROCESS`/`REPLICATION CLIENT` + `SELECT` on `performance_schema` only;
provisioned only when the obs profile is on — re-run `db-users` after
enabling it), rewrites the credential files with distinct generated
passwords, and retires root to admin-only use. A compromised webapp then
cannot touch `drugref2`/`mysql` schemas, and a leaked backup credential
cannot write anything.

**Why SOPS + age, and not a sidecar.** A secrets *manager* (Vault/OpenBao) is
a stateful service with its own unseal/HA/DR surface — out of proportion for
a per-clinic single-host pod, and the 2026 consensus is that its overhead
isn't justified below fleet scale. SOPS + age is file-based, needs **no
running service**, and gives exactly the "one master decrypts the rest"
model: one age keypair, one encrypted bundle. What we still did **not** do:
*hash the client-side credentials* (impossible — the app/DrugRef/restic must
*present* them; hashing only works where this host *verifies* a password,
i.e. the log view). And **full-disk encryption (LUKS) on `$EMR_HOME` remains
the complementary control** — it covers the datadir, documents, logs, the TLS
key, and the age key at rest in one stroke (`systemd-cryptenroll` can bind
the LUKS key to the TPM for unattended boot).

### Sealing

Consolidate into the single-master bundle:

```bash
sudo carlos-ctl seal      # needs `sops` and `age` on the host
```

`seal` folds every reversible secret into `conf/secrets/secrets.enc.yaml`
(encrypted to the age recipient the playbook generated), rewrites the db
passwords to a `__SEALED__` placeholder in the base properties, and protects
the age private key at rest (TPM-sealed via `systemd-creds`, or — with
`CARLOS_SEAL_NO_TPM=1` — a 0600 file on a TPM-less host).

**Attended recovery (optional TPM-failure fallback).** On TPM hosts, `seal`
offers to set a **recovery passphrase** (interactive prompt, or headless via
`CARLOS_RECOVERY_PASSPHRASE_FILE`; ≥ 12 characters): it stores a
passphrase-wrapped copy of the same age key at
`secrets-private/age-key.recovery.enc` (round-trip verified before it is
trusted). If a kernel/Secure-Boot/firmware change later breaks the TPM
unseal, the boot-time render **prompts on the console** (via
`systemd-ask-password`, 90 s timeout, 3 attempts) instead of taking the EMR
down — type the passphrase and boot continues; the journal records loudly
that recovery was used, and you should re-run `seal` to re-seal to the new
TPM state. An **unattended** boot is unchanged: no answer within the timeout
and the unit fails loud with the same alert as today (the fallback never
turns a failure into a silent hang, and the backup timers deliberately keep
their non-prompting behavior). The wrap does not replace **off-host escrow**
— it only covers TPM failure on a surviving host; host loss still needs the
escrowed key. At boot,
`<instance>-secrets.service` (installed and re-rendered by `seal`; ordered
`Before=user@<uid>.service`) runs `carlos-ctl secrets render`, which
**resolves the age key itself** — TPM-sealed credstore blob (`systemd-creds
decrypt`, in-process, deliberately NOT `LoadCredentialEncrypted=` whose
decrypt failure would kill the unit before the attended fallback could run),
else the 0600 key file on a no-TPM host, else the attended-recovery
passphrase — then `sops -d` materializes the db fragments into
`/run/<instance>-emr` (tmpfs, RAM only). Only the **backup timers** keep
`LoadCredentialEncrypted=` drop-ins (a timer must never sit on a prompt).
Each app's `*-init` initContainer
then assembles `base + fragment` (Java last-one-wins, so the fragment
overrides the placeholder). Backup runs `sops -d` on the same bundle
just-in-time for restic and backup-db creds. Unsealed hosts skip all of
this: no bundle, the plaintext base files are used as-is. `db-users`/`rotate`
fold new values straight into the bundle; `carlos-ctl play` starts
`<instance>-secrets.service` before the pod.

### Portable disaster recovery

The reason for age: the old per-secret TPM
sealing was **host-bound** — sealed blobs decrypt only on the original
hardware. The age master is **portable**: the encrypted bundle **rides
inside the restic backup** (safe — it's encrypted), so a full recovery on
*new* hardware needs exactly the **two things you escrowed off-host**:

1. the **age private key** (excluded from the backup — it must never ride in
   the repo it unlocks), and
2. the **full `restic.env` content** — `RESTIC_PASSWORD`, the
   `RESTIC_REPOSITORY` URL, and any offsite-backend credentials (S3 keys
   etc.). These **cannot** come from the bundle: the bundle lives *inside*
   the repo those very credentials reach and open — with only the age key
   you are locked out.

Restore = escrowed restic.env → `restic restore`, then the age key →
`sops -d` opens everything else. This is why `seal` **refuses until you
confirm an off-host copy of both** (`AGE_ESCROW_CONFIRMED=1`
non-interactively; `RESTIC_ESCROW_CONFIRMED=1` is accepted as an alias):
lose either and your backups are unrecoverable.

### Rotating credentials

Every stored credential has a rotation command that updates **both sides** —
the verifier (database account, bcrypt hash, restic key) and every store
holding the secret — re-encrypting the age bundle in place on a sealed host:

```bash
sudo carlos-ctl rotate db        # carlos/drugref/backup/exporter db passwords
sudo carlos-ctl rotate db-root   # MariaDB root password
sudo carlos-ctl rotate log-view  # log view (Caddy basic_auth) password
sudo carlos-ctl rotate restic    # restic repository password
sudo carlos-ctl rotate obs       # obs-store basic-auth credential (re-mints,
                                 # re-renders every client, restarts obs+app+waf)
sudo carlos-ctl rotate age-key   # the SOPS master key itself: new keypair,
                                 # re-encrypt the bundle, re-seal the TPM blob,
                                 # retire the old recipient, force re-escrow
```

`rotate age-key` re-keys the single master, so it deletes the escrow-confirmed
marker and REQUIRES you to re-escrow the NEW private key off-host (the old
escrow copy no longer decrypts the re-encrypted bundle).

**Choosing the password (instead of a random one):** every target accepts a
specific value via its environment variable — set it for the one run, e.g.
`sudo LOG_VIEW_PASSWORD='...' carlos-ctl rotate log-view`:

| Target | Variable(s) |
| --- | --- |
| `rotate log-view` | `LOG_VIEW_PASSWORD` |
| `rotate db-root` | `CARLOS_DB_NEW_ROOT_PASSWORD` |
| `rotate restic` | `RESTIC_NEW_PASSWORD` |
| `rotate obs` | `OBS_HTTP_NEW_PASSWORD` |
| `rotate db` / `db-users` | `CARLOS_DB_APP_PASSWORD`, `CARLOS_DB_DRUGREF_PASSWORD`, `CARLOS_DB_BACKUP_PASSWORD`, `CARLOS_DB_EXPORTER_PASSWORD` |

A value you supply is known to you by definition. When a value is
*generated*, the human-facing ones (log-view, db-root, restic) are printed
exactly once — store them immediately. The app-tier db passwords are
machine-to-machine credentials no human ever types, so they are never
printed; on an unsealed host you can read them from the credential files
(`conf/carlos/carlos.properties` etc.), and on a sealed host supply your own
via the variables above if you need to know them. Supplied values must be a
single line; avoid backslashes (Java `.properties` escape character) and
quotes/spaces in the restic password (the env file is parsed by both the CLI
and Podman).

What each one does:

- **`rotate db`** re-runs the idempotent `db-users` provisioning with fresh
  passwords: `ALTER USER` in MariaDB, a **re-auth probe** as each new account
  (`SELECT 1` — no credential file is rewritten until every new password
  provably authenticates), rewrite of the credential stores, automatic reseal
  on a sealed host, and an **automatic app+WAF restart** so the running app
  never sits on retired credentials. `--no-restart` defers the bounce for a
  batched maintenance window — then finish with `carlos-ctl play` promptly.
- **`rotate db-root`** changes root inside the db container and refreshes the
  `carlos-db` Podman secret. If the secret is in use it says so and defers —
  the secret only bootstraps an *empty* datadir, so that can wait (re-run the
  playbook after the next `down` to recreate it). The
  `CARLOS_DB_ROOT_PASSWORD` line in `carlos-app.env` is updated in place, and
  the sealed bundle's DR copy is refreshed. **One manual step the tooling
  cannot do:** `carlos-app.env` is playbook-owned, so also update the vaulted
  `carlos_db_root_password` in `host_vars/<instance>.yml` — otherwise the
  next playbook run re-renders the env file with the **old** password and
  every provisioning/rotation/admin path desyncs from the database.
- **`rotate log-view`** rehashes (bcrypt, in-process via `python3-bcrypt` —
  no plaintext leaves the process) and replaces only the credential line
  inside the Caddyfile's `basic_auth` block (local edits survive) and
  restarts the logview container — no pod restart needed. Refuses when the
  obs profile is disabled (there is no log view).
- **`rotate restic`** rotates the repository password with a no-stranding
  sequence: `restic key add` (old AND new both valid), **persist** the new
  password to the store, **verify** the repo opens with the stored value, and
  only then `restic key remove` the old key — at no point can a crash leave
  the repository on a password that exists nowhere. The stored env's extra
  variables (offsite backend credentials) are preserved. **Update the
  off-host escrow copy immediately: the old password no longer opens the
  repository once the old key is removed.**
- **TLS certificate**: not a `rotate` target — renewal depends on
  `carlos_tls_mode`. In **acme** mode renewal is AUTOMATED: the daily
  `<instance>-cert-renew.timer` runs `carlos-ctl cert-renew` (certbot in a
  one-shot rootless container, HTTP-01 behind the acme port-80 redirect),
  installs a changed cert, and restarts the two consumers (WAF + log view);
  a failed renewal or a failed consumer restart exits nonzero (OnFailure
  pages) and a `.cert-restart-needed` marker keeps the monitor nagging and
  the next daily run retrying until the restart lands. In **manual** mode
  renew by replacing `conf/waf/certs/{fullchain,privkey}.pem` and running
  `carlos-ctl play` (both consumers stage the files at start and only pick
  up a new cert on restart); **selfsigned** regenerates at `play` when its
  own cert nears expiry. In every mode the health monitor warns
  `CERT_EXPIRY_WARN_DAYS` (default 21) ahead of expiry **and** checks the
  certificate the WAF is actually *serving* on the wire — a cert replaced
  on disk but never reloaded is still caught.

## Opt-in hardening & data-integrity knobs

These postures ship with upstream-compatible defaults and a documented
switch. Each is OFF (or permissive) because flipping behavior under a
running clinic is its own risk — evaluate on a staging copy, then opt in.

**MariaDB strictness and data integrity.** `zz-carlos.cnf` ships
`sql_mode = ""` and `innodb_strict_mode = 0` (the OSCAR-lineage schema/app
can rely on permissive coercion). The cost: over-length clinical free-text
is silently TRUNCATED, out-of-range values are coerced, and zero dates are
allowed — silent corruption instead of errors. A ready-to-enable STRICT
block sits in the file (`STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,
NO_ENGINE_SUBSTITUTION` + `innodb_strict_mode = 1`); uncomment both lines
and restart the db pod after validating your workload. Related caveat: the
server is utf8mb4 end-to-end, but oscar-schema columns are frequently
utf8mb3 — a 4-byte codepoint (emoji, astral-plane CJK in a real name)
inserted into a utf8mb3 column TRUNCATES the string at that character under
the permissive mode; STRICT turns that into an error you can see. Column
conversion is upstream schema work.

**Database audit trail.** DBA access via the host socket, `podman exec`,
or phpMyAdmin bypasses the app's user-activity audit AND the WAF log —
MariaDB records nothing by default. `zz-carlos.cnf` carries a commented
`server_audit` plugin block (CONNECT + DDL/DCL events, size-rotated under
the datadir). Full QUERY logging is heavy and can persist PHI inside
statements — size retention and treat the audit file as PHI if you widen
the event set.

**Clinical-safety toggles.** `carlos_rx_allergy_checking` (default `no`,
the inherited upstream value): prescriptions are NOT checked against the
patient's recorded allergies until a site opts in — interaction warnings
are separately on. Sites SHOULD evaluate `yes`.
`carlos_jdbc_zero_date` (default `round`): a stored `0000-00-00` becomes a
REAL date on read — a fabricated clinical date; `convertToNull` surfaces it
as null instead. Both are host_vars knobs; changes re-render on the next
playbook run only for fresh installs (`carlos.properties` is
operator-owned after first render — merge by hand on existing installs).

**Edge hardening.** `carlos_waf_paranoia` (default 1) raises the CRS
paranoia level — evaluate 2 after inventorying false positives on your
workflows. `conf/waf/nginx-headers.conf` carries a commented enforcing-CSP
promotion block: once the shipped Report-Only header runs clean in your
site's browser consoles, swap it in (it pins the ORIGIN scripts may load
from; `unsafe-inline`/`unsafe-eval` stay — the UI is inline-script heavy).

**Deferred (tracked, not yet implemented).** App↔DB TLS with verification
(`require_secure_transport` + `REQUIRE SSL` on the app accounts): today the
hop crosses only the in-pod loopback/localhost boundary; enforcing TLS
needs CA plumbing into three clients and the server. GTID-based
replication/PITR (file+position is coherent for the single-server design).
Server `time_zone` stays SYSTEM (containers pin `TZ`, app and db agree);
pin it explicitly if you ever split app and db hosts. `wait_timeout` is
600s — if you tune the app's connection pool, keep its idle-validation
under that or raise `wait_timeout` alongside.

## Choosing the CARLOS and DrugRef versions

Which CARLOS and DrugRef the images carry — and whether each build compiles
its source, uses a published WAR, or pulls the release's prebuilt image — is
governed by four vars **per app**
(host_vars → rendered into `carlos-app.env`) plus one persisted **pin** per
app. The contract is identical for both; DrugRef simply uses its own keys
(`carlos_drugref_ref` / `carlos_drugref_artifact` /
`carlos_drugref_source_branch` / `carlos_drugref_image_repo` → `DRUGREF_*`)
and its own pin file:

- **`carlos_ref: auto` / `carlos_drugref_ref: auto`** (the defaults). The
  first `carlos-ctl build` resolves each app's newest **GitHub release** —
  newest non-prerelease by publish time, else the newest prerelease, else
  the HEAD of the app's `*_source_branch` (`main` for `carlos-emr/carlos` —
  its stable/release branch, which `develop` is promoted into — and `master`
  for `carlos-emr/drugref2026`) — and
  **pins** the answers in `$EMR_HOME/build/.source-pin` (CARLOS) and
  `$EMR_HOME/build/.source-pin.drugref` (DrugRef). A pin records the release
  tag AND its commit SHA (tags are mutable; nothing downstream trusts one),
  so **every later build is offline and identical** until an operator moves
  the pin. Any other ref value (branch/tag/40-hex SHA) is a manual ref with
  the historical build-from-source semantics — no API lookup, no pin. An
  operator who wants to keep tracking a development branch does exactly
  that: `carlos_ref: develop` and/or `carlos_drugref_ref: master` (or any
  other branch name).
- **`carlos_artifact: auto` / `carlos_drugref_artifact: auto`** (the
  defaults). A pinned release that publishes a WAR deploys that WAR —
  sha256-verified in-image against the release's published digest, no Maven
  compile — else the build compiles that exact release's source. CARLOS
  releases ship `carlos-<tag>.war`; DrugRef releases ship `drugref2.war`.
  `war` / `source` force one side per app; `image` (opt-in only — `auto`
  never selects it) pulls the release's prebuilt image by digest instead of
  building (see [Prebuilt images](#prebuilt-images-app_artifactimage)). The
  choice made under `auto` is persisted in that app's pin. (In WAR mode the
  CARLOS login page shows the release's own buildVersion, not a local build
  stamp.)
- **`carlos_source_branch: main` / `carlos_drugref_source_branch:
  master`** — only used by each app's no-releases fallback.
- **`carlos_image_repo` / `carlos_drugref_image_repo`** — the registry
  repository `image` mode resolves digests from and pulls (defaults:
  `ghcr.io/carlos-emr/carlos-app` / `ghcr.io/carlos-emr/carlos-drugref`);
  override for an internal mirror.

Day to day (`--drugref` targets the DrugRef pin; without it, CARLOS):

```bash
carlos-ctl source            # both pins, and what the next build does
carlos-ctl source update     # re-resolve BOTH apps to their newest releases
carlos-ctl source set 2026.08.0-alpha4                   # pin a CARLOS release (WAR-first)
carlos-ctl source set 2026.08.0-alpha4 --artifact source # …but compile it
carlos-ctl source set 2026.08.0-alpha4 --artifact image  # …or pull its prebuilt image
carlos-ctl source set <40-hex-sha>                  # pin a CARLOS commit, offline
carlos-ctl source set --drugref v1.0.0rc2           # pin a DrugRef release
carlos-ctl source set --drugref master              # pin DrugRef master's CURRENT head
carlos-ctl source clear      # forget both pins; next build re-resolves
```

(`source set <branch>` is the manual-but-sticky middle ground: it pins that
branch's head **as of now**, so the deployment still doesn't drift until the
next `source update`/`set`. A manual `*_ref: <branch>` in host_vars instead
re-fetches the branch tip on every build — the historical behavior.)

`source update`/`set` and the first unpinned build are the ONLY things that
touch the GitHub API (unauthenticated quota: 60 requests/hour; a handful of
calls each). A pinned build makes **zero** network calls beyond the artifact
fetch itself, so an air-gapped host works by pinning once (`source set
[--drugref] <sha>`, or manual refs) — if resolution is needed but
unreachable, `build` refuses with exactly that guidance. One more edge: a
pin taken between "release published" and "WAR uploaded" records a source
build — `source update` re-resolves it.

**Upgrade note (default flip):** installs provisioned before the
release-first `carlos_ref`/`carlos_drugref_ref` default rendered
`CARLOS_REF=develop` and `DRUGREF_REF=master`, and any explicit
value keeps exactly that behavior. But a host_vars file that never set
`carlos_ref`/`carlos_drugref_ref` flips to `auto` (release-first) at its
next playbook run + build — set `carlos_ref: develop` /
`carlos_drugref_ref: master` to keep tracking the branches instead.
Multi-instance hosts sharing one service user share one image store: keep
sibling pins aligned (run `source update` in lockstep), as the provisioning
assert already requires for the vars.

### Prebuilt images (`<APP>_ARTIFACT=image`)

The third artifact, **opt-in only** (`auto` never selects it): instead of
building locally, `carlos-ctl build` pulls the pinned release's **prebuilt
multi-arch image** — published per app release, via a **manual dispatch** of
this repo's *Publish Images* workflow (see
[Supply chain & published images](#supply-chain--published-images)), to
`ghcr.io/carlos-emr/carlos-app` / `ghcr.io/carlos-emr/carlos-drugref` — **by
digest**, and feeds it through the exact same `:build-<stamp>` →
`:previous`/`:latest` promotion, smoke test, rollback, and pod machinery as
a local build. The pod spec keeps deploying `localhost/carlos-app:latest`;
nothing downstream changes.

- **Trust model**: at pin time the resolver asks the registry for the tag's
  manifest-list digest and records it in the pin; every pull is
  `<repo>@sha256:<digest>` — the tag is for humans, the digest is the trust
  anchor, exactly like the third-party `repo:tag@sha256:` pins. A pinned
  image build is fully offline (no API, no registry lookup).
- **Refuse, never substitute**: a release whose image was not published yet
  refuses with guidance (dispatch *Publish Images*, or fall back with
  `<APP>_ARTIFACT=auto/war/source`); a failed pull aborts before any tag
  moves. An artifact class is never silently swapped for another.
- **Verify before trusting** a digest you didn't just publish:
  `gh attestation verify oci://ghcr.io/carlos-emr/carlos-app:<tag>-rN --owner carlos-emr`.
- **Air-gap / mirror**: a digest pin makes pin-time resolution offline, but
  the `podman pull` itself still fetches from the configured registry unless
  the image is already in the local store under that exact digest. A prior
  `podman pull` on the same host satisfies later builds offline; to move
  images into an air-gapped environment, replicate them into an internal
  registry with a digest-preserving copy (`skopeo copy --all
  --preserve-digests docker://ghcr.io/... docker://mirror/...`) and point
  `carlos_image_repo` / `carlos_drugref_image_repo` at the mirror. (`podman
  save`/`Podman load` does NOT reliably preserve registry digests or
  manifest lists — a loaded image may not match the pin.) The manual
  channel skips resolution entirely:
  `<APP>_REF=<tag>`, `<APP>_ARTIFACT=image`,
  `<APP>_IMAGE_DIGEST=<sha256:...>` (the digest is printed by every
  *Publish Images* run summary). Under the full deployment, put
  `<APP>_IMAGE_DIGEST` in **`carlos_extra_env`** (host_vars) — never
  hand-edit `carlos-app.env`, which is playbook-owned and overwritten on
  every run (the same applies to the manual WAR channel's
  `<APP>_WAR_URL`/`<APP>_WAR_SHA256`).
- **TLS-inspecting proxy**: pulls use Podman's own trust —
  `/etc/containers/certs.d/ghcr.io/ca.crt` (the `CARLOS_EXTRA_CA_BUNDLE`
  build-stage hook deliberately does not apply; nothing compiles).
- **Release gate**: under `CARLOS_BUILD_MODE=release` an image artifact
  satisfies the gate by construction — the digest IS the content checksum —
  so an all-image release build needs no `*_SRC_SHA256` and no
  `SOURCE_DATE_EPOCH`.

## Updating

Different kinds of update take different commands. The rule of thumb: **the
playbook renders, `play` deploys** — anything that lives in host_vars flows
`edit host_vars → ansible-playbook → carlos-ctl play`; anything in an
operator-owned file flows `edit the file → carlos-ctl play`.

- **Bump a tunable or an image tag.** Edit `host_vars/<instance>.yml` (a
  `carlos_*_mem_limit`, a JVM heap, `carlos_db_image`, `carlos_waf_image`,
  …), `sudo ansible-playbook -i inventory ansible/site.yml` (re-renders
  `carlos-app.env` + the pod specs), then `carlos-ctl play`. Do **not**
  hand-edit `carlos-app.env` — the next playbook run overwrites it.
- **Pull a same-tag security patch.** A rebuilt image published under a tag
  you already run is **not** re-pulled by `play` on its own. Run `carlos-ctl
  play --pull` to force podman to fetch the new digest — it refuses to
  deploy if any pull fails (a silent stale-image deploy defeats the point;
  `CARLOS_ALLOW_STALE_IMAGES=1` overrides). Third-party images are
  digest-pinned in `defaults/main.yml`, so bumping one is an edit to the pin
  plus playbook + `play --pull`.
- **Deploy a new (or rebuild the current) CARLOS/DrugRef version.** The
  normal flow under the default `auto` refs is
  `carlos-ctl source update && carlos-ctl rebuild` — update moves both pins
  to the newest releases (nothing changes without it; see
  [Choosing the CARLOS and DrugRef versions](#choosing-the-carlos-and-drugref-versions)),
  rebuild builds and redeploys them. `carlos-ctl source` answers "what am I
  running / about to build". `carlos-ctl rebuild [--ref <branch|tag|sha>]
  [--drugref-ref <branch|tag|sha>]` remains the escape hatch: both flags are
  **one-shot** overrides (the pins are untouched — the next plain build
  returns to them; `carlos-ctl source set [--drugref] <ref>` makes one
  durable); no flag rebuilds the pinned (or manual `CARLOS_REF`/
  `DRUGREF_REF`) selections (the build always runs `--no-cache`,
  so a same-ref rebuild can never ship a stale cached source tarball; the
  Maven `.m2` cache stays warm). Images and pod processes only — **the
  database, documents, and backups are never touched.** `play` (and
  therefore `rebuild`/`rollback`) waits per container (db/carlos/drugref
  1320 s, waf 420 s — sized above the pod's own 20-minute WAR-deploy/startup
  budget; an explicit `READY_WAIT_SECONDS` overrides all four)
  for the app container to turn **healthy**, and exits nonzero
  with rollback guidance if it never does; a slow host with
  `MARIADB_AUTO_UPGRADE` churn may need the knob raised. Validate with
  `carlos-ctl check`.
- **Pick up shipped changes after `git pull` of this repo.** Re-run the
  playbook — this replaces the old `sync-conf`. This also updates the
  **`carlos-ctl` CLI itself** (the playbook copies the `carlos_ctl` package
  to `/usr/local/lib/carlos-ctl` and refreshes the `/usr/local/sbin`
  shim — no pip involved). Playbook-owned files are re-rendered in place;
  preview what would change with
  `ansible-playbook ... --check --diff`. **Operator-owned files are never
  overwritten** (`carlos.properties`, `drugref2.properties`, `Caddyfile`,
  `restic.env`, `exporter.my.cnf`, `zz-carlos.cnf` and the `conf/` verbatim
  files) — when a shipped fix lands in one of those, diff your installed
  copy against the repo's `conf/` file or the role template and merge it
  yourself. Follow with `carlos-ctl play`.
- **Roll back the app.** `carlos-ctl build` keeps the previous CARLOS *and*
  DrugRef images as `:previous` (both retagged together, only after both new
  builds succeed). `carlos-ctl rollback` reverts to those images and
  re-plays — **one build deep** (a second build overwrites `:previous`, so
  roll back before rebuilding again). It refuses when either `:previous` tag
  is missing, and when the recorded schema fingerprint says the database has
  moved past the older image — pass `--accept-schema-mismatch` (or set
  `CARLOS_ACCEPT_SCHEMA_MISMATCH=1`) only when you have verified the older
  code tolerates the newer schema.
- **Maintenance that must survive a reboot.** A plain `carlos-ctl down`
  stops the pods and the timers, but the quadlet units restart the pods at
  the next boot (lingering user manager). `carlos-ctl down --disable` masks
  the pod units and disables the timers so a reboot leaves everything down;
  `carlos-ctl play` (or `carlos-ctl enable`) reverses both.

### Upgrade considerations

Behavior changes an existing install should review before/after pulling:

- **`encryption.util.secret.key` is now required in `carlos.properties`**
  (boot-fatal on the next `rebuild` to current CARLOS develop — the app
  refuses first boot without a pre-provisioned key because it would
  otherwise try to persist a generated one into the read-only mounted
  config). Set `carlos_encryption_secret_key` in host_vars (the playbook
  now asserts it); the play run then **appends the line to your installed
  `carlos.properties` automatically if — and only if — no
  `encryption.util.secret.key` line exists** (additive-only; an
  operator-supplied line is never touched). `carlos-ctl check` warns while
  the line is missing. Escrow the key with your other instance secrets:
  rotating or losing it orphans values already encrypted under it.
- **`OBS_ENABLED=false` now means disabled.** The old parser read any
  non-`0` value as enabled. Role-rendered envs always write `1`/`0`; only a
  hand-edited `carlos-app.env` changes behavior — and it now does what it
  says. Unrecognized values warn and default to enabled.
- **`zz-carlos.cnf` baseline changed** (`max_allowed_packet` 256M → 1G so
  `--hex-blob` dumps of large blobs stay RELOADABLE — at 256M a 128–256 MB
  raw blob was writable but its backup could not be restored). The file is
  operator-owned: the play run will show the security-conf drift WARNING —
  merge the new value into your installed copy and restart the db pod.
- **Restore-to-latest now ships the final binlogs AFTER the confirmation
  and app-stop** (writes made while the operator sat at the prompt used to
  be silently lost).
- **The restore load is now drop-and-recreate, not a merge** (supersedes the
  earlier "the load is a MERGE" note): every schema carried by the dump is
  `DROP DATABASE`'d and re-created from it, so the binlog replay applies onto
  exactly the dump state — the merge left post-dump tables in place and the
  replayed `CREATE TABLE` aborted the restore (error 1050) with the app
  already stopped. Load and replay also run with `sql_log_bin=0`, so a failed
  restore can simply be re-run (re-logged replay events used to double-apply
  on retry, error 1062) and the chain no longer bloats with a full DB copy
  per restore. Side effect: the dump's `CREATE DATABASE` charset/collation
  now actually applies. User databases absent from the dump and `mysql`/`sys`
  remain untouched.
- **Readiness budgets are per-container** (db/carlos/drugref 1320 s, waf
  420 s — carlos matches the db because its command now serializes behind
  the db's wait-for-3306). An explicit `READY_WAIT_SECONDS` still overrides
  everything, and the auto-provisioning db wait uses the same 1320 s.
- **`cert-renew` exits nonzero when a consumer restart fails** and leaves a
  `.cert-restart-needed` marker (retried daily, nagged by the monitor,
  cleared by a healthy `play`). On a not-yet-deployed instance (first-time
  acme issuance before the first play) consumer restarts are skipped and the
  run stays rc 0.
- **Binlog snapshot retention only applies while nightly fulls are fresh**:
  during a full-backup outage the 15-minute ships keep accumulating instead
  of age-expiring, preserving the replay chain that rolls the last good dump
  forward (disk growth is the alerted, recoverable direction).
- **Runtime floors are enforced**: Podman ≥ 4.9 and systemd ≥ 248 (the
  documented requirements) are now asserted by the playbook and re-checked
  by `carlos-ctl check`; `carlos_allow_old_runtime: true` opts out.
- **Non-interactive `carlos-ctl setup` refuses to write a plaintext DB root
  password** — provide `CARLOS_VAULT_PASSWORD_FILE`/
  `ANSIBLE_VAULT_PASSWORD_FILE` for headless vaulting, or ack with
  `CARLOS_SETUP_ALLOW_PLAINTEXT=1`. The wizard's BIND_IP default is now
  `127.0.0.1` (was a made-up LAN address).
- **Release builds require `SOURCE_DATE_EPOCH`** (pin the build timestamp,
  e.g. `git show -s --format=%ct <sha>`), and every build now smoke-tests
  the images (process runs + exploded WAR present) before `:latest` moves.
- **Schema migrations remain manual by design** (the images carry no
  machine-readable schema marker to gate on): when an image bump ships
  schema changes, apply the new `database/mysql/migration/` files in
  version order through `carlos-ctl db-migrate` BEFORE `carlos-ctl play`
  starts the new code against the old schema; the recorded schema
  fingerprint keeps guarding the rollback direction.
- **Multi-instance inventories**: the cross-instance collision asserts
  compare `ansible_host` as a STRING — co-located instances must use the
  identical host string (both `192.0.2.10`, not one IP and one DNS name)
  or the collision checks cannot see they share a machine. The host
  firewall is host-global and SINGLE-OWNER: the asserts now refuse two
  owners (previously undetected with both at the default — a mutual
  front-door blackhole), and the owning instance must admit each sibling's
  front door via `carlos_host_firewall_extra_allow` (list of {ip, port}
  pairs), or siblings' traffic hits the drop policy.
- `login_local_ip=192.168` in carlos.properties treats any 192.168/16
  client as "local" for login handling — inherited upstream; adjust to
  your management subnet if it matters behind your WAF.

### Data-safety invariants

What each mutation path may touch — the contract the lifecycle is built on:

- **Never touch `$EMR_HOME/data`** (MariaDB datadir, binlogs,
  `OscarDocument`): `build`, `rebuild`, `play`, `rollback`, `check`,
  `status`, `down`, `enable`, `monitor`, `guard`. App upgrades and config
  changes cannot lose data.
- **Read data, never write it**: `backup` (and its timers), `db-dump`,
  `db-backup`.
- **Write data ONLY when you ask them to**: `carlos-ctl db` with an import
  (`db oscar < dump.sql`), `backup restore` (double-confirmed), and SQL you
  run through `db`/`pma` — these are the break-glass paths and run as the
  MariaDB account you supply.
- **The playbook adopts but never destroys**: it renames
  `data/OpenoDocument` → `data/OscarDocument` once and creates missing
  directories; it never overwrites an operator-owned conf/properties/secret
  file, and it regenerates a credential only when no store (plain file,
  legacy cred blob, sealed bundle) holds one.
- **`uninstall` preserves all data** (datadir, documents, backups, conf, TLS
  certs, TPM blobs) — deleting data is always a manual, documented step.

## Backups (restic)

Backups are deliberately **not** a pod sidecar: they must run on their own
schedule and keep working while the pod is replaced or broken. The playbook
installs the Podman equivalent of a Kubernetes CronJob — a **host systemd
timer** (`<instance>-backup.timer`, nightly at 01:30, `Persistent=true` so
missed runs catch up) executing `carlos-ctl backup full`, which runs restic
as a one-shot container (`restic/restic`, digest-pinned). The timers are
enabled at provisioning but only **start** at the first successful
`carlos-ctl play` (they would otherwise fire — and page — against a
not-yet-deployed stack; a `ConditionPathExists` on the go-live marker
enforces it).

**Three tiers — the standard MariaDB point-in-time-recovery (PITR) model,
plus intra-day document snapshots:**

*Nightly full* (`<instance>-backup.timer` → `carlos-ctl backup full`), in
order of importance:

1. **MariaDB** — a consistent logical dump (`mariadb-dump
   --single-transaction --quick --routines --events --hex-blob` via
   `podman exec`; `--hex-blob` keeps BLOB columns — encrypted notes,
   attachments — byte-exact across dump and reload) **staged to a mode-0600
   temp file and verified complete** (the `-- Dump completed` footer must be
   present) before it is handed to restic as `carlos-databases.sql`;
   streaming straight into `restic backup --stdin` would commit a truncated,
   silently unrestorable dump if the dump died mid-stream. The staged file
   is transient plaintext PHI — keep `$EMR_HOME/backup` on a LUKS volume
   with free space ≥ the dump size. The live datadir is never file-copied (a
   raw copy of a running InnoDB datadir is not a valid backup). With binlogs
   on, the dump embeds its binlog coordinates (`--master-data=2`) and
   rotates the binlog (`--flush-logs`) — the replay anchor. (`--master-data`
   is correct on `mariadb:11.4` but is being phased out for `--source-data`;
   verify it when bumping the db image.) `--single-transaction` only
   snapshots InnoDB tables consistently; the nightly run audits the storage
   engines and warns if any non-InnoDB (e.g. MyISAM/Aria) table exists —
   convert those to InnoDB for a consistent PITR guarantee *where the table
   can take it* (see the fresh-install note below: the one table the stock
   schema trips this on cannot). (A *failed* engine audit fails the backup
   rather than reading as "all InnoDB"; `CARLOS_ALLOW_NON_INNODB=1` accepts
   dump-time-only consistency.)

   **`formRourke2009` is a known exception and needs no operator action.**
   The upstream ON/BC schema ships it as `ENGINE=Aria`
   (`migration/on/V1.0.1__on_schema.sql`), and it *cannot* be converted: it
   has **1227 columns**, over InnoDB's hard limit of 1017, so
   `ALTER TABLE oscar.formRourke2009 ENGINE=InnoDB` fails with
   `ERROR 1005 (errno: 185 "Too many columns")` under every `ROW_FORMAT`
   (DYNAMIC/COMPRESSED/COMPACT/REDUNDANT), and `innodb_page_size` is already
   at its 32 KiB maximum. Aria is a deliberate
   upstream choice for that form's width.

   Because there is no remedy to apply, the engine audit **allows this one
   table by name and proceeds** (it still prints a warning naming it). A
   fresh ON/BC install therefore backs up successfully out of the box; you
   do *not* need `CARLOS_ALLOW_NON_INNODB=1` for it. That blanket override
   remains available for other cases, but prefer converting a table over
   setting it — the override also silences tables that *could* have been
   fixed.

   **Any OTHER non-InnoDB table still refuses the dump**, which is the
   point: the guard keeps its value for the case where conversion is the
   right answer.

   **Residual risk this accepts, in plain terms:** a point-in-time restore
   can silently lose Rourke-2009 edits made between the nightly dump and the
   restore point. Every other table stays fully PITR-consistent. In current
   CARLOS the 2009 form is *not* offered in the encounter's form picker
   (`encounterForm` lists Rourke, 2006, 2017 and 2020), so the table holds
   legacy rows only and the practical write volume on a 2017/2020 practice
   is nil. Note it is retired by configuration, not enforced — the save path
   is still allowlisted in the app's `FrmRecordFactory` and the view routes
   are still registered, so an existing record reached by a direct URL, or a
   bulk data job touching the table, can still write to it.
2. **`data/OscarDocument`** — patient documents (read-only mount).
3. **`container/`** — rendered config including the encrypted secrets bundle
   (the repository is encrypted; the plaintext `carlos-app.env`, the
   superseded plaintext `conf/restic`, and the age private key are
   excluded — the key must never ride in the repo it unlocks). A
   **secrets-stripped** `carlos-app.env.dr` copy IS staged into the backup:
   it carries the non-secret site identity (SERVER_NAME, BIND_IP, ports,
   image pins) a bare-host restore needs, with every credential-looking key
   dropped fail-safe.

*Binlog shipping every 15 minutes* (`<instance>-binlog.timer` → `carlos-ctl
backup binlogs`, `carlos_binlog_oncalendar`): `zz-carlos.cnf` enables the
binary log (`log_bin` into the dedicated `data/mariadb-binlog` volume, `ROW`
format, `sync_binlog=1` for per-commit durability), and each run does
`FLUSH BINARY LOGS` then ships every **closed** binlog to restic
(`--tag binlog`; the active file is excluded and picked up next round).
**At-rest expectation:** ROW-format binlogs carry full before/after row
images — the complete PHI change stream — in cleartext on the binlog volume
(the restic repository itself is encrypted end-to-end by restic). Run the
data volumes on LUKS full-disk encryption; nothing in this stack verifies
that for you.

**Binary logging can stop without stopping the server.** MariaDB latches the
binary log OFF *for the rest of the server process* the first time it cannot
open a new binlog file — a full `data/mariadb-binlog` volume (`ENOSPC`) or an
ownership/permission change on it (`EACCES`) is enough:

```text
[ERROR] Could not use /var/lib/mysql-binlog/binlog.000006 for logging (error 13).
Turning logging off for the whole duration of the MariaDB server process.
To turn it on again: fix the cause, shutdown the MariaDB server and restart it.
```

The database keeps serving normally and **`@@log_bin` still reads `1`**, so
that variable cannot detect the state. Point-in-time recovery is dead from
that instant: nothing is being logged, so no amount of shipping can reach the
transactions committed after it. `carlos-ctl` therefore probes the *runtime*
state with `SHOW BINLOG STATUS` (one row = open, zero rows = closed; the
pre-11.4 `SHOW MASTER STATUS` spelling is the fallback), which needs only the
`REPLICATION CLIENT` the least-privilege `backup` account already has:

- `backup binlogs` **refuses** and does **not** stamp `.last-binlog-ok`, so
  the monitor's `BINLOG_MAX_AGE_MIN` check pages within ~35 minutes. (Without
  this the ship was a clean success forever: `FLUSH BINARY LOGS` is a no-op
  returning 0 once logging is off, and the already-closed binlogs are all
  still on disk to re-ship.)
- `backup full` **refuses before running the dump** — `mariadb-dump` would
  otherwise run the whole multi-GB dump and only then fail resolving the
  `--master-data` anchor (`Couldn't execute 'SELECT BINLOG_GTID_POS(...)': You
  are not using binary logging (1381)`).
- `carlos-ctl check` reports it as a FAIL.

**Recovery:** fix the cause on the binlog volume (free space, ownership), then
**restart the db container** — nothing short of a restart re-opens the log.
Everything committed while it was closed is unreachable by PITR, so take a
fresh `carlos-ctl backup full` immediately afterwards to re-anchor the chain.

**Binlog chain identity.** Each ship records the server's `@@server_uuid`
(persisted in the datadir — a physical restore keeps it, a DR-initialized
blank datadir mints a new one) three ways: a `-- carlos-server-uuid:` header
line in the dump, a `.carlos-server-identity` sidecar that rides *inside* the
binlog restic snapshot, and a local `.binlog-identity` marker. A ship whose
identity differs from the marker is REFUSED (it would splice one server's
binlogs onto another's chain — silent corruption) unless
`CARLOS_ACCEPT_NEW_BINLOG_IDENTITY=1` acknowledges a deliberate server change;
at replay, a dump whose uuid ≠ the chain's is refused unless
`CARLOS_ACCEPT_BINLOG_IDENTITY_MISMATCH=1`. Pre-identity (legacy) snapshots
carry no marker and proceed with an "identity UNVERIFIED" warning — backward
compatible. Reload/replay clients run with `--max-allowed-packet=1G` (and the
server cnf is raised to 256M) so a large hex-blob row never truncates on
restore, and with `sql_log_bin=0` — the restore never re-enters the binlog
chain, so retries never double-apply and ships never carry restore churn.
Staged plaintext dumps are reaped on the next run and on SIGTERM.

*Document snapshots every 15 minutes* (`<instance>-docs.timer` → `carlos-ctl
backup docs`, `carlos_docs_oncalendar`): a `--tag docs` snapshot of
`data/OscarDocument`, so a scan or lab PDF uploaded mid-morning does not wait
for the 01:30 full to be protected. restic uploads only files added since the
last run, so the cadence costs a directory scan plus the new files; the run
is deliberately database-free, so documents keep shipping even while the db
(or the whole pod) is down.

**Worst-case loss is one 15-minute interval for BOTH the database (binlogs)
and documents (docs snapshots), not one day.** All runs share a lock, so they
queue instead of colliding (long prunes/verifies release it so the 15-minute
tiers keep their RPO).

Retention per class (scoped `--host <instance>-emr` so a shared repository
never expires another instance's snapshots): dumps and files keep
`--keep-daily 7 --keep-weekly 5 --keep-monthly 12` (`BACKUP_KEEP`), binlog
snapshots keep `--keep-within 9d` (`BACKUP_KEEP_BINLOG` — sized to cover
roll-forward from the oldest daily dump, and below the 10-day local
`binlog_expire_logs_seconds`), and the fine-grained `docs` snapshots keep
`--keep-within 3d` (`BACKUP_KEEP_DOCS` — they only close the intra-day gap;
the nightly `files` tier carries the long document horizon); then one `prune`
and a repository check. The nightly check is structural; **once a week —
Sundays by default (`CHECK_READ_DATA_DOW`), the same day as the restore
drill — it reads ALL of the repository's pack data** (`check --read-data`),
so the entire repository is data-verified weekly.

> **Retention is a deliberate site-policy knob.** The `--keep-monthly 12`
> default (~12 months) is an operational default, **not** a records-retention
> guarantee — many healthcare jurisdictions require clinical records be kept
> 10+ years. Backups are a *recovery* tier, not a *records-archive* tier; if
> long-term retention is a legal obligation for your deployment, set
> `BACKUP_KEEP`/`BACKUP_KEEP_BINLOG`/`BACKUP_KEEP_DOCS` accordingly (in
> `restic.env` — operator-owned) and size the repository for it as a
> conscious decision.

A plain `restic check` alone would let silent disk corruption (bit rot) hide
until a restore fails; Sunday is the deep-verification day: the 01:30 full
backup reads every byte, then the 04:30 drill proves the data restores.
**Practical PITR reach is this binlog window (~9 days), not the 12-month dump
horizon** — dumps older than the window can only be restored to their exact
instant.

**Repository & credentials** live in `container/conf/restic/restic.env`
(mode 600; rendered by the playbook with a generated `RESTIC_PASSWORD` — or
vault an explicit `carlos_restic_password`; the render is guarded so it never
regenerates over an existing credential in *any* store, which would mint a
password that no longer opens the existing repository). Two things the
tooling cannot do for you:

- **Copy the whole `restic.env` content somewhere safe off this host** —
  `RESTIC_PASSWORD`, the repository URL, and any offsite-backend
  credentials. Without the password every backup is permanently unreadable;
  without the backend credentials you cannot even reach an offsite repo —
  and after `seal` the on-host copy is shredded (it then exists only inside
  the backup it unlocks). This off-host escrow is mandatory: `carlos-ctl
  seal` **refuses to run without acknowledging it** (confirm interactively,
  or set `AGE_ESCROW_CONFIRMED=1` / `RESTIC_ESCROW_CONFIRMED=1` for a
  non-interactive run).
- **Point `RESTIC_REPOSITORY` offsite — this is the real one.** The default
  repository is a **local** path (`$EMR_HOME/backup/restic-repo`), which is
  a fine first tier but is **not disaster recovery**: a local-only backup
  dies with the host it protects — disk failure, ransomware, theft, or fire
  takes the EMR and its backups together. For genuine recovery, set
  `RESTIC_REPOSITORY` to an **offsite** backend; any restic backend works
  (`s3:`, `rest:`, `sftp:`, `b2:`), and backend credentials go in the same
  env file. Both `check` and the recurring monitor nag about a local-only
  repository (on sealed installs via the non-secret `backup/.repo-posture`
  marker every backup run refreshes) until you either move it offsite or
  set `CARLOS_ACCEPT_LOCAL_REPO=1` to accept the posture explicitly.

Operations:

```bash
sudo carlos-ctl backup                          # full backup now
sudo carlos-ctl backup binlogs                  # ship binlogs now
sudo carlos-ctl backup docs                     # snapshot documents now
sudo carlos-ctl backup verify                   # restore drill now
sudo carlos-ctl backup status                   # stamp ages vs thresholds, DR posture
systemctl list-timers 'carlos-*'                # next scheduled runs
journalctl -u carlos-backup.service -e          # last full run's output
```

`backup status` is credential- and lock-free: it reads the success stamps
(full/binlog/docs/drill ages vs their alert thresholds) and the
`.repo-posture` marker, and exits nonzero when anything is stale — "did last
night's backup run?" without touching restic.

**Fail-closed override knobs** (each is loud when it trips; set only after
reading the error): `CARLOS_INIT_REPO=1` lets `backup` initialize a fresh
repository when the configured one reads uninitialized — the refusal exists
because an unmounted/wiped backend looks identical, and blindly re-initing
orphans the real backup history. `CARLOS_DRILL_ALLOW_NO_PITR=1` accepts a
base-dump-only drill when the dump carries no binlog anchor (binary logging
off) — without it the drill fails rather than green-lighting an unexercised
PITR chain. `CARLOS_ACCEPT_LOCAL_REPO=1` accepts a local-only repository
(see above).

### Guided point-in-time restore

`carlos-ctl backup restore` loads the last
nightly dump into the **live** database and replays the shipped binlogs from
the dump's own anchor (read automatically from the dump header — no
hand-typed `MASTER_LOG_POS`). It is **safe by default**: `--dry-run` shows
the snapshot, the anchor, and the replay plan without touching anything, and
the real run refuses unless you either type the literal `RESTORE <instance>`
at the prompt or set `CARLOS_RESTORE_CONFIRMED=<instance>` (the instance
name, e.g. `carlos` — the legacy `=1` still works one release with a
deprecation warning). It **drops and re-creates every schema carried by the
dump** (`oscar`/`drugref2` on a stock install; the `mysql`/`sys` system
schemas and user databases absent from the dump are preserved) so the binlog
replay applies onto exactly the dump state, runs the load and replay with
`sql_log_bin=0` (a failed restore can simply be re-run — nothing is
double-applied), and needs the MariaDB root password (from `carlos-app.env`,
falling back to the sealed bundle's `carlos.db_root_password` — so a DR
restore works before the env file carries the password again).

```bash
# See exactly what would happen — no changes:
sudo carlos-ctl backup restore --dry-run
# Restore to the latest shipped state (base dump + all binlogs):
sudo CARLOS_RESTORE_CONFIRMED=carlos carlos-ctl backup restore
# Restore to a specific instant (recover short of a bad change):
sudo carlos-ctl backup restore --stop-datetime='2026-07-05 14:30:00'
# From a specific snapshot (not the latest):
sudo carlos-ctl backup restore --snapshot=<restic-snapshot-id>
# Afterwards, restart the app so it reconnects:
sudo carlos-ctl play
```

Documents/config are separate restic tags — recover them directly with
`restic restore latest --tag files --target /tmp/restore` (any restic — the
same containerized restic the backup verb runs, or a host-installed one).

**If the restore fails mid-flight** (dump load or binlog replay errored; the
app containers are stopped):

1. **Re-run `backup restore` unchanged** — the restore is idempotent: the
   load re-creates each dumped schema from scratch and replayed events are
   never re-binlogged, so a retry converges to the same state.
2. If the replay keeps failing, the fetched chain is still staged **inside
   the db container** at `/tmp/binlog-replay` (absent only if the failure was
   at the copy step). Manual fallback, mirroring what the verb runs:
   `podman exec -it <instance>-app-db bash`, then
   `mariadb-binlog --no-defaults --start-position=<anchor-pos> /tmp/binlog-replay/binlog.0000NN ... | mariadb -uroot -p --init-command='SET SESSION sql_log_bin=0'`.
3. **After any `--stop-datetime` restore, run `sudo carlos-ctl backup full`
   immediately** — the local chain still contains the discarded timeline, and
   only a fresh dump (new anchor, `--flush-logs`) fences it off from a later
   restore-to-latest.
4. A hung break-glass session (`carlos-ctl db` / `pma`) holding a metadata
   lock can stall the load's `DROP DATABASE` — close those sessions first.

Not backed up by design: the mariadb datadir (superseded by the dump) and
the VictoriaLogs store (retention-bound operational telemetry).

### Disaster-recovery runbook (bare host → running EMR)

The consolidated sequence when the original host is gone. Prerequisites: the
**two escrowed off-host secrets** — the **age private key** and the **full
`restic.env` content** (`RESTIC_PASSWORD`, the offsite `RESTIC_REPOSITORY`
URL, and its backend credentials). The backend credentials must come from
your escrow, not the bundle: the bundle rides *inside* the repo they unlock.

```bash
# 0. New host: clone this repo on the control node and provision the instance
#    with the SAME host_vars (your inventory/host_vars live in version
#    control, vaulted — that IS the site-identity escrow):
#      sudo ansible-playbook -i inventory ansible/site.yml
#    Do NOT play yet. (host_vars lost too? The backup carries a
#    secrets-stripped carlos-app.env.dr with the non-secret site identity —
#    SERVER_NAME, BIND_IP, ports, image pins — reconstruct host_vars from it.)
# 1. Restore config + documents from the offsite repo (restic on any host):
#      RESTIC_REPOSITORY=<offsite> restic restore latest \
#        --host <instance>-emr --tag files --target /tmp/dr
#    Copy /tmp/dr/backup/container/conf/* over $EMR_HOME/container/conf/
#    (operator-owned conf, TLS certs, the encrypted secrets bundle) and
#    /tmp/dr/backup/OscarDocument/* into $EMR_HOME/data/OscarDocument/.
# 2. Re-materialize secrets: place the escrowed age private key at
#    $EMR_HOME/secrets-private/age-key.txt (root-only 0700 dir, 0600 file)
#    and run `carlos-ctl seal` (re-seals to this host's TPM where available).
#    The key is NOT in the restored container/ tree by design: it must never
#    ride in the repo it unlocks, so it comes only from your off-host escrow.
# 3. Build images (carlos-ctl build) and start the stack (carlos-ctl play) —
#    the datadir is empty, so MariaDB initializes fresh
#    (CARLOS_ACCEPT_EMPTY_DATADIR=1 if the guard has already armed).
# 4. Load the database and replay to the last shipped binlog:
#      sudo CARLOS_RESTORE_CONFIRMED=<instance> carlos-ctl backup restore
#    (--stop-datetime only if recovering short of the end; the root password
#    comes from the playbook-rendered carlos-app.env, or the sealed bundle.)
# 5. carlos-ctl check; carlos-ctl backup verify; carlos-ctl alert-test —
#    prove the restored system, its backups, and its paging all work.
```

Practice this on scratch hardware before you need it; the weekly drill proves
the data restores, not that YOU can drive the sequence under pressure.

### Restore drill

A backup you never restore is not a backup.
`<instance>-backup-verify.timer` runs weekly, Sundays
(`carlos_backup_verify_oncalendar`), executing `carlos-ctl backup verify`: it
restores this instance's latest dump (`--host <instance>-emr`) into a
**throwaway** MariaDB (tmpfs datadir, no host mounts, never published),
**replays the shipped binlogs from the dump's recorded anchor** (so the
point-in-time-recovery path itself is exercised, not just the base dump), and
sanity-checks the core tables (`oscar.provider` must be **non-empty**;
`demographic` and `appointment` must be present). It also asserts the
**document and config tiers**: the latest `docs` snapshot must be listable
and non-empty (an unmounted/mis-pathed `OscarDocument` cannot pass — the
15-minute docs run likewise refuses to stamp success on an empty store;
`CARLOS_DOCS_MIN_FILES=0` is the explicit pre-go-live opt-out), and the
`files` snapshot must contain the encrypted secrets bundle (the DR contract).
The `mysql`/`sys` system schemas are excluded on load so production account
rows can't break the drill's own auth. `restic check` only proves repository
integrity; this proves the data actually restores. Run it now with
`carlos-ctl backup verify`. Success writes `backup/.last-verify-ok`; the
monitor alerts when that stamp goes stale (`VERIFY_MAX_AGE_HOURS`, default
192 h ≈ 8 days) — so a drill whose *timer* silently stops firing surfaces,
not just a drill that runs and fails. The scratch DB loads into a RAM tmpfs
sized by **`VERIFY_TMPFS_SIZE`** (default `4g`, set in `restic.env`): it
must exceed the restored database size, or the drill fails every week — a
database larger than host RAM needs a disk-backed drill. The drill also
FAILS when the dump's binlog anchor is missing from the shipped set or the
chain has a gap — a broken PITR chain must not pass green.

### Native MariaDB physical backups (manual alternative)

For operators who want the native MariaDB tooling alongside restic:
`carlos-ctl db-dump` is native `mariadb-dump` (a logical export — the same
tool the restic tier stages), and **`carlos-ctl db-backup [name]`** is native
**`mariadb-backup`** — a **physical (hot) snapshot** of the whole running
instance, taken with zero downtime and `--prepare`d immediately so it is
restore-ready. Each run lands in its own directory under
`$EMR_HOME/backup/mariadb-hot/<name>` (default name: a timestamp). Physical
snapshots restore by **file copy-back, not SQL replay**, which for a large
database is minutes instead of hours — useful as a quick safety point before
schema migrations or a db-image bump.

Know what this tier deliberately is **not**: it is not scheduled, not
encrypted, not shipped offsite, and not monitored — a `db-backup` run does
not update the `.last-full-ok` freshness marker, so the health monitor still
alerts if the *restic* tier goes stale. Restic remains the primary backup
(scheduled, encrypted, offsite-capable, binlog PITR, weekly-drilled).
Retention here is manual: delete old snapshot dirs yourself (the monitor's
disk-free check covers the volume, and the snapshots are plaintext PHI in a
root-only directory — keep the filesystem LUKS-encrypted like the rest of
`$EMR_HOME`).

**When to consider *scheduling* physical backups:** they buy restore *time*,
not RPO — the 15-minute loss windows are set by the binlog and docs tiers
regardless of base-backup type. Logical dumps stay the scheduled base because
they are the path the weekly drill proves end to end, they restore across
MariaDB versions (physical snapshots do not), and they deduplicate far better
in restic. Escalate to a scheduled physical tier only if a timed drill shows
dump-restore (SQL replay) exceeding your outage tolerance — typically once
the database reaches tens of GB. Until then, `db-backup` before risky
maintenance is the right use.

**Restore** (manual and deliberately not a one-keystroke command — it
replaces the entire datadir). Use the same db-image version that took the
snapshot:

Run the restore container **in the rootless engine** (as the SERVICE_USER),
so the in-container `chown mysql:mysql` lands on the same subuid-mapped
ownership the rootless `db` container expects — a root `podman run` would
leave the datadir owned wrong for the rootless engine:

```bash
sudo carlos-ctl down
sudo runuser -u carlos -- podman run --rm \
  -v /usr/local/emr/data/mariadb-mnt:/var/lib/mysql \
  -v /usr/local/emr/backup/mariadb-hot/<name>:/restore \
  <DB_IMAGE> bash -c 'rm -rf /var/lib/mysql/* && \
    mariadb-backup --copy-back --target-dir=/restore --datadir=/var/lib/mysql && \
    chown -R mysql:mysql /var/lib/mysql'
sudo carlos-ctl play
```

The snapshot records its binlog coordinates in `mariadb_backup_binlog_info`
inside the target dir (MariaDB's `mariadb-backup` renamed the old
`xtrabackup_*` metadata files; the `xtrabackup_binlog_pos_innodb` that is
still written carries InnoDB LSN positions, not the binlog coordinates), so
rolling forward to a point in time with the shipped binlogs works from a
physical restore too.

## Alerting & health monitoring

The deployment used to fail silently — a broken backup, a full disk, or an
expiring TLS cert only surfaced if someone ran `journalctl`. Now the alerting
stack has three layers, and `play` **refuses go-live** until the off-box
paths exist (or are explicitly declined):

- **Failure alerting.** The backup, binlog, docs, verify, and guard units
  carry `OnFailure=<instance>-alert@%n.service`, whose ExecStart is
  `carlos-ctl alert "%i"`. The dispatcher writes a WARNING to the journal
  and, if configured, POSTs to `ALERT_WEBHOOK` (generic JSON `{"text": …}` —
  Slack/Mattermost style; the URL travels via `curl -K -` stdin config, never
  argv) and/or emails `ALERT_EMAIL` (needs a sendmail-compatible MTA); each
  configured channel is attempted independently (so either is a fallback for
  the other), and the dispatcher exits nonzero when NO configured channel
  delivered. With neither set it is journal-only — and `play` refuses that
  silently-pages-nobody posture unless `ALERT_JOURNAL_ONLY=1` explicitly
  accepts it. **Prove delivery end to end with `carlos-ctl alert-test`** — a
  configured channel is itself a single point of failure until a test message
  has actually arrived off-box.
- **Continuous metric rules (obs profile on): vmalert.** The obs pod's
  `vmalert` evaluates `conf/vmalert/rules.yml` against the co-located
  VictoriaMetrics every 30 s — the metric-derived checks the shell monitor
  used to re-derive by polling the API once an hour: `MysqlDown`
  (`mysql_up != 1`), `ScrapeTargetDown` (`up == 0`), `ScrapingDead`
  (`absent(up)` — *absence* is not health: a dead vmagent/remote-write would
  otherwise leave every other rule reading green), `DiskLow`
  (`node_filesystem_avail_bytes` below `carlos_disk_min_free`% on real
  filesystems), `LogIngestionStalled`
  (`sum(rate(vl_rows_ingested_total)) == 0 or absent(...)` while VictoriaLogs
  is up — aggregated across series so a per-stream label churn cannot make it
  fire spuriously, and `absent()`-guarded so a vanished metric still pages; a
  running-but-non-shipping log pipeline would otherwise let the WAF PHI
  audit trail die green; vmagent scrapes VictoriaLogs' self-metrics for
  exactly this; the stall window is `carlos_logs_max_age_min`, which
  replaces the bash monitor's `LOGS_MAX_AGE_MIN` env knob), and the
  lead-time capacity rules `MemoryLowHost`
  (node-exporter `MemAvailable` below `carlos_mem_min_avail_pct`% for 10m) and
  `LoadHigh` (`node_load15` above `carlos_load15_per_core_max`× the CPU count
  for 30m) — early
  warning before an OOM-kill or a thrash spiral, not just after. `for:` windows
  absorb scrape blips so a single missed sample never pages. vmalert
  **notifies nobody itself** (`-notifier.blackhole` — no Alertmanager); the
  monitor relays.
- **Health monitor.** `<instance>-monitor.timer` runs `carlos-ctl monitor`
  every 15 minutes (`carlos_monitor_oncalendar`). Because vmalert notifies
  nobody itself, this cadence **is the paging ceiling** for metric-derived
  alerts: vmalert detects within seconds, the next monitor tick pages. It
  polls vmalert's `/api/v1/alerts`
  and dispatches anything firing through the alert path — treats an
  **unreachable vmalert (while its container is listed running) as itself an
  alert** (a dead alerting engine must not read as "no alerts"), and probes
  **VictoriaMetrics' own `/health` while its container runs**: a
  running-but-wedged store keeps vmalert perfectly reachable while every
  rule evaluates against a dead datasource and silently reads green
  (`absent()` needs a *successful* query to fire). It KEEPS everything that
  has no metric equivalent: a tracked volume (datadir, binlog, logs, backup, metrics,
  the rootless image store, the journal) below `DISK_MIN_FREE` percent free
  (the obs-independent floor — and the only disk check when obs is off);
  the WAF/log-view TLS cert within `CERT_EXPIRY_WARN_DAYS`, **both on disk
  and as SERVED on the wire** (a renewed-but-never-reloaded cert is caught);
  a **failed sealed-secrets unit** (an unseal failure that would leave the
  app on the `__SEALED__` placeholder); a **JVM heap dump** present under
  `logs/` (an OOM happened and left large plaintext PHI); the **pod-unit
  is-active bridge** (`systemctl --user -M <SERVICE_USER>@ is-active` on the
  three pod units — this replaces the per-quadlet `OnFailure=`, which a
  `systemd --user` unit cannot target at a root alert template); a
  **local-only restic repository** (DR posture nag; `CARLOS_ACCEPT_LOCAL_REPO=1`
  accepts); a **missing HEARTBEAT_URL on a deployed instance**; and the
  **local container liveness sweep** — every expected container present
  (12 in the app/obs/waf pods with the obs profile on; 4 without),
  Podman's own `unhealthy` verdict, a **rising restart count** between
  sweeps (a crash-looping container stays listed in `podman ps` — presence
  alone reads green), and an authoritative cred-free DB
  accepting-connections probe. The sweep is deliberately
  **store-independent by design**: it must still work while the obs pod
  itself is down, and with the obs profile off it is the only liveness
  signal. Also: a **stale or MISSING backup stamp** — the newest successful
  full older than `BACKUP_MAX_AGE_HOURS` (default 26), binlog ship older
  than `BINLOG_MAX_AGE_MIN` (default 35), document snapshot older than
  `DOCS_MAX_AGE_MIN` (default 35), or a stamp absent entirely (backups that
  NEVER ran must not read green; the first successful `play` seeds the
  stamps so a fresh install gets the full window before its first alert) —
  which catches a silently-stopped timer that `OnFailure=` cannot. A
  missing `podman`/`systemctl`/`curl`/`openssl` on the monitor's PATH is
  itself an alert ("cannot check" is not "healthy"), a malformed numeric
  knob degrades that one check to its default instead of killing the whole
  sweep, and a post-reboot **boot grace**
  (`BOOT_GRACE_SECONDS`, default 900) suppresses only the liveness checks
  while the user-manager stack is still starting. The monitor also runs
  (all `.deployed`-gated): a **front-door probe** — an on-box HTTPS request to
  `BIND_IP:HTTPS_PORT` (works with obs off), classifying `502/503` as
  `front-door-502` (app down or the WAF cached a stale app-pod IP) distinctly
  from a total `front-door-down`, plus a root-only second leg that asserts the
  `<instance>-nat` prerouting DNAT is loaded (the HTTP probe can't see a
  missing NAT table); a **dev-mode-build nag** (`build-unpinned`) when a
  deployed instance runs images built from a moving source ref
  (`CARLOS_ACCEPT_UNPINNED_BUILD=1` accepts); an **unexpected phpMyAdmin
  container present** (the on-demand `pma` session should self-expire at its
  `--ttl`); and the **obs-pod containers** in the restart-count sweep when obs
  is on. Alert channels are also read from a root-only sidecar
  (`/etc/carlos-podman/instances/<instance>.alert.env`, 0600) so the webhook/
  heartbeat capability URLs survive an unmounted `$EMR_HOME` — the exact
  failure the guard page needs to escape. Persistent conditions
  (cert expiring, stale backups, low disk) re-deliver off-box at most once
  per `ALERT_REMIND_HOURS` (default 24) while they persist — and only once
  a page actually *went out* (a webhook blip at first occurrence must not
  silence the condition for a day) — and re-arm as soon as they recover: no
  every-tick re-page storms. If `HEARTBEAT_URL` is set, the monitor pings it on
  an all-clear and `…/fail` otherwise — an **off-host dead-man's switch**
  that fires even when the whole host or obs pod is down. Size the external
  service's missed-ping window to at least `BOOT_GRACE_SECONDS` (default
  900 s) **plus one monitor cadence**: during boot grace the healthy ping is
  deliberately withheld (liveness was not checked), so a reboot skips 1–2
  pings by design. `play` refuses go-live without a heartbeat unless
  `CARLOS_NO_HEARTBEAT=1` accepts the blind spot. Run it now with
  `carlos-ctl monitor`.

The admin ports (`9443`, and the on-demand phpMyAdmin) have no login rate
limit by design — keep them firewalled to the clinic network (they bind
`BIND_IP`; the playbook installs the log-view source filter). For
defence-in-depth against basic-auth brute force, run host **fail2ban**
against Caddy's auth-failure log lines (`podman logs carlos-obs-logview`); a
Caddy `rate_limit` directive would require a custom `xcaddy` image and is
intentionally not used.

### Validating a deployment (`carlos-ctl check`)

Run it after every `play`.
It's a **read-only** end-to-end check of the running deployment — the runtime
paths the hermetic test suite can't exercise — printing `ok`/`FAIL` per check
and exiting nonzero if anything is wrong (so it can gate a deploy or feed
alerting):

- all pods + every expected container up, `carlos-net` and `carlos-edge`
  present, the app and waf pods on the journald log driver;
- **WAF/DB isolation** (probed from inside the waf container):
  `carlos-app:8443` (the TLS backend) IS reachable over the edge network
  (proves pod-name DNS + the proxy path), `carlos-app:8080` is NOT (proves
  the plaintext connector stayed loopback-pinned), `carlos-app:3306` is NOT
  (proves the MariaDB loopback bind), and `carlos-obs:9428` is NOT (proves
  the internet-facing WAF has no route to the PHI log store) — the store is
  ALSO basic-auth protected now, and `check` proves that enforcement
  positively: a deliberately credential-free store query must be rejected
  `401` (a store that answered would mean auth silently fell open);
- **the front door, end to end**: an HTTPS request through the nft redirect →
  WAF TLS → proxy → Tomcat must answer 2xx/3xx (502/503 isolates "WAF up,
  backend not"), and the served response must carry the
  `Strict-Transport-Security` header (nginx `add_header` does not inherit
  into blocks with their own `add_header` — a CRS-image change that
  suppresses the security headers is caught here);
- **DrugRef** answering on pod loopback `:8180` from inside the carlos
  container;
- (obs profile on) both stores reachable on host loopback; **metrics**
  actually landing (`up{job=node,mariadb,vmagent}==1` and `mysql_up==1` in
  VictoriaMetrics) — this single check proves scrape + cross-pod
  remote-write + the shared-network DNS + the exporter credentials; **logs**
  flowing (recent `carlos`/`db`/`waf-access` entries in VictoriaLogs) and
  `logcollect` free of `journalctl` errors;
- persistent journald, a non-expired TLS cert, unencrypted-looking swap
  warned about, and the local-repository DR posture nag.

If the metrics checks fail while `vmagent` is up, `check` names the likely
cause — cross-pod name resolution — and the one-line fix (point
`-remoteWrite.url` at `carlos-obs-victoria-metrics:8428` and the waf pod's
`BACKEND` at `https://carlos-app-carlos:8443` if your podman's aardvark-dns
registers container names rather than pod names).

(The bash-era `check` also re-verified every pod-spec security field —
runAsNonRoot per container, readOnlyRootFilesystem per container — against
the running state. Those spec-restating sweeps were deliberately trimmed in
the rewrite: the specs declare them, Podman enforces them, and a violation
fails the container loudly at start; `check` spends its budget probing the
behaviors the specs *can't* declare.)

### Alert → response runbook

When a page fires (webhook/email, or a missed heartbeat), map it to a first
action here. All commands run as the host root shell; `carlos-ctl` resolves
the instance from `$EMR_HOME` (or `--instance <name>`).

| Alert | First diagnostic | Common cause → remediation |
| --- | --- | --- |
| **missed heartbeat** (external monitor) | `systemctl status <inst>-monitor.timer`; `carlos-ctl check` | Host down / monitor timer dead / total outage. If the host is up, restart the timer; if the whole box is unreachable, this is the DR path (see the disaster-recovery runbook). |
| **container-down-…** | `runuser -u <svc> -- podman ps -a`; `podman logs <pod>-<ctr>` | Crash loop (bad config/secret, OOM). Fix the cause, `carlos-ctl play`. A blank/unmounted datadir pages the guard — see "a container won't start". |
| **MysqlDown / app-db-root** | `carlos-ctl db -e 'SELECT 1'` | DB not accepting connections, or app still on root: run `carlos-ctl db-users` (see [Least-privilege DB accounts](#least-privilege-db-accounts)). |
| **DiskLow** | `df -h $EMR_HOME`; `du -sh $EMR_HOME/backup/mariadb-hot/* $EMR_HOME/logs/*.hprof 2>/dev/null` | See the reclaim order below. |
| **backup-stamp-stale / restore-drill-stale** | `carlos-ctl backup status`; `journalctl -u <inst>-backup.service` | Backup/verify timer failing — read the unit log, fix the repo/creds, `systemctl start <inst>-backup.service`. A stale drill means the last restore test did not complete: investigate before trusting the backups. |
| **cert-served-mismatch / cert-expiry** | `curl -skI https://<server>/` | Renew the cert at `$EMR_HOME/container/conf/waf/certs/`, then `carlos-ctl play` (or restart the WAF pod). |
| **LogIngestionStalled** | `journalctl -u <inst>.service \| grep logcollect`; `carlos-ctl check` | vector/VictoriaLogs wedged — restart the obs pod; check disk (the vector buffer blocks when full). |
| **heap-dump-present** | `ls -lh $EMR_HOME/logs/*.hprof` | A JVM OOM dumped a heap. Analyse then DELETE it (it is plaintext PHI and large — see reclaim order). |
| **cert-restart-needed** (acme) | `systemctl status <inst>-cert-renew.service`; `ls -l $EMR_HOME/container/conf/waf/.cert-restart-needed` | A renewed cert is installed on disk but a consumer pod restart FAILED — the WAF/log view still serve the OLD cert. Restart by hand (`carlos-ctl play`) or let the next daily cert-renew run retry; the marker clears on success. A failed *renewal* itself (certbot error) pages via the unit's OnFailure: check DNS for the server name, that :80 reaches this host (acme redirect), and the certbot output in the unit log. |
| **hostfw-table-missing** | `nft list table inet <inst>-hostfw`; `systemctl status <inst>-nft.service` | The default-deny host firewall is NOT loaded (the apply unit is fail-open) — the host is running unfirewalled. Fix the ruleset error in the unit log, `systemctl restart <inst>-nft.service`, and confirm the guard/monitor stop paging. |
| **waf-access-stream-silent** | `journalctl -u <inst>-obs.service \| grep logcollect`; check the WAF access log | Zero waf-access lines reached the log store in an hour on a deployed instance (the monitor's own probes guarantee traffic) — 5xx surveillance is blind. Either log shipping is down (restart the obs pod) or the WAF log format/stream label drifted (update the monitor's regex in the same change). |
| **failed-unit-…** | `systemctl status <unit>` | A system unit for this instance is sitting in a FAILED state (its one OnFailure page may have been missed). Fix the cause, then `systemctl reset-failed <unit>`. |
| **no MariaDB metrics** (obs profile; `mysqld_up` absent, MysqlDown never evaluates) | `stat -c '%u:%g' $EMR_HOME/container/conf/metrics/exporter.my.cnf` | The exporter credential file is owned by the wrong uid — `carlos-ctl play` repairs it. Root cause and the EPERM/EINVAL distinction: see the subuid-ownership note below this table. |
| **waf-5xx-burst** (obs profile) | `carlos-ctl logs waf`; check recent deploys | The WAF served more 5xx responses than the threshold (`WAF_5XX_MAX`, default 25, per `WAF_5XX_WINDOW_MIN`, default 10 min) — the app is up but erroring; check the DB connection pool and the last deploy (liveness probes stay green while `/carlos/` still 302s). |
| **pma-lingering** | `runuser -u <svc> -- podman ps` | Break-glass phpMyAdmin is still running — if no active admin session, stop it (a dropped SSH tunnel can leave it serving; the `--ttl` bound auto-removes it eventually). |
| **db-not-accepting** | `carlos-ctl db -e 'SELECT 1'` | The db container runs but MariaDB is not accepting connections on 3306 — check `carlos-ctl logs db` for a crash/recovery loop. |
| **front-door-nat-missing** | `nft list table ip <inst>-nat` | The DNAT table (or its prerouting rule) is gone — external clients cannot reach the EMR even though on-host probes read healthy; `systemctl restart <inst>-nft.service`. |
| **vm-wedged / vmalert-unreachable / vmalert-response-malformed** (obs profile) | `curl -s 127.0.0.1:<port>/health` | The metrics store or rule evaluator is up but not answering (or answering garbage) — every metric-derived rule silently reads green; restart the obs pod. |
| **cert-file-missing** | `ls -l $EMR_HOME/container/conf/waf/certs/` | The served cert/key file vanished on a deployed instance — expiry monitoring is blind and the next WAF restart will fail; restore the cert+key. |
| **accept-empty-marker-present** | `ls $EMR_HOME/container/guard/` | The blank-datadir guard is disarmed by a leftover `accept-empty-datadir` marker — re-run `carlos-ctl play` to clear it. |
| **alert-channel-unset** | check `ALERT_WEBHOOK` / `ALERT_EMAIL` in `carlos-app.env` | A deployed instance has no alert channel configured — pages only reach the local journal; set a channel (or ack with `ALERT_JOURNAL_ONLY=1`). |
| **waf-db-isolation-unverified** | `carlos-ctl check` | The WAF→DB isolation probe could not run at all (podman exec failed) — the boundary is unverified, which is treated as a fault, not health. |
| **waf-db-isolation-broken** | `carlos-ctl check` | The edge pod can reach MariaDB on 3306 — the WAF/DB boundary is broken (usually a hand-edited `bind_address` in zz-carlos.cnf). Merge `bind_address = 127.0.0.1` back and re-play. |
| **no-heartbeat-configured** (weekly) | — | Standing reminder that CARLOS_NO_HEARTBEAT=1 is acked on a deployed instance: a total host/monitor death is invisible. Set HEARTBEAT_URL to close the blind spot. |

#### Subuid ownership of exporter/log-view config files

The mysqld-exporter reads its 0600 credential file as container uid
**65534**, so on the host it must be owned by the service user's subuid for
65534 (a five- or six-digit uid, e.g. `231069:231069`) — **not** `root:root`
and **not** `<svc>:root`. A root-written replacement left group-root cannot
be handed over: `chown(2)` refuses a file whose owner *or group* is outside
the rootless userns id_map, and host uid/gid 0 are never in it, so
`podman unshare chown` fails with `EPERM`. `carlos-ctl play` repairs it (it
re-hands the file to `<svc>:<svc>` first, then maps it); the same applies to
`conf/caddy/Caddyfile` and container uid **10013** for the log view. If the
chown fails with `EINVAL` rather than `EPERM`, the id is not in the map at
all: check `awk -F: '$1=="<svc>"' /etc/subuid /etc/subgid` — the third field
must exceed 65534, and rootless Podman maps from the FIRST grant only, so
widen that one (appending a second range does not help) and re-run
`podman system migrate`. `carlos-ctl build`/`play` warn about this; the role
asserts it.

**Disk-full reclaim order** (safe first): delete analysed `*.hprof` heap
dumps in `$EMR_HOME/logs`; prune old manual `$EMR_HOME/backup/mariadb-hot/*`
snapshots (these are unmanaged — retention is manual); `journalctl --vacuum-size=`;
verify `restic forget --prune` is running (the backup timer does this). Never
delete `$EMR_HOME/data` or the restic repo.

### Patching & rebooting the host

The stack has several boot-time moving parts (the service user's lingering
`systemd --user` manager, the root blank-datadir guard ordered before the
pod, the nftables redirect unit, and the TPM unseal of the age key). To patch
the host OS and reboot safely:

1. `carlos-ctl backup full` (a fresh offsite backup before any risky change),
   and confirm `carlos-ctl backup status` is green.
2. `carlos-ctl down --disable` — masks the units so nothing races the reboot;
   `play`/`enable` reverse it.
3. Apply updates and reboot.
4. After boot: `carlos-ctl play && carlos-ctl check`. Expect the external
   heartbeat to miss 1–2 pings across the reboot window (`BOOT_GRACE_SECONDS`).
5. **TPM-sealed secrets:** a kernel/Secure-Boot change alters the PCRs the age
   key is sealed against, so the unseal can FAIL and `carlos-ctl secrets
   render` leaves the `__SEALED__` placeholder (the app then can't read its
   DB password). If an **attended-recovery passphrase** was set at seal time,
   the render prompts for it on the boot console (90 s timeout) — type it,
   let the boot finish, then re-run `carlos-ctl seal` to re-seal to the new
   TPM state. Otherwise verify `carlos-ctl secrets render` succeeds after the
   reboot; if it fails, re-seal from the escrowed age key (see "Secrets").
   This is why step 1's backup + the off-host age-key escrow are
   non-negotiable before a firmware/kernel update.

## Troubleshooting

### A container won't start

- `runuser -u <SERVICE_USER> -- podman ps -a --pod` — which container is
  restarting/exited; `podman logs <pod>-<name>` (or `journalctl` for the
  journald-driver pods) for the reason.
- **db crash-loop on an adopted datadir**: almost always the documented
  `innodb_page_size` mismatch (the cnf ships 32K; stock MariaDB datadirs are
  16K — the db stream says exactly this) or a datadir newer than the db
  image.
- **db-init refuses with `FATAL: … no initialized MariaDB datadir`**: the
  blank-datadir guard — the data volume looks unmounted or wiped on a
  deployed instance. Mount the data volume; `CARLOS_ACCEPT_EMPTY_DATADIR=1`
  + `carlos-ctl play` only if a fresh datadir is intended.
- **db crash-loop `File '/var/lib/mysql-binlog/binlog.index' … Permission
  denied`** on an *adopted* binlog directory: db-init chowns the datadir
  recursively but the binlog dir non-recursively (a fresh install's binlog
  dir is empty, so the dir chown suffices). Binlog files carried over from
  another install and owned by a different uid then block the db uid. Fix
  once with `chown -R 999:999 $EMR_HOME/data/mariadb-binlog` (999 = the
  docker-library mariadb uid; on a rootless host use the mapped subuid).
- **carlos/drugref exit with `FATAL: db_password is __SEALED__`**: the
  secrets unit failed to render — `journalctl -u <instance>-secrets.service`;
  a TPM/Secure-Boot change means re-sealing with the escrowed age key.
- **waf exits immediately**: missing TLS material (play preflights it now) or
  the `BACKEND` hostname not resolving (aardvark registering container names —
  `carlos-ctl check` names the fix), or an Apache-style `WAF_SSL_PROTOCOLS`
  carried over (play warns).
- **every pod volume fails with `statfs …: permission denied`** (`kube play`
  dies on its first mount): the shared parents under `$EMR_HOME` are
  root-owned and not traversable by the service user. Fixed in the role
  (the traversal parents — `$EMR_HOME`, `container/`, `container/conf/`,
  `data/`, `logs/`, `metrics/` — are now declared explicitly with their own
  owner/mode); re-run the playbook. Check with
  `namei -l $EMR_HOME/container/conf/carlos/carlos.properties`: `conf/` must
  be `root:<service user>` `0750`, and `data/`, `logs/`, `metrics/` must be
  service-user-owned `0750`.
- **`carlos-obs-logcollect` (vector) crash-loops with `Missing environment
  variable in config`**: vector env-interpolates its config file — comments
  included — before parsing it, so ANY un-doubled `$` in
  `conf/vector/journald-collector.toml` is fatal. Double it (`$$`).
- **`carlos-app-vmagent` restarts silently and no metrics arrive**: vmagent
  hard-fails on an unparseable `conf/vmagent/scrape.yml`. With the app pod on
  the journald log driver its output is invisible to `podman logs`, so run the
  image by hand to see it, or just
  `python3 -c 'import yaml,sys; yaml.safe_load(open(sys.argv[1]))' \
  $EMR_HOME/container/conf/vmagent/scrape.yml`.
- **`/drugref2` serves 404 forever and the drugref probe never greens**: the
  DrugRef context failed to start. Against MariaDB this is almost always the
  Hibernate dialect auto-detect — DrugRef bundles mysql-connector-j 9.x,
  whose `getSQLKeywords()` reads `INFORMATION_SCHEMA.KEYWORDS.RESERVED`, a
  column MariaDB does not have. The pod spec and the image now pass
  `-Dhibernate.dialect=org.hibernate.dialect.MariaDBDialect` and
  `-Dhibernate.boot.allow_jdbc_metadata_access=false`; re-run the playbook
  (and rebuild for the standalone image) if a hand-edited spec lost them.
- **pod unit `failed` in `systemctl --user`**: `carlos-ctl play` re-runs the
  full preflight and restarts everything; the units retry forever
  (`StartLimitIntervalSec=0`), so a fixed cause self-heals within
  `RestartSec=30`.

## Resource limits, JVM heap & health checks

Per-container memory limits and the two JVMs' heap sizes are **site
configuration** in host_vars, rendered into the pod specs by the playbook
(not hardcoded in the yaml). Defaults:

| Container | Pod | mem limit | JVM heap |
| --- | --- | --- | --- |
| carlos | app | `12Gi` | `carlos_java_xms: 4g` / `carlos_java_xmx: 8g` |
| db | app | `6Gi` | — (see the memory-budget arithmetic in `zz-carlos.cnf`) |
| drugref | app | `2Gi` | `carlos_drugref_java_xms: 256m` / `carlos_drugref_java_xmx: 1g` |
| waf | waf | `1Gi` | — |
| mysqld-exporter | app (obs-gated) | `128Mi` | — |
| vmagent | app (obs-gated) | `512Mi` | — |
| node-exporter | obs | `128Mi` | — |
| victorialogs | obs | `2Gi` | — |
| victoria-metrics | obs | `2Gi` | — |
| vmalert | obs | `256Mi` | — |
| logcollect | obs | `512Mi` | — |
| logview (caddy) | obs | `256Mi` | — |

Podman enforces each limit as a hard cgroup ceiling. Keep each limit
**above** its `*_java_xmx` by a non-heap margin (~2–4 GiB for CARLOS) so a
Java `OutOfMemoryError` — which triggers the heap dump — fires *before* the
kernel OOM-killer SIGKILLs the JVM (a SIGKILL leaves no dump); `carlos-ctl
play` validates the margin and refuses the clearly-broken case. The host must
have RAM ≥ the sum of the limits (~27 GiB at defaults with the obs profile
on; ~21 GiB without it). The db limit is sized against the worst-case MariaDB
allocation documented as arithmetic in `zz-carlos.cnf` — change the two
together.

Each long-lived container also carries a **CPU limit** (`carlos_*_cpu_limit`,
in cores — `carlos`/`db` default `4`, others `1`–`2`) so a runaway process
cannot starve MariaDB or the host; the initContainers carry literal
`256Mi`/`1`-core limits. There are **no `requests`** — `podman kube play` has
no scheduler, so requests are inert; only limits map to a cgroup cap. Other
rendered knobs: `carlos_tz`, `carlos_log_verbosity`,
`carlos_db_auto_upgrade` (gate the one-way datadir upgrade), and the WAF/CRS
tuning (`carlos_waf_image`, `carlos_waf_paranoia`,
`carlos_waf_anomaly_inbound`, `carlos_waf_anomaly_outbound`,
`carlos_waf_ssl_protocols`, `carlos_waf_ssl_ciphers`,
`carlos_waf_audit_log_parts`).

**WAF paranoia level (`carlos_waf_paranoia`, default 1).** CRS paranoia 1 is
deliberate for an EMR: CARLOS is a form-heavy clinical app, and higher
paranoia levels flag increasing amounts of *legitimate* clinical input
(free-text notes, unusual but valid field content), so PL2+ raises the
false-positive rate against real patient care. Raise it per-install only
after watching the `waf-error` log stream for what a level would block, and
add targeted exclusions in
`conf/waf/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf` (operator-owned)
rather than lowering the level globally. The security response headers on the
app front door (HSTS, `X-Content-Type-Options`, `X-Frame-Options:
SAMEORIGIN`, `Referrer-Policy`) live in `conf/waf/nginx-headers.conf`;
`carlos-ctl check` probes the served HSTS header so a CRS-image change that
suppresses them is caught.

**App-restart 502/404 window (expected).** The WAF's nginx resolves its
`BACKEND` (the app pod) hostname once at startup and caches it, so during a
`carlos-ctl play`/app restart the WAF briefly returns 502/404 until the app
answers again — there is **no in-nginx upstream retry by design**. The
Quadlet orders the WAF after the app pod and `Restart=on-failure` re-runs it
if the backend was unresolvable at start; the window is short and
self-healing, not a fault to chase.

PID caps are applied via Podman's `io.podman.annotations.pids-limit/<ctr>`
pod annotations (a `pids` entry under `resources.limits` is **not** read by
`podman kube play` — only `cpu`/`memory` are).

### Liveness probes

`carlos`, `drugref`, `db`, and `waf` carry an exec
liveness probe. These are `exec` probes on purpose: `podman kube play`
rewrites `httpGet`/`tcpSocket` probes into in-container `curl`/`nc` calls,
which those images do not all ship — a bash `/dev/tcp` check needs only the
shell they already run. `carlos` and `drugref` go one level deeper than a
bare port-open: they send a real `GET /carlos/` (resp. `/drugref2/`) over
`/dev/tcp` and require an HTTP status line (2xx/3xx for carlos; 2xx–4xx for
drugref), so a Tomcat that is up but serving 404s because the WAR failed to
deploy **fails** the probe instead of passing forever. `db` stays a TCP-open
check (the image's `healthcheck.sh --connect` needs a healthcheck account
this deployment does not provision). `carlos` also has a **`startupProbe`**
(a 1200 s budget — up to 20 min of slow first-boot: WAR explode, schema
migration — before liveness starts counting, so a slow migration is not
liveness-killed into a crash-loop). **Whether a failed liveness probe actually restarts the
container, and whether `startupProbe` is honored, is
Podman-version-dependent** — the generous `carlos` `initialDelaySeconds`
(180 s) is retained as belt-and-braces for versions that ignore
`startupProbe`. Validate on your target Podman version before relying on
self-healing (the monitor's `unhealthy` + restart-count checks page either
way). Note `podman kube play` **ignores `readinessProbe` entirely** — there
is no readiness gating of WAF→app traffic; startup ordering relies on
container list order plus the quadlet `After=` between pods.

**First-boot DB-not-ready race.** `podman kube play` starts a pod's
containers in list order (db first) with **no readiness gating between
them**, and because the db is a regular container in the *same* pod, an
initContainer cannot wait on it (initContainers must complete before any
regular container, including the db, starts). So on a fresh datadir the
`carlos` container can briefly start before MariaDB accepts connections.
Mitigations: the app retries its connection pool, and `carlos-ctl play`'s
default least-privilege provisioning waits for the db to be ready before it
bounces the app (so the post-provision app start races against an
already-ready db). If the app still comes up before the db on a very slow
first init, `carlos-ctl play` once more after the db is healthy.

## Supply chain & published images

### Release builds

The `maven`/`tomcat` base images in the
`Containerfile`s are digest-pinned (like every third-party runtime image —
mariadb, restic, exporters, vector, caddy, victoria*, vmalert), and
`carlos-ctl build` runs `--no-cache` by default so a same-ref rebuild can
never ship a stale cached source tarball (`--use-cache` opts back in for
pinned-SHA iteration). What remains site policy: under the
default `auto` refs both app sources are **pinned release commits** (and a
WAR build verifies the release asset's sha256 in-image — for that image the
published digest IS the content checksum), but a manual `carlos_ref`/
`carlos_drugref_ref` may name a moving branch — `build` warns whenever a
SOURCE-compiled ref is not a full commit SHA. For a reproducible, audited
release build:

1. pin `carlos_ref`/`carlos_drugref_ref` to full commit SHAs (deterministic
   sources),
2. compute each source tarball's sha256 and set `CARLOS_SRC_SHA256` /
   `DRUGREF_SRC_SHA256` (e.g. `curl -sL
   https://github.com/carlos-emr/carlos/archive/<sha>.tar.gz | sha256sum`) —
   the Containerfiles then verify the fetched tarball with `sha256sum -c`
   before building (empty = skipped, for moving-ref dev builds), and
3. enforce the dependency-lock check (`BUILD_DEP_LOCK=1`, which drops
   `-Pskip-dependency-lock` — no hand-editing the Containerfile).

The fastest path to all three is **`CARLOS_BUILD_MODE=release`**: `carlos-ctl
build` then **hard-fails** unless every source-compiled ref is a 40-hex
commit SHA with its `*_SRC_SHA256` set, and forces `BUILD_DEP_LOCK=1` —
turning the three warn-only layers above into a single gate. A WAR-artifact
build (either app) satisfies the gate differently: it requires that app's
pinned WAR sha256 (verified in-image) instead of its `*_SRC_SHA256`, and the
compile-only layers apply only to images that actually compile (the
dependency-lock profile exists in the CARLOS pom only; DrugRef has none).
A prebuilt-image artifact satisfies it by construction — its pinned digest
IS the content checksum, so it needs neither a `*_SRC_SHA256` nor a WAR
sha256. `SOURCE_DATE_EPOCH` is required whenever anything compiles — an
all-WAR (or all-image, or mixed WAR/image) release build runs no compiler
and needs no timestamp pin. Without
`CARLOS_BUILD_MODE=release` (the default), a
manually configured moving-branch ref only warns. Redeploy a specific pair with
`carlos-ctl rebuild --ref <sha> --drugref-ref <sha>`. (`build` reads its
context from `$EMR_HOME/build/` — installed by the role — or a repo checkout
via `CARLOS_BUILD_DIR`.)

apt packages (`unzip`, `tini`) are deliberately **not** version-pinned: they
install inside a digest-pinned base image (an already integrity-pinned
lineage), so per-package pins would add checksum-maintenance churn without a
meaningful supply-chain gain.

### Published prebuilt images (ghcr.io)

The two images this repo customizes
are also published, pre-built, to GitHub Container Registry by the
**Publish Images** workflow (`.github/workflows/publish-images.yml`,
manually dispatched per app release):

- `ghcr.io/carlos-emr/carlos-app` and `ghcr.io/carlos-emr/carlos-drugref`,
  multi-arch (amd64 + arm64) manifest lists, built in **WAR mode** from the
  app repos' release assets — the release WAR's sha256 is verified in-image,
  so the chain composes: attested WAR → attested image → digest-pinned pull.
- Tags: `<app-tag>-rN` is **immutable** (N = packaging generation — a
  Containerfile fix or base-image bump for the same app version bumps N and
  never re-pushes an existing tag); `<app-tag>` is a **mutable alias** to the
  newest rN. The alias exists for humans and one-time digest discovery only —
  anything that runs an image must reference the digest, the same
  tag-for-humans / digest-for-trust model as every third-party
  `repo:tag@sha256:` pin in this repo. No `latest` tag is ever published.
- Every published manifest list carries a GitHub build-provenance
  attestation. Verify before trusting a digest you didn't just publish:

  ```bash
  gh attestation verify oci://ghcr.io/carlos-emr/carlos-app:<app-tag>-rN --owner carlos-emr
  podman pull ghcr.io/carlos-emr/carlos-app@sha256:<digest>   # pulls verify the digest
  ```

  Each workflow run's summary page prints the copy-pasteable digest-pinned
  pull line (and manual pin env lines) per image.

Local builds remain first-class and are the default: prebuilt images are an
opt-in convenience for hosts that don't want to compile or download-and-bake
per host, not a replacement for `carlos-ctl build`'s source/WAR modes.
Consumption is `<APP>_ARTIFACT=image` (see
[Choosing the CARLOS and DrugRef versions](#choosing-the-carlos-and-drugref-versions)):
a third trust chain — attested WAR → attested multi-arch image →
digest-pinned pull — alongside the compile-from-pinned-source and
verified-WAR chains.
(One-time setup note for maintainers: new ghcr packages default **private**
— after the first publish, an org admin must set both packages public and
confirm they're linked to this repo.)

### TLS-inspecting egress proxy

On a host whose outbound HTTPS is
re-terminated by a corporate/hospital proxy, the in-image Maven dependency
fetch fails PKIX validation. Point `CARLOS_EXTRA_CA_BUNDLE` at the proxy's CA
bundle (a PEM file) and `carlos-ctl build` stages it into the build context;
the Containerfiles import it into the **build stage's** trust store (system CAs
+ the JDK cacerts) so the fetch succeeds. This affects the build stages only —
it is never baked into the runtime images, and it does **not** weaken the
digest-pinned base images (image digests are verified independently of
transport trust). The staged file is restored to its committed 0-byte
placeholder after every build; leave `CARLOS_EXTRA_CA_BUNDLE` unset on hosts
with direct egress.

## Tests

`make check` runs the full battery on a dev workstation; nothing here runs on
(or needs) a production host:

- **`tests/run-tests.sh`** — the hermetic e2e suite for the CLI: no root, no
  Podman, no systemd, no TPM, no sops/age. `tests/stubs/` provides recording
  fakes for every external binary (Podman, systemctl, systemd-creds, sops,
  age, nft, ss, curl, runuser, loginctl, …), and the
  `CARLOS_{CREDSTORE,SYSTEMD,QUADLET,INSTANCE_REGISTRY,JOURNAL}_DIR`
  overrides redirect every system write into a throwaway work directory. The
  suite fabricates an **Ansible-rendered instance home** — the playbook's
  output contract — and drives the CLI against it, asserting the go-live
  gates, the data-plane fail-closed guards, the secrets flows, and the
  off-argv credential discipline (the stubs record forwarded-env values, so
  "this secret reached the container without ever being an argv token" is a
  provable assertion). The curl stub also answers the GitHub releases API
  deterministically (`STUB_GH_RELEASES`/`STUB_GH_DOWN`), so the release-first
  version resolution, the sticky pin, and its offline behavior are asserted
  end to end. Run it after changing anything under `carlos_ctl/`.
- **`tests/unit/`** — pytest for the pure logic: env-file parse-don't-source
  semantics, port/BIND_IP/CIDR validation, PITR anchor extraction, secrets
  bundle round-trips, monitor throttling, and the release-resolution policy
  (ordering, drafts, WAR-asset detection, pin round-trips).
- **`tests/ansible-checks.sh`** — the role's own checks: playbook syntax,
  `ansible-lint`, a render-only pass that templates **every** file for
  **both** obs profiles into a temp prefix and asserts token-free output,
  second-run idempotency (changed=0), and the obs-toggle round trip
  (on → off → on). Skips itself with a notice when `ansible-playbook` is
  absent, so the CLI suite stays runnable anywhere.

What the harness deliberately does NOT cover: live `podman kube play`
behavior, the restore drill's binlog-replay leg, and the WAF/login cookie
flow — those are what `carlos-ctl check`, `carlos-ctl backup verify`, and a
live login are for, on a real host.

Beyond the hermetic battery, **`scripts/validation/`** holds an intensive
real-usage harness for the release-first source selection: real Podman
builds of both apps, real curl + TLS against a local mock of
`api.github.com` serving a frozen snapshot of real release data, tamper and
mid-resolution failure drills, and a no-silent-failure contract on every
check. It needs root and a disposable dev machine — see
`scripts/validation/README.md` before running it.

## Requirements

**Target hosts** (per instance):

- Podman ≥ 4.9 with **netavark + aardvark-dns** (kube play with secrets/init
  containers; `LogDriver=journald`; cross-pod name resolution on the shared
  `carlos-net` network for the app→obs remote-write path and on `carlos-edge`
  for the waf→app proxy path; multi-network pods — two `Network=` lines in
  the app quadlet / repeated `--network` on kube play; `podman secret
  exists`; build cache mounts). podman 5.x (with **pasta** as the default
  rootless network backend) is recommended for the rootless engine
- **python3** with **python3-yaml** (RHEL family: `python3-pyyaml`) and
  **python3-bcrypt** — the `carlos-ctl` runtime dependencies. The playbook
  installs them from distro packages; **no pip and no PyPI access** are ever
  needed on a host
- **Rootless-engine prerequisites** (the pods run as an unprivileged
  `SERVICE_USER`, see "Rootless engine"): **cgroups v2** (unified hierarchy
  at `/sys/fs/cgroup`, for rootless resource limits);
  **`newuidmap`/`newgidmap`** from `shadow-utils`/`uidmap` (the playbook
  allocates the 65536-wide subuid+subgid range); **nftables** (`nft`) for the
  `:443 → :8443` redirect; **`runuser`** and **`loginctl`** (systemd) for
  running commands as the service user with an enabled linger session; and
  **systemd ≥ 248** on the host for `systemctl --user -M <user>@` remote
  user-manager control. The playbook fail-fasts with the missing tool named
- **sops + age** for `carlos-ctl seal` (the playbook warns if absent; the
  hard requirement is enforced at seal time)
- systemd on the host (Quadlet pods + backup/monitor timers) with
  **persistent journald** — the playbook creates `/var/log/journal`; size
  `SystemMaxUse` (journald.conf) to cover the longest VictoriaLogs outage you
  want log shipping to backfill (obs profile on) or your whole log-retention
  policy (obs profile off), and set a high `RateLimitBurst` (or
  `RateLimitIntervalSec=0`) so journald does not *drop* the WAF audit /
  access stream under load — dropped lines never reach Vector, so the
  disk-buffer/backfill guarantee only protects lines that reach the journal.
  Keep journald's default **`SplitMode=uid`** (per-user journal files): the
  rootless log collector reads only the service user's `user-<uid>.journal`
  via journald's owner ACL — with `SplitMode=none` everything lands in the
  root-only system journal and log shipping silently stops (`carlos-ctl
  check`'s "logs flowing" checks catch it). **PHI governance**: the journal
  holds the raw (pre-redaction) copy of every container's output, including
  WAF access lines with PHI-correlating query strings — treat
  `systemd-journal` group membership as PHI access, and treat `SystemMaxUse`
  as this copy's retention bound
- **SELinux is not handled**: the pod specs bind-mount host paths with no
  `:z`/`:Z` relabeling, so on an enforcing SELinux host (RHEL/Fedora family)
  the containers will get permission denials on every hostPath. Target hosts
  are assumed permissive/AppArmor (Debian/Ubuntu); on an enforcing host,
  label `$EMR_HOME` for container access (e.g. `chcon -R -t
  container_file_t`) or add relabeling before relying on this deployment
- **Encrypted swap, zram, or no swap.** Decrypted secret material (the age
  master key, the restic env, staged PHI dumps) lives in `/run` tmpfs while
  in use; under memory pressure tmpfs pages can be written to swap and
  survive a reboot in cleartext. Use dm-crypt swap (or swap on a LUKS-backed
  volume), zram, or disable swap entirely — `carlos-ctl check` warns when
  active swap does not look encrypted
- **Time synchronization** (chrony or systemd-timesyncd): correct time
  underpins TLS validation, the monitor's cert-expiry math, backup scheduling
  and log correlation across streams — a skewed clock silently breaks them
- **TLS material (`manual` mode only)**: cert/key placed at
  `$EMR_HOME/container/conf/waf/certs/{fullchain,privkey}.pem` — the default
  `selfsigned` mode auto-generates the pair and `acme` mode issues/renews
  it, so neither needs pre-placed files
- Host RAM ≥ the sum of all pods' container memory limits (~27 GiB at the
  shipped defaults with the obs profile on, ~21 GiB without it; see
  "Resource limits, JVM heap & health checks" to tune down)
- A **real resolver** in the host's `/etc/resolv.conf`. The playbook copies
  that file into the `carlos` container ONLY (a DNS workaround carried over
  from the OpenO setup; Podman kube play's own `dnsConfig` is unreliable —
  Podman #20562/#9132). The `waf` container deliberately keeps Podman's
  generated resolv.conf: that is what carries the aardvark-dns server
  resolving `carlos-app` for `BACKEND` proxying, and the WAF needs no
  external DNS. On a host running **systemd-resolved** the host file points
  at the stub `127.0.0.53`, which inside the pod's network namespace is
  loopback with nothing listening — CARLOS outbound integrations (Teleplan,
  HRM, MCEDT) then silently fail to resolve. The playbook detects this and,
  if you set **`carlos_pod_dns`** (upstream nameservers) in host_vars,
  writes those into the container `resolv.conf`; otherwise it warns. You can
  also hand-edit `$EMR_HOME/container/conf/tomcat/resolv.conf` (operator-owned)
- Outbound network during `carlos-ctl build` (CARLOS and DrugRef tarballs,
  Maven dependencies) and on first `carlos-ctl play` (pulls the third-party
  images)

**Control node** (your workstation / management host):

- **ansible-core**, plus **passlib** (bcrypt-hashes the log-view credential
  on the control node — the plaintext never crosses to the target, only the
  hash does) and **netaddr** with the **`ansible.utils` collection**
  (the log-view subnet derivation and IP validation filters):
  `pip install ansible-core passlib 'bcrypt<4.1' netaddr && ansible-galaxy
  collection install ansible.utils` (the `bcrypt<4.1` pin keeps
  `password_hash('bcrypt')` working with passlib 1.7.4)
- **ansible-vault** discipline for `carlos_db_root_password` (and any
  explicit `carlos_restic_password` / `carlos_log_view_password`) in
  host_vars — treat the inventory + host_vars repo as part of your
  site-identity escrow
- For the dev/test battery (`make check`): python3 with ruff/mypy/pytest,
  and optionally ansible-lint

## License

This project is licensed under the **GNU Affero General Public License
v3.0** (see [LICENSE](LICENSE)), with the following exceptions derived from
the [CARLOS EMR](https://github.com/carlos-emr/carlos) project. Their upstream
sources are **GPL-2.0-or-later**; they are distributed here under
**GPL-3.0-or-later**, as the upstream grant's "or later" option permits:

- `ansible/roles/carlos_podman/templates/carlos.properties.j2` (from upstream
  `.devcontainer/development/config/shared/volumes/carlos.properties`)
- `ansible/roles/carlos_podman/templates/drugref2.properties.j2` (from
  upstream `.devcontainer/development/config/shared/volumes/drugref2.properties`)
- `conf/tomcat/server.xml` and `conf/drugref/server.xml` (based on upstream
  `.devcontainer/development/config/tomcat/conf/server.xml`)
- `conf/tomcat/logging.properties` (based on the stock Apache Tomcat
  `logging.properties`, Apache License 2.0 upstream)

CARLOS itself, and the container images this pod runs, carry their own
licenses.
