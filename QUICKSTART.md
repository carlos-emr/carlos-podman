<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 CARLOS Contributors -->
# Quick start: deploy CARLOS with rootless Podman

> **Status: alpha.** carlos-podman is new and deployment procedures may change.
> Two installation paths are documented below. A site considering production
> use must complete its own technical, security, privacy, backup, restore, and
> regulatory review before using the system with patient information.

This guide covers:

1. a small sample-data pod for local evaluation; and
2. the standard Ansible deployment for Ontario (`ON`) or British Columbia
   (`BC`), including the WAF, DrugRef, monitoring, backups, and secret sealing.

The sample path runs MariaDB and CARLOS in one rootless Podman pod and publishes
the application only on `127.0.0.1:8443`. It is useful for learning the
container workflow before configuring a standard environment.

## Choose a deployment path

- **Sample-data evaluation:** continue with steps 1–6. This path uses the
  upstream seeded account and a loopback-only endpoint.
- **Standard ON or BC environment:** review the host concepts in step 1,
  then continue at [Standard Ontario or British Columbia deployment](#standard-ontario-or-british-columbia-deployment).

The sample-data instructions assume that you:

- are comfortable with a Debian or Ubuntu shell, `apt`, and `sudo`;
- understand basic MariaDB concepts such as a database, schema, and root
  password;
- are new to Podman or to running CARLOS as containers; and
- are working on a single-user development machine.

Commands without `sudo` must run as the same non-root user. Podman stores
rootless images, containers, and networks per user, so changing users partway
through the procedure creates a separate Podman environment.

## 1. Install and check the host tools

These package names apply to current Debian and Ubuntu releases:

```bash
sudo apt update
sudo apt install -y \
  podman uidmap slirp4netns passt fuse-overlayfs \
  git curl openssl python3
```

This project requires Podman 4.9 or newer. If `apt` installs an older release,
use the supported backports or vendor repository for your Debian or Ubuntu
version before continuing.

Confirm that Podman works as your normal user:

```bash
podman --version
podman info --format \
  'rootless={{.Host.Security.Rootless}} storage={{.Store.GraphDriverName}} cgroups={{.Host.CgroupsVersion}}'
```

Expected results:

- `rootless=true` confirms that Podman is not using the root-owned container
  store;
- `storage=overlay` is the expected storage driver; `vfs` works but makes
  builds and database I/O much slower; and
- cgroup version `2` is preferred. The development pod does not set resource
  limits, so cgroup delegation is not required for this guide.

### Check subordinate user and group IDs

Rootless Podman maps container users through `/etc/subuid` and `/etc/subgid`.
The account needs at least 65,536 IDs in its first entry in each file.

```bash
USER_NAME=$(id -un)
awk -F: -v user="$USER_NAME" '$1 == user {print FILENAME ": start=" $2 ", count=" $3}' \
  /etc/subuid /etc/subgid
```

You should see one line from each file with `count=65536` or larger. If both
lines are missing, allocate ranges and refresh Podman's user namespace:

```bash
sudo usermod --add-subuids 100000-165535 "$USER_NAME"
sudo usermod --add-subgids 100000-165535 "$USER_NAME"
podman system migrate
```

If only one file lacks an entry, run only the corresponding `--add-subuids` or
`--add-subgids` command. Use ranges assigned by your system administrator if
`100000-165535` is already allocated. Check for overlap before adding it:

```bash
cat /etc/subuid /etc/subgid
```

If an entry exists but its count is below 65,536, do not append a second
entry. Rootless Podman uses the first entry on supported versions. Ask the
system administrator to replace the narrow range, then run
`podman system migrate` as your normal user.

### Check networking and open-file limits

```bash
test -r /dev/net/tun -a -w /dev/net/tun && echo '/dev/net/tun is usable'
ulimit -Sn
ulimit -Hn
```

The build command requests an open-file limit of 65,536. The hard limit shown
by `ulimit -Hn` must be at least 4,096; 65,536 is recommended. If it is lower,
configure a higher limit in `/etc/security/limits.d/` and start a new login
session before continuing.

`/dev/net/tun` must be readable and writable by the user. On Debian and Ubuntu,
the packaged device rule normally configures this automatically. Fix the host
udev or device permissions if the check prints nothing.

## 2. Build the application image

Clone this repository if you have not already done so:

```bash
git clone https://github.com/carlos-emr/carlos-podman.git
cd carlos-podman
```

CARLOS publishes GitHub releases, and a release usually ships a prebuilt
`carlos-<tag>.war` — using it skips the long Maven compile. List the releases
and pick the newest one (the full Ansible deployment automates exactly this
policy; see the README's "Choosing the CARLOS and DrugRef versions"):

```bash
curl -s https://api.github.com/repos/carlos-emr/carlos/releases \
  | grep -E '"(tag_name|prerelease)"'
```

**Path 0 — pull the prebuilt image (fastest, no build at all).** Each app
release also gets a prebuilt multi-arch image on ghcr.io (published by this
repo's *Publish Images* workflow). Pull it **by digest** (printed in that
workflow's run summary, or resolved from the tag) and tag it as the local
image the pod deploys:

```bash
podman pull ghcr.io/carlos-emr/carlos-app@sha256:<digest>
podman tag  ghcr.io/carlos-emr/carlos-app@sha256:<digest> localhost/carlos-app:latest
```

Under the full deployment this is `<APP>_ARTIFACT=image` — see the README's
"Prebuilt images" subsection for the trust model and air-gap channel. To
build locally instead:

**Path A — a release publishes a WAR (preferred).** Record its tag, source
commit, and the WAR's sha256 (from the sibling `.war.sha256` asset), then
build with the download stage:

```bash
CARLOS_TAG=2026.08.0-alpha1     # the newest release tag you picked
CARLOS_SHA=$(curl -s "https://api.github.com/repos/carlos-emr/carlos/commits/$CARLOS_TAG" \
  | grep -m1 '"sha"' | cut -d'"' -f4)
WAR_URL="https://github.com/carlos-emr/carlos/releases/download/$CARLOS_TAG/carlos-$CARLOS_TAG.war"
WAR_SHA=$(curl -sL "$WAR_URL.sha256" | cut -d' ' -f1)
test -n "$CARLOS_SHA" && test -n "$WAR_SHA"
printf 'Building CARLOS release %s (commit %s)\n' "$CARLOS_TAG" "$CARLOS_SHA"

podman build --no-cache --ulimit nofile=65536:65536 \
  --build-arg CARLOS_WAR_STAGE=download \
  --build-arg CARLOS_WAR_URL="$WAR_URL" \
  --build-arg CARLOS_WAR_SHA256="$WAR_SHA" \
  --tag localhost/carlos-app:latest \
  --file Containerfile .
```

The WAR is verified against its sha256 inside the build; a mismatch fails the
build.

**Path B — compile from source.** Use this when no release exists (build the
`main` branch HEAD — the stable branch `develop` is promoted into for
release — as shown) or
when you want to compile a release's own source (set `CARLOS_SHA` to the
release's source commit instead). Substitute `develop` for `main` if you
deliberately want the development branch:

```bash
CARLOS_SHA=$(git ls-remote https://github.com/carlos-emr/carlos.git main | cut -f1)
test -n "$CARLOS_SHA"
printf 'Building CARLOS commit %s\n' "$CARLOS_SHA"

podman build --no-cache --ulimit nofile=65536:65536 \
  --build-arg CARLOS_REF="$CARLOS_SHA" \
  --tag localhost/carlos-app:latest \
  --file Containerfile .
```

The first source build downloads the application source, base images, and
Maven dependencies. It can take considerably longer than the WAR path (twenty
minutes is normal). Either way, keep the terminal open until Podman prints the
image ID.

Confirm that the image exists:

```bash
podman image inspect localhost/carlos-app:latest \
  --format 'image={{.Id}} created={{.Created}}'
```

## 3. Create the development configuration

The setup helper creates `$HOME/emr` by default, copies the required
configuration files, generates an application encryption key, and renders the
pod specification. It prompts for a MariaDB root password without placing the
password in shell history or process arguments.

```bash
scripts/dev-setup.sh
```

Use a password created for this disposable instance. Do not include `${` or
`#{`; Spring treats those sequences as expressions rather than literal
password characters.

For a British Columbia test instance, run:

```bash
scripts/dev-setup.sh --province BC
```

For a different instance directory, pass an absolute path and keep the same
value in later commands:

```bash
scripts/dev-setup.sh --emr-home /srv/carlos-dev
export EMR_HOME=/srv/carlos-dev
```

Otherwise, set the default path now:

```bash
export EMR_HOME="$HOME/emr"
```

The helper refuses to overwrite an existing configuration. This protects the
database password and encryption key from an accidental re-render. To start
again, follow [Remove the development instance](#remove-the-development-instance)
instead of using `--force` unless you understand which values will change.

Check the generated files:

```bash
test -s "$EMR_HOME/container/conf/carlos/carlos.properties"
test -s "$EMR_HOME/carlos-app-dev.yaml"
stat -c '%a %n' \
  "$EMR_HOME/container/conf/carlos/carlos.properties" \
  "$EMR_HOME/carlos-app-dev.yaml"
```

Both modes should be `600`.

## 4. Start the pod

```bash
podman kube play "$EMR_HOME/carlos-app-dev.yaml"
podman pod ps
podman ps --pod
```

The pod is named `carlos-app`. On a new instance, MariaDB initializes its data
directory first. The application container then waits for the `oscar` database
that you create in the next step. A `starting` health state is expected at this
point.

Use these commands to follow startup or investigate a stopped container:

```bash
podman logs --tail 100 carlos-app-db
podman logs --tail 100 carlos-app-carlos
podman ps -a --pod
```

Do not rerun `podman kube play` repeatedly while the pod is starting. Load the
database schema first.

## 5. Load the database schema

This step is required once for a new, empty MariaDB data directory. It uses the
migration files from the CARLOS application repository.

Clone that repository beside the deployment repository, or use an existing
checkout:

```bash
cd ..
git clone https://github.com/carlos-emr/carlos.git carlos
cd carlos-podman
```

For reproducible results, check out the same commit used for the image build
(`$CARLOS_SHA` from step 2 — for a WAR-path build that is the release's
source commit; under the full Ansible deployment `carlos-ctl source` prints
the pinned tag and commit):

```bash
cd ../carlos
git checkout "$CARLOS_SHA"
cd ../carlos-podman
```

If you opened a new shell and no longer have `CARLOS_SHA`, use the commit you
printed or recorded in step 2.

Read the development database password into the current shell without echoing
it or saving it in shell history:

```bash
read -rsp 'Development MariaDB root password: ' DB_PW; echo
```

Create the database:

```bash
printf '%s\n' "$DB_PW" | podman exec -i carlos-app-db bash -c \
  'read -r password; export MYSQL_PWD="$password"; mariadb -uroot \
   -e "CREATE DATABASE IF NOT EXISTS oscar DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci"'
```

Apply the migrations in order. The `SET NAMES` line pins the session to the
schema's `utf8mb4_general_ci` collation family — MariaDB 11.4+ images ship
`character_set_collations = utf8mb4=uca1400_ai_ci`, and under that session
default some upstream migrations abort with `ERROR 1267` (illegal mix of
collations) when applied through the mariadb CLI. The following list is for
Ontario:

```bash
MIGRATIONS=../carlos/database/mysql/migration
(
  set -e
  for file in \
    common/V1__baseline_schema.sql \
    on/V1.0.1__on_schema.sql \
    on/V1.0.2__on_data.sql \
    common/V1.0.3__performance_indexes.sql \
    on/V1.0.4__on_performance_indexes.sql \
    common/V1.0.5__restore_live_legacy_common_tables.sql \
    on/V1.0.6__restore_reporting_privilege.sql
  do
    printf 'Applying %s\n' "$file"
    { printf '%s\n' "$DB_PW"
      printf 'SET NAMES utf8mb4 COLLATE utf8mb4_general_ci;\n'
      cat "$MIGRATIONS/$file"; } |
      podman exec -i carlos-app-db bash -c \
        'read -r password; export MYSQL_PWD="$password"; mariadb -uroot oscar'
  done
)
MIGRATION_RC=$?
unset DB_PW
test "$MIGRATION_RC" -eq 0
```

For British Columbia, follow the ordering in
`../carlos/database/mysql/migration/README.md` and substitute the `bc/`
migrations for the `on/` files. Always check that upstream README for migration
files added after this guide.

Restart the application container after the schema load so Tomcat opens the
new database cleanly:

```bash
podman restart carlos-app-carlos
podman logs --follow --tail 100 carlos-app-carlos
```

Press `Ctrl-C` to stop following the log; the container continues running.
Then check its state:

```bash
podman ps --filter name=carlos-app-carlos
```

## 6. Open CARLOS and complete the first login

Open this address on the same machine:

<https://127.0.0.1:8443/carlos/>

The development certificate is self-signed, so the browser will display a
certificate warning. Confirm that the address is exactly `127.0.0.1:8443`
before accepting the warning.

The Ontario development data provides this initial account:

- username: `carlosdoc`
- password: `carlos2026`
- PIN: `2026`

The first login requires a password change. Complete it immediately. Although
the port listens only on loopback, every local account on the machine can reach
loopback services. Use this guide only on a machine whose local users you
trust.

Check the endpoint from the terminal if the browser does not load:

```bash
curl --insecure --silent --output /dev/null \
  --write-out 'HTTP %{http_code}\n' \
  https://127.0.0.1:8443/carlos/
```

An HTTP `200` response confirms that the login page is available. For other
responses, inspect both container logs:

```bash
podman logs --tail 200 carlos-app-carlos
podman logs --tail 200 carlos-app-db
```

The optional Playwright suite in the CARLOS repository requires additional
browser and database-client setup. Follow the environment instructions at the
top of `scripts/login-playwright-checks.js` and the repository's
[development deployment notes](docs/development-notes.md#run-the-optional-playwright-checks).
It is not required to complete this quick start.

## Standard Ontario or British Columbia deployment

The standard path uses Ansible to provision the complete three-pod topology on
a target host. It supports a new ON or BC database and adoption of an existing
OpenO/OSCAR database. Unlike the sample path, it configures the WAF, DrugRef,
monitoring, scheduled backups, systemd units, and secret management.

Because carlos-podman is alpha software, these steps are not a production
certification. Before using patient information, the organization operating the
system must review and test the deployment, including access controls, TLS,
network exposure, backup destinations, restore procedures, alert delivery,
host hardening, and applicable privacy requirements.

### Prepare the control node

Run Ansible from a Debian or Ubuntu workstation or management host. A Python
virtual environment avoids changing distribution-managed Python packages:

```bash
sudo apt update
sudo apt install -y git python3 python3-venv
python3 -m venv .venv
. .venv/bin/activate
python -m pip install ansible-core passlib 'bcrypt<4.1' netaddr
ansible-galaxy collection install ansible.utils
```

Clone the repository and create a working inventory:

```bash
git clone https://github.com/carlos-emr/carlos-podman.git
cd carlos-podman
cp ansible/inventory.example ansible/inventory
```

Edit `ansible/inventory` so the inventory name identifies the CARLOS instance
and `ansible_host` resolves to the target host. The SSH account must be able to
use `sudo`. Inventory and `host_vars` contain site identity and encrypted
secrets; keep them in access-controlled version control or another managed
configuration store.

### Capture the site configuration

Run the setup wizard from the repository root:

```bash
python3 -m carlos_ctl.cli setup
```

When prompted for **Billing province**, choose `ON` for Ontario or `BC` for
British Columbia. The wizard writes
`ansible/host_vars/<instance-name>.yml`. The instance name must match the name
in `ansible/inventory`.

Review every generated value. In particular:

- set the address and DNS name that users will use;
- choose `manual` or `acme` TLS for a publicly trusted certificate, or retain
  `selfsigned` only when the site's review accepts browser trust management;
- configure an alert email or webhook and an off-host heartbeat service;
- configure an off-host restic repository rather than relying on a backup
  stored on the protected host; and
- review all variables and explanations in
  `ansible/roles/carlos_podman/defaults/main.yml`.

The MariaDB root password must be encrypted before the host variables are
stored or committed. If the wizard did not vault it, run:

```bash
ansible-vault encrypt_string --name carlos_db_root_password
```

Paste the resulting `!vault` block over the plaintext
`carlos_db_root_password` value. Store the vault password through the site's
credential-management process; do not commit it beside the encrypted file.

### Provision and build

Preview the Ansible changes, then apply them. Add `--ask-vault-pass` when the
vault password is not supplied by the configured credential store, and use
`--ask-become-pass` when the target account does not have passwordless sudo:

```bash
ansible-playbook -i ansible/inventory ansible/site.yml --check --diff --ask-become-pass
ansible-playbook -i ansible/inventory ansible/site.yml --ask-become-pass
```

The role installs `carlos-ctl` on the target and creates the selected instance.
Log in to the target host before running the remaining commands. The examples
below use the default `$EMR_HOME`:

```bash
sudo EMR_HOME=/usr/local/emr carlos-ctl build
sudo EMR_HOME=/usr/local/emr carlos-ctl play
```

The first `build` resolves the newest CARLOS **and** DrugRef GitHub releases
(preferring each release's published, sha256-verified WAR over a source
compile), prints what it chose, and pins both — later builds stay on those
pins until `carlos-ctl source update`. `carlos-ctl source` shows the pins;
the README's "Choosing the CARLOS and DrugRef versions" section covers
manual pinning (including tracking a development branch deliberately) and
air-gapped hosts.

On a new database, the first `play` is expected to return nonzero after starting
the database because the CARLOS and DrugRef schemas do not exist yet. This
prevents the deployment from being marked ready before schema initialization.

### Initialize a new ON or BC database

Skip this subsection when adopting an existing OpenO/OSCAR database. Follow the
migration adoption instructions in the CARLOS source repository instead, and
test the upgrade against a restorable copy before using the existing data.

For a new database, clone the CARLOS source and check
`database/mysql/migration/README.md` for the current migration order. Create the
`oscar` database through the local container boundary:

```bash
sudo EMR_HOME=/usr/local/emr carlos-ctl db -e \
  'CREATE DATABASE IF NOT EXISTS oscar DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci'
```

Apply `common/` migrations and the selected province's migrations in version
order. For Ontario, use the `on/` files; for British Columbia, use the `bc/`
files. Do not load both province data sets. The migration README in the CARLOS
revision used for the image is authoritative because new migrations may be
added after this document is published.

Use `carlos-ctl db` for each file because the standard deployment does not
publish MariaDB on a TCP port. Prefix each file with a `SET NAMES` that pins
the session to the schema's `utf8mb4_general_ci` collation family (MariaDB
11.4+ images default utf8mb4 sessions to `uca1400_ai_ci` via
`character_set_collations`, which makes some upstream migrations abort with
`ERROR 1267` when applied through the CLI):

```bash
{ printf 'SET NAMES utf8mb4 COLLATE utf8mb4_general_ci;\n'; cat path/to/migration.sql; } |
  sudo EMR_HOME=/usr/local/emr carlos-ctl db oscar
```

Create and load `drugref2` using the procedure in the project guide's
[DrugRef section](README.md#drugref), including its required InnoDB conversion.

### Complete the standard deployment

After both schemas are ready, run the deployment and validation again:

```bash
sudo EMR_HOME=/usr/local/emr carlos-ctl play
sudo EMR_HOME=/usr/local/emr carlos-ctl check
sudo EMR_HOME=/usr/local/emr carlos-ctl alert-test
sudo EMR_HOME=/usr/local/emr carlos-ctl backup full
sudo EMR_HOME=/usr/local/emr carlos-ctl backup verify
```

Before sealing, escrow the age private key and the complete restic credentials
off-host according to the organization's recovery procedure. Then seal the
runtime secrets:

```bash
sudo EMR_HOME=/usr/local/emr carlos-ctl seal
```

Complete a documented restore exercise, confirm that alerts and the heartbeat
reach their external destinations, replace or trust the TLS certificate as
planned, and review the remaining site-specific settings listed by the setup
wizard. The detailed operational and recovery procedures are in the
[project guide](README.md).

## Stop and restart the development instance

Stop and remove the pod while keeping the database and configuration files:

```bash
podman kube down "$EMR_HOME/carlos-app-dev.yaml"
```

Start it again later:

```bash
podman kube play "$EMR_HOME/carlos-app-dev.yaml"
```

The MariaDB data, documents, and logs remain under `$EMR_HOME`. The database
root-password hash in the pod secret is used only when MariaDB initializes an
empty data directory. Re-rendering the YAML does not change the password of an
existing database.

## Remove the development instance

This permanently deletes the development database and its files:

```bash
podman kube down "$EMR_HOME/carlos-app-dev.yaml" || true
podman secret rm carlos-db-secret 2>/dev/null || true
printf 'Review before deleting: %s\n' "$EMR_HOME"
```

After confirming that `EMR_HOME` points to the disposable development
instance, remove it manually:

```bash
rm -rf -- "$EMR_HOME"
```

## Troubleshooting

### The build reports `Too many open files`

Check `ulimit -Hn`. Start a new login session after raising the account's
open-file limit, then repeat the build command with
`--ulimit nofile=65536:65536`.

### The build reports `setgroups 65534 failed`

The first subordinate UID or GID range is too small. Repeat the checks in
[Check subordinate user and group IDs](#check-subordinate-user-and-group-ids),
correct the host allocation, and run `podman system migrate` as the same user
that runs Podman.

### Podman cannot open `/dev/net/tun`

Confirm that your normal user can read and write `/dev/net/tun`. On a managed
host, ask the administrator to correct the device or udev permissions rather
than applying a temporary permission change after every reboot.

### The login page has an empty logo area

A new development database has no clinic logo configured. The empty area above
the login fields is expected. Open `/carlos/` rather than the legacy
`/carlos/index.jsp` path, which uses a simpler logout-page layout.

### The application remains unavailable after loading the schema

Restart the application container and inspect its log:

```bash
podman restart carlos-app-carlos
podman logs --follow --tail 200 carlos-app-carlos
```

A message about a missing `encryption.util.secret.key` means the generated
`carlos.properties` file is missing or was replaced. Stop the pod and rerun the
setup from a clean `$EMR_HOME`.

### `podman kube play` reports permission denied for a mounted file

Confirm that every command in this guide ran as the same non-root user. Then
inspect path ownership and traversal permissions:

```bash
namei -l "$EMR_HOME/container/conf/carlos/carlos.properties"
```

Do not run `podman kube play` with `sudo`; root has a separate Podman store and
will not see the image built by your normal user.
