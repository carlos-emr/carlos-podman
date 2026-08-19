<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 CARLOS Contributors -->
# Development deployment notes

This page supplements [the development quick start](../QUICKSTART.md). The
quick start contains the shortest supported path to a local CARLOS instance;
this page covers optional host integration, browser regression testing, and
implementation details that are useful when maintaining the development
workflow.

The development pod is not a reduced production deployment. It omits the WAF,
DrugRef, observability containers, backup timers, secret sealing, and resource
limits. Use the Ansible procedure in the [project guide](../README.md#quick-start)
when evaluating those components.

## What the setup helper renders

`scripts/dev-setup.sh` performs the configuration work between the image build
and `podman kube play`. It:

1. creates the instance directory tree under `$EMR_HOME`;
2. copies the Tomcat and MariaDB configuration files;
3. generates the application encryption key;
4. renders `carlos.properties` with mode `0600`;
5. derives the `mysql_native_password` hash used to initialize MariaDB; and
6. renders `$EMR_HOME/carlos-app-dev.yaml` with mode `0600`.

The database password and encryption key are not placed in command arguments.
The helper also checks for unrendered Jinja expressions and refuses to replace
an existing configuration unless `--force` is supplied.

Do not use `--force` as a routine update command. It replaces values in
`carlos.properties`, including the application encryption key. For a disposable
development instance, removing `$EMR_HOME` and following the quick start again
is safer than changing those values in place.

## Rootless Podman and login sessions

Rootless Podman keeps its image and container storage under the invoking user.
An image built by one account is not available to another account, including
root. Run the build, setup helper, `podman kube play`, and later Podman commands
as the same non-root user. The same applies to prebuilt-image pulls
(`<APP>_ARTIFACT=image`): the pulled layers land in the pulling user's store,
which is why same-service-user sibling instances must agree on
`carlos_image_repo`/`carlos_drugref_image_repo` (the provisioning assert
enforces it) just as they must on the image tags.

A rootless service managed by the user's systemd manager may need that manager
to remain available after logout. Enable lingering for the account when testing
such a service:

```bash
sudo loginctl enable-linger "$(id -un)"
```

Lingering alone does not make the development pod start at boot; the pod would
also need a systemd unit. The production Ansible role installs and manages those
units and should be used for a managed deployment.

## Resource limits and cgroup delegation

The development manifest intentionally omits CPU and memory limits. Rootless
resource controls require cgroup v2 and delegation from the system user
manager. Check the cgroup version with:

```bash
podman info --format '{{.Host.CgroupsVersion}}'
```

On a workstation where resource limits are needed, configure systemd delegation
according to the operating system's documentation, log out, and log back in
before testing limits. Do not assume a limit in a local manifest is enforced;
confirm it with `podman inspect` and a workload test.

## Run the optional Playwright checks

The CARLOS source repository contains
`scripts/login-playwright-checks.js`. Read that file's header for the current
list of environment variables and seeded-account values. Set the application
URL to the development endpoint:

```bash
export BASE_URL=https://127.0.0.1:8443/carlos
```

The browser checks also make database queries. MariaDB does not publish a TCP
port in the development manifest. A host MariaDB client can reach the socket at
`$EMR_HOME/run/db-socket/mysqld.sock`.

Install the command-line client if it is not already present:

```bash
sudo apt install mariadb-client
```

If no host MariaDB service owns `/var/run/mysqld/mysqld.sock`, expose the pod
socket at the client's conventional location:

```bash
sudo mkdir -p /var/run/mysqld
if [ -e /var/run/mysqld/mysqld.sock ] || [ -L /var/run/mysqld/mysqld.sock ]; then
  echo 'Refusing to replace the existing MariaDB socket path' >&2
else
  sudo ln -s \
    "$EMR_HOME/run/db-socket/mysqld.sock" \
    /var/run/mysqld/mysqld.sock
fi
export MYSQL_HOST=localhost
```

If a host MariaDB service already uses that path, do not replace its socket.
Run database checks through `podman exec`, or adapt the test harness to use the
socket under `$EMR_HOME`.

### Password escaping in the test harness

The Playwright helper writes `MYSQL_PASSWORD` to a MariaDB option file. In that
format, a backslash introduces an escape sequence. If the development password
contains a literal backslash, double each backslash in `MYSQL_PASSWORD` before
running the suite. This requirement applies to the test harness input, not to
`scripts/dev-setup.sh`, which handles Java-properties escaping itself.

The same distinction matters in hand-written SQL: string literals process
backslash escapes. Prefer an interactive password prompt or
`carlos_ctl.util.sql_escape` rather than interpolating an unescaped password
into an SQL command.

Passwords containing `${` or `#{` are unsupported because Spring interprets
those sequences after reading `carlos.properties`. The setup helper rejects
them before rendering the file.

## Client-address limitations

The development pod publishes Tomcat directly and does not include the WAF.
Rootless port forwarding can replace the original source address before the
request reaches Tomcat. Forwarded-address headers are therefore not a reliable
record of the client in this topology. Do not use development access logs for
security attribution or expose this endpoint beyond the local workstation.

## Inspect the pod without changing it

These commands are safe starting points when the application does not become
ready:

```bash
podman pod ps
podman ps -a --pod
podman logs --tail 200 carlos-app-db
podman logs --tail 200 carlos-app-carlos
podman inspect carlos-app-carlos --format '{{json .State.Health}}'
```

A new instance waits for the `oscar` schema before starting Tomcat. Load the
schema as described in the quick start before treating a `starting` health
state as a fault.

## Configuration ownership

The following paths persist after `podman kube down`:

- `$EMR_HOME/container/conf`: rendered application and database configuration;
- `$EMR_HOME/data/mariadb-mnt`: the MariaDB data directory;
- `$EMR_HOME/data/mariadb-binlog`: binary logs;
- `$EMR_HOME/data/OscarDocument`: uploaded development documents; and
- `$EMR_HOME/logs`: application logs.

`podman kube down` removes the pod but does not remove these host directories.
The MariaDB root-password hash in the Podman secret is initialization material:
it is used when the data directory is empty and does not rotate the password in
an existing database.
