# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""carlos-ctl — host runtime CLI for the CARLOS EMR podman deployment.

Provisioning (host prep, instance bootstrap, config rendering, drift) lives in
the Ansible role under ansible/; this package owns everything that runs ON the
host at runtime: image builds, pod lifecycle, secrets sealing/rotation, backup
and PITR, monitoring, and the break-glass database verbs. The split is
deliberate — see README "Design rationale".

This is NOT the carlos-ctl of the single-host Debian deployment. That one —
the `carlos-ctl` package the `carlos-emr` .deb depends on — lives in its own
repository, github.com/carlos-emr/carlos-ctl, with the same command name,
the same import name and the same verb names wherever the two deployments
share a concept (check, db, db-migrate, db-users, db-dump, backup,
cert-renew, rotate, status). This tree drives rootless podman pods; that one
drives systemd services and a host MariaDB. They are separate on purpose (a
premature abstraction over the two would be worse than the duplication), so
this project is named carlos-podman-ctl in pyproject.toml to keep the two
unambiguous; unifying them is a separate, later issue.
"""

__version__ = "2.0.0-beta2"
