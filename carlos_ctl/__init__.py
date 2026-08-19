# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""carlos-ctl — host runtime CLI for the CARLOS EMR podman deployment.

Provisioning (host prep, instance bootstrap, config rendering, drift) lives in
the Ansible role under ansible/; this package owns everything that runs ON the
host at runtime: image builds, pod lifecycle, secrets sealing/rotation, backup
and PITR, monitoring, and the break-glass database verbs. The split is
deliberate — see README "Design rationale".
"""

__version__ = "2.0.0-beta1"
