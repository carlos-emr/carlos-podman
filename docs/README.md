<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 CARLOS Contributors -->
# Documentation

The project documentation is organized by audience:

- [Project guide](../README.md): architecture, provisioning, configuration,
  security controls, operations, backup and recovery, and maintenance.
- [Quick start](../QUICKSTART.md): choose between the sample-data pod and the
  standard Ontario or British Columbia Ansible deployment.
- [Development deployment notes](development-notes.md): optional rootless
  Podman integration, browser regression testing, and configuration details.
- [`carlos_podman` role defaults](../ansible/roles/carlos_podman/defaults/main.yml):
  the authoritative Ansible variable reference, including defaults and
  operational implications.
- [Example inventory](../ansible/inventory.example) and
  [example application manifest](../examples/carlos-app-dev.yaml): starting
  points that must be adapted before use.

The project is alpha software. A site considering production use must complete
its own technical, security, privacy, backup, restore, and regulatory review.
Operational procedures in the project guide assume a dedicated service account
and rootless Podman.

Unless a file states another compatible license, the repository is licensed
under the [GNU Affero General Public License v3.0](../LICENSE), SPDX identifier
`AGPL-3.0-only`. See the project guide's [license section](../README.md#license)
for the derived-file exceptions.
