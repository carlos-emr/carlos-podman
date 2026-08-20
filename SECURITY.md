<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 CARLOS Contributors -->
# Security policy

carlos-podman is deployment tooling for CARLOS EMR — a system that, once
deployed, handles patient health information. Security findings in this
repository (the CLI, the Ansible role, the pod specs, the WAF/firewall
posture, the backup and secrets machinery) are taken seriously even while
the project is pre-production.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** through GitHub's
security advisories:

1. Go to the repository's **Security** tab →
   [**Report a vulnerability**](https://github.com/carlos-emr/carlos-podman/security/advisories/new).
2. Describe the issue, the affected file(s)/component, and — where possible —
   reproduction steps or a proof of concept.

Please do **not** open a public issue for something exploitable: public
issues are indexed immediately, and deployed sites may hold real patient
data.

This is a volunteer-maintained pre-production project: reports are handled
on a best-effort basis, and there is no formal SLA. You will get an
acknowledgement in the advisory thread, and a fix or a documented accepted
risk (the project guide keeps a
[compliance risk register](README.md#compliance-risk-register-accepted-risks-at-a-glance))
before the advisory is closed.

## Scope notes

- This repository contains **no patient data** and no production
  credentials; findings about a specific deployed site should go to that
  site's operator, not this tracker.
- Hardening suggestions that are not exploitable vulnerabilities (defense
  in depth, configuration tightening) are welcome as ordinary issues or
  pull requests.
- Vulnerabilities in the CARLOS EMR application itself belong to
  [carlos-emr/carlos](https://github.com/carlos-emr/carlos); this repo's
  scope is the deployment layer.
