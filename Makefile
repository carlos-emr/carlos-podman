# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
# Dev convenience targets. The production install path is the Ansible role
# (no pip on the target host); these targets serve a workstation checkout.
.PHONY: lint type test e2e ansible-checks check db-migrate-int cds-launcher-int

lint:
	ruff check carlos_ctl tests/unit tests/cds-launcher-boundary.py

type:
	mypy carlos_ctl

test:
	pytest tests/unit -q

e2e:
	tests/run-tests.sh

ansible-checks:
	tests/ansible-checks.sh

# check stays hermetic: db-migrate-int needs root, real podman, and network
# (it runs a REAL MariaDB and fetches upstream migrations) — disposable
# hosts/CI only, so it is a separate target, not part of check.
db-migrate-int:
	sudo tests/db-migrate-integration.sh

# Real OCI runtime boundary, synthetic Java probe; no DB/clinical deployment.
cds-launcher-int:
	python3 tests/cds-launcher-boundary.py

check: lint type test e2e ansible-checks
