<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 CARLOS Contributors -->
# Contributing to carlos-podman

Thanks for helping improve the CARLOS EMR deployment tooling. This guide
covers the development workflow; the architecture itself is documented in
the [project guide](README.md).

## Development setup

Everything runs from a workstation checkout — production hosts never see
pip or make:

```bash
git clone https://github.com/carlos-emr/carlos-podman.git && cd carlos-podman
pip install ruff==0.15.8 mypy==1.19.1 pytest PyYAML bcrypt types-PyYAML
```

(The exact pinned toolchain CI uses is in
[`.github/workflows/tests.yml`](.github/workflows/tests.yml) — match it when
a local result disagrees with CI. For the Ansible checks you also need
`ansible-core`, `ansible-lint`, `passlib`, `bcrypt<4.1`, `netaddr`, and the
`ansible.utils` collection.)

## Tests

```bash
make check            # the hermetic battery: ruff + mypy + pytest +
                      # tests/run-tests.sh (e2e, needs sudo) + ansible-checks
make db-migrate-int   # NON-hermetic: real MariaDB via podman — disposable
                      # hosts only; refuses to run beside a live deployment
```

The [Tests section](README.md#tests) of the project guide explains what each
suite covers and what is deliberately left to a live host. Every behavior
change needs coverage in the matching suite; the e2e suite's stubs make even
"this secret never appeared on argv" assertable, so there are few excuses.

## Pull requests

- Branch from `main`; keep PRs focused (one concern per PR).
- Commit messages follow
  [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`,
  `fix:`, `docs:`, `test:`, `chore:` — scopes welcome).
- New files carry the SPDX header
  (`SPDX-License-Identifier: AGPL-3.0-only`) and the project copyright
  line; contributions are accepted under
  [AGPL-3.0-only](LICENSE) (see the
  [license section](README.md#license) for the few derived-file
  exceptions).
- Run `make check` before pushing — CI runs the same battery on
  Python 3.9 (the EL9 production floor) and a current interpreter, so
  3.10+-only syntax fails there even when it works locally.
- CI also validates both Containerfiles with BuildKit `--check` and, on
  every PR, runs the real-MariaDB `db-migrate-integration` job.

## Security issues

Do **not** open public issues for exploitable problems — use the private
reporting flow in [SECURITY.md](SECURITY.md).

## Releases

Maintainers cut releases per
[Releases & versioning](README.md#releases--versioning): bump
`carlos_ctl/__init__.py` and `pyproject.toml` together (a unit test pins
them equal), then dispatch the **Release** workflow.
