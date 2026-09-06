#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Build a CARLOS-source-shaped tarball carrying a MINIMAL OSCAR 19 engine.

The hermetic e2e suite (tests/run-tests.sh) cannot download the real CARLOS
tree, but the fetch -> verify -> load path is the part of the podman port most
likely to break silently: it takes a tarball off the network, unpacks a scoped
member set, checks the engine's imports against podman's shims, and imports
twelve modules under a synthetic package. Serving a real tarball with the real
layout exercises every step of that with the real `tar` and the real loader.

What is inside is deliberately small: the modules the loader requires, the
`_sql_literal` the shims are built from, a `Host` for the podman behaviour to
compose onto, and entrypoints that report which host they ran under. It is a
STRUCTURAL stand-in, not a second implementation of the importer.

    tests/o19_fake_engine.py <out.tar.gz> <commit-sha>
"""

import io
import os
import sys
import tarfile

REQUIRED = (
    "o19_preflight", "o19bundle", "o19digest", "o19docs", "o19etl",
    "o19host", "o19import", "o19map_props", "o19map_schema", "o19props",
    "o19report", "o19roles",
)

PREFLIGHT = '''\
def _sql_literal(value):
    return (value.replace("\\\\", "\\\\\\\\").replace("'", "\\\\'")
            .replace("\\0", "\\\\0").replace("\\r", "\\\\r"))
'''

HOST = '''\
from . import dbops
from .util import STATE, log, run, warn

STAGING_USER = "o19_import"
STATE_DIR = STATE + "/o19-import"


class Host(object):
    label = "the carlos-emr deb package"

    @property
    def state_dir(self):
        return STATE_DIR

    @property
    def documents_root(self):
        return STATE + "/OscarDocument"

    def is_packaged_host(self):
        return False

    def configured_province(self):
        return "on"

    def configured_db_name(self):
        return None

    def identity_source(self):
        return "deb"

    def client_base_argv(self, mariadb_args):
        return ["mariadb", "--protocol=socket", "--user=root"]

    def client_env(self):
        return {}

    def stage_credential(self, password, client_cnf):
        return {}

    def clear_stage_credential(self, client_cnf):
        return None

    def staging_client_argv(self, base, cnf, timeout=0):
        return ["mariadb"]

    def document_ownership(self):
        return ("carlos", "2750", "0640")

    def sql_escape(self, value):
        return dbops.sql_escape(value)

    def flyway_validate(self):
        return 0

    def backup_configured(self):
        return False

    def backup_configuration_hint(self):
        return "deb"

    def pre_import_backup(self):
        log("backup")
        run(["true"])
        return (True, "")

    def app_running_refusal(self):
        warn("no gate in the fake engine")
        return None
'''

IMPORT = '''\
from . import o19host
from .util import log

HOST = o19host.Host()
STAGING_SCHEMA = "o19_import"


def staging_init_command(statement_timeout=0):
    return "SET SESSION sql_log_bin=0"


def strip_client_identity(args):
    return [a for a in args if not a.startswith(("-u", "-p"))]


def _report(verb, argv):
    log("fake-engine {0} argv={1}".format(verb, " ".join(argv)))
    log("fake-engine workspace={0}".format(HOST.state_dir))
    log("fake-engine documents={0}".format(HOST.documents_root))
    log("fake-engine province={0}".format(HOST.configured_province()))
    log("fake-engine client={0}".format(
        " ".join(HOST.client_base_argv(None))))


def cmd_import_o19(argv):
    _report("import", list(argv))
    return 0


def cmd_o19_preflight(argv):
    _report("preflight", list(argv))
    return 2
'''

BODIES = {
    "o19_preflight": PREFLIGHT,
    "o19host": HOST,
    "o19import": IMPORT,
}


def main():
    if len(sys.argv) != 3:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    out, commit = sys.argv[1], sys.argv[2]
    prefix = "carlos-{0}/debian/assets/carlos_ctl".format(commit)
    with tarfile.open(out, "w:gz") as tar:
        # A file OUTSIDE the engine directory: the extract is member-scoped,
        # so this must not land on disk. Its absence after a fetch is what
        # proves the scoping, with a real tar.
        payload = b"this file is not part of the engine\n"
        info = tarfile.TarInfo("carlos-{0}/README.md".format(commit))
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
        # And one INSIDE the engine directory that is not an engine module.
        # This is what the `o19*.py` pattern actually buys: without it this
        # lands beside the modules, inside the package the loader imports
        # from — the sharp edge of an archive fetched over the network.
        info = tarfile.TarInfo("{0}/not_an_engine_module.py".format(prefix))
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
        for name in REQUIRED:
            body = BODIES.get(name, "VALUE = {0!r}\n".format(name)).encode()
            info = tarfile.TarInfo("{0}/{1}.py".format(prefix, name))
            info.size = len(body)
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(body))
    return 0


if __name__ == "__main__":
    sys.exit(main())
