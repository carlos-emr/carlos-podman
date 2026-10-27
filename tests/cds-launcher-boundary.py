#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Exercise the real image launcher with a Java25 synthetic boundary probe.

Requires Docker. Never connects to a DB or clinical deployment. This proves
launcher identity/mount/attestation boundaries; paired CARLOS engine tests are
separate and remain mandatory for clinical import acceptance.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from carlos_ctl.cdsprotocol import arguments_digest  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def run(argv: list[str], *, input_text: Optional[str] = None) -> subprocess.CompletedProcess:
    result = subprocess.run(argv, input=input_text, text=True, capture_output=True, check=False,
                            timeout=180)
    if result.returncode:
        print(result.stdout, file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        result.check_returncode()
    return result


def main() -> None:
    runtime = re.findall(r"^FROM (docker.io/library/tomcat:[^\s]+)$",
                         (ROOT / "Containerfile").read_text(), re.MULTILINE)
    if len(runtime) != 1 or "jdk25" not in runtime[0] or "@sha256:" not in runtime[0]:
        raise RuntimeError("missing immutable Java25 runtime contract")
    image = "carlos-cds-boundary:" + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="carlos-cds-boundary-") as temporary:
        work = Path(temporary)
        shutil.copy(ROOT / "scripts/carlos-cds-import", work / "launcher")
        shutil.copy(ROOT / "tests/fixtures/cds-launcher/CdsImport.java", work / "CdsImport.java")
        (work / "Dockerfile").write_text(
            "FROM " + runtime[0] + "\n"
            "COPY --chmod=0755 launcher /usr/local/bin/carlos-cds-import\n"
            "COPY CdsImport.java /fixture/CdsImport.java\n"
            "RUN mkdir -p /usr/local/tomcat/webapps/carlos/WEB-INF/classes "
            "&& javac -d /usr/local/tomcat/webapps/carlos/WEB-INF/classes /fixture/CdsImport.java "
            "&& mkdir -p /run/carlos-cds-delegations "
            "&& chown 0:10001 /run/carlos-cds-delegations "
            "&& chmod 0750 /run/carlos-cds-delegations\n"
            "ENTRYPOINT [\"/usr/local/bin/carlos-cds-import\"]\n")
        config, source = work / "config", work / "source"
        config.mkdir()
        source.mkdir()
        config.chmod(0o755)
        source.chmod(0o755)
        # Valid Java Properties syntax deliberately differs from key=value.
        (config / "carlos.properties").write_text("cds.import.cliHeapMiB:384\n")
        (source / "é.xml").write_text("<synthetic/>\n")
        (config / "carlos.properties").chmod(0o644)
        (source / "é.xml").chmod(0o644)
        common = ["docker", "run", "--rm", "--read-only", "--network=none",
                  "--security-opt=no-new-privileges", "--cap-drop=ALL", "--memory=640m",
                  "--mount", "type=bind,src=" + str(config) + ",dst=/run/carlos-config,readonly",
                  "--mount", "type=bind,src=" + str(source)
                  + ",dst=/var/lib/carlos-emr/cds-import/source,readonly",
                  "--tmpfs", "/carlos-tmp:rw,nosuid,nodev,noexec,"
                  "size=8m,mode=0700,uid=10001,gid=10001",
                  "--tmpfs", "/var/lib/carlos-emr/cds-import/state:rw,"
                  "size=1m,mode=0700,uid=10001,gid=10001",
                  "--tmpfs", "/var/lib/CarlosDocument:rw,size=1m,mode=0700,uid=10001,gid=10001",
                  "--tmpfs", "/run/carlos-cds-delegations:rw,nosuid,nodev,noexec,"
                  "size=1m,mode=0750,uid=0,gid=10001",
                  "--env", "JAVA_TOOL_OPTIONS=-Dforbidden.inherited.option=true",
                  "--env", "JDK_JAVA_OPTIONS=-Dforbidden.inherited.option=true",
                  "--env", "CARLOS_CDS_HEAP_MIB=384"]
        try:
            run(["docker", "build", "--quiet", "--tag", image, str(work)])
            caps = json.loads(run([*common, "--user=10001:10001", image, "--capabilities"]).stdout)
            if caps.get("cliHeapMiB") != 384 or caps.get("java") != 25:
                raise RuntimeError("synthetic capability contract failed")
            args = ["--operation", "import", "--provider", "999998", "--input",
                    "/var/lib/carlos-emr/cds-import/source/é.xml"]
            nonce = str(uuid.uuid4())
            issued = int(time.time())
            ticket = json.dumps({"protocol": 1, "operator": "synthetic-operator",
                                 "operatorUid": 999998, "provider": "999998", "operation": "import",
                                 "argvSha256": arguments_digest(args), "nonce": nonce,
                                 "issuedEpochSeconds": issued, "expiresEpochSeconds": issued + 300},
                                separators=(",", ":"))
            actual = run([*common, "--interactive", "--user=0:0", "--cap-add=CHOWN",
                          "--cap-add=SETUID", "--cap-add=SETGID", "--cap-add=SETPCAP",
                          image, nonce, *args], input_text=ticket)
            if json.loads(actual.stdout) != {"syntheticBoundaryVerified": True}:
                raise RuntimeError("synthetic launcher receipt failed")
            try:
                run([*common, "--user=10001:10001", image, nonce, *args], input_text=ticket)
            except subprocess.CalledProcessError as denied:
                if denied.returncode != 3:
                    raise
            else:
                raise RuntimeError("non-root attestation publication was accepted")
            print("CDS launcher boundary: Java25, non-root, zero capabilities, "
                  "immutable attestation, read-only source/config, writable state/docs, "
                  "UTF-8 digest and bounded heap verified")
        finally:
            run(["docker", "image", "rm", "--force", image])


if __name__ == "__main__":
    main()
