#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Local HTTPS mock of the two GitHub API endpoint families carlos-ctl's
source resolver uses (/releases and /commits/<ref>), serving a FROZEN
snapshot of real release data for carlos-emr/carlos and
carlos-emr/drugref2026 (as returned by the live API on 2026-08-18/19).

Run by scripts/validation/run-validation.sh, which binds api.github.com to
127.0.0.1 via /etc/hosts and installs a throwaway CA so the CLI's real curl
+ TLS path is exercised end to end. Asset browser_download_urls are the REAL
github.com URLs, so WAR downloads still travel the real network.

The snapshot is intentionally frozen: the harness's assertions
(tags/commits/sha256 values in ctl-validation.sh) pin the SAME constants, so
the suite stays deterministic even after the live repos move on.

Serving mode is read per request from the file named by MOCK_MODE_FILE
(default: ./mode next to this script), so tests can toggle it live:
  full            (default) snapshot data for both repos
  norelease       carlos answers []; drugref keeps its snapshot
  ratelimit-half  carlos /releases OK, carlos /commits 403s
                  (drives the mid-pair resolution failure path)

Certificate/key paths come from MOCK_CERT / MOCK_KEY (default: api.crt /
api.key next to this script). Listens on 127.0.0.1:443 (needs root).
"""
import http.server
import json
import os
import ssl
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODE_FILE = Path(os.environ.get("MOCK_MODE_FILE", HERE / "mode"))
CERT = Path(os.environ.get("MOCK_CERT", HERE / "api.crt"))
KEY = Path(os.environ.get("MOCK_KEY", HERE / "api.key"))

# Frozen live-repo facts. If you refresh these, refresh the matching
# constants at the top of ctl-validation.sh in the same commit.
CARLOS_SHA = "74b4c0c67881ebc9879357dc68299a056d64efa9"
DRUGREF_SHA = "101063bbd13d3c767cc3c3daf5f64ac673d8d327"

CARLOS_RELEASES = [{
    "tag_name": "2026.08.0-alpha1",
    "name": "CARLOS EMR 2026.08.0-alpha1",
    "prerelease": True,
    "draft": False,
    "published_at": "2026-08-18T19:22:53Z",
    "assets": [
        {
            "name": "carlos-2026.08.0-alpha1.war",
            "browser_download_url": "https://github.com/carlos-emr/carlos/releases/download/2026.08.0-alpha1/carlos-2026.08.0-alpha1.war",
            "digest": "sha256:3815d94e081d5587dc218443956c5d121b21c9fd40b47b8ccae080af69fb4129",
            "size": 322820102,
        },
        {
            "name": "carlos-2026.08.0-alpha1.war.sha256",
            "browser_download_url": "https://github.com/carlos-emr/carlos/releases/download/2026.08.0-alpha1/carlos-2026.08.0-alpha1.war.sha256",
            "size": 94,
        },
    ],
}]

DRUGREF_RELEASES = [{
    "tag_name": "v1.0.0rc2",
    "name": "v1.0.0-rc2",
    "prerelease": False,
    "draft": False,
    "published_at": "2026-03-21T22:27:21Z",
    "assets": [{
        "name": "drugref2.war",
        "browser_download_url": "https://github.com/carlos-emr/drugref2026/releases/download/v1.0.0rc2/drugref2.war",
        "digest": "sha256:5b367e65f5c0c0262ea36a4662d9040818754bea307ffb70a0c81931a0aaf6fc",
        "size": 34258525,
    }],
}]


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("MOCK %s\n" % (fmt % args))

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        mode = MODE_FILE.read_text().strip() if MODE_FILE.is_file() else "full"
        p = self.path
        if p.startswith("/repos/carlos-emr/carlos/releases"):
            if mode == "norelease":
                return self._json([])
            return self._json(CARLOS_RELEASES)
        if p.startswith("/repos/carlos-emr/carlos/commits/"):
            if mode == "ratelimit-half":
                return self._json({"message": "API rate limit exceeded"}, 403)
            return self._json({"sha": CARLOS_SHA})
        if p.startswith("/repos/carlos-emr/drugref2026/releases"):
            return self._json(DRUGREF_RELEASES)
        if p.startswith("/repos/carlos-emr/drugref2026/commits/"):
            return self._json({"sha": DRUGREF_SHA})
        return self._json({"message": "Not Found"}, 404)


def main():
    httpd = http.server.HTTPServer(("127.0.0.1", 443), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print("mock api.github.com listening on 127.0.0.1:443", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
