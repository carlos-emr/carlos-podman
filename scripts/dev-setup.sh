#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
#
# scripts/dev-setup.sh — automate QUICKSTART.md step 3 (the dev configuration).
#
# Lays out the DEVELOPMENT/TEST instance directory tree, copies the verbatim
# conf files, renders carlos.properties from the role template, and renders
# the dev pod spec with the MariaDB root-password hash — everything between
# "build the image" and "podman kube play". The manual commands it replaces
# remain in QUICKSTART.md as the documented reference; this script exists
# because the sed/hash incantations are the most error-prone part of the
# walk-through (wrong delimiter escaping, forgotten chmod 600, an empty
# encryption key silently rendering a boot-fatal blank line).
#
#   Usage: scripts/dev-setup.sh [--emr-home DIR] [--province ON|BC]
#                               [--server-name NAME] [--force]
#
#   --emr-home DIR      instance home (default: $EMR_HOME, else $HOME/emr)
#   --province ON|BC    billing province rendered into carlos.properties
#                       (default ON; BC also means: load the bc/ migrations
#                       in QUICKSTART step 5)
#   --server-name NAME  server_name rendered into carlos.properties
#                       (default localhost)
#   --force             overwrite an existing rendered carlos.properties /
#                       pod YAML (default: refuse — a re-render replaces the
#                       stored db password and encryption key references)
#
# The MariaDB root password is read from the terminal (never argv, never
# shell history). For unattended runs (CI) set CARLOS_DEV_DB_PASSWORD in the
# environment — acceptable for a throwaway dev password only, never a real
# credential (the production path vaults it via `carlos-ctl setup`).
#
# DEV ONLY: this prepares the QUICKSTART app+db pod with well-known seeded
# credentials — no PHI, single-user workstation, loopback publish only. The
# production path is the Ansible role (ansible/site.yml).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

EMR_HOME="${EMR_HOME:-$HOME/emr}"
PROVINCE=ON
SERVER_NAME=localhost
FORCE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --emr-home)    EMR_HOME="${2:?--emr-home needs a directory}"; shift 2 ;;
        --province)    PROVINCE="${2:?--province needs ON or BC}"; shift 2 ;;
        --server-name) SERVER_NAME="${2:?--server-name needs a name}"; shift 2 ;;
        --force)       FORCE=1; shift ;;
        -h|--help)     sed -n '5,32p' "$0"; exit 0 ;;
        *) echo "ERROR: unknown argument '$1' (see --help)" >&2; exit 1 ;;
    esac
done

case "$PROVINCE" in ON|BC) ;; *)
    echo "ERROR: --province must be ON or BC (got '$PROVINCE')" >&2; exit 1 ;;
esac

TEMPLATE="$ROOT/ansible/roles/carlos_podman/templates/carlos.properties.j2"
DEV_YAML="$ROOT/examples/carlos-app-dev.yaml"
for f in "$TEMPLATE" "$DEV_YAML" "$ROOT/conf/tomcat/server.xml" \
         "$ROOT/conf/tomcat/context.xml" "$ROOT/conf/tomcat/logging.properties" \
         "$ROOT/conf/mariadb/zz-carlos.cnf"; do
    [ -f "$f" ] || { echo "ERROR: $f not found — run from a carlos-podman checkout" >&2; exit 1; }
done
for tool in python3 openssl; do
    command -v "$tool" >/dev/null || { echo "ERROR: $tool not found" >&2; exit 1; }
done

PROPS="$EMR_HOME/container/conf/carlos/carlos.properties"
POD_YAML="$EMR_HOME/carlos-app-dev.yaml"
if [ "$FORCE" != 1 ]; then
    for f in "$PROPS" "$POD_YAML"; do
        if [ -e "$f" ]; then
            echo "ERROR: $f already exists — this instance looks set up." >&2
            echo "       Re-rendering replaces the stored db password/encryption key;" >&2
            echo "       pass --force only if that is what you want." >&2
            exit 1
        fi
    done
fi

# --- password (off-argv: terminal read or environment, never a $1) -----------------
if [ -n "${CARLOS_DEV_DB_PASSWORD:-}" ]; then
    DB_PW="$CARLOS_DEV_DB_PASSWORD"
else
    if [ ! -t 0 ]; then
        echo "ERROR: no terminal to prompt on and CARLOS_DEV_DB_PASSWORD is unset" >&2
        exit 1
    fi
    read -rsp "Choose a MariaDB root password (dev instance only): " DB_PW; echo >&2
    read -rsp "Repeat it: " DB_PW2; echo >&2
    [ "$DB_PW" = "$DB_PW2" ] || { echo "ERROR: passwords do not match" >&2; exit 1; }
fi
[ -n "$DB_PW" ] || { echo "ERROR: empty password" >&2; exit 1; }
# carlos.properties is line-oriented, so a newline in the password would split
# the db_password line — that is the one hard limit. The '@' and '\' the old
# sed render choked on are fine now: the render below is done in-process by
# python3 (values passed by ENV, never argv), and the db password is
# properties-escaped, exactly as the Ansible template's replace() filter does.
case "$DB_PW" in
    *$'\n'*) echo "ERROR: the password must not contain a newline" >&2; exit 1 ;;
esac
# Spring interpolates db_password after reading carlos.properties
# (spring_jpa.xml: value="${db_password}"). It evaluates '#{' as SpEL and '${'
# as a nested placeholder, which changes the credential and may expose part of
# it in application logs. These sequences cannot be escaped safely in this
# property, so reject them consistently with
# carlos_ctl.secrets.validate_db_password.
case "$DB_PW" in
    *'${'*|*'#{'*)
        echo "ERROR: the password must not contain '\${' or '#{' — Spring would evaluate" >&2
        echo "       it as a placeholder/SpEL expression instead of using it literally" >&2
        echo "       (boot-fatal for the CARLOS webapp). Choose another password." >&2
        exit 1 ;;
esac
# --- 1. directory layout (QUICKSTART step 3) ---------------------------------------
mkdir -p "$EMR_HOME/container/conf/tomcat" \
         "$EMR_HOME/container/conf/carlos" \
         "$EMR_HOME/container/conf/mariadb" \
         "$EMR_HOME/container/guard" \
         "$EMR_HOME/data/mariadb-mnt" \
         "$EMR_HOME/data/mariadb-binlog" \
         "$EMR_HOME/data/OscarDocument/oscar/document" \
         "$EMR_HOME/logs/carlos" \
         "$EMR_HOME/backup/mariadb-hot" \
         "$EMR_HOME/run/db-socket" \
         "$EMR_HOME/run/app-secrets"
echo "==> Instance directories created under $EMR_HOME"

cp "$ROOT/conf/tomcat/server.xml" "$ROOT/conf/tomcat/context.xml" \
   "$ROOT/conf/tomcat/logging.properties" "$EMR_HOME/container/conf/tomcat/"
cp "$ROOT/conf/mariadb/zz-carlos.cnf" "$EMR_HOME/container/conf/mariadb/"
echo "==> Verbatim tomcat/mariadb confs copied"

# --- 2+3. render carlos.properties AND the dev pod spec, secrets OFF ARGV ----------
# REQUIRED: current CARLOS develop refuses first boot without a pre-provisioned
# encryption key (the config mount is read-only, so its generate-and-persist
# fallback cannot run).
ENC_KEY="$(openssl rand -base64 32)"

umask 077   # both rendered files carry the db password + key from first write
# ONE python3 pass does both renders in-process. The db password and encryption
# key travel by ENVIRONMENT (private to the process), never on argv where `ps`
# would expose them; paths/province/server-name are not secrets and ride argv.
# The substitution matches each `{{ ... carlos_<name> ... }}` token by variable
# NAME and swaps the value in (robust against the backslash-filter syntax the
# old sed had to escape). The db password is properties-escaped for the
# line/key=value store, and hashed RAW for the mysql_native_password secret.
CARLOS_DEV_DB_PW="$DB_PW" CARLOS_DEV_ENC_KEY="$ENC_KEY" python3 - \
    "$TEMPLATE" "$PROPS" "$DEV_YAML" "$POD_YAML" "$PROVINCE" "$SERVER_NAME" "$EMR_HOME" <<'PY'
import base64, hashlib, os, re, sys

template, props, dev_yaml, pod_yaml, province, server_name, emr_home = sys.argv[1:8]
db_pw = os.environ["CARLOS_DEV_DB_PW"]
enc_key = os.environ["CARLOS_DEV_ENC_KEY"]

# Java Properties: a backslash is an escape, so double it (the Ansible template
# does the same via replace('\\', '\\\\')). The RAW db_pw is used for the hash.
db_pw_props = db_pw.replace("\\", "\\\\")
values = {
    "jdbc_zero_date": "round",
    "db_root_password": db_pw_props,
    "encryption_secret_key": enc_key,
    "rx_allergy_checking": "no",
    "billing_province": province,
    "server_name": server_name,
    "pin_encrypted_effective": "no",
    "tomcat_keystore_password": "changeit",
    "tomcat_truststore_password": "changeit",
    # Dev renders keep A04 generation off, like the role default: the pod has
    # no writable /var/lib/adt and every registration would log an error.
    "hl7_a04_generation": "false",
    "hl7_a04_dir": "/var/lib/adt/",
    # Browser eForm->PDF renderer: off like the role default — the image
    # carries no Chromium, so the boot probe could only log an ERROR burst.
    "eform_pdf_browser_startup_check": "off",
    "eform_pdf_browser_chromium_path": "",
    "eform_pdf_browser_chromedriver_path": "",
    "buildtag": "carlos-podman",
}

with open(template, encoding="utf-8") as fh:
    text = fh.read()

# Drop Jinja comment blocks ({# ... #}) and ## heading lines — mirrors the
# documented sed render's `/{#/,/#}/d ; /^##/d`. This runs BEFORE
# substitution: the strip exists for the TEMPLATE's own text, and running it
# after meant a substituted VALUE containing '{#' (a legal password char)
# flipped the in-comment state and silently swallowed the db_password line
# plus everything to the next '#}' (found seventh pass).
kept, in_comment = [], False
for line in text.splitlines(keepends=True):
    if not in_comment and "{#" in line:
        in_comment = True
    if in_comment:
        if "#}" in line:
            in_comment = False
        continue
    if line.startswith("##"):
        continue
    kept.append(line)
stripped = "".join(kept)

# Render-safety BEFORE substitution (so no VALUE content can confuse it,
# and line numbers never expose the file content): every remaining Jinja
# token must be a {{ ... carlos_<name> ... }} this script knows how to fill.
problems = []
for i, ln in enumerate(stripped.splitlines()):
    for tok in re.findall(r"\{\{[^{}]*\}\}", ln):
        m = re.search(r"\bcarlos_(\w+)\b", tok)
        if not m or m.group(1) not in values:
            problems.append(str(i + 1))
    if "{%" in ln or re.search(r"\{\{(?![^{}]*\bcarlos_\w+)", ln):
        problems.append(str(i + 1))
if problems:
    sys.exit("ERROR: unrenderable Jinja remains at line(s) "
             + ",".join(sorted(set(problems))[:5]) + " — template drifted from this script")

def _sub(m):
    return values[m.group(1)]  # every token was validated above

# [^{}] keeps a match inside one {{ ... }}; \bcarlos_(\w+)\b picks the variable.
rendered = re.sub(r"\{\{[^{}]*?\bcarlos_(\w+)\b[^{}]*?\}\}", _sub, stripped)

if not re.search(r"(?m)^encryption\.util\.secret\.key=.+", rendered):
    sys.exit("ERROR: encryption.util.secret.key rendered BLANK — boot-fatal")

with os.fdopen(os.open(props, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as fh:
    fh.write(rendered)

# Pod spec: mysql_native_password hash (double SHA1 of the RAW password) -> b64.
h = "*" + hashlib.sha1(hashlib.sha1(db_pw.encode()).digest()).hexdigest().upper()
hash_b64 = base64.b64encode(h.encode()).decode()
with open(dev_yaml, encoding="utf-8") as fh:
    spec = fh.read()
spec = spec.replace("__EMR_HOME__", emr_home).replace("__DB_ROOT_HASH_B64__", hash_b64)
if "__EMR_HOME__" in spec or "__DB_ROOT_HASH_B64__" in spec:
    sys.exit("ERROR: unrendered placeholder remains in the pod spec")
with os.fdopen(os.open(pod_yaml, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as fh:
    fh.write(spec)
PY
echo "==> carlos.properties rendered (province $PROVINCE, mode 600)"
echo "==> Dev pod spec rendered to $POD_YAML (mode 600)"

cat <<EOF

Setup complete. Next (QUICKSTART.md steps 2 and 4-6):

  1. build the image (if not done) — QUICKSTART step 2 has both paths.
     Preferred: a published release WAR (fast, sha256-verified):
       CARLOS_TAG='<newest tag from api.github.com/repos/carlos-emr/carlos/releases>'
       WAR_URL=https://github.com/carlos-emr/carlos/releases/download/\$CARLOS_TAG/carlos-\$CARLOS_TAG.war
       WAR_SHA=\$(curl -sL "\$WAR_URL.sha256" | cut -d' ' -f1)
       podman build --no-cache --ulimit nofile=65536:65536 \\
         --build-arg CARLOS_WAR_STAGE=download \\
         --build-arg CARLOS_WAR_URL=\$WAR_URL --build-arg CARLOS_WAR_SHA256=\$WAR_SHA \\
         -t localhost/carlos-app:latest -f Containerfile .
     No release / compiling from source instead (main = the stable branch;
     use develop deliberately for the development branch):
       CARLOS_SHA=\$(git ls-remote https://github.com/carlos-emr/carlos main | cut -f1)
       podman build --no-cache --ulimit nofile=65536:65536 \\
         --build-arg CARLOS_REF=\$CARLOS_SHA \\
         -t localhost/carlos-app:latest -f Containerfile .
  2. deploy:      podman kube play $POD_YAML
  3. load the Flyway schema (fresh install, once) — QUICKSTART step 5
     ($([ "$PROVINCE" = BC ] && echo "you rendered BC — use the bc/ migrations" || echo "ON migrations as shown"))
  4. log in at https://127.0.0.1:8443/ and complete the forced password
     reset for the seeded dev account IMMEDIATELY (see QUICKSTART step 6)
  5. (optional) for the app repo's Playwright suite, give the host mysql
     client a path to the pod's DB socket (needs root; refuses to replace
     an existing socket path — if a host MariaDB owns it, use 'podman exec'
     instead):
       sudo mkdir -p /var/run/mysqld
       if [ -e /var/run/mysqld/mysqld.sock ] || [ -L /var/run/mysqld/mysqld.sock ]; then
         echo 'Refusing to replace the existing MariaDB socket path' >&2
       else
         sudo ln -s -- "$EMR_HOME/run/db-socket/mysqld.sock" /var/run/mysqld/mysqld.sock
       fi
     then run it with MYSQL_HOST=localhost (see QUICKSTART step 6's
     Playwright notes)
EOF
