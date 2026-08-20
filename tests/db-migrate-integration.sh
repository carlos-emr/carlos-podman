#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
# Integration test for `carlos-ctl db-migrate` (issue #17) against a REAL
# MariaDB 11.4+ server. The hermetic e2e suite pins the CLI's argv/stdin
# contract; this proves the collation semantics on the actual server:
#
#   1. REPRO: a plain `carlos-ctl db` session hits V1.0.7's ERROR 1267
#      (illegal mix of collations) when the server's utf8mb4 session
#      collation is not in the general_ci family — MariaDB 11.4+ images
#      ship character_set_collations = utf8mb4=uca1400_ai_ci — leaving the
#      database in the exact partially-migrated state the issue describes
#      (DDL applied, backfills aborted).
#   2. RECOVERY: `carlos-ctl db-migrate V1.0.7 V1.0.13` reruns each file in
#      its own collation-pinned client session (the pin rides --init-command
#      in the SAME session that consumes that file's SQL), and the PHCP
#      diagnosis-group rows come out populated.
#   3. RERUNNABILITY: a second db-migrate pass is a no-op (the migrations'
#      existence guards), so retrying after a transient failure is safe.
#
# Requires: root (the CLI's runuser service-user boundary), real podman,
# and network (db image pull + migration download). Migration files come
# from a local carlos checkout when CARLOS_MIGRATIONS_DIR is set, or from
# raw.githubusercontent.com at CARLOS_MIGRATIONS_REF when set; by default
# the ref is resolved through the DOCUMENTED release-picking rule — the
# newest published CARLOS release, prereleases only as a fallback — the
# same rule carlos-ctl's `source` resolution and the Publish Images
# workflow apply. The resolved tag is immutable (published tags are never
# moved and their Flyway files never edited, per the app repo's release
# policy) and is printed for attribution. There is deliberately NO branch
# default; to test a branch head, pass CARLOS_MIGRATIONS_REF=main (the
# release-train branch) explicitly.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[ "$(id -u)" = 0 ] || { echo "must run as root (sudo)"; exit 1; }
command -v podman >/dev/null || { echo "podman not installed"; exit 1; }

# The SAME pinned db image the deployment uses — one source of truth.
DB_IMAGE=$(grep -E '^carlos_db_image:' "$ROOT/ansible/roles/carlos_podman/defaults/main.yml" \
    | sed -E 's/^carlos_db_image:[[:space:]]*"(.*)"$/\1/')
[ -n "$DB_IMAGE" ] || { echo "could not read carlos_db_image from the role defaults"; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/carlos-dbmigrate-int.XXXXXX")"
IHOME="$WORK/home"
CTR="carlos-app-db"
# NEVER touch a pre-existing container by this name: it is the DEPLOYMENT
# db container name, and this root-required script force-removes $CTR on
# cleanup — running it on a live CARLOS host must refuse, not kill the db.
if podman container exists "$CTR" 2>/dev/null; then
    echo "refusing to run: a container named $CTR already exists on this host"
    echo "(this looks like a live deployment — this test only runs on disposable hosts/CI)"
    exit 1
fi
CTR_CREATED=0
cleanup() {
    [ "$CTR_CREATED" = 1 ] && podman rm -f "$CTR" >/dev/null 2>&1
    rm -rf "$WORK"
}
trap cleanup EXIT

PASS=0 FAIL=0
ok()  { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }

DB_PW="int-test-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"

# Minimal instance home: only what the db verbs read. SERVICE_USER=root so
# the CLI's runuser boundary resolves without provisioning a service user.
mkdir -p "$IHOME/container" /run/user/0
cat > "$IHOME/container/carlos-app.env" <<EOF
EMR_HOME=$IHOME
INSTANCE=carlos
SERVICE_USER=root
CARLOS_DB_ROOT_PASSWORD=$DB_PW
EOF
chmod 0600 "$IHOME/container/carlos-app.env"

ctl() { EMR_HOME="$IHOME" PYTHONPATH="$ROOT" python3 -m carlos_ctl.cli "$@"; }

echo "== starting $DB_IMAGE as $CTR"
podman run -d --name "$CTR" -e MYSQL_ROOT_PASSWORD="$DB_PW" "$DB_IMAGE" >/dev/null
CTR_CREATED=1

echo "== waiting for the server to accept root connections"
for _ in $(seq 1 90); do
    if podman exec -e MYSQL_PWD="$DB_PW" "$CTR" mariadb -uroot -e 'SELECT 1' >/dev/null 2>&1; then
        break
    fi
    sleep 2
done
podman exec -e MYSQL_PWD="$DB_PW" "$CTR" mariadb -uroot -e 'SELECT 1' >/dev/null \
    || { echo "MariaDB never became ready"; exit 1; }

# Schema fixture: the oscar database in the deployment's collation, the
# diagnosticcode source table V1.0.7 backfills from, and a pre-existing
# legacy dxphcpgroup mapping so the legacy-expansion join (the statement
# that raises 1267) has real rows to work on. V1.0.7's DDL is
# IF-NOT-EXISTS, so pre-creating the table matches an adopted-legacy DB.
ctl db -e "CREATE DATABASE IF NOT EXISTS oscar DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci"
ctl db oscar <<'SQL'
CREATE TABLE diagnosticcode (
  diagnostic_code varchar(10) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
INSERT INTO diagnosticcode VALUES ('320'),('0320'),('4659'),('V700');
CREATE TABLE dxphcpgroup (
  dxcode varchar(5) NOT NULL,
  level1 varchar(100) NOT NULL,
  level2 varchar(100) NOT NULL,
  PRIMARY KEY (dxcode)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
INSERT INTO dxphcpgroup VALUES ('320','01 Legacy chapter','Legacy group');
SQL
ok "oscar schema fixture created (diagnosticcode + legacy dxphcpgroup row)"

echo "== fetching the migrations under test"
MIG="$WORK/migrations"; mkdir -p "$MIG"
V7=V1.0.7__restore_phcp_diagnosis_groups.sql
V13=V1.0.13__fix_phcp_diagnosis_group_backfill_collation.sql
if [ -n "${CARLOS_MIGRATIONS_DIR:-}" ]; then
    cp "$CARLOS_MIGRATIONS_DIR/common/$V7" "$CARLOS_MIGRATIONS_DIR/common/$V13" "$MIG/"
    ok "migrations copied from $CARLOS_MIGRATIONS_DIR"
else
    REF="${CARLOS_MIGRATIONS_REF:-}"
    if [ -z "$REF" ]; then
        # The documented release-picking rule: newest published release,
        # prereleases only as a fallback (same rule as carlos-ctl `source`
        # and the Publish Images workflow). The resolved tag is immutable.
        # GH_TOKEN (when present, e.g. github.token in CI) avoids the
        # anonymous API rate limit shared across runner IPs.
        auth=()
        [ -n "${GH_TOKEN:-}" ] && auth=(-H "Authorization: Bearer $GH_TOKEN")
        REF=$(curl -fsSL --retry 3 "${auth[@]}" \
            "https://api.github.com/repos/carlos-emr/carlos/releases?per_page=100" \
            | python3 -c '
import json, sys
rels = [r for r in json.load(sys.stdin) if not r.get("draft")]
stable = [r for r in rels if not r.get("prerelease")]
pool = stable or rels
print(pool[0]["tag_name"] if pool else "")' ) || REF=""
        [ -n "$REF" ] || {
            echo "could not resolve a CARLOS release (API unreachable or no releases)."
            echo "Set CARLOS_MIGRATIONS_REF to a release tag (or 'main' for the"
            echo "release-train branch head), or CARLOS_MIGRATIONS_DIR to a local checkout."
            exit 1
        }
        echo "== resolved newest CARLOS release: $REF"
    fi
    BASE="https://raw.githubusercontent.com/carlos-emr/carlos/$REF/database/mysql/migration/common"
    curl -fsSL --retry 3 -o "$MIG/$V7" "$BASE/$V7"
    curl -fsSL --retry 3 -o "$MIG/$V13" "$BASE/$V13"
    ok "migrations fetched at $REF"
fi

# -- 1. REPRO: an unpinned utf8mb4 session fails exactly as the issue says --
# The issue's failure environment is "an utf8mb4 client session": under
# MariaDB 11.4+'s character_set_collations = utf8mb4=uca1400_ai_ci, a bare
# `SET NAMES utf8mb4` / --default-character-set=utf8mb4 (no COLLATE) lands
# on uca1400_ai_ci, and V1.0.7's bare CAST comparison dies with 1267. The
# container image's own client still defaults to utf8mb3, so force the
# utf8mb4 session explicitly to reproduce deterministically.
UTF8MB4_COLL=$(ctl db -N -B --default-character-set=utf8mb4 \
    -e 'SELECT @@collation_connection' 2>/dev/null | tail -1)
echo "== utf8mb4 client session collation: $UTF8MB4_COLL"
if [[ "$UTF8MB4_COLL" == *general_ci* ]]; then
    echo "NOTE: this server maps utf8mb4 sessions to general_ci —"
    echo "      the 1267 repro is not applicable here; testing the pinned path only."
else
    set +e
    REPRO_OUT=$(ctl db --default-character-set=utf8mb4 oscar < "$MIG/$V7" 2>&1)
    REPRO_RC=$?
    set -e
    if [ "$REPRO_RC" -ne 0 ] && grep -q "1267" <<<"$REPRO_OUT"; then
        ok "unpinned utf8mb4 session reproduces ERROR 1267 on $V7 (rc=$REPRO_RC)"
    else
        bad "expected the unpinned utf8mb4 $V7 run to fail with 1267 (rc=$REPRO_RC): $REPRO_OUT"
    fi
fi

# -- 2. RECOVERY: db-migrate reruns V1.0.7 pinned, then continues to V1.0.13
if ctl db-migrate "$MIG/$V7" "$MIG/$V13"; then
    ok "db-migrate applied $V7 + $V13 through the pinned session"
else
    bad "db-migrate failed on the pinned session"
fi

ROWS=$(ctl db -N -B oscar -e 'SELECT COUNT(*) FROM dxphcpgroup' | tail -1)
if [ "${ROWS:-0}" -gt 1 ]; then
    ok "PHCP diagnosis-group rows are populated (dxphcpgroup: $ROWS rows)"
else
    bad "dxphcpgroup not populated (rows: ${ROWS:-unreadable})"
fi
EXPANDED=$(ctl db -N -B oscar -e "SELECT COUNT(*) FROM dxphcpgroup WHERE dxcode='0320'" | tail -1)
if [ "${EXPANDED:-0}" -eq 1 ]; then
    ok "legacy mapping expanded to the zero-padded spelling (0320)"
else
    bad "legacy-expansion row for 0320 missing"
fi

# -- 3. RERUNNABILITY: a second pass is a guarded no-op --------------------
if ctl db-migrate "$MIG/$V7" "$MIG/$V13"; then
    ROWS2=$(ctl db -N -B oscar -e 'SELECT COUNT(*) FROM dxphcpgroup' | tail -1)
    if [ "$ROWS2" = "$ROWS" ]; then
        ok "second db-migrate pass is a no-op (still $ROWS rows)"
    else
        bad "second pass changed the row count ($ROWS -> $ROWS2)"
    fi
else
    bad "second db-migrate pass failed (migrations must be re-runnable)"
fi

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
