# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Boot-time guard (`carlos-ctl guard`), run as a ROOT oneshot
(@INSTANCE@-guard.service) BEFORE the service user's manager starts the pod:
blank-datadir detection plus verification that a
hostfw-enabled instance's default-deny nft table is actually loaded.

WHY: `carlos-ctl play` refuses a DEPLOYED instance whose MariaDB datadir has
no `mysql/` system-schema signature (an unmounted/wiped data volume that would
otherwise be initialized as a BLANK database over the empty mountpoint —
catastrophic silent PHI loss). But at REBOOT the Quadlet-generated user unit
starts the pod directly, bypassing that play-time check. This verb restores
the guarantee at boot: it fails loudly (paging via the unit's OnFailure=) when
a deployed instance's data volumes look unmounted.

The in-pod db-init container ALSO refuses the same condition (it reads the
guard/deployed + guard/accept-empty-datadir markers), which is the actual hard
stop — this verb is the detector/pager. The datadir signature is defined ONCE
here (datadir_initialized) and consumed by guard, play, and — via the Ansible
variable carlos_datadir_signature — the in-pod db-init check, so the three
can never drift."""

from __future__ import annotations

import sys
from pathlib import Path

from .runner import Runner
from .util import log

# THE datadir signature: an initialized MariaDB datadir ALWAYS holds a
# `mysql/` system-schema dir. Referenced by guard + play; the Ansible role
# renders the same relative path into the in-pod db-init refusal.
DATADIR_SIGNATURE = "mariadb-mnt/mysql"


def datadir_initialized(data_dir: Path) -> bool:
    return (data_dir / DATADIR_SIGNATURE).is_dir()


def _hostfw_failures(runner: Runner) -> list:
    """Check 2b: the nft apply unit is FAIL-OPEN — if all its
    retries fail, nothing blocks the user manager from starting the pods on a
    host with NO default-deny table loaded. This guard runs as a root oneshot
    ordered After= the nft unit and Before= the user manager, so it is the
    boot-path detector: a hostfw-enabled instance whose table is absent (or
    lost its default-deny) pages via OnFailure the moment it matters.
    HOSTFW_ENABLED is rendered by the role from carlos_host_firewall_enabled;
    pre-existing env files default to 0."""
    s = runner.settings
    if s.get("HOSTFW_ENABLED", "0") != "1":
        return []
    if not runner.have("nft"):
        return [
            f"HOSTFW_ENABLED=1 but the nft binary is missing — the host firewall "
            f"for instance '{s.instance}' can never be applied on this host."
        ]
    cp = runner.run(
        ["nft", "list", "table", "inet", f"{s.instance}-hostfw"],
        capture=True, quiet=True,
    )
    if cp.returncode != 0 or "policy drop" not in (cp.stdout or ""):
        return [
            f"host firewall table inet {s.instance}-hostfw is not loaded (or "
            f"lost its default-deny 'policy drop') — the host is FAIL-OPEN; "
            f"systemctl status {s.instance}-nft.service, fix the ruleset, then "
            f"systemctl restart {s.instance}-nft.service."
        ]
    return []


def cmd_guard(runner: Runner) -> int:
    from .config import warn_if_persisted_oneshot

    s = runner.settings
    data_dir = s.data_dir
    # A persisted accept-flag is the same standing-config footgun here as in
    # play — flag it so a stale line does not silently green-light a blank
    # datadir at every boot.
    warn_if_persisted_oneshot(
        s, "CARLOS_ACCEPT_EMPTY_DATADIR",
        "this override is meant to be a ONE-SHOT shell prefix; remove the line or a "
        "future unmounted/wiped datadir will silently initialize a BLANK database at boot",
    )
    # The boot-time guard runs as a root oneshot with none of play's shell
    # env, so the one-shot CARLOS_ACCEPT_EMPTY_DATADIR prefix an operator gave
    # `play` is gone. play persists that intent to guard/accept-empty-datadir
    # (the SAME marker the in-pod db-init reads) — honor it here too, so the
    # three refusal points (play, this guard, in-pod db-init) never disagree.
    accept_marker = (s.emr_home / "container" / "guard" / "accept-empty-datadir").is_file()
    accept_empty = s.flag("CARLOS_ACCEPT_EMPTY_DATADIR") or accept_marker
    # get_int_or (not bare int()): a typo'd CARLOS_DOCS_MIN_FILES degrades to
    # the default with a warning instead of raising ValueError, which — because
    # the guard is ordered before the pod at boot — would turn a config typo
    # into a boot outage rather than a warning.
    docs_min = s.get_int_or("CARLOS_DOCS_MIN_FILES", 1)

    # First-ever install (no go-live marker): nothing deployed yet, an empty
    # datadir is the expected state — pass.
    if not (s.emr_home / "container" / ".deployed").is_file():
        print(f"guard: instance '{s.instance}' not yet deployed — nothing to guard")
        return 0
    # Operator override: accept a fresh datadir on purpose (env flag now, or
    # the marker play persisted from a prior CARLOS_ACCEPT_EMPTY_DATADIR run).
    if accept_empty:
        how = "CARLOS_ACCEPT_EMPTY_DATADIR=1" if s.flag("CARLOS_ACCEPT_EMPTY_DATADIR") \
            else "accept-empty-datadir marker set by play"
        print(f"guard: {how} — accepting the current data volumes as-is")
        # The acceptance covers the DATA VOLUMES only: the host-firewall boot
        # check is about the nft table, not datadir state, and skipping it
        # here would let a reboot inside the accept window come up FAIL-OPEN
        # (nft apply failed, guard exits 0, nothing pages) — the exact blind
        # spot the boot-path detector exists to close.
        fw_failures = _hostfw_failures(runner)
        for f in fw_failures:
            print(f"GUARD FAILURE: {f}", file=sys.stderr)
        if fw_failures:
            print(
                f"guard: REFUSING to let instance '{s.instance}' start — see the "
                f"failures above",
                file=sys.stderr,
            )
            return 1
        return 0

    failures = []

    # 1. MariaDB datadir signature — its absence on a deployed instance means
    # the data volume is unmounted or wiped; starting the pod now would
    # initialize a BLANK database over it.
    if not datadir_initialized(data_dir):
        failures.append(
            f"{data_dir}/mariadb-mnt holds no initialized MariaDB datadir (no mysql/ system "
            f"schema) — the data volume looks unmounted or wiped; starting the pod would "
            f"create a BLANK database. Mount it, or set CARLOS_ACCEPT_EMPTY_DATADIR=1 to "
            f"accept a fresh datadir on purpose."
        )
    # 2. Binlog volume: point-in-time recovery ships closed binlogs from
    # here; an unmounted binlog dir would silently break PITR. Existence
    # alone is NOT enough — an unmounted mountpoint leaves the empty
    # underlying directory in place, so on a DEPLOYED instance (binary
    # logging on since first boot) the volume must also hold at least one
    # binlog.* entry.
    binlog_dir = data_dir / "mariadb-binlog"
    if not binlog_dir.is_dir():
        failures.append(
            f"{binlog_dir} is missing — the binlog volume looks unmounted "
            f"(point-in-time recovery would silently break)."
        )
    elif not any(p.name.startswith("binlog.") for p in binlog_dir.iterdir()):
        failures.append(
            f"{binlog_dir} holds no binlog.* files — on a deployed instance the empty "
            f"directory means the binlog volume is UNMOUNTED (the mountpoint dir "
            f"underneath it always exists); point-in-time recovery would silently break."
        )
    # 2b. Host firewall — see _hostfw_failures (also run on the accept-empty
    # path above; the acceptance covers data volumes only).
    failures.extend(_hostfw_failures(runner))
    # 3. Document store: a deployed instance's OscarDocument should not be
    # empty (an unmounted/mis-pathed dir). Iteration is bounded — cheap on
    # huge stores. CARLOS_DOCS_MIN_FILES=0 skips (pre-go-live opt-out).
    if docs_min > 0:
        count = 0
        docs = data_dir / "OscarDocument"
        if docs.is_dir():
            for p in docs.rglob("*"):
                if p.is_file():
                    count += 1
                    if count >= docs_min:
                        break
        if count < docs_min:
            failures.append(
                f"{data_dir}/OscarDocument holds fewer than {docs_min} file(s) — the document "
                f"volume looks unmounted or mis-pathed (set CARLOS_DOCS_MIN_FILES=0 for a "
                f"pre-go-live install)."
            )

    for f in failures:
        print(f"GUARD FAILURE: {f}", file=sys.stderr)
    if failures:
        print(
            f"guard: REFUSING to let instance '{s.instance}' start — see the failures above",
            file=sys.stderr,
        )
        return 1
    hostfw_note = ", host firewall loaded" if s.get("HOSTFW_ENABLED", "0") == "1" else ""
    log(
        f"guard: instance '{s.instance}' data volumes present (datadir signature, binlog, "
        f"documents{hostfw_note}) — OK"
    )
    return 0
