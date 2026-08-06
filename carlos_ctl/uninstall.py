# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Decommission THIS instance's host-global wiring. PRESERVES all data,
backups, config, and TPM cred blobs — data removal on a PHI system stays a
deliberate manual step. Double-confirmation; every step existence-guarded /
best-effort so a partly-removed instance uninstalls cleanly (idempotent),
and only $INSTANCE-* names are ever touched."""

from __future__ import annotations

import contextlib
import shutil
import sys
from pathlib import Path
from typing import List, Tuple

from .config import Settings
from .runner import Runner
from .util import CtlError, log, warn


def _instance_unit_paths(s: Settings) -> Tuple[List[Path], List[Path]]:
    """systemd unit + drop-in paths that belong to THIS instance, EXCLUDING any
    that actually belong to a prefix-overlapping sibling. The bare glob
    `{instance}-*` matches a sibling whose name extends this one with a hyphen
    (instance 'carlos' → 'carlos-test-backup.timer'), so an unguarded uninstall
    of 'carlos' would stop/remove a live 'carlos-test' instance's timers,
    silently taking its backups and monitoring dark. Provisioning asserts
    reject overlapping names, but uninstall carries its own runtime guard so a
    bypassed assert can't cross-decommission a sibling. Returns (units, dropins)."""
    from .config import read_registry

    siblings = []
    reg_dir = s.instance_registry_dir
    if reg_dir.is_dir():
        for f in reg_dir.glob("*.conf"):
            name = read_registry(f).get("INSTANCE", "")
            if name and name != s.instance:
                siblings.append(name)

    def mine(name: str) -> bool:
        # LONGEST-prefix wins: a unit file is THIS instance's unless a sibling
        # whose name is a STRICTLY LONGER prefix also matches. The old check
        # ("not any sibling is a prefix") was inverted for the longer-named
        # instance: uninstalling 'carlos-test' beside sibling 'carlos' matched
        # every 'carlos-test-*.timer' against the 'carlos-' prefix and skipped
        # ALL of them — decommission silently removed zero units. Our own
        # prefix ('carlos-test-') is longer than the sibling's ('carlos-'),
        # so it must win.
        own = f"{s.instance}-"
        if not name.startswith(own):
            return False
        for sib in siblings:
            sp = f"{sib}-"
            if len(sp) > len(own) and name.startswith(sp):
                return False  # a more-specific sibling genuinely owns it
        return True

    units = sorted(
        p for p in list(s.systemd_dir.glob(f"{s.instance}-*.service"))
        + list(s.systemd_dir.glob(f"{s.instance}-*.timer"))
        if mine(p.name)
    )
    dropins = sorted(
        p for p in s.systemd_dir.glob(f"{s.instance}-*.service.d") if mine(p.name)
    )
    return units, dropins


def cmd_uninstall(runner: Runner) -> int:
    s = runner.settings
    print(f"""About to DECOMMISSION instance '{s.instance}' (EMR_HOME={s.emr_home}).

WILL REMOVE (host wiring only):
  - pods {s.app_pod} / {s.obs_pod} / {s.waf_pod} (stopped and removed)
  - podman networks {s.net_name}, {s.edge_net_name} and the secrets
    {s.db_secret}, {s.instance}-obs-http
  - systemd units/timers {s.instance}-*.{{service,timer}}, drop-ins, and quadlets
  - the nftables tables ({s.instance}-nat/-filter/-hostfw) and
    {s.emr_home}/container/{s.instance}-nat.nft
  - {s.run_secrets_dir} and /etc/tmpfiles.d/{s.instance}-emr.conf
  - the registry entry {s.instance_registry_dir}/{s.instance}.conf and the
    alert-channel mirror {s.instance_registry_dir}/{s.instance}.alert.env

WILL PRESERVE (delete by hand only if you truly intend to destroy data):
  - {s.emr_home}/data       (MariaDB datadir, binlogs, OscarDocument — PHI)
  - {s.emr_home}/backup      (restic repo, hot backups)
  - {s.emr_home}/container/conf (rendered config incl. TLS certs) and carlos-app.env
  - TPM cred blobs {s.credstore_dir}/{s.instance}-*.cred (needed to decrypt backups)
  - the shared service user '{s.service_user}' and image store
""")
    # A confirmation pair PERSISTED in the env file pre-confirms EVERY future
    # uninstall — including an interactive one months later — with no prompt,
    # decommissioning the instance (pods down, units/nft/registry gone) from
    # two stale lines. Warn value-agnostically, mirroring the restore path's
    # persisted-CARLOS_RESTORE_CONFIRMED warning.
    from .config import parse_env_file

    if s.env_file.is_file():
        _persisted = parse_env_file(s.env_file.read_text(errors="replace"))
        if _persisted.get("CARLOS_UNINSTALL_CONFIRMED") or \
                _persisted.get("CARLOS_UNINSTALL_INSTANCE"):
            warn(
                f"CARLOS_UNINSTALL_CONFIRMED/CARLOS_UNINSTALL_INSTANCE is PERSISTED in "
                f"{s.env_file} — this pre-confirms every future 'carlos-ctl uninstall' "
                f"with no prompt. These are meant as a one-shot shell prefix; remove the "
                f"line(s) after this decommission."
            )
    # Guard 1: explicit 'yes'. Guard 2: retype the instance name (protects
    # against decommissioning the WRONG instance when several exist).
    if s.get("CARLOS_UNINSTALL_CONFIRMED") == "1":
        if s.get("CARLOS_UNINSTALL_INSTANCE") != s.instance:
            raise CtlError(
                f"refusing to uninstall non-interactively: set "
                f"CARLOS_UNINSTALL_INSTANCE={s.instance} to confirm the target"
            )
    elif sys.stdin.isatty():
        ans1 = input(f"This decommissions instance '{s.instance}'. Type 'yes' to continue: ")
        if ans1 != "yes":
            raise CtlError("uninstall aborted")
        ans2 = input("Confirm by typing the instance name to remove: ")
        if ans2 != s.instance:
            raise CtlError(f"name mismatch ('{ans2}' != '{s.instance}') — uninstall aborted")
    else:
        raise CtlError(
            f"refusing to uninstall non-interactively without confirmation: set "
            f"CARLOS_UNINSTALL_CONFIRMED=1 and CARLOS_UNINSTALL_INSTANCE={s.instance}"
        )

    log(f"Decommissioning instance '{s.instance}' (data preserved)")
    from . import lifecycle2

    with contextlib.suppress(CtlError):
        lifecycle2.cmd_down(runner, [])

    # systemd system units/timers/drop-ins + the nft + secrets units. The unit
    # set is sibling-filtered so a prefix-overlapping instance is never touched.
    unit_paths, dropin_paths = _instance_unit_paths(s)
    if runner.systemd_running():
        # ExecStop deletes the nft table.
        runner.run(["systemctl", "stop", f"{s.instance}-nft.service"], quiet=True)
        for unit in unit_paths:
            runner.run(["systemctl", "disable", "--now", unit.name], quiet=True)
    for unit in unit_paths:
        with contextlib.suppress(OSError):
            unit.unlink()
    for dropin in dropin_paths:
        shutil.rmtree(dropin, ignore_errors=True)
    if runner.systemd_running():
        runner.run(["systemctl", "daemon-reload"], quiet=True)

    # Rootless-user quadlets + reload the user manager.
    #
    # OSError is suppressed alongside CtlError, and the user-manager reload is
    # systemd_running()-gated, because THIS verb must never stop half-way: everything
    # below (the nft tables, the podman networks and BOTH credential-bearing
    # podman secrets, the decrypted /run fragments, the tmpfiles.d entry and
    # the registry claim) is still in place at this point. Measured live on a
    # host with no systemctl: the unguarded `systemctl_user` raised
    # FileNotFoundError, cli.py's top-level guard printed a bare
    # "ERROR: unexpected FileNotFoundError: … 'systemctl'", and the
    # decommission ABORTED right here — leaving the front-door DNAT table, the
    # host-global default-deny `-hostfw` table, both podman networks, the
    # `<instance>-db` (MariaDB root) and `<instance>-obs-http` secrets, the
    # decrypted sealed-credential fragments in /run, and the registry entry
    # behind, with the operator told only the exception's type.
    with contextlib.suppress(CtlError, OSError):
        qdir = s.quadlet_dir()
        for kube in (f"{s.instance}.kube", f"{s.obs_pod}.kube", f"{s.waf_pod}.kube"):
            with contextlib.suppress(OSError):
                (qdir / kube).unlink()
        if runner.systemd_running():
            runner.systemctl_user(["daemon-reload"], quiet=True)

    # nftables: the unit's ExecStop should have dropped the table; delete
    # explicitly too (idempotent) and remove the rendered ruleset.
    if runner.have("nft"):
        runner.run(["nft", "delete", "table", "ip", f"{s.instance}-nat"], quiet=True)
        runner.run(["nft", "delete", "table", "inet", f"{s.instance}-filter"], quiet=True)
        # The host default-deny firewall table, if this instance owned it — else
        # a decommission leaves a stale host-global 'policy drop' input chain
        # dropping traffic (possibly SSH) with no CARLOS instance behind it.
        runner.run(["nft", "delete", "table", "inet", f"{s.instance}-hostfw"], quiet=True)
    with contextlib.suppress(OSError):
        (s.emr_home / "container" / f"{s.instance}-nat.nft").unlink()
    # Drop the go-live marker(s): a future re-install of this instance must
    # not inherit "already deployed" timer gating (or the reboot blank-datadir
    # guard's armed state) from the decommissioned one.
    with contextlib.suppress(OSError):
        (s.emr_home / "container" / ".deployed").unlink()
    shutil.rmtree(s.emr_home / "container" / "guard", ignore_errors=True)

    # Rootless engine objects.
    with contextlib.suppress(CtlError):
        runner.podman_user(["network", "rm", s.edge_net_name], quiet=True)
        runner.podman_user(["network", "rm", s.net_name], quiet=True)
        runner.podman_user(["secret", "rm", s.db_secret], quiet=True)
        # BOTH instance-owned podman secrets. The role creates
        # <instance>-obs-http alongside <instance>-db (the obs-store
        # basic-auth credential that guards 180 days of PHI-adjacent logs),
        # and `rotate obs` recreates it — but decommission only ever removed
        # the db one, so an uninstalled instance left a LIVE credential in the
        # shared service user's secret store, listed in neither the WILL
        # REMOVE nor the WILL PRESERVE half of the confirmation banner
        # (measured live: `podman secret ls` still showed carlos-obs-http
        # after a clean uninstall). Named per-instance, so a sibling's secret
        # is never touched.
        runner.podman_user(["secret", "rm", f"{s.instance}-obs-http"], quiet=True)

    # /run tmpfs + its tmpfiles.d persistence, and the registry claim. ONE
    # removal path from the same setting the role installs into (the old code
    # derived a wrong /etc/systemd/tmpfiles.d path — which never exists — then
    # depended on a hardcoded /etc/tmpfiles.d literal that ignored a
    # customized carlos_tmpfiles_dir and broke test hermeticity).
    shutil.rmtree(s.run_secrets_dir, ignore_errors=True)
    with contextlib.suppress(OSError):
        (s.tmpfiles_dir / f"{s.instance}-emr.conf").unlink()
    with contextlib.suppress(OSError):
        (s.instance_registry_dir / f"{s.instance}.conf").unlink()
    with contextlib.suppress(OSError):
        (s.instance_registry_dir / f"{s.instance}.alert.env").unlink()

    log(
        f"instance '{s.instance}' decommissioned — data preserved under {s.emr_home} "
        f"(remove by hand to reclaim disk). Also remove its host_vars entry from the "
        f"Ansible inventory so a playbook run does not re-provision it."
    )
    return 0
