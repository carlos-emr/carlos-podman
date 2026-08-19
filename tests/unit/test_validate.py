# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Unit tests for the play-time validation gates."""

from pathlib import Path

import pytest

from carlos_ctl.util import CtlError
from carlos_ctl.validate import (
    MAX_CONTAINER_ID,
    check_mem_margin,
    graphroot_preflight,
    port_in_use_preflight,
    subid_map_preflight,
    validate_bind_ip,
    validate_image_digests,
    validate_instance_name,
    validate_log_view_cidr,
    validate_ports,
)


class TestBindIp:
    def test_accepts_specific_ipv4(self, mk_settings) -> None:
        validate_bind_ip(mk_settings("BIND_IP=192.168.20.250\n"))

    def test_rejects_ipv6(self, mk_settings) -> None:
        with pytest.raises(CtlError, match="IPv6"):
            validate_bind_ip(mk_settings("BIND_IP=::1\n"))

    def test_rejects_garbage(self, mk_settings) -> None:
        with pytest.raises(CtlError, match="not a valid IPv4"):
            validate_bind_ip(mk_settings("BIND_IP=999.1.1.1\n"))

    def test_rejects_any_bind_without_ack(self, mk_settings) -> None:
        # 0.0.0.0 makes the nftables 'ip daddr' gate a no-op — fail closed.
        with pytest.raises(CtlError, match="0.0.0.0"):
            validate_bind_ip(mk_settings("BIND_IP=0.0.0.0\n"))

    def test_any_bind_with_explicit_ack(self, mk_settings) -> None:
        validate_bind_ip(
            mk_settings("BIND_IP=0.0.0.0\n", {"CARLOS_ALLOW_ANY_BIND": "1"})
        )


class TestLogViewCidr:
    @pytest.mark.parametrize("v", ["", "rfc1918", "10.0.0.0/24", "10.0.0.0/24,192.168.1.0/28",
                                   "{10.0.0.0/24, 172.16.0.0/12}"])
    def test_accepts(self, mk_settings, v: str) -> None:
        validate_log_view_cidr(mk_settings(f"LOG_VIEW_ALLOW_CIDR={v}\n"))

    @pytest.mark.parametrize("v", ["10.0.0.0", "10.0.0.0/33", "999.0.0.0/24", "bogus",
                                   "10.0.0.0/24;drop"])
    def test_rejects_malformed_fail_closed(self, mk_settings, v: str) -> None:
        # A malformed value would fail the nftables apply and leave the PHI
        # log view unfiltered — reject before it reaches the ruleset.
        with pytest.raises(CtlError, match="LOG_VIEW_ALLOW_CIDR"):
            validate_log_view_cidr(mk_settings(f"LOG_VIEW_ALLOW_CIDR={v}\n"))


class TestInstanceName:
    def test_accepts_safe_charset(self, mk_settings) -> None:
        validate_instance_name(mk_settings("INSTANCE=clinic-b2\n"))

    @pytest.mark.parametrize("name", ["Clinic", "a_b", "-lead", "sp ace"])
    def test_rejects_unsafe(self, mk_settings, name: str) -> None:
        with pytest.raises(CtlError, match="INSTANCE"):
            validate_instance_name(mk_settings(f"INSTANCE={name}\n"))


class TestPorts:
    def test_defaults_pass(self, mk_settings) -> None:
        validate_ports(mk_settings())

    def test_rejects_out_of_range(self, mk_settings) -> None:
        with pytest.raises(CtlError, match="not a valid TCP port"):
            validate_ports(mk_settings("HTTPS_PORT=70000\n"))

    def test_rejects_duplicate_ports(self, mk_settings) -> None:
        # HTTPS_PORT == HTTPS_PUBLISH_PORT would make the nft redirect a no-op.
        with pytest.raises(CtlError, match="duplicates"):
            validate_ports(mk_settings("HTTPS_PORT=8443\n"))

    def test_rejects_privileged_rootless_port(self, mk_settings) -> None:
        with pytest.raises(CtlError, match="below 1024"):
            validate_ports(mk_settings("LOG_VIEW_PORT=443\nHTTPS_PORT=444\n"))


class TestPortInUsePreflight:
    _LISTEN = "LISTEN 0 128 127.0.0.1:0 0.0.0.0:*\n"

    def test_running_own_pod_short_circuits(self, mk_runner) -> None:
        # Our app pod is already up — it legitimately owns every port.
        r = mk_runner("OBS_ENABLED=0\n")
        r.script("podman", "ps", out="carlos-app-carlos\ncarlos-app-db\n")
        port_in_use_preflight(r)  # returns without any ss probe

    def test_foreign_listener_refuses(self, mk_runner) -> None:
        # Nothing of ours is up, yet HTTPS_PUBLISH_PORT is held — a foreign
        # process squats the port; refuse before the opaque bind error.
        r = mk_runner("OBS_ENABLED=0\n")
        r.script("podman", "ps", out="")
        r.script("ss", "-tlnH", "sport = :8443", out=self._LISTEN)
        with pytest.raises(CtlError, match="already in use"):
            port_in_use_preflight(r)

    def test_own_waf_holding_its_port_is_exempt(self, mk_runner) -> None:
        # Partial-outage recovery: app pod down, but OUR waf still holds
        # HTTPS_PUBLISH_PORT — that is not a foreign process; don't refuse.
        r = mk_runner("OBS_ENABLED=0\n")
        r.script("podman", "ps", out="carlos-waf-waf\n")
        r.script("ss", "-tlnH", "sport = :8443", out=self._LISTEN)
        port_in_use_preflight(r)

    def test_skip_flag_still_warns_on_positive_detection(self, mk_runner, capsys) -> None:
        r = mk_runner("OBS_ENABLED=0\n", {"CARLOS_SKIP_PORT_PREFLIGHT": "1"})
        r.script("podman", "ps", out="")
        r.script("ss", "-tlnH", "sport = :8443", out=self._LISTEN)
        port_in_use_preflight(r)  # bypass engaged — no raise
        assert "suppressed the refusal" in capsys.readouterr().err


class TestSubidMapPreflight:
    """The rootless userns must map every container id the pods and the image
    builds pin (65534 is the ceiling). The Ansible role skips its grant when
    the user already has ANY subuid line, so a narrow pre-existing grant
    survives and nothing else checks the WIDTH."""

    @staticmethod
    def _write(tmp_path: Path, subuid: str, subgid: str) -> Path:
        d = tmp_path / "etc"
        d.mkdir(parents=True, exist_ok=True)
        (d / "subuid").write_text(subuid)
        (d / "subgid").write_text(subgid)
        return d

    def test_warns_when_the_first_grant_cannot_map_65534(
        self, mk_runner, tmp_path, capsys
    ) -> None:
        d = self._write(tmp_path, "carlos:165536:34464\n", "carlos:165536:34464\n")
        subid_map_preflight(mk_runner("", {"CARLOS_SUBID_DIR": str(d)}))
        err = capsys.readouterr().err
        assert "maps only 34464 subuids" in err
        assert "maps only 34464 subgids" in err
        # The remedy must say WIDEN, not "add another range" — podman maps
        # from the first grant only.
        assert "WIDEN THE EXISTING GRANT" in err

    def test_second_range_does_not_satisfy_the_check(
        self, mk_runner, tmp_path, capsys
    ) -> None:
        # The exact shape that looks fixed but is not: a narrow first grant
        # plus an appended wide one still maps only the narrow first range.
        two = "carlos:165536:34464\ncarlos:200000:65536\n"
        d = self._write(tmp_path, two, two)
        subid_map_preflight(mk_runner("", {"CARLOS_SUBID_DIR": str(d)}))
        assert "maps only 34464" in capsys.readouterr().err

    def test_silent_on_a_full_width_grant(self, mk_runner, tmp_path, capsys) -> None:
        d = self._write(tmp_path, "carlos:165536:65536\n", "carlos:165536:65536\n")
        subid_map_preflight(mk_runner("", {"CARLOS_SUBID_DIR": str(d)}))
        assert capsys.readouterr().err == ""

    def test_boundary_grant_is_exactly_sufficient(
        self, mk_runner, tmp_path, capsys
    ) -> None:
        # Off-by-one pin, measured live: a grant of COUNT maps container ids
        # 1..COUNT, so COUNT == MAX_CONTAINER_ID covers 65534 exactly and must
        # NOT warn — while one less must.
        ok = f"carlos:165536:{MAX_CONTAINER_ID}\n"
        d = self._write(tmp_path, ok, ok)
        subid_map_preflight(mk_runner("", {"CARLOS_SUBID_DIR": str(d)}))
        assert capsys.readouterr().err == ""

        short = f"carlos:165536:{MAX_CONTAINER_ID - 1}\n"
        d2 = self._write(tmp_path / "b", short, short)
        subid_map_preflight(mk_runner("", {"CARLOS_SUBID_DIR": str(d2)}))
        assert f"maps only {MAX_CONTAINER_ID - 1} subuids" in capsys.readouterr().err

    def test_absent_or_unreadable_grant_is_silent(
        self, mk_runner, tmp_path, capsys
    ) -> None:
        # No line for this user (or no file at all): podman itself fails
        # loudly on the missing map — this probe must not add noise.
        d = self._write(tmp_path, "someone-else:100000:65536\n", "")
        subid_map_preflight(mk_runner("", {"CARLOS_SUBID_DIR": str(d)}))
        subid_map_preflight(mk_runner("", {"CARLOS_SUBID_DIR": str(tmp_path / "nope")}))
        assert capsys.readouterr().err == ""

    def test_other_users_narrow_grant_is_ignored(
        self, mk_runner, tmp_path, capsys
    ) -> None:
        # Anchored on the user field, not a substring: 'xcarlos' must not be
        # read as our grant (the same trap the role's regex guards).
        both = "xcarlos:100000:1000\ncarlos:165536:65536\n"
        d = self._write(tmp_path, both, both)
        subid_map_preflight(mk_runner("", {"CARLOS_SUBID_DIR": str(d)}))
        assert capsys.readouterr().err == ""


class TestMemMargin:
    def test_xmx_at_limit_dies(self) -> None:
        # Heap >= cgroup limit: OOM-killer SIGKILLs before any heap dump.
        with pytest.raises(CtlError, match="OOM-killer"):
            check_mem_margin("carlos", "8Gi", "8g", 2048)

    def test_healthy_margin_passes(self) -> None:
        check_mem_margin("carlos", "12Gi", "8g", 2048)

    def test_unparseable_skips_with_warning(self, capsys) -> None:
        check_mem_margin("carlos", "twelve", "8g", 2048)
        assert "skipping margin check" in capsys.readouterr().err


class TestGraphrootPreflight:
    """podman's rootless network namespace hides part of the filesystem from
    itself, and podman's own graphroot (hence netavark's <graphroot>/networks)
    can land inside it — every named bridge network then resolves as 'network
    not found' while `podman network ls` on the host lists it. /run is masked
    unconditionally; the CNI-state parent only when the state dir is absent,
    because podman walks UP from it to the first existing path. Verified live
    on podman 4.9.3 with two pristine accounts differing only in store
    location, flipped by nothing but `mkdir /var/lib/cni`."""

    @staticmethod
    def _runner(mk_runner, tmp_path, graphroot: str, cni_exists: bool):
        cni = tmp_path / "cnistate" / "cni"
        (cni if cni_exists else cni.parent).mkdir(parents=True, exist_ok=True)
        r = mk_runner("", {"CARLOS_CNI_STATE_DIR": str(cni)})
        r.script("podman", "info", rc=0, out=graphroot + "\n")
        return r, cni.parent

    @pytest.mark.parametrize("root", ["/run/carlos/storage", "/var/run/carlos/storage"])
    def test_run_graphroot_always_refuses(self, mk_runner, tmp_path, root: str) -> None:
        # No escape hatch for /run: podman replaces it with MS_BIND|MS_REC
        # regardless of what exists.
        r, _ = self._runner(mk_runner, tmp_path, root, cni_exists=True)
        with pytest.raises(CtlError, match="network not found"):
            graphroot_preflight(r)

    def test_cni_parent_graphroot_refuses_when_the_state_dir_is_absent(
        self, mk_runner, tmp_path
    ) -> None:
        cni_parent = tmp_path / "cnistate"
        r, parent = self._runner(
            mk_runner, tmp_path, f"{cni_parent}/carlos/storage", cni_exists=False
        )
        with pytest.raises(CtlError) as e:
            graphroot_preflight(r)
        assert "walking UP" in str(e.value)
        assert "mkdir -p" in str(e.value)

    def test_same_graphroot_passes_once_the_state_dir_exists(self, mk_runner, tmp_path) -> None:
        # The point of checking the live condition instead of the prefix:
        # refusing every /var/lib store would fail working hosts.
        cni_parent = tmp_path / "cnistate"
        r, _ = self._runner(
            mk_runner, tmp_path, f"{cni_parent}/carlos/storage", cni_exists=True
        )
        graphroot_preflight(r)

    @pytest.mark.parametrize(
        "root", ["/var/opt/carlos/storage", "/home/carlos/storage", "/srv/carlos/storage"]
    )
    def test_unmasked_graphroot_passes(self, mk_runner, tmp_path, root: str) -> None:
        r, _ = self._runner(mk_runner, tmp_path, root, cni_exists=False)
        graphroot_preflight(r)

    def test_sibling_of_the_masked_parent_is_not_matched(self, mk_runner, tmp_path) -> None:
        # Prefix matching must be on a PATH SEGMENT: a bare startswith on the
        # parent string would also refuse '<parent>foo/...'.
        cni_parent = tmp_path / "cnistate"
        r, _ = self._runner(
            mk_runner, tmp_path, f"{cni_parent}foo/carlos/storage", cni_exists=False
        )
        graphroot_preflight(r)

    def test_unreadable_podman_info_defers(self, mk_runner, tmp_path) -> None:
        # podman itself reports a broken engine far more clearly than this
        # probe could; do not turn that into a confusing network message.
        r, _ = self._runner(mk_runner, tmp_path, "", cni_exists=False)
        r.script("podman", "info", rc=125, out="")
        graphroot_preflight(r)

    def test_asks_podman_rather_than_deriving_from_the_home(self, mk_runner, tmp_path) -> None:
        # A site storage.conf (rootless_storage_path) can move the store, so
        # the service user's home says nothing about where the hazard applies.
        r, _ = self._runner(mk_runner, tmp_path, "/var/opt/carlos/storage", cni_exists=False)
        graphroot_preflight(r)
        assert r.called_with("info", "--format", "{{.Store.GraphRoot}}")

    @pytest.mark.parametrize("override", ["", "relative/cni"])
    def test_malformed_cni_override_fails_closed_to_the_default(
        self, mk_runner, tmp_path, monkeypatch, override: str
    ) -> None:
        # An empty or relative CARLOS_CNI_STATE_DIR must degrade to the
        # default, not silently disable the /var/lib branch: the prefix match
        # would be unsatisfiable against an absolute graphroot and is_dir()
        # would resolve against cwd. Patch the default to a tmp path (not the
        # real /var/lib/cni, whose existence varies by host) and prove the
        # fallback lands there: a graphroot under its ABSENT parent refuses.
        default_cni = tmp_path / "cnidefault" / "cni"
        default_cni.parent.mkdir(parents=True)
        monkeypatch.setattr("carlos_ctl.validate.CNI_STATE_DIR", str(default_cni))
        r = mk_runner("", {"CARLOS_CNI_STATE_DIR": override})
        r.script("podman", "info", rc=0, out=f"{default_cni.parent}/carlos/storage\n")
        with pytest.raises(CtlError, match="network not found"):
            graphroot_preflight(r)


class TestImageRepoDigestExemption:
    def test_image_repo_defaults_do_not_trip_the_digest_warning(self, mk_settings, capsys) -> None:
        # CARLOS_IMAGE_REPO/DRUGREF_IMAGE_REPO are repo-only by design (the
        # digest lives in the source pin) — the third-party digest-pin warning
        # must stay silent about them.
        s = mk_settings()
        validate_image_digests(s)
        err = capsys.readouterr().err
        assert "IMAGE_REPO" not in err
