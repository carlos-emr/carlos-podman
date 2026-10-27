# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""CDS transport contract: exact runtime, bounded protocol and durable semantics."""

import json
from contextlib import closing
from pathlib import Path
from typing import List

import pytest

from carlos_ctl import cdsimport, cdsprotocol, cli
from carlos_ctl.backup import BackupContext
from carlos_ctl.util import CtlError


@pytest.mark.parametrize("provider", ["T099", "T002", "007", "test-provider_1"])
def test_framework_provider_keys_are_literal_strings(provider: str) -> None:
    args = cdsprotocol.parse_args(["--status", "run-1", "--provider", provider])
    assert cdsprotocol.engine_arguments(args) == [
        "--operation", "status", "--provider", provider, "--run", "run-1"]

CAPS = {"protocol": 1, "java": 25, "cliHeapMiB": 512,
        "operations": ["import", "status", "resume", "cancel", "report"]}
IMAGE = "sha256:" + "a" * 64
MOUNTS = [
    {"Destination": cdsimport.CONTAINER_SOURCE, "RW": False},
    {"Destination": cdsimport.CONTAINER_STATE, "RW": True},
    {"Destination": cdsimport.CONTAINER_PROPERTIES, "RW": False},
    {"Destination": "/var/lib/CarlosDocument", "RW": True},
]


@pytest.fixture
def prepared(mk_runner, monkeypatch):
    runner = mk_runner()
    source = runner.settings.data_dir / "cds-import" / "source"
    source.mkdir(parents=True)
    sample = source / "source 'é;$(literal).zip"
    sample.write_bytes(b"synthetic transport fixture; Java validates clinical input")
    runner.script("podman", "inspect", "--format", "{{.Image}}", out=IMAGE)
    runner.script("podman", "inspect", "--format", "{{json .Mounts}}", out=json.dumps(MOUNTS))
    # The more-specific actual-operation prefix must precede the probe prefix.
    runner.script("podman", "start", "--attach", "--interactive", rc=0)
    runner.script("podman", "start", "--attach", out=json.dumps(CAPS))
    monkeypatch.setattr(cdsimport.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cdsimport, "_operator", lambda: ("operator.name", 1001))
    argv = ["--input", str(sample), "--provider", "999998", "--source-namespace", "vendor",
            "--source-profile", "omd-5.2", "--program", "1", "--facility", "2"]
    return runner, argv, sample


def test_literal_arguments_and_root_attestation_use_the_exact_deployed_image(prepared) -> None:
    runner, argv, sample = prepared
    original = sample.read_bytes()
    assert cdsimport.cmd_cds_import(runner, argv + ["--merge-existing", "--dry-run"]) == 0
    creates = [call for call in runner.calls if call[:2] == ["podman", "create"]]
    assert len(creates) == 2
    probe, actual = creates
    assert probe[probe.index("--user") + 1] == "10001:10001"
    assert actual[actual.index("--user") + 1] == "0:0"
    for call in creates:
        assert IMAGE in call
        assert "--pull=never" in call
        assert "--read-only" in call
        assert "--cap-drop=ALL" in call
        assert call[call.index("--volumes-from") + 1] == runner.settings.app_pod + "-carlos"
    assert actual[actual.index("--memory") + 1] == "768m"
    for capability in ("CHOWN", "SETUID", "SETGID", "SETPCAP"):
        assert "--cap-add=" + capability in actual
    payloads = [json.loads(value) for value in runner.stdins if value]
    assert len(payloads) == 1
    ticket = payloads[0]
    assert ticket["operator"] == "operator.name"
    assert ticket["operatorUid"] == 1001
    assert ticket["provider"] == "999998"
    assert ticket["expiresEpochSeconds"] - ticket["issuedEpochSeconds"] == 300
    engine = actual[actual.index("--operation"):]
    assert ticket["argvSha256"] == cdsprotocol.arguments_digest(engine)
    expected_input = str(Path(cdsimport.CONTAINER_SOURCE) / sample.name)
    assert engine[engine.index("--input") + 1] == expected_input
    assert "--merge-existing" in engine and "--dry-run" in engine
    assert str(sample) not in json.dumps(ticket)
    assert sample.read_bytes() == original
    inspected = [call for call in runner.calls if "{{json .Mounts}}" in call]
    assert len(inspected) == 3  # producer, bounded probe, actual one-shot before start
    assert any(call[:4] == ["podman", "rm", "--force", "--ignore"] for call in runner.calls)


@pytest.mark.parametrize("operation", ["status", "resume", "cancel", "report"])
def test_existing_operations_bind_run_without_source_replacement(prepared, operation: str) -> None:
    runner, _, _ = prepared
    assert cdsimport.cmd_cds_import(runner, ["--" + operation, "run-123", "--provider", "4"]) == 0
    actual = [call for call in runner.calls if "--operation" in call][-1]
    assert actual[actual.index("--operation"):] == [
        "--operation", operation, "--provider", "4", "--run", "run-123"]
    assert "--input" not in actual


@pytest.mark.parametrize("outcome", [0, 1, 2, 3, 4, 130, 137, 143])
def test_engine_outcomes_are_not_reclassified_as_success(prepared, outcome: int) -> None:
    runner, argv, _ = prepared
    runner.script("podman", "start", "--attach", "--interactive", rc=outcome)
    assert cdsimport.cmd_cds_import(runner, argv) == outcome


@pytest.mark.parametrize("outcome", [125, 126, 127])
def test_reserved_container_runtime_failures_are_runtime_exit_two(prepared, outcome: int) -> None:
    runner, argv, _ = prepared
    runner.script("podman", "start", "--attach", "--interactive", rc=outcome)
    assert cdsimport.cmd_cds_import(runner, argv) == 2


def test_nonroot_cannot_start_runtime(prepared, monkeypatch) -> None:
    runner, argv, _ = prepared
    monkeypatch.setattr(cdsimport.os, "geteuid", lambda: 1000)
    assert cdsimport.cmd_cds_import(runner, argv) == 3
    assert runner.calls == []


def test_outside_and_linked_input_refuse_without_rewriting_source(prepared, tmp_path) -> None:
    runner, argv, sample = prepared
    outside = tmp_path / "outside.xml"
    outside.write_text("outside")
    link = sample.parent / "link.xml"
    link.symlink_to(sample)
    for selected in (outside, link):
        request = list(argv)
        request[1] = str(selected)
        assert cdsimport.cmd_cds_import(runner, request) == 2
    assert runner.calls == []
    assert outside.read_text() == "outside"
    assert link.is_symlink()


@pytest.mark.parametrize("change", [
    {"protocol": 2}, {"protocol": True}, {"java": 21}, {"operations": ["import"]},
    {"cliHeapMiB": 127}, {"cliHeapMiB": 16385}, {"cliHeapMiB": "512"}, {"cliHeapMiB": True},
])
def test_incompatible_capabilities_never_start_clinical_operation(prepared, change) -> None:
    runner, argv, _ = prepared
    runner.script("podman", "start", "--attach", out=json.dumps({**CAPS, **change}))
    assert cdsimport.cmd_cds_import(runner, argv) == 2
    assert not any("--operation" in call for call in runner.calls)
    assert not any(runner.stdins)


def test_java_authoritative_heap_is_used_without_python_property_parsing(prepared) -> None:
    runner, argv, _ = prepared
    runner.script("podman", "start", "--attach", out=json.dumps({**CAPS, "cliHeapMiB": 768}))
    assert not runner.settings.properties_file.exists()
    assert cdsimport.cmd_cds_import(runner, argv) == 0
    actual = [call for call in runner.calls if "--operation" in call][-1]
    assert "CARLOS_CDS_HEAP_MIB=768" in actual
    assert actual[actual.index("--memory") + 1] == "1024m"


@pytest.mark.parametrize("unsafe", [
    [{"Destination": cdsimport.CONTAINER_SOURCE, "RW": True}],
    [{"Destination": cdsimport.CONTAINER_PROPERTIES, "RW": True}],
    [{"Destination": [], "RW": False}],
])
def test_missing_or_writable_sensitive_mounts_refuse_before_start(prepared, unsafe) -> None:
    runner, argv, _ = prepared
    runner.script("podman", "inspect", "--format", "{{json .Mounts}}", out=json.dumps(unsafe))
    assert cdsimport.cmd_cds_import(runner, argv) == 2
    assert not any(call[:2] == ["podman", "create"] for call in runner.calls)


def test_runtime_errors_and_bad_arguments_do_not_echo_patient_values(prepared, capsys) -> None:
    runner, argv, _ = prepared
    sentinel = "PATIENT_SENTINEL_1970-01-01"
    assert cdsimport.cmd_cds_import(runner, argv + ["--" + sentinel]) == 1
    runner.script("podman", "inspect", "--format", "{{.Image}}", rc=125, out=sentinel)
    assert cdsimport.cmd_cds_import(runner, argv) == 2
    assert sentinel not in capsys.readouterr().err


def test_cleanup_failure_remains_visible_without_claiming_rollback(
    prepared, monkeypatch, capsys,
) -> None:
    runner, argv, _ = prepared
    monkeypatch.setattr(cdsimport, "_remove", lambda r, name: "-cds-import-" not in name)
    assert cdsimport.cmd_cds_import(runner, argv) == 2
    assert "clinical commits" in capsys.readouterr().err


def test_status_report_cancel_do_not_wait_for_foreground_deployment_lock() -> None:
    for operation in ("status", "report", "cancel"):
        assert cli._gating("cds-import", ["--" + operation, "run-1", "--provider", "4"]) == (
            False, True)
    assert cli._gating("cds-import", ["--resume", "run-1", "--provider", "4"]) == (True, True)


def test_strict_import_lock_failure_cannot_proceed_without_serialization(mk_settings) -> None:
    settings = mk_settings()
    absent = settings.emr_home / "absent"
    settings.emr_home = absent
    with pytest.raises(cdsprotocol.CdsCommandError) as error:
        cli._acquire_ctl_lock(settings, strict=True)
    assert error.value.code == 2


def test_provisioned_state_is_included_in_encrypted_backup_mounts(mk_runner) -> None:
    runner = mk_runner()
    state = runner.settings.cds_state_dir
    state.mkdir(parents=True)
    restic = runner.settings.conf_dir / "restic" / "restic.env"
    restic.parent.mkdir(parents=True)
    restic.write_text("RESTIC_REPOSITORY=s3:synthetic/repo\nRESTIC_PASSWORD=test-secret\n")
    with closing(BackupContext(runner)) as context:
        assert context.cds_state_paths() == ["/backup/cds-import-state"]
        context.run_restic(["backup", *context.cds_state_paths()])
    assert runner.called_with(str(state) + ":/backup/cds-import-state:ro")


def test_linked_state_cannot_be_silently_backed_up_elsewhere(mk_runner, tmp_path) -> None:
    runner = mk_runner()
    state = runner.settings.cds_state_dir
    state.parent.mkdir(parents=True)
    state.symlink_to(tmp_path, target_is_directory=True)
    restic = runner.settings.conf_dir / "restic" / "restic.env"
    restic.parent.mkdir(parents=True)
    restic.write_text("RESTIC_REPOSITORY=s3:synthetic/repo\nRESTIC_PASSWORD=test-secret\n")
    with closing(BackupContext(runner)) as context:
        with pytest.raises(CtlError, match="real directory"):
            context.cds_state_paths()


@pytest.mark.parametrize("argv", [
    ["--provider", "4", "--input", "/allowed/file.xml"],
    ["--resume", "run-1", "--provider", "4", "--dry-run"],
    ["--status", "run-1", "--cancel", "run-1", "--provider", "4"],
])
def test_shared_protocol_rejects_ambiguous_or_reconfigured_work(argv: List[str]) -> None:
    with pytest.raises(cdsprotocol.CdsCommandError):
        cdsprotocol.parse_args(argv)
