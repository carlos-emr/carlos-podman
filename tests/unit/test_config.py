# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Unit tests for carlos_ctl.config — env parsing, precedence, derived identity."""

from pathlib import Path

import pytest

from carlos_ctl.config import (
    Settings,
    parse_env_file,
    read_registry,
    resolve_instance_home,
)
from carlos_ctl.util import CtlError


class TestParseEnvFile:
    def test_basic_and_comments(self) -> None:
        text = "# comment\n\nA=1\n  B=2\nexport C=3\nnot a kv line\n"
        assert parse_env_file(text) == {"A": "1", "B": "2", "C": "3"}

    def test_quote_stripping_one_layer(self) -> None:
        text = 'A="quoted"\nB=\'single\'\nC="\'nested\'"\n'
        got = parse_env_file(text)
        assert got == {"A": "quoted", "B": "single", "C": "'nested'"}

    def test_percent_q_decoding(self) -> None:
        # persist_db_root_password wrote %q-encoded values; sourcing decoded
        # them for free — the parser must too.
        text = "CARLOS_DB_ROOT_PASSWORD=$'p@\\nss'\nOTHER=a\\ b\n"
        got = parse_env_file(text)
        assert got["CARLOS_DB_ROOT_PASSWORD"] == "p@\nss"
        assert got["OTHER"] == "a b"

    def test_whitelist_filters(self) -> None:
        text = "GOOD=1\nEVIL=2\n"
        assert parse_env_file(text, whitelist=["GOOD"]) == {"GOOD": "1"}

    def test_rejects_non_shell_names(self) -> None:
        # A hostile line is inert data, never executed and never assigned.
        text = "rm -rf /=x\n1BAD=2\nOK_1=3\n"
        assert parse_env_file(text) == {"OK_1": "3"}

    def test_strips_unquoted_inline_comment_but_keeps_quoted_hash(self) -> None:
        # bash drops ' #...' on an unquoted value; a quoted '#' and a '#' with
        # no leading space are literal (a password may contain '#').
        text = 'A=value # note\nB="pa#ss"\nC=a#b\n'
        got = parse_env_file(text)
        assert got == {"A": "value", "B": "pa#ss", "C": "a#b"}

    def test_strips_quotes_fromQuotedValue_withInlineComment(self) -> None:
        # KEY="a b" # note — the sourcing shell assigned `a b`; the literal
        # quotes must not leak into the value (a webhook URL stored as
        # '"https://…"' fails every delivery). Same for single quotes and for
        # a quoted '#' followed by a real comment.
        text = (
            'HOOK="https://hooks/x" # ops channel\n'
            "S='a b' # note\n"
            'H="a #b" # note\n'
        )
        got = parse_env_file(text)
        assert got == {"HOOK": "https://hooks/x", "S": "a b", "H": "a #b"}

    def test_dropsTrailingWhitespace_beforeInlineComment(self) -> None:
        # KEY=abc  # note — the whitespace terminated the value word in bash;
        # it is never part of the value.
        assert parse_env_file("A=abc  # note\n") == {"A": "abc"}


class TestRegistry:
    def test_read_registry_value_may_contain_equals(self, tmp_path: Path) -> None:
        f = tmp_path / "carlos.conf"
        f.write_text("# header\nINSTANCE=carlos\nEMR_HOME=/usr/local/emr\nX=a=b\n")
        reg = read_registry(f)
        assert reg["X"] == "a=b"
        assert reg["INSTANCE"] == "carlos"

    def test_resolve_instance_home(self, tmp_path: Path) -> None:
        (tmp_path / "clinicb.conf").write_text("INSTANCE=clinicb\nEMR_HOME=/srv/emr-b\n")
        env = {"CARLOS_INSTANCE_REGISTRY_DIR": str(tmp_path)}
        assert resolve_instance_home("clinicb", env) == "/srv/emr-b"

    def test_resolve_unregistered_fails_closed(self, tmp_path: Path) -> None:
        env = {"CARLOS_INSTANCE_REGISTRY_DIR": str(tmp_path)}
        with pytest.raises(CtlError, match="no registered instance"):
            resolve_instance_home("ghost", env)

    def test_resolve_missing_home_field(self, tmp_path: Path) -> None:
        (tmp_path / "bad.conf").write_text("INSTANCE=bad\n")
        env = {"CARLOS_INSTANCE_REGISTRY_DIR": str(tmp_path)}
        with pytest.raises(CtlError, match="no EMR_HOME"):
            resolve_instance_home("bad", env)


class TestInstanceHomePin:
    """M1: with --instance, the registry-resolved EMR_HOME (exported as
    CARLOS_EMR_HOME_PINNED) is authoritative over the selected instance's own
    env-file EMR_HOME line — else a stale line redirects every mutating verb."""

    def _home_with_env(self, tmp_path: Path, env_body: str) -> Path:
        home = tmp_path / "reg-home"
        (home / "container").mkdir(parents=True, exist_ok=True)
        (home / "container" / "carlos-app.env").write_text(env_body)
        return home

    def test_pin_wins_over_envfile_and_warns(self, tmp_path: Path, capsys) -> None:
        home = self._home_with_env(tmp_path, "EMR_HOME=/srv/somewhere-else\n")
        s = Settings({"EMR_HOME": str(home), "CARLOS_EMR_HOME_PINNED": str(home)})
        assert s.emr_home == home
        err = capsys.readouterr().err
        assert "WINS" in err and str(home) in err and "/srv/somewhere-else" in err

    def test_pin_silent_when_envfile_agrees(self, tmp_path: Path, capsys) -> None:
        home = self._home_with_env(tmp_path, f"EMR_HOME={tmp_path / 'reg-home'}\n")
        s = Settings({"EMR_HOME": str(home), "CARLOS_EMR_HOME_PINNED": str(home)})
        assert s.emr_home == home
        assert "WINS" not in capsys.readouterr().err

    def test_no_pin_keeps_envfile_precedence(self, tmp_path: Path) -> None:
        # Without the pin (no --instance), the historical file-wins order holds.
        home = self._home_with_env(tmp_path, "EMR_HOME=/srv/somewhere-else\n")
        s = Settings({"EMR_HOME": str(home)})
        assert s.emr_home == Path("/srv/somewhere-else")


class TestInstanceIdentityPin:
    """Seventh pass: --instance must pin the instance IDENTITY (pod/unit/nft
    names all derive from it), not only EMR_HOME — with the selected home's
    env file missing (unmounted volume) identity fell back to 'carlos' and
    verbs targeted the WRONG instance's pods."""

    def test_pinned_identity_wins_when_envfile_missing(self, tmp_path: Path) -> None:
        home = tmp_path / "gone-home"  # no env file at all (unmounted volume)
        s = Settings({"EMR_HOME": str(home), "CARLOS_EMR_HOME_PINNED": str(home),
                      "CARLOS_INSTANCE_PINNED": "clinicb"})
        assert s.instance == "clinicb"
        assert s.app_pod == "clinicb-app"

    def test_pinned_identity_wins_over_stale_envfile_and_warns(
        self, tmp_path: Path, capsys
    ) -> None:
        home = tmp_path / "reg-home"
        (home / "container").mkdir(parents=True, exist_ok=True)
        (home / "container" / "carlos-app.env").write_text("INSTANCE=clinica\n")
        s = Settings({"EMR_HOME": str(home), "CARLOS_INSTANCE_PINNED": "clinicb"})
        assert s.instance == "clinicb"
        err = capsys.readouterr().err
        assert "registry WINS" in err and "clinica" in err

    def test_no_pin_reads_envfile_instance(self, tmp_path: Path) -> None:
        home = tmp_path / "reg-home2"
        (home / "container").mkdir(parents=True, exist_ok=True)
        (home / "container" / "carlos-app.env").write_text("INSTANCE=clinica\n")
        s = Settings({"EMR_HOME": str(home)})
        assert s.instance == "clinica"


class TestAlertChannelSidecar:
    """The root-only mirror outside $EMR_HOME fills EMPTY channel keys only —
    it exists so the boot guard's page survives an unmounted data volume."""

    def _sidecar(self, tmp_path: Path, lines: str) -> Path:
        reg = tmp_path / "registry"
        reg.mkdir(exist_ok=True)
        (reg / "carlos.alert.env").write_text(lines)
        return reg

    def test_sidecar_fills_empty_keys_when_env_file_absent(self, tmp_path: Path) -> None:
        reg = self._sidecar(
            tmp_path,
            "ALERT_WEBHOOK=https://hooks/side\nHEARTBEAT_URL=https://hb/side\n",
        )
        s = Settings({
            "EMR_HOME": str(tmp_path / "nonexistent"),
            "CARLOS_INSTANCE_REGISTRY_DIR": str(reg),
        })
        assert s.get("ALERT_WEBHOOK") == "https://hooks/side"
        assert s.get("HEARTBEAT_URL") == "https://hb/side"
        assert s.get("ALERT_EMAIL") == ""

    def test_env_file_value_wins_over_sidecar(self, tmp_path: Path) -> None:
        home = tmp_path / "emr"
        (home / "container").mkdir(parents=True)
        (home / "container" / "carlos-app.env").write_text(
            "ALERT_WEBHOOK=https://hooks/envfile\n"
        )
        reg = self._sidecar(tmp_path, "ALERT_WEBHOOK=https://hooks/side\n")
        s = Settings({
            "EMR_HOME": str(home),
            "CARLOS_INSTANCE_REGISTRY_DIR": str(reg),
        })
        assert s.get("ALERT_WEBHOOK") == "https://hooks/envfile"

    def test_sidecar_only_channel_keys_are_read(self, tmp_path: Path) -> None:
        # A hostile/mangled sidecar must not inject arbitrary settings.
        reg = self._sidecar(
            tmp_path, "ALERT_WEBHOOK=https://hooks/side\nCARLOS_ALLOW_DB_ROOT=1\n"
        )
        s = Settings({
            "EMR_HOME": str(tmp_path / "nonexistent"),
            "CARLOS_INSTANCE_REGISTRY_DIR": str(reg),
        })
        assert s.get("ALERT_WEBHOOK") == "https://hooks/side"
        assert not s.flag("CARLOS_ALLOW_DB_ROOT")

    def test_missing_sidecar_is_silent(self, tmp_path: Path) -> None:
        s = Settings({
            "EMR_HOME": str(tmp_path / "nonexistent"),
            "CARLOS_INSTANCE_REGISTRY_DIR": str(tmp_path / "no-registry"),
        })
        assert s.get("ALERT_WEBHOOK") == ""

    def test_pinned_instance_reads_its_own_sidecar_not_the_default(
        self, tmp_path: Path
    ) -> None:
        # The unmounted-volume incident: --instance clinicb, its env file gone.
        # The sidecar must key on the PINNED identity, not fall back to the
        # default 'carlos' and deliver clinicb's page to the wrong instance's
        # channel (ninth-pass finding).
        reg = tmp_path / "registry"
        reg.mkdir()
        (reg / "clinicb.alert.env").write_text("ALERT_WEBHOOK=https://hooks/clinicb\n")
        (reg / "carlos.alert.env").write_text("ALERT_WEBHOOK=https://hooks/DEFAULT\n")
        s = Settings({
            "EMR_HOME": str(tmp_path / "clinicb-home-unmounted"),
            "CARLOS_INSTANCE_PINNED": "clinicb",
            "CARLOS_INSTANCE_REGISTRY_DIR": str(reg),
        })
        assert s.instance == "clinicb"
        assert s.get("ALERT_WEBHOOK") == "https://hooks/clinicb"


class TestFlagTruthinessSharedWithPersistedWarning:
    """Settings.flag() and warn_if_persisted_oneshot must honor the SAME
    truthy spellings — otherwise a persisted CARLOS_ACCEPT_EMPTY_DATADIR=true
    disarms the guard on every boot while the warning stays silent (ninth-pass
    finding: the fail-open half never warned)."""

    def test_word_true_flag_is_honored(self, tmp_path: Path) -> None:
        s = Settings({"EMR_HOME": str(tmp_path), "CARLOS_ACCEPT_EMPTY_DATADIR": "true"})
        assert s.flag("CARLOS_ACCEPT_EMPTY_DATADIR")

    def test_persisted_word_true_warns(self, tmp_path: Path) -> None:
        from carlos_ctl import config as cfg

        home = tmp_path / "emr"
        (home / "container").mkdir(parents=True)
        ef = home / "container" / "carlos-app.env"
        ef.write_text("CARLOS_ACCEPT_EMPTY_DATADIR=true\n")
        s = Settings({"EMR_HOME": str(home)})
        warnings: list = []
        import carlos_ctl.util as util

        orig = util.warn
        util.warn = lambda m: warnings.append(m)
        try:
            cfg.warn_if_persisted_oneshot(s, "CARLOS_ACCEPT_EMPTY_DATADIR", "hint")
        finally:
            util.warn = orig
        assert any("PERSISTED" in w for w in warnings)


class TestSettings:
    def _mk_home(self, tmp_path: Path, env_lines: str) -> Path:
        home = tmp_path / "emr"
        (home / "container").mkdir(parents=True)
        (home / "container" / "carlos-app.env").write_text(env_lines)
        return home

    def test_file_wins_over_environ_and_default(self, tmp_path: Path) -> None:
        home = self._mk_home(tmp_path, "BIND_IP=10.1.2.3\nINSTANCE=clinicb\n")
        s = Settings({"EMR_HOME": str(home), "BIND_IP": "9.9.9.9"})
        assert s.get("BIND_IP") == "10.1.2.3"
        assert s.instance == "clinicb"
        assert s.app_pod == "clinicb-app"
        assert s.db_secret == "clinicb-db"

    def test_environ_wins_over_default(self, tmp_path: Path) -> None:
        home = self._mk_home(tmp_path, "A=1\n")
        s = Settings({"EMR_HOME": str(home), "SERVICE_USER": "svc2"})
        assert s.service_user == "svc2"

    def test_defaults_when_unset(self, tmp_path: Path) -> None:
        home = self._mk_home(tmp_path, "")
        s = Settings({"EMR_HOME": str(home)})
        assert s.get("HTTPS_PORT") == "443"
        assert s.get("HTTPS_PUBLISH_PORT") == "8443"
        assert s.instance == "carlos"
        assert s.get("WAF_AUDIT_LOG_PARTS") == "ABFHKZ"  # no-PHI-bodies default
        assert s.obs_enabled is True

    def test_env_file_can_repoint_emr_home(self, tmp_path: Path) -> None:
        # The hermetic harness seds EMR_HOME in the env file — file wins.
        home = self._mk_home(tmp_path, f"EMR_HOME={tmp_path}/elsewhere\n")
        s = Settings({"EMR_HOME": str(home)})
        assert str(s.emr_home) == f"{tmp_path}/elsewhere"

    def test_derived_paths(self, tmp_path: Path) -> None:
        home = self._mk_home(tmp_path, "INSTANCE=x\n")
        s = Settings({"EMR_HOME": str(home)})
        assert s.rendered_yaml == home / "container" / "x-app.yaml"
        assert s.secrets_bundle == home / "container" / "conf" / "secrets" / "secrets.enc.yaml"
        assert s.age_key_file == home / "secrets-private" / "age-key.txt"
        assert str(s.run_secrets_dir) == "/run/x-emr"
        assert s.get("RESTIC_REPOSITORY") == str(home / "backup" / "restic-repo")

    def test_system_dir_overrides_for_hermetic_tests(self, tmp_path: Path) -> None:
        home = self._mk_home(tmp_path, "")
        s = Settings({
            "EMR_HOME": str(home),
            "CARLOS_CREDSTORE_DIR": "/tmp/cred",
            "CARLOS_QUADLET_DIR": "/tmp/quadlet",
            "CARLOS_INSTANCE_REGISTRY_DIR": "/tmp/reg",
        })
        assert str(s.credstore_dir) == "/tmp/cred"
        assert s.quadlet_dir() == Path("/tmp/quadlet")
        assert str(s.instance_registry_dir) == "/tmp/reg"

    def test_obs_disabled_flag(self, tmp_path: Path) -> None:
        home = self._mk_home(tmp_path, "OBS_ENABLED=0\n")
        s = Settings({"EMR_HOME": str(home)})
        assert s.obs_enabled is False

    def test_acknowledgement_flags(self, tmp_path: Path) -> None:
        home = self._mk_home(tmp_path, "")
        s = Settings({"EMR_HOME": str(home), "ALERT_JOURNAL_ONLY": "1"})
        assert s.flag("ALERT_JOURNAL_ONLY") is True
        assert s.flag("CARLOS_NO_HEARTBEAT") is False

    def test_flag_accepts_word_booleans(self, tmp_path: Path) -> None:
        home = self._mk_home(tmp_path, "A=true\nB=Yes\nC=on\nD=false\nE=no\n")
        s = Settings({"EMR_HOME": str(home)})
        assert s.flag("A") and s.flag("B") and s.flag("C")
        assert not s.flag("D") and not s.flag("E")

    def test_flag_unrecognized_value_fails_closed_and_warns(
        self, tmp_path: Path, capsys
    ) -> None:
        # An ambiguous truthy-looking value must NOT enable a safety opt-out.
        home = self._mk_home(tmp_path, "CARLOS_ALLOW_DB_ROOT=enabled\n")
        s = Settings({"EMR_HOME": str(home)})
        capsys.readouterr()  # drop construction-time warnings
        assert s.flag("CARLOS_ALLOW_DB_ROOT") is False
        assert "not a recognized boolean" in capsys.readouterr().err

    def test_get_int_or_falls_back_on_garbage(self, tmp_path: Path) -> None:
        # The monitor path: a malformed knob degrades to its default instead
        # of crashing the sweep.
        home = self._mk_home(tmp_path, "DISK_MIN_FREE=10%\n")
        s = Settings({"EMR_HOME": str(home)})
        assert s.get_int_or("DISK_MIN_FREE", 10) == 10
        assert s.get_int_or("ALERT_REMIND_HOURS", 24) == 24  # unset -> default

    def test_unknown_env_key_warns(self, tmp_path: Path, capsys) -> None:
        # A typo'd knob is kept-but-orphaned and the intended setting silently
        # no-ops to its default — the parse must SAY so.
        home = self._mk_home(tmp_path, "CARLOS_ACCEPT_EMPTY_DATADIRR=1\n")
        Settings({"EMR_HOME": str(home)})
        err = capsys.readouterr().err
        assert "CARLOS_ACCEPT_EMPTY_DATADIRR" in err
        assert "does not read" in err

    def test_known_keys_do_not_warn(self, tmp_path: Path, capsys) -> None:
        home = self._mk_home(
            tmp_path,
            "BIND_IP=10.0.0.1\nALERT_REMIND_HOURS=12\nDISK_MIN_FREE=15\n"
            "CARLOS_ACCEPT_LOCAL_REPO=1\nVERIFY_TMPFS_SIZE=8g\nJOURNAL_DIR=/srv/j\n"
            # pass-8 N1: read via Settings.get in the attended-recovery
            # unwrap, so persisting it must not trip the unknown-key warning.
            "CARLOS_RECOVERY_PASSPHRASE_FILE=/etc/carlos/recovery-pass\n",
        )
        Settings({"EMR_HOME": str(home)})
        assert "does not read" not in capsys.readouterr().err

    def test_source_selection_keys_are_registered(self, tmp_path: Path, capsys) -> None:
        # The version/artifact selection surface: all readable from the env
        # file without tripping the unknown-key warning, and the CARLOS_REF
        # default is the `auto` sentinel (release-first sticky resolution) —
        # env files that persist an explicit ref keep manual semantics.
        from carlos_ctl.config import known_keys

        assert {
            "CARLOS_REF", "CARLOS_ARTIFACT", "CARLOS_SOURCE_BRANCH",
            "CARLOS_WAR_URL", "CARLOS_WAR_SHA256",
            "DRUGREF_REF", "DRUGREF_ARTIFACT", "DRUGREF_SOURCE_BRANCH",
            "DRUGREF_WAR_URL", "DRUGREF_WAR_SHA256",
        } <= known_keys()
        home = self._mk_home(
            tmp_path,
            "CARLOS_ARTIFACT=war\nCARLOS_SOURCE_BRANCH=develop\n"
            "CARLOS_WAR_URL=https://x/x.war\nCARLOS_WAR_SHA256=" + "d" * 64 + "\n"
            "DRUGREF_ARTIFACT=source\nDRUGREF_SOURCE_BRANCH=master\n"
            "DRUGREF_WAR_URL=https://x/drugref2.war\nDRUGREF_WAR_SHA256=" + "f" * 64 + "\n",
        )
        s = Settings({"EMR_HOME": str(home)})
        assert "does not read" not in capsys.readouterr().err
        assert s.get("CARLOS_REF") == "auto"
        assert s.get("CARLOS_ARTIFACT") == "war"
        assert s.get("DRUGREF_REF") == "auto"
        assert s.get("DRUGREF_ARTIFACT") == "source"

    def test_journal_dir_env_file_knob(self, tmp_path: Path) -> None:
        # Operator knob JOURNAL_DIR (env-file, as the bash monitor read it);
        # the CARLOS_JOURNAL_DIR test override must still win.
        home = self._mk_home(tmp_path, "JOURNAL_DIR=/srv/journal\n")
        s = Settings({"EMR_HOME": str(home)})
        assert str(s.journal_dir) == "/srv/journal"
        s2 = Settings({"EMR_HOME": str(home), "CARLOS_JOURNAL_DIR": "/tmp/j"})
        assert str(s2.journal_dir) == "/tmp/j"
        s3 = Settings({"EMR_HOME": str(self._mk_home(tmp_path / "d", ""))})
        assert str(s3.journal_dir) == "/var/log/journal"


class TestObsEnabledStrictParse:
    """The old `!= "0"` coercion read ANY non-"0" value as enabled — a
    hand-edited OBS_ENABLED=false silently ran the full obs stack."""

    def _mk(self, tmp_path: Path, value) -> Settings:
        home = tmp_path / "emr"
        (home / "container").mkdir(parents=True, exist_ok=True)
        content = f"OBS_ENABLED={value}\n" if value is not None else ""
        (home / "container" / "carlos-app.env").write_text(content)
        return Settings({"EMR_HOME": str(home)})

    @pytest.mark.parametrize("value,expected", [
        (None, True),      # unset -> default enabled
        ("1", True),
        ("true", True),
        ("yes", True),
        ("on", True),
        ("0", False),
        ("false", False),  # the finding: this used to mean ENABLED
        ("no", False),
        ("off", False),
        ("FALSE", False),
    ])
    def test_recognized_values(self, tmp_path: Path, value, expected) -> None:
        assert self._mk(tmp_path, value).obs_enabled is expected

    def test_unrecognized_value_warns_and_defaults_enabled(
        self, tmp_path: Path, capsys
    ) -> None:
        s = self._mk(tmp_path, "maybe")
        assert s.obs_enabled is True
        assert "not a recognized boolean" in capsys.readouterr().err


class TestNonUtf8EnvFile:
    """A single non-UTF-8 byte in carlos-app.env must degrade that value, not
    raise UnicodeDecodeError inside Settings() — which is constructed before
    verb dispatch and would kill EVERY verb, including `alert` (the OnFailure
    dispatcher) and `monitor` before its crash-relay exists."""

    def test_settings_survives_cp1252_byte(self, tmp_path) -> None:
        home = tmp_path / "emr"
        (home / "container").mkdir(parents=True)
        (home / "container" / "carlos-app.env").write_bytes(
            b"INSTANCE=carlos\n# pasted cp1252 dash \x96 in a comment\nTZ=UTC\n"
        )
        s = Settings({"EMR_HOME": str(home)})
        assert s.get("INSTANCE") == "carlos"
        assert s.get("TZ") == "UTC"


def test_every_host_path_setting_is_redirected(mk_settings) -> None:
    """Drift pin for the hermeticity fixture above (pass-15 H2).

    Every Settings attribute that resolves to a HOST path must land inside
    the test's tmp_path — a new one added without a `CARLOS_*_DIR` knob (or a
    knob the fixture forgets) silently re-opens the leak, and the damage is
    invisible: the suite still reports "528 passed" while it deletes the
    host's real units, tmpfiles entry, /run secrets and registry claim.
    Lives here (not in conftest.py, which pytest does not collect tests
    from) so it actually runs."""
    s = mk_settings()
    host_attrs = [
        "systemd_dir", "tmpfiles_dir", "instance_registry_dir",
        "credstore_dir", "journal_dir", "run_secrets_dir",
    ]
    escaped = [
        f"{a}={getattr(s, a)}"
        for a in host_attrs
        if not str(getattr(s, a)).startswith(str(s.emr_home.parent))
    ]
    assert not escaped, (
        "these Settings paths point at the REAL host during a unit test — add "
        "their CARLOS_*_DIR knob to _HERMETIC_DIR_KNOBS (and to Settings if it "
        f"has none): {', '.join(escaped)}"
    )
