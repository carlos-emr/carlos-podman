# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Single-master secrets (SOPS + age): bundle ops, seal, rotate, render.

All reversible secrets live in ONE SOPS-encrypted bundle (settings.
secrets_bundle), keyed by the instance's age keypair. Values are stored RAW
(canonical plaintext); every format-specific escape (.properties, option-
file, SQL) happens at MATERIALIZATION time, never in the bundle.

sops/age remain external binaries (no maintained Python sops library), but
plaintext NEVER crosses an argv boundary: values move via 0600 tempfiles in
/run tmpfs, stdin, or the environment. The bash needed a 35-line awk program
to upsert the decrypted YAML off-argv; PyYAML does it in-process."""

from __future__ import annotations

import base64
import contextlib
import errno
import getpass
import os
import re
import secrets as pysecrets
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Dict, Iterator, List, Optional

import yaml

from .runner import Runner
from .util import (
    CtlError,
    curl_config_quote,
    log,
    native_password_hash,
    properties_unescape_value,
    restic_local_path,
    set_kv,
    sql_escape,
    warn,
)

if TYPE_CHECKING:
    from .config import Settings

# --- small shared helpers -------------------------------------------------------


def validate_db_password(value: str, label: str) -> None:
    """Reject credential values that would corrupt the stores holding them:
    empty (every downstream store treats empty as "unset" and the SQL grants
    would be passwordless) or an embedded newline (the env/properties/option
    files are line-oriented — a newline splits the secret)."""
    if not value:
        raise CtlError(f"{label} must not be empty")
    if "\n" in value:
        raise CtlError(
            f"{label} must not contain a newline (line-oriented credential stores would "
            f"be corrupted)"
        )
    # A carriage return is the same corruption class as a newline: Java
    # Properties.load and shell/option-file readers treat CR as a line
    # terminator, so a CR-bearing password (a Windows-pasted value) passes the
    # env-channel re-auth probe but SILENTLY TRUNCATES in carlos.properties /
    # exporter.my.cnf — the app then fails auth at its next reconnect. Reject
    # every other C0 control too; none belongs in a DB password and each can
    # corrupt one of the line- or key=value-oriented stores.
    bad = next((c for c in value if c == "\r" or (ord(c) < 0x20 and c != "\t")), None)
    if bad is not None:
        raise CtlError(
            f"{label} must not contain control characters (0x{ord(bad):02x}) — the "
            f"line-oriented credential stores (carlos.properties, exporter.my.cnf, the "
            f"env files) would be silently truncated or corrupted"
        )
    # A bash-era env value with non-UTF-8 bytes decodes to lone surrogates
    # (surrogateescape); those survive the ENV channel but every strict text
    # sink (bundle write, SQL over stdin) would raise a bare
    # UnicodeEncodeError mid-verb. Refuse up front with a real message.
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise CtlError(
            f"{label} contains bytes that are not valid UTF-8 (likely a corrupt value "
            f"carried over from a bash-era env file) — re-enter the credential"
        ) from None
    # Spring INTERPOLATES bean property values, and every DB password reaches
    # the app as one: spring_jpa.xml does
    #   <property name="password" value="${db_password}" />
    # so after the Properties lookup the resulting VALUE is still run through
    # the placeholder resolver and the SpEL BeanExpressionResolver. A password
    # containing '#{' is evaluated as an expression and the whole webapp
    # context fails to start against carlos-emr/carlos
    # develop, where a password ending '#{ok}' produced
    #   SpelEvaluationException: EL1008E: Property or field 'ok' cannot be found
    # (which also writes a FRAGMENT OF THE PASSWORD into the application log),
    # and /carlos served 404 until the password was changed. '${' is the same
    # class one layer earlier: it is re-resolved as a nested placeholder, so
    # the app silently authenticates with a DIFFERENT string than the one
    # provisioned. Neither is escapable — .properties has no escape that
    # survives Spring's second pass — so the only correct answer is refusal.
    for token in ("${", "#{"):
        if token in value:
            raise CtlError(
                f"{label} contains '{token}' — Spring re-interpolates every DB password "
                f"it reads from carlos.properties, so this value would be evaluated as a "
                f"placeholder/SpEL expression instead of used literally (a boot-fatal "
                f"webapp context failure, with part of the password echoed into the app "
                f"log). There is no escape for it; choose a password without '${{' and "
                f"'#{{'."
            )


_URL_USERINFO_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+.\-]*://)[^/@\s]+@")


def scrub_repo_creds(text: str) -> str:
    """Redact URL userinfo (user:password@) from restic diagnostics before they
    reach an operator-facing CtlError / journald. A restic repository can be a
    `rest:https://user:password@backup-host/…` (or creds-in-URL S3) form — a
    documented backend shape (see restic.env template) — so echoing restic's
    stderr or the RESTIC_REPOSITORY string verbatim would leak the backend
    password. The db-root rotation path avoids this by keeping quiet=True and
    not echoing stderr; this brings the restic path to the same standard."""
    return _URL_USERINFO_RE.sub(r"\1<redacted>@", text)


def percent_q(value: str) -> str:
    """bash printf-%q-compatible encoding for values written into
    carlos-app.env. The only consumers left are this package's own
    parse_env_file and any operator shell that sources the file — both decode
    the $'...' ANSI-C form %q uses for non-printables."""
    if re.fullmatch(r"[A-Za-z0-9@%_+=:,./-]+", value or "x") and value:
        return value
    out = ["$'"]
    for ch in value:
        if ch == "\\":
            out.append("\\\\")
        elif ch == "'":
            out.append("\\'")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20:
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(ch)
    out.append("'")
    return "".join(out)


def reap_credential_dropfiles(settings: Settings) -> None:
    """Shred any leftover .new-* one-time credential drop-files. They hold
    live cleartext credentials in the persistent root-only private dir; the
    operator is told to shred each after reading, but nothing enforced it, so
    they accumulated every rotation. Called by seal and the
    boot-time secrets render — the two root paths that run after a rotation."""
    d = settings.secrets_private_dir
    if not d.is_dir():
        return
    for f in d.glob(".new-*"):
        try:
            # Best-effort overwrite before unlink (same intent as _shred; a
            # plain unlink leaves the plaintext recoverable on non-LUKS).
            size = f.stat().st_size
            with open(f, "r+b") as fh:
                fh.write(b"\0" * size)
                fh.flush()
                os.fsync(fh.fileno())
            f.unlink()
        except OSError as e:
            if e.errno == errno.EROFS:
                # The secrets unit mounts EMR_HOME read-only except a nested
                # ReadWritePaths for this dir; if that is missing (an older
                # unit not yet re-rendered), the reap silently no-ops and live
                # cleartext credential drop-files persist across reboots. Warn
                # loudly rather than mask it.
                warn(
                    f"cannot reap cleartext credential drop-files in {d} — the path is "
                    f"READ-ONLY in this context; the plaintext .new-* files REMAIN until "
                    f"'carlos-ctl seal' runs from a shell (re-run the playbook to install "
                    f"the updated secrets unit)"
                )
                return
            # Other per-file errors stay best-effort (next run retries).


def emit_secret(settings: Settings, message: str, secret: str, slug: str) -> None:
    """Surface a freshly generated credential SAFELY. On a terminal, print it
    (the operator is watching). On a NON-terminal (systemd/tee/pipe), echoing
    it would leak the plaintext into the journal — instead write it to a 0600
    file in the root-only private dir and log the PATH. seal / secrets-render
    reap these afterward (reap_credential_dropfiles) so a read-and-forget
    never leaves cleartext lying around."""
    if sys.stdout.isatty():
        log(message)
        return
    dropf = settings.secrets_private_dir / f".new-{slug}"
    try:
        settings.secrets_private_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        # O_NOFOLLOW|O_EXCL: the private dir is root-only 0700, but a planted
        # symlink/pre-existing file at this name must never be followed (the
        # write would land the plaintext on the link target) — fail closed and
        # replace our own prior drop-file explicitly.
        with contextlib.suppress(FileNotFoundError):
            dropf.unlink()
        fd = os.open(dropf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secret + "\n")
        log(
            f"credential written to {dropf} (0600) — NOT echoed to a non-terminal "
            f"(journal/pipe); read it, then shred it (seal/secrets-render reap it too)"
        )
    except OSError:
        log(
            f"a new credential was generated but could not be written to {dropf}; re-run on "
            f"a terminal to see it"
        )


def _run_tmpfile(prefix: str, *, root_required: bool, suffix: str = "") -> str:
    """0600 tempfile in /run (tmpfs): decrypted secret material must never
    land on persistent disk. As root that is a hard requirement — fail closed
    rather than stage a key somewhere that survives a reboot. The default-tmp
    fallback remains only for non-root runs (the hermetic test suite).

    suffix matters when the file is handed to `sops -e`: sops picks its store
    by file EXTENSION, and an extension-less file silently selects the BINARY
    store, which wraps the whole input in a single `data:` key — a YAML
    bundle re-encrypted that way nests one level deeper on every write.
    Pass suffix='.yaml' for any file sops must treat as a YAML store."""
    # CARLOS_RUN_DIR: test-suite hook so a ROOT test run (CI runs the suites
    # under sudo) stages into the throwaway workdir instead of the host's
    # real /run — overridable ONLY so the hermetic suites can run, never set
    # in production (same doctrine as the Settings CARLOS_*_DIR overrides).
    # Read from os.environ ONLY, never Settings.get: this helper has no
    # Settings in scope, and a persisted carlos-app.env line must not be able
    # to redirect secret staging (same reasoning as CARLOS_ATTENDED_RECOVERY
    # above). Fail CLOSED on a broken override — a typo'd dir silently
    # falling back to /run would resurrect the exact host-write the override
    # exists to prevent.
    override = os.environ.get("CARLOS_RUN_DIR", "")
    if override:
        try:
            fd, path = tempfile.mkstemp(dir=override, prefix=prefix, suffix=suffix)
        except OSError as e:
            raise CtlError(
                f"CARLOS_RUN_DIR={override} is set but not usable for tempfiles ({e}) — "
                f"fix or unset the override (it exists for hermetic test runs only)"
            ) from None
        os.fchmod(fd, 0o600)
        os.close(fd)
        return path
    try:
        fd, path = tempfile.mkstemp(dir="/run", prefix=prefix, suffix=suffix)
    except OSError:
        if root_required and os.getuid() == 0:
            raise CtlError(
                "cannot create a tempfile in /run (tmpfs) — refusing to stage decrypted "
                "secret material on persistent disk"
            ) from None
        fd, path = tempfile.mkstemp(prefix=prefix, suffix=suffix)
    os.fchmod(fd, 0o600)
    os.close(fd)
    return path


# PBKDF2 iteration count for the attended-recovery wrap of the age key. The
# wrapped copy is an offline-crackable artifact by design (that is the price
# of an attended fallback) — the passphrase policy (>= 12 chars) plus this
# count plus LUKS underneath is the accepted posture; bump on re-seal as
# hardware advances.
_RECOVERY_KDF_ITER = "600000"


def _attended_recovery_unwrap(runner: Runner) -> Optional[str]:
    """TPM unseal failed: try the passphrase-wrapped recovery copy of the age
    key, if `seal` wrote one. Prompts on the operator's tty when there is
    one, else through systemd-ask-password (boot console / password agents)
    with a timeout so an unattended boot still fails loud instead of
    hanging. Returns a transient 0600 /run tmpfile path holding the key, or
    None (caller keeps its existing fail-loud path). The passphrase rides
    stdin, never argv."""
    s = runner.settings
    rec = s.age_key_recovery_file
    if not rec.is_file():
        return None
    for attempt in range(3):
        if sys.stdin.isatty():
            passphrase = getpass.getpass(
                f"TPM unseal failed for instance '{s.instance}' — attended-recovery "
                f"passphrase (attempt {attempt + 1}/3): ")
        elif os.environ.get("CARLOS_ATTENDED_RECOVERY") != "1":
            # Console prompting is scoped to contexts that OPTED IN (the
            # secrets unit sets Environment=CARLOS_ATTENDED_RECOVERY=1). Read
            # it from os.environ ONLY, never Settings.get — the env FILE gives
            # file-values precedence over process env, so reading it via
            # Settings would let a persisted carlos-app.env line both WIDEN
            # the opt-in to every headless verb (270 s hangs on a broken
            # backup-timer credential) and, as =0, silently DISABLE the unit's
            # own opt-in. Every other headless caller fails immediately.
            return None
        elif runner.have("systemd-ask-password"):
            cp = runner.run(
                ["systemd-ask-password", "--timeout=90",
                 f"CARLOS {s.instance}: TPM unseal failed — recovery passphrase "
                 f"(attempt {attempt + 1}/3):"],
                capture=True, quiet=True)
            if cp.returncode != 0 or not (cp.stdout or "").rstrip("\n"):
                # Timeout or no password agent answered: unattended boot —
                # give up immediately rather than burn 3 timeouts.
                return None
            passphrase = cp.stdout.rstrip("\n")
        else:
            return None
        if not passphrase:
            continue
        tmp = _run_tmpfile(f"{s.instance}-age-recovery.", root_required=True)
        cp = runner.run(
            ["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2",
             "-iter", _RECOVERY_KDF_ITER, "-pass", "stdin",
             "-in", str(rec), "-out", tmp],
            input_text=passphrase + "\n", quiet=True)
        try:
            # read_BYTES: AES-CBC has no integrity tag, so a wrong passphrase
            # yields valid-padding garbage ~1/256 of the time — decoding that
            # as text would raise UnicodeDecodeError (a ValueError, NOT
            # OSError) and crash the render past the retry loop, orphaning
            # this tmpfile. Match on bytes and treat any read error as "bad".
            good = cp.returncode == 0 and b"AGE-SECRET-KEY-" in Path(tmp).read_bytes()
        except OSError:
            good = False
        # Prove the unwrapped key is the CURRENT master, not a stale wrap of a
        # rotated-out key: an old key unwraps cleanly with its own passphrase
        # but no longer opens the bundle, so a bare "looks like a key" check
        # would yield a recovery slot that LIES mid-incident (every sops -d
        # then fails). Compare its public half to the live recipient. If we
        # can't derive it (no age-keygen), fall through on the prefix check —
        # sops will still fail loudly, just less specifically.
        if good and s.age_pub_file.is_file() and runner.have("age-keygen"):
            derived = runner.output(["age-keygen", "-y", tmp]).strip()
            want = s.age_pub_file.read_text().strip()
            if derived and want and derived != want:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)
                warn(
                    "the recovery wrap unwrapped a key that does NOT match this instance's "
                    "current age recipient — it is a STALE wrap of a rotated-out key and "
                    "cannot open the bundle. Delete age-key.recovery.enc and recover from "
                    "the ESCROWED current key."
                )
                return None
        if good:
            warn(
                f"TPM unseal FAILED for instance '{s.instance}' — proceeding on the "
                f"ATTENDED RECOVERY passphrase. Investigate the TPM/Secure-Boot state and "
                f"re-run 'carlos-ctl seal' to re-seal to this host's TPM."
            )
            return tmp
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        warn("recovery passphrase did not unwrap the key — wrong passphrase?")
    return None


@contextlib.contextmanager
def age_key(runner: Runner) -> Iterator[str]:
    """Resolve the age PRIVATE key for SOPS_AGE_KEY_FILE. Four sources, in
    order: a systemd-delivered credential (backup-timer unit context), the
    0600 key file (unsealed / no-TPM host), a transient decrypt of the
    TPM-sealed blob into /run, or — when THAT decrypt fails and `seal` wrote
    a passphrase-wrapped recovery copy — an attended unwrap (prompt with
    timeout; unattended runs still fail loud). The context manager
    guarantees the transient copy is removed even when the caller dies
    mid-operation (the bash needed a script-global EXIT trap for this)."""
    s = runner.settings
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY", "")
    if cred_dir and (Path(cred_dir) / s.cred_age).exists():
        yield str(Path(cred_dir) / s.cred_age)
        return
    if cred_dir:
        # Unit context but the expected credential is absent: the unit's
        # LoadCredentialEncrypted line is broken (renamed cred, replaced
        # credstore file). The sealed-blob fallback below deliberately keeps
        # the render working — a fixable unit misconfiguration must not take
        # the EMR down — but the incident has to reach the journal, or the
        # fallback masks it until the blob too is lost.
        warn(
            f"running under systemd but credential '{s.cred_age}' is not in "
            f"{cred_dir} — the unit's LoadCredentialEncrypted is broken; falling back to "
            f"the on-host key material (fix the unit: re-run 'carlos-ctl seal')"
        )
    if s.age_key_file.is_file():
        yield str(s.age_key_file)
        return
    sealed = s.credstore_dir / f"{s.cred_age}.cred"
    if sealed.is_file() and runner.have("systemd-creds"):
        tmp = _run_tmpfile(f"{s.instance}-age.", root_required=True)
        try:
            # --name is REQUIRED: _seal_one encrypts with --name=<cred_age>, and
            # systemd-creds refuses a decrypt whose embedded name does not match
            # the filename ("<cred_age>.cred" != embedded "<cred_age>"). Omitting
            # it makes every TPM-host boot render fail the decrypt and fall to
            # attended recovery — while _seal_one's own round-trip verify (which
            # DOES pass --name) reports success, so the operator seals into an
            # outage. Verified against systemd-creds 255.
            cp = runner.run(
                ["systemd-creds", "decrypt", f"--name={s.cred_age}", str(sealed), tmp],
                quiet=True)
            # A failed/empty decrypt must not masquerade as a usable key:
            # every caller would then die inside sops with a misleading error.
            if cp.returncode != 0 or os.path.getsize(tmp) == 0:
                # TPM state changed (PCR/Secure-Boot/firmware, cleared chip)?
                # Attended fallback before failing loud.
                rec_tmp = _attended_recovery_unwrap(runner)
                if rec_tmp is None:
                    raise CtlError(
                        f"could not decrypt the sealed age key {sealed} — no age key "
                        f"available for instance '{s.instance}'. Recovery paths: the "
                        f"attended-recovery passphrase (if 'seal' wrote one), or re-seal "
                        f"from the ESCROWED age key."
                    )
                os.replace(rec_tmp, tmp)
            yield tmp
        finally:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
        return
    # No key file and no (readable) sealed blob — e.g. the credstore blob was
    # deleted. The recovery copy still saves an attended session.
    rec_tmp = _attended_recovery_unwrap(runner)
    if rec_tmp is not None:
        try:
            yield rec_tmp
        finally:
            with contextlib.suppress(OSError):
                os.unlink(rec_tmp)
        return
    raise CtlError(f"no age key available for instance '{s.instance}'")


# --- upgrade-path helpers (called from play too) ----------------------------------


def migrate_age_key_location(runner: Runner) -> None:
    """One-time relocation for installs created before the private key moved
    out of container/. Idempotent: no-op once the key is at the new path, or
    on a TPM host where the key was shredded at seal. MUST run before any
    ownership sweep, or the sweep would hand the still-old key to the
    service user."""
    s = runner.settings
    old = s.conf_dir / "secrets" / "age-key.txt"
    if old.is_file() and not s.age_key_file.is_file():
        s.secrets_private_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        old.rename(s.age_key_file)
        with contextlib.suppress(OSError):
            os.chown(s.age_key_file, 0, 0)
        s.age_key_file.chmod(0o600)
        log(
            f"Migrated the age private key to {s.age_key_file} (root-only, out of the "
            f"backed-up container/ tree)"
        )


def harden_secrets_ownership(runner: Runner) -> None:
    """Re-pin conf/secrets to ROOT ownership with encrypted-content modes. The
    dir and the age-encrypted bundle/recipient must be READABLE by the
    rootless backup but never WRITABLE by the service user: a writable
    recipient/bundle is a re-encryption-recipient injection vector.
    Idempotent and root-guarded (the non-root test suite skips it)."""
    s = runner.settings
    if os.getuid() != 0 or not s.secrets_dir.is_dir():
        return
    with contextlib.suppress(OSError):
        os.chown(s.secrets_dir, 0, 0)
        s.secrets_dir.chmod(0o755)
    for f in (s.secrets_bundle, s.age_pub_file, s.age_marker):
        if f.exists():
            with contextlib.suppress(OSError):
                os.chown(f, 0, 0)
                f.chmod(0o644)


# --- bundle primitives -----------------------------------------------------------

_BUNDLE_SECTIONS = ("carlos", "drugref", "backup_db", "exporter", "restic")


def bundle_available(runner: Runner) -> bool:
    return runner.settings.secrets_bundle.is_file()


def ensure_age_key(runner: Runner) -> None:
    """Generate the instance's age keypair once (idempotent). The private key
    lands 0600 (seal later TPM-seals + shreds it); the public recipient stays
    cleartext. Self-heals a missing recipient from the private key instead of
    wedging."""
    s = runner.settings
    if s.age_key_file.is_file() and not s.age_pub_file.is_file():
        pub = ""
        for line in s.age_key_file.read_text().splitlines():
            if line.startswith("# public key: "):
                pub = line[len("# public key: "):]
                break
        if not pub and runner.have("age-keygen"):
            pub = runner.output(["age-keygen", "-y", str(s.age_key_file)]).strip()
        if pub:
            s.age_pub_file.parent.mkdir(parents=True, exist_ok=True)
            s.age_pub_file.write_text(pub + "\n")
            s.age_pub_file.chmod(0o644)
            log(f"Re-derived the missing age recipient ({s.age_pub_file}) from the private key")
            return
        raise CtlError(
            f"the age private key exists but its recipient cannot be derived — investigate "
            f"{s.age_key_file} (the key file may be corrupt)"
        )
    if s.age_pub_file.is_file() or s.age_key_file.is_file() \
            or (s.credstore_dir / f"{s.cred_age}.cred").is_file():
        return
    if not runner.have("age-keygen"):
        warn("age-keygen not found — skipping age key generation; 'carlos-ctl seal' will need it")
        return
    s.secrets_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    s.secrets_private_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    old_umask = os.umask(0o077)
    try:
        runner.run(["age-keygen", "-o", str(s.age_key_file)], quiet=True)
    finally:
        os.umask(old_umask)
    if not s.age_key_file.is_file():
        raise CtlError("age-keygen failed — no keypair generated")
    s.age_key_file.chmod(0o600)
    pub = ""
    for line in s.age_key_file.read_text().splitlines():
        if line.startswith("# public key: "):
            pub = line[len("# public key: "):]
            break
    s.age_pub_file.write_text(pub + "\n")
    s.age_pub_file.chmod(0o644)
    log(
        f"Generated the instance age keypair (recipient {s.age_pub_file}) — its private key "
        f"becomes the single-master DR secret at 'seal'"
    )


def bundle_init(runner: Runner) -> None:
    """Create the empty encrypted bundle if absent (idempotent). Uses only the
    PUBLIC recipient, so it works before the private key is even sealed. The
    dir + the ENCRYPTED bundle must be traversable/readable by the rootless
    restic container but NOT writable by it — a service-user-writable
    recipient/bundle lets a compromised app container inject its own age
    recipient that the next root-run re-encrypt would fold in."""
    s = runner.settings
    if s.secrets_bundle.is_file():
        return
    if not s.age_pub_file.is_file():
        raise CtlError(f"no age recipient ({s.age_pub_file}) — run the provisioning playbook first")
    s.secrets_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    skeleton = "".join(f"{sec}: {{}}\n" for sec in _BUNDLE_SECTIONS)
    fd = os.open(s.secrets_bundle, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(skeleton)
    cp = runner.run(
        ["sops", "-e", "-i", str(s.secrets_bundle)],
        env={"SOPS_AGE_RECIPIENTS": s.age_pub_file.read_text().strip()},
        quiet=True,
    )
    if cp.returncode != 0:
        s.secrets_bundle.unlink(missing_ok=True)
        raise CtlError("sops encryption of the new secrets bundle failed")
    # 0644 root-owned: the content is age-encrypted (safe to be world-readable
    # so the rootless backup can archive it) but must NOT be service-user-writable.
    s.secrets_bundle.chmod(0o644)


def _bundle_recipients(runner: Runner) -> str:
    """Every recipient the existing bundle records (an operator may have added
    an escrow/DR recipient via `sops updatekeys` — silently re-encrypting to
    only the instance key would cut that escrow key off, discovered exactly
    when it is the last key standing). Falls back to the instance recipient
    when the metadata is unreadable (fresh bundle)."""
    s = runner.settings
    recipients: List[str] = []
    try:
        meta = yaml.safe_load(s.secrets_bundle.read_text())
        for entry in (meta.get("sops", {}) or {}).get("age", []) or []:
            r = entry.get("recipient", "")
            if r and r not in recipients:
                recipients.append(r)
    except (OSError, yaml.YAMLError, AttributeError):
        pass
    if not recipients:
        recipients = [s.age_pub_file.read_text().strip()]
    return ",".join(recipients)


def bundle_set(runner: Runner, section: str, key: str, value: str) -> None:
    """Upsert section.key in the bundle. NOT `sops --set`: that would put the
    secret VALUE on the sops argv, readable from the process list by any
    local user while sops runs. Instead: decrypt into a 0700 /run tmpdir,
    upsert IN-PROCESS (PyYAML — the value never leaves this process), and
    re-encrypt to every recorded recipient. Write-then-move keeps the on-disk
    bundle atomic."""
    s = runner.settings
    if not bundle_available(runner):
        bundle_init(runner)
    if not s.age_pub_file.is_file():
        raise CtlError(
            f"no age recipient ({s.age_pub_file}) — cannot re-encrypt the secrets bundle "
            f"for '{s.instance}'"
        )
    with age_key(runner) as key_path:
        # .yaml suffix is LOAD-BEARING: `sops -e` below picks the YAML store
        # from the extension; without it the whole bundle gets wrapped into a
        # binary-store `data:` scalar (corrupting the bundle on first upsert).
        plain = _run_tmpfile(f"{s.instance}-bundle.", root_required=True, suffix=".yaml")
        try:
            with open(plain, "w") as f:
                cp = runner.run(
                    ["sops", "-d", str(s.secrets_bundle)],
                    env={"SOPS_AGE_KEY_FILE": key_path}, capture=True,
                )
                if cp.returncode != 0:
                    raise CtlError(
                        f"cannot decrypt {s.secrets_bundle} with the available age key — "
                        f"refusing to modify the bundle"
                    )
                f.write(cp.stdout)
            data = yaml.safe_load(Path(plain).read_text()) or {}
            data.setdefault(section, {})
            if not isinstance(data[section], dict):
                data[section] = {}
            data[section][key] = value
            try:
                Path(plain).write_text(
                    yaml.safe_dump(data, default_flow_style=False, sort_keys=False)
                )
            except (UnicodeEncodeError, yaml.YAMLError):
                # A surrogate-bearing value (non-UTF-8 bytes from a bash-era
                # env file) must fail as an operator-facing message, not a
                # bare traceback mid-seal.
                raise CtlError(
                    f"cannot store {section}.{key}: the value contains bytes that are not "
                    f"valid UTF-8 — re-enter the credential (the bundle was NOT modified)"
                ) from None
            new_bundle = str(s.secrets_bundle) + ".new"
            cp = runner.run(
                ["sops", "-e", plain],
                env={"SOPS_AGE_RECIPIENTS": _bundle_recipients(runner)}, capture=True,
            )
            if cp.returncode != 0 or not cp.stdout:
                Path(new_bundle).unlink(missing_ok=True)
                raise CtlError(
                    f"re-encrypting {s.secrets_bundle} failed — the bundle was NOT modified"
                )
            fd = os.open(new_bundle, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
            # os.open's mode is umask-subject: from a umask-077 root shell
            # (the QUICKSTART's own instruction) the bundle would land 0600
            # and the rootless `files` backup could no longer read it —
            # breaking the bundle_init contract above (world-readable
            # ciphertext) until the next play/seal re-hardens. fchmod pins it.
            os.fchmod(fd, 0o644)
            with os.fdopen(fd, "w") as f:
                f.write(cp.stdout)
            os.replace(new_bundle, s.secrets_bundle)
        finally:
            with contextlib.suppress(OSError):
                os.unlink(plain)


def bundle_get(runner: Runner, section: str, key: str) -> str:
    """Extract one section.key from the bundle (raw value; '' when absent).
    Trailing newlines are stripped: some sops builds append one to --extract
    output, and a credential with an invisible trailing '\\n' fails auth in
    ways that are miserable to diagnose (multiline sections lose nothing —
    writers re-add the final newline)."""
    s = runner.settings
    if not bundle_available(runner):
        return ""
    with age_key(runner) as key_path:
        cp = runner.run(
            ["sops", "-d", "--extract", f'["{section}"]["{key}"]', str(s.secrets_bundle)],
            env={"SOPS_AGE_KEY_FILE": key_path}, capture=True,
        )
        return cp.stdout.rstrip("\n") if cp.returncode == 0 else ""


def bundle_decrypts(runner: Runner) -> bool:
    """Whole-bundle decrypt probe: True iff the bundle exists AND sops can
    decrypt it with the available age key. Lets callers distinguish a corrupt
    bundle / wrong-or-lost key (decrypt FAILS) from a merely-absent section
    (decrypt succeeds, `bundle_get` returns '') — a bare `bundle_get` == ''
    conflates the two and misdirects a DR operator toward 'no credentials'."""
    s = runner.settings
    if not bundle_available(runner):
        return False
    try:
        with age_key(runner) as key_path:
            return runner.run(
                ["sops", "-d", str(s.secrets_bundle)],
                env={"SOPS_AGE_KEY_FILE": key_path}, quiet=True,
            ).returncode == 0
    except CtlError:
        return False


# --- secrets render (the @INSTANCE@-secrets.service ExecStart) --------------------


def _assert_owned_by(p: Path, uid: int) -> None:
    """Render-ownership verification: the chowns above/below it
    are contextlib.suppress(OSError)-wrapped, so a failed chown used to leave
    a fragment (or the run-secrets dir) root-owned while the render reported
    SUCCESS — the rootless init containers then could not read it, the app
    came up refusing on the __SEALED__ placeholder, and nothing pointed back
    at the render. Verify the uid actually landed and fail loudly."""
    if os.stat(p).st_uid != uid:
        raise CtlError(
            f"secrets render: {p} is not owned by the service user (uid {uid}) "
            f"after chown — the rootless pod cannot read it and the app would "
            f"refuse to start on the __SEALED__ placeholder. Fix the ownership "
            f"boundary (SERVICE_USER wrong? userns/ACL?) and re-run "
            f"'carlos-ctl secrets render'."
        )


def cmd_secrets_render(runner: Runner) -> int:
    """Decrypt the bundle and materialize the per-app credential fragments
    into RUN_SECRETS_DIR (tmpfs — RAM only, repopulated every boot), owned by
    the service user so the rootless app initContainers can read them.

    Values are stored RAW in the bundle; the .properties fragments need the
    value side backslash-escaped (a lone '\\' otherwise starts a Java
    Properties escape), so each secret is re-escaped at materialization."""
    from .util import properties_escape_value

    s = runner.settings
    if not s.secrets_bundle.is_file():
        raise CtlError(f"no secrets bundle at {s.secrets_bundle}")
    with age_key(runner) as key_path:
        # Whole-bundle decrypt probe, FAIL-LOUD: this unit is only installed
        # by `seal` (the bundle existed and the key resolved then), so a
        # failed decrypt here is always an incident (rotated/lost key, TPM
        # change, corrupt bundle) — never a fresh-install state. Without this
        # probe the per-key extracts below swallow the failure, render zero
        # fragments, and exit 0: the unit reads green while the app starts on
        # __SEALED__ placeholders.
        probe = runner.run(
            ["sops", "-d", str(s.secrets_bundle)],
            env={"SOPS_AGE_KEY_FILE": key_path}, quiet=True,
        )
        if probe.returncode != 0:
            raise CtlError(
                f"FAILED to decrypt {s.secrets_bundle} with the available age key — no "
                f"credential fragment was rendered; the app would start on __SEALED__ "
                f"placeholders. Check the age key (TPM change? key rotated?) and the bundle "
                f"integrity."
            )

        def extract(section: str, key: str) -> str:
            cp = runner.run(
                ["sops", "-d", "--extract", f'["{section}"]["{key}"]', str(s.secrets_bundle)],
                env={"SOPS_AGE_KEY_FILE": key_path}, capture=True,
            )
            return cp.stdout if cp.returncode == 0 else ""

        uid = s.service_uid()
        s.run_secrets_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            os.chown(s.run_secrets_dir, uid, -1)

        _assert_owned_by(s.run_secrets_dir, uid)

        def fragment(filename: str, pairs: Dict[str, str]) -> None:
            p = s.run_secrets_dir / filename
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                for k, v in pairs.items():
                    f.write(f"{k}={properties_escape_value(v)}\n")
            with contextlib.suppress(OSError):
                os.chown(p, uid, -1)
            _assert_owned_by(p, uid)

        # carlos app db fragment (skip if the section has no password — a
        # partial bundle still renders whatever it does have).
        c_pass = extract("carlos", "db_password")
        if c_pass:
            fragment("carlos-db.properties", {
                "db_username": extract("carlos", "db_username"),
                "db_password": c_pass,
            })
        d_pass = extract("drugref", "db_password")
        if d_pass:
            fragment("drugref-db.properties", {
                "db_user": extract("drugref", "db_user"),
                "db_password": d_pass,
            })
    # Boot-time reap: shred any .new-* credential drop-file a rotation left
    # in the persistent private dir now that a fresh render has
    # re-materialized the live values into tmpfs.
    reap_credential_dropfiles(s)
    return 0


# --- seal --------------------------------------------------------------------------

_SECRETS_UNIT_TEMPLATE = """\
# SPDX-License-Identifier: AGPL-3.0-only
# Rendered and installed by `carlos-ctl seal` (one per pod-group). Decrypts the
# single-master SOPS+age secrets bundle and materializes the app db-credential
# fragments into {run_dir} (tmpfs — RAM only, repopulated every boot). The pod
# mounts that directory and each app container assembles base-config + fragment
# in its own tmpfs at start, so credentials never exist on disk in plaintext.
#
# This is a ROOT SYSTEM unit. The ONE age private key is TPM-sealed at rest;
# the render decrypts it ITSELF (systemd-creds decrypt inside ExecStart) —
# deliberately NOT via LoadCredentialEncrypted=, whose decrypt failure kills
# the unit BEFORE any code runs. Doing it in-process is what makes the
# attended fallback reachable: when the TPM unseal fails and `seal` wrote a
# passphrase-wrapped recovery copy of the key, the render prompts via
# systemd-ask-password (90 s timeout, console/password-agent) and unwraps it.
# No recovery file, no answer in time, or a no-TPM host without the 0600 key
# file: the unit still fails LOUD (OnFailure alert), exactly as before — the
# fallback never weakens unattended semantics into a hang.
# (The backup timers keep LoadCredentialEncrypted= drop-ins on purpose: a
# timer must never sit on a prompt; its TPM-failure mode stays alert-driven.)
# A bundle with no drugref section still renders the carlos fragment.
[Unit]
Description=CARLOS EMR {instance} app secrets -> /run tmpfs (SOPS+age single master)
After=local-fs.target
# Render the fragments before the service user's manager starts its pods.
Before=user@{service_uid}.service
# Alert on a failed decrypt (e.g. lost/!escrowed age key, sops missing) — this
# is a system unit, so a system alert template is valid here. The pod-side
# backstop is carlos-init's __SEALED__ fail-loud guard.
OnFailure={instance}-alert@%n.service

[Service]
Type=oneshot
RemainAfterExit=yes
# sops/age commonly install under /usr/local/bin; give the oneshot a full PATH
# rather than baking absolute tool paths at render time.
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=EMR_HOME={emr_home}
# The render resolves the age key itself: TPM-sealed credstore blob first
# (systemd-creds decrypt), else the 0600 {age_key_file} (no-TPM host), else
# the attended recovery passphrase (see the header comment). The opt-in below
# scopes console prompting to THIS unit — every other headless carlos-ctl
# context (backup timers above all) fails immediately instead of sitting on
# an ask-password timeout.
Environment=CARLOS_ATTENDED_RECOVERY=1
ExecStart=/usr/local/sbin/carlos-ctl secrets render
# Wipe the unsealed plaintext on stop so a `systemctl stop` (maintenance,
# decommission-without-reboot) doesn't leave DB credentials in the /run tmpfs.
ExecStop=/bin/rm -f {run_dir}/carlos-db.properties {run_dir}/drugref-db.properties
# Sweep any decrypted age-key tempfile the render staged in /run tmpfs
# (age.* / age-recovery.*). The render removes them in a finally block, but a
# SIGKILL (OOM, `systemctl kill -s KILL`) between the systemd-creds/openssl
# decrypt and that cleanup would otherwise orphan the plaintext master key in
# tmpfs until reboot. ExecStopPost runs even after a KILLED ExecStart. (This
# regains the systemd-managed cleanup that LoadCredentialEncrypted gave for
# free; the in-process decrypt is what makes the attended fallback reachable.)
# Instance-scoped globs: an unscoped /run/age.* also matched a SIBLING
# instance's in-flight decrypted key (multi-instance host), deleting it
# mid-render. (Pre-scoping tempfile names from an older install are not
# swept — they die with the tmpfs at reboot.)
ExecStopPost=/bin/sh -c 'rm -f /run/{instance}-age.* \
    /run/{instance}-age-recovery.* 2>/dev/null || true'

# Sandbox: the render decrypts the bundle and writes only under /run (the
# fragments tmpfs + transient age-key tempfiles); chown to the service user
# needs CAP_CHOWN, which NoNewPrivileges permits (no setuid involved).
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/run
# The bundle + age key are read from under {emr_home}; punch it through
# ProtectHome=yes (required if an operator puts EMR_HOME under /home or /root).
ReadOnlyPaths={emr_home}
# ...but the reap of leftover .new-* cleartext credential drop-files (see
# reap_credential_dropfiles) must WRITE there — a nested ReadWritePaths wins
# over the ReadOnlyPaths above (longest-prefix), and the leading '-' tolerates
# the dir not existing yet on a never-rotated install.
ReadWritePaths=-{emr_home}/secrets-private

[Install]
WantedBy=multi-user.target
"""


def _recovery_passphrase_from_file(runner: Runner) -> Optional[str]:
    """Read + validate CARLOS_RECOVERY_PASSPHRASE_FILE (first line, >= 12
    chars), or None when the knob is unset. Deterministic and side-effect
    free, so cmd_seal calls it in PREFLIGHT — a bad headless passphrase file
    must refuse BEFORE seal shreds the plaintext key, not mid-mutation."""
    s = runner.settings
    pf = s.get("CARLOS_RECOVERY_PASSPHRASE_FILE")
    if not pf:
        return None
    try:
        passphrase = Path(pf).read_text().splitlines()[0]
    except (OSError, IndexError):
        raise CtlError(
            f"CARLOS_RECOVERY_PASSPHRASE_FILE={pf} is unreadable or empty"
        ) from None
    if len(passphrase) < 12:
        raise CtlError(
            "the attended-recovery passphrase must be at least 12 characters — the "
            "wrapped key is an offline-crackable artifact; do not weaken it"
        )
    return passphrase


def _maybe_write_recovery_wrap(runner: Runner) -> None:
    """Write/refresh the attended-recovery copy of the age key: the SAME key,
    wrapped with an operator passphrase (openssl AES-256-CBC, PBKDF2). Skips
    with guidance when no passphrase is offered — the recovery slot is
    optional, and its absence keeps today's fail-loud-only behavior. Never
    leaves a half-written or unverifiable wrap behind."""
    s = runner.settings
    passphrase = _recovery_passphrase_from_file(runner) or ""
    if not passphrase and sys.stdin.isatty():
        for _ in range(2):
            p1 = getpass.getpass(
                "Attended-recovery passphrase (typed at the console if the TPM unseal "
                "ever fails; >= 12 chars; Enter to skip): ")
            if not p1:
                break
            if len(p1) < 12:
                warn("too short (< 12 chars) — try again or Enter to skip")
                continue
            p2 = getpass.getpass("Repeat the recovery passphrase: ")
            if p1 != p2:
                warn("passphrases did not match — try again or Enter to skip")
                continue
            passphrase = p1
            break
    if not passphrase:
        if s.age_key_recovery_file.is_file():
            log(f"Keeping the existing attended-recovery wrap "
                f"({s.age_key_recovery_file}); delete it to disable the fallback")
        else:
            log("No attended-recovery passphrase set — a TPM unseal failure will fail "
                "loud and need the ESCROWED age key (set one on a future 'seal', or "
                "headless via CARLOS_RECOVERY_PASSPHRASE_FILE)")
        return
    rec = s.age_key_recovery_file
    # Write to a STAGING file and atomically os.replace it in only after the
    # round-trip verify passes — same discipline as bundle_set. Writing openssl
    # -out straight to `rec` truncated a previously-good wrap the instant a
    # re-seal's openssl/verify hit a transient error, silently revoking a
    # working recovery slot the operator still believed they had.
    staging = rec.with_name(rec.name + ".new")
    with age_key(runner) as kp:
        key_text = Path(kp).read_text()
        cp = runner.run(
            ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", _RECOVERY_KDF_ITER,
             "-salt", "-pass", "stdin", "-in", kp, "-out", str(staging)],
            input_text=passphrase + "\n", quiet=True)
    if cp.returncode != 0:
        staging.unlink(missing_ok=True)
        raise CtlError("openssl failed to write the attended-recovery wrap")
    staging.chmod(0o600)
    # VERIFY-BEFORE-TRUST, same discipline as _seal_one: a wrap that cannot
    # unwrap back to the key would advertise a recovery slot that dies in the
    # operator's hands during the actual incident. Verify the STAGING file, so
    # a failure leaves any existing good wrap untouched.
    back = _run_tmpfile(f"{runner.settings.instance}-age-recovery-verify.", root_required=True)
    try:
        cp = runner.run(
            ["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2",
             "-iter", _RECOVERY_KDF_ITER, "-pass", "stdin",
             "-in", str(staging), "-out", back],
            input_text=passphrase + "\n", quiet=True)
        ok = cp.returncode == 0
        if ok:
            try:
                ok = Path(back).read_text() == key_text
            except OSError:
                ok = False
        if not ok:
            staging.unlink(missing_ok=True)
            raise CtlError(
                "attended-recovery wrap verification FAILED (decrypt did not round-trip "
                "to the age key) — the staging wrap was discarded and any existing wrap "
                "left intact; re-run 'carlos-ctl seal'"
            )
    finally:
        with contextlib.suppress(OSError):
            os.unlink(back)
    os.replace(staging, rec)
    log(f"Attended-recovery wrap written -> {rec} (passphrase unwrap round-trip "
        f"verified). ESCROW of the age key remains mandatory — the wrap only covers "
        f"TPM failure on THIS host.")


def _seal_one(runner: Runner, name: str, file: Path) -> None:
    """Encrypt one plaintext file into the TPM credstore and shred the source
    — with a round-trip verify BEFORE shredding the only on-host plaintext: a
    silent bad seal (e.g. a TPM policy that can encrypt but not later unseal)
    would otherwise destroy the sole recoverable copy."""
    s = runner.settings
    if not file.is_file():
        return
    cred = s.credstore_dir / f"{name}.cred"
    cp = runner.run(["systemd-creds", "encrypt", f"--name={name}", str(file), str(cred)])
    if cp.returncode != 0:
        raise CtlError(f"systemd-creds encrypt failed for {name}")
    cred.chmod(0o600)
    back = runner.run(
        ["systemd-creds", "decrypt", f"--name={name}", str(cred), "-"], capture=True
    )
    if back.returncode != 0 or back.stdout != file.read_text():
        cred.unlink(missing_ok=True)
        raise CtlError(
            f"seal verification FAILED for {name} — the sealed blob did not decrypt back to "
            f"{file}. REFUSING to shred the plaintext (it is the only on-host copy). Check "
            f"the TPM/systemd-creds state and retry."
        )
    _shred(runner, file)
    log(f"Sealed {file} -> {cred} (decrypt round-trip verified)")


def _shred(runner: Runner, file: Path) -> None:
    if runner.have("shred"):
        if runner.ok(["shred", "-u", str(file)]):
            return
    # Fell through to a plain unlink: on a real filesystem the plaintext
    # secret bytes may remain recoverable. Warn so the operator knows the
    # at-rest wipe was best-effort (install `shred`, or rely on LUKS).
    warn(f"shred unavailable/failed for {file} — removed with a plain unlink; the "
         f"plaintext may be recoverable on disk (install shred, or ensure the volume "
         f"is LUKS-encrypted)")
    file.unlink(missing_ok=True)


def _seal_migrate_legacy(runner: Runner) -> None:
    """One-time migration from a pre-SOPS install: decrypt any legacy
    per-fragment systemd-creds blobs into the bundle, then remove them.
    PERSIST-BEFORE-DESTROY: each legacy .cred is the ONLY copy of its secret —
    a failed/empty decrypt keeps the .cred in place and warns.

    VESTIGIAL: the bash carlos-ctl that sealed these per-fragment blobs was
    never deployed, so no such blob exists in the wild — this path no-ops on
    every real install and is a candidate for retirement. The decrypts pass
    --name (matching _seal_one's convention, the only sealer this repo has
    ever had) so that if a blob does surface it decrypts instead of tripping
    systemd-creds' embedded-name/filename mismatch refusal."""
    s = runner.settings
    if not runner.have("systemd-creds"):
        return
    for name, section in ((s.cred_db_fragment, "carlos"), (s.cred_drugref_fragment, "drugref")):
        cred = s.credstore_dir / f"{name}.cred"
        if not cred.is_file():
            continue
        cp = runner.run(
            ["systemd-creds", "decrypt", f"--name={name}", str(cred), "-"],
            capture=True)
        if cp.returncode != 0 or not cp.stdout:
            warn(
                f"could not decrypt legacy {name}.cred — KEEPING it in place (nothing was "
                f"migrated); fix systemd-creds/TPM access and re-run 'carlos-ctl seal'"
            )
            continue
        # carlos/drugref fragments were "key=escaped-value" pairs.
        for line in cp.stdout.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                if k:
                    bundle_set(runner, section, k, properties_unescape_value(v))
        cred.unlink(missing_ok=True)
        log(f"Migrated legacy {name}.cred into the bundle")
    for name, section in ((s.cred_restic, "restic"), (s.cred_backup_db, "backup_db")):
        cred = s.credstore_dir / f"{name}.cred"
        if not cred.is_file():
            continue
        cp = runner.run(
            ["systemd-creds", "decrypt", f"--name={name}", str(cred), "-"],
            capture=True)
        if cp.returncode != 0 or not cp.stdout:
            warn(
                f"could not decrypt legacy {name}.cred — KEEPING it in place (nothing was "
                f"migrated); fix systemd-creds/TPM access and re-run 'carlos-ctl seal'"
            )
            continue
        # restic/backup-db blobs were whole env files -> store wholesale.
        bundle_set(runner, section, "env", cp.stdout)
        cred.unlink(missing_ok=True)
        log(f"Migrated legacy {name}.cred into the bundle")


def cmd_seal(runner: Runner) -> int:
    from .util import first_match

    s = runner.settings
    for tool, why in (
        ("sops", "required to encrypt the single-master secrets bundle (install sops)"),
        ("age", "required for the bundle's age recipient (install age)"),
        ("age-keygen", "not found (ships with age)"),
    ):
        if not runner.have(tool):
            raise CtlError(f"{tool} not found — {why}")
    # PREFLIGHT the headless recovery passphrase (deterministic, side-effect
    # free) BEFORE any mutation: _maybe_write_recovery_wrap runs LATE (after
    # the key is TPM-sealed and the plaintext shredded), so an unreadable /
    # too-short CARLOS_RECOVERY_PASSPHRASE_FILE must fail HERE, not leave a
    # half-sealed instance with no boot-render unit installed.
    _recovery_passphrase_from_file(runner)
    s.credstore_dir.mkdir(parents=True, exist_ok=True)
    ensure_age_key(runner)
    if not s.age_pub_file.is_file():
        raise CtlError(f"no age recipient ({s.age_pub_file}) — run the provisioning playbook first")
    # Re-pin conf/secrets to root before we scrape recipients / re-encrypt, so
    # a service-user-writable bundle from a pre-hardening install can't steer
    # the re-encryption recipient set.
    harden_secrets_ownership(runner)

    # TPM is OPTIONAL: it protects the age key AT REST for unattended boot,
    # but portable DR (restore on ANY hardware) means the key must also be
    # escrowed off-host. A TPM-less host keeps the key as a 0600 file — refuse
    # unless the operator explicitly accepts rely-on-LUKS at-rest protection.
    have_tpm = runner.have("systemd-creds") and runner.ok(["systemd-creds", "has-tpm2"])
    if not have_tpm:
        if not s.flag("CARLOS_SEAL_NO_TPM"):
            raise CtlError(
                f"no usable TPM2 — sealing here would leave the age private key "
                f"({s.age_key_file}) as a plaintext 0600 file at rest (protected only by "
                f"LUKS full-disk encryption, which is NOT verified). Set CARLOS_SEAL_NO_TPM=1 "
                f"to accept rely-on-LUKS at-rest protection (off-host escrow of the key "
                f"remains mandatory)."
            )
        warn(
            f"no usable TPM2 — the age private key stays a 0600 file ({s.age_key_file}); "
            f"relying on LUKS full-disk encryption for at-rest protection "
            f"(CARLOS_SEAL_NO_TPM=1). The OFF-HOST escrow of that key remains mandatory — "
            f"it is the only recovery path if this host is lost"
        )

    # Escrow gate FIRST (before any mutation). TWO things must exist off-host
    # before seal may shred the plaintext copies, because recovery is
    # otherwise CIRCULAR: the age private key decrypts every secret, but the
    # bundle holding the restic credentials rides INSIDE the restic repo —
    # after a host loss you cannot reach or open the repo without the
    # restic.env content, and that content lives only in the repo you are
    # locked out of. The escrow-confirmation marker lives in the ROOT-ONLY
    # private dir, NOT conf/secrets: a marker in a service-user-reachable dir
    # could be pre-created by a compromised app user to suppress this
    # data-loss prompt.
    s.secrets_private_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    escrow_marker = s.secrets_private_dir / ".age-escrow-confirmed"
    legacy_marker = s.secrets_dir / ".age-escrow-confirmed"
    if legacy_marker.is_file() and not escrow_marker.is_file():
        with contextlib.suppress(OSError):
            escrow_marker.write_text(legacy_marker.read_text())
            escrow_marker.chmod(0o600)
            legacy_marker.unlink()
    # Fallback CHAIN, not OR (bash ${AGE_ESCROW_CONFIRMED:-${RESTIC_...:-}}):
    # an explicit AGE_ESCROW_CONFIRMED=0 must refuse even when the legacy
    # alias is set to 1 — the operator's most specific answer wins.
    ack = s.get("AGE_ESCROW_CONFIRMED") or s.get("RESTIC_ESCROW_CONFIRMED")
    env_confirmed = ack == "1"
    if s.age_key_file.is_file() and not escrow_marker.is_file() and not env_confirmed:
        if sys.stdin.isatty():
            ans = input(
                f"Disaster recovery needs TWO things escrowed OFF-HOST: (1) the age private "
                f"key ({s.age_key_file}) and (2) the full restic.env content (RESTIC_PASSWORD, "
                f"repository URL, any offsite-backend credentials) — seal shreds the on-host "
                f"plaintext of both. Have you copied BOTH to safe off-host storage? "
                f"Type 'yes' to proceed: "
            )
            if ans != "yes":
                raise CtlError(
                    f"escrow not confirmed — copy {s.age_key_file} and the restic.env content "
                    f"off-host first, then re-run 'carlos-ctl seal'"
                )
        else:
            raise CtlError(
                f"refusing to seal non-interactively: copy the age private key "
                f"({s.age_key_file}) AND the full restic.env content off-host, then set "
                f"AGE_ESCROW_CONFIRMED=1 (RESTIC_ESCROW_CONFIRMED=1 is accepted as an alias)"
            )
    if s.age_key_file.is_file() and not escrow_marker.is_file():
        with contextlib.suppress(OSError):
            import datetime

            escrow_marker.write_text(
                datetime.datetime.now(datetime.timezone.utc).isoformat() + "\n"
            )
            escrow_marker.chmod(0o600)

    # Fold any pre-SOPS install's legacy sealed blobs into the bundle (no-op
    # on greenfield), then ensure the bundle exists.
    _seal_migrate_legacy(runner)
    bundle_init(runner)

    # Ingest all reversible secrets (RAW) into the one bundle; leave a
    # __SEALED__ placeholder in the editable base properties (unchanged
    # initContainer contract). db-values are un-escaped back to raw.
    for props, section, user_key in (
        (s.properties_file, "carlos", "db_username"),
        (s.drugref_properties_file, "drugref", "db_user"),
    ):
        if not props.is_file():
            continue
        lines = props.read_text().splitlines()
        if any(line.startswith("db_password=__SEALED__") for line in lines):
            continue
        u = first_match(lines, user_key) or ""
        p = properties_unescape_value(first_match(lines, "db_password") or "")
        bundle_set(runner, section, user_key, u)
        bundle_set(runner, section, "db_password", p)
        set_kv(props, "db_password", "__SEALED__")
        log(f"Ingested {section} db credentials into the bundle "
            f"({props.name} keeps a __SEALED__ placeholder)")
    # DISASTER RECOVERY: ingest the MariaDB root password so a rebuild can
    # recover it (the nightly `files` backup carries only the SECRETS-STRIPPED
    # carlos-app.env.dr).
    if s.get("CARLOS_DB_ROOT_PASSWORD"):
        bundle_set(runner, "carlos", "db_root_password", s.get("CARLOS_DB_ROOT_PASSWORD"))
    # restic.env / backup-db.env are consumed wholesale (parsed by the backup
    # verb), so store each file's WHOLE content under one key — extra
    # offsite-backend vars survive for free.
    restic_env = s.conf_dir / "restic" / "restic.env"
    backup_db_env = s.conf_dir / "restic" / "backup-db.env"
    if restic_env.is_file():
        bundle_set(runner, "restic", "env", restic_env.read_text())
    if backup_db_env.is_file():
        bundle_set(runner, "backup_db", "env", backup_db_env.read_text())
    if s.exporter_mycnf_file.is_file():
        ex = ""
        for line in s.exporter_mycnf_file.read_text().splitlines():
            if line.startswith("password = "):
                ex = line[len("password = "):]
                break
        # Skip the fail-closed placeholder: a seal performed BEFORE db-users
        # would otherwise ingest the useless "__UNPROVISIONED__" string as the
        # exporter password. db-users writes the real value and re-seals.
        if ex and ex != "__UNPROVISIONED__":
            bundle_set(runner, "exporter", "password", properties_unescape_value(ex))
    if not bundle_available(runner):
        raise CtlError("nothing to seal — run the provisioning playbook / 'db-users' first")

    # Protect the age key at rest (TPM) + shred the now-ingested plaintext env
    # files. On a no-TPM host the age key stays the 0600 file (LUKS at-rest).
    if have_tpm:
        _seal_one(runner, s.cred_age, s.age_key_file)
        # Attended-recovery slot (the LUKS "extra key slot" model, applied
        # here): a passphrase-wrapped copy of the same age key, so a TPM/PCR
        # change degrades to a console prompt instead of an outage. Optional;
        # meaningful only on TPM hosts (a no-TPM host already keeps the 0600
        # key file). Runs AFTER _seal_one on purpose: the key material is
        # re-read through age_key() (TPM path — just round-trip-verified), so
        # this also works on a RE-seal where the plaintext file is long gone.
        _maybe_write_recovery_wrap(runner)
    # VERIFY-BEFORE-SHRED: _shred'ing restic.env/backup-db.env
    # after bundle_set — WITHOUT confirming the bundle actually decrypts back
    # to their content — would, on an age recipient/key mismatch (a stale
    # age.pub from an earlier keypair), destroy the ONLY on-host restic
    # credentials, leaving recovery to the off-host escrow alone. Prove the
    # round-trip first; refuse the shred (files intact) if it fails.
    for f, section in ((restic_env, "restic"), (backup_db_env, "backup_db")):
        if not f.is_file():
            continue
        if bundle_get(runner, section, "env").rstrip("\n") != f.read_text().rstrip("\n"):
            raise CtlError(
                f"refusing to shred {f}: the sealed bundle does NOT decrypt back to its "
                f"content (age recipient/key mismatch? stale age-recipient.pub?). The "
                f"plaintext is LEFT INTACT — fix the age keypair and re-run 'carlos-ctl "
                f"seal' before this file is the only copy."
            )
        _shred(runner, f)
    # Legacy .bak copies (pre-fix set_kv kept a rolling backup) can still hold
    # LIVE plaintext passwords that would outlive the seal — shred them too.
    for bak in (
        Path(str(s.properties_file) + ".bak"),
        Path(str(s.drugref_properties_file) + ".bak"),
        Path(str(restic_env) + ".bak"), Path(str(backup_db_env) + ".bak"),
        Path(str(s.exporter_mycnf_file) + ".bak"),
    ):
        if bak.is_file():
            _shred(runner, bak)

    # Install the secrets service: boot-time render via `carlos-ctl secrets
    # render`, which resolves the age key itself (TPM blob -> 0600 file ->
    # attended recovery). Deliberately NO LoadCredentialEncrypted here — its
    # decrypt failure would kill the unit before the render's attended
    # fallback could run (see the unit template header).
    cred_file = s.credstore_dir / f"{s.cred_age}.cred"
    unit_path = s.systemd_dir / f"{s.instance}-secrets.service"
    log(f"Installing {unit_path}")
    s.systemd_dir.mkdir(parents=True, exist_ok=True)
    unit_path.write_text(_SECRETS_UNIT_TEMPLATE.format(
        instance=s.instance, service_uid=s.service_uid(), emr_home=s.emr_home,
        run_dir=s.run_secrets_dir, age_key_file=s.age_key_file,
    ))
    unit_path.chmod(0o644)
    # Backup timers get the same ONE age credential (they decrypt the bundle
    # to resolve restic + backup-db creds just-in-time).
    for svc in (f"{s.instance}-backup", f"{s.instance}-binlog", f"{s.instance}-docs",
                f"{s.instance}-backup-verify"):
        dropin = s.systemd_dir / f"{svc}.service.d"
        dropin.mkdir(parents=True, exist_ok=True)
        content = "[Service]\n"
        if have_tpm and cred_file.is_file():
            content += f"LoadCredentialEncrypted={s.cred_age}:{cred_file}\n"
        (dropin / "credentials.conf").write_text(content)
    # NOTE: the app pod is a USER unit in the service user's manager, which
    # cannot order against this ROOT system secrets unit — boot ordering is
    # the secrets unit's own Before=user@<uid>.service, and the failure mode
    # is caught LOUDLY at pod start by carlos-init's __SEALED__ guard.
    if runner.systemd_running():
        # Fail LOUD (the bash ran these bare under `set -e`): a seal that
        # shredded the plaintext but silently failed to enable/start the
        # render unit leaves the app to die on __SEALED__ placeholders at the
        # next restart with a green seal in the operator's terminal. Every
        # seal mutation is durable and idempotent — fixing the unit and
        # re-running is always safe.
        for argv, what in (
            (["systemctl", "daemon-reload"], "daemon-reload"),
            (["systemctl", "enable", f"{s.instance}-secrets.service"], "enable"),
            (["systemctl", "restart", f"{s.instance}-secrets.service"], "start"),
        ):
            if runner.run(argv, quiet=True).returncode != 0:
                raise CtlError(
                    f"systemctl {what} failed for {s.instance}-secrets.service — the sealed "
                    f"credential fragments will NOT materialize at boot (the app would start "
                    f"on __SEALED__ placeholders). The seal itself is complete; fix the unit "
                    f"(journalctl -u {s.instance}-secrets.service) and re-run 'carlos-ctl "
                    f"seal' (idempotent)."
                )
    else:
        # No systemctl (the documented no-systemd fallback): the unit above is
        # inert, so the render that the seal just made MANDATORY would never
        # run — and `seal` has already shredded the plaintext and left
        # db_password=__SEALED__ in both properties files. Silence here meant a
        # green seal followed by an app that refuses to start at its next
        # restart. Do the render inline (this is the unit's ExecStart) and name
        # the standing boot requirement.
        log("no usable systemd — rendering the sealed credential fragments inline "
            "(the installed unit cannot be started on this host)")
        try:
            cmd_secrets_render(runner)
        except CtlError as e:
            warn(
                f"inline secrets render FAILED after sealing ({e}) — the app will start "
                f"on the __SEALED__ placeholder and refuse to run. Fix the age key/bundle "
                f"and run 'carlos-ctl secrets render'."
            )
        warn(
            f"no systemd on this host: NOTHING re-renders {s.run_secrets_dir} (tmpfs) at "
            f"boot — run 'carlos-ctl secrets render' from your boot scheduler BEFORE the "
            f"pods start, or the app dies on its __SEALED__ guard"
        )
    at_rest = "TPM-sealed at rest" if have_tpm else "a 0600 file — use LUKS"
    # Reap any .new-* credential drop-file a prior rotation left in the
    # persistent private dir — sealing is a natural checkpoint.
    reap_credential_dropfiles(s)
    log(f"Secrets consolidated into {s.secrets_bundle} (SOPS+age single master); "
        f"the age key is {at_rest}")
    warn(
        "KEEP your OFF-HOST escrow of the age private key AND the restic.env content "
        "(repo URL + password + backend credentials) — together they are the only recovery "
        "path on new hardware: the key opens the secrets, the restic credentials reach and "
        "open the backup repo that carries them"
    )
    return 0


# --- rotation ------------------------------------------------------------------------


def need_db_password(runner: Runner) -> str:
    """The MariaDB root password: from settings, else an interactive prompt.
    Deliberately NOT persisted here — this helper also serves one-off
    break-glass verbs, where silently storing an ad-hoc (possibly mistyped)
    value would poison every later run."""
    s = runner.settings
    pw = s.get("CARLOS_DB_ROOT_PASSWORD")
    if not pw:
        if sys.stdin.isatty():
            pw = getpass.getpass(
                "MariaDB root password (existing DBs: the password already in use): "
            )
        else:
            raise CtlError(f"CARLOS_DB_ROOT_PASSWORD is not set (set it in {s.env_file})")
    validate_db_password(pw, "the MariaDB root password")
    return pw


def preflight_reseal(runner: Runner) -> None:
    """Called BEFORE credential-mutating paths that touch the sealed bundle:
    every refusal cmd_seal/bundle_set would raise must fire HERE, while
    nothing has changed — discovering it AFTER the DB and plaintext files
    were re-passworded leaves the bundle holding the OLD credentials, which
    the boot-time render re-materializes into /run (app auth failure at the
    next reboot)."""
    s = runner.settings
    if not bundle_available(runner):
        return
    # The seal toolchain itself: cmd_seal hard-fails on these first.
    for tool in ("sops", "age", "age-keygen"):
        if not runner.have(tool):
            raise CtlError(
                f"this install is SEALED but '{tool}' is not on PATH — the "
                f"post-rotation re-seal would refuse AFTER the passwords were already "
                f"changed, stranding a stale bundle. Install {tool}, then re-run."
            )
    have_tpm = runner.have("systemd-creds") and runner.ok(["systemd-creds", "has-tpm2"])
    if not have_tpm and not s.flag("CARLOS_SEAL_NO_TPM"):
        raise CtlError(
            "this install is SEALED but the host has no usable TPM2 and "
            "CARLOS_SEAL_NO_TPM=1 is not set — the post-rotation re-seal would refuse "
            "AFTER the passwords were already changed, leaving the sealed bundle stale "
            "(old credentials re-materialize at the next boot). Set CARLOS_SEAL_NO_TPM=1 "
            "to accept rely-on-LUKS at-rest protection, then re-run."
        )
    # The escrow-confirmation gate cmd_seal enforces. Its marker
    # lives in secrets_private_dir, which is deliberately EXCLUDED from
    # backups — so a DR-rebuilt host never has it, and a non-interactive
    # `rotate` would re-password the DB and THEN hit the seal's escrow
    # refusal, stranding a stale bundle. Pre-check the exact same condition
    # here (marker OR env ack OR an interactive tty that can answer).
    escrow_ok = (
        (s.secrets_private_dir / ".age-escrow-confirmed").is_file()
        or (s.secrets_dir / ".age-escrow-confirmed").is_file()
        or (s.get("AGE_ESCROW_CONFIRMED") or s.get("RESTIC_ESCROW_CONFIRMED")) == "1"
        or sys.stdin.isatty()
    )
    if s.age_key_file.is_file() and not escrow_ok:
        raise CtlError(
            "this install is SEALED but off-host escrow is not confirmed for a "
            "non-interactive run (no .age-escrow-confirmed marker — expected on a "
            "DR-rebuilt host, since it is excluded from backups — and no "
            "AGE_ESCROW_CONFIRMED=1). The post-rotation re-seal would refuse AFTER the "
            "passwords changed, leaving a stale bundle. Confirm your off-host escrow of "
            "the age key + restic.env and set AGE_ESCROW_CONFIRMED=1, then re-run."
        )


def create_db_secret(runner: Runner, password_hash: str) -> None:
    """(Re)create the db-root-password podman secret from a
    mysql_native_password hash."""
    s = runner.settings
    manifest = (
        "apiVersion: v1\n"
        "kind: Secret\n"
        "metadata:\n"
        f"  name: {s.db_secret}\n"
        "data:\n"
        f"  mariadb-root-password-hash: "
        f"{base64.b64encode(password_hash.encode()).decode()}\n"
    )
    # Fail loud: the caller may have just `secret rm`'d the old secret, so a
    # silently failed re-create leaves NO db-root secret for the next empty-
    # datadir bootstrap — discovered only when that bootstrap fails.
    if runner.podman_user(["kube", "play", "-"], input_text=manifest).returncode != 0:
        raise CtlError(
            f"failed to (re)create the '{s.db_secret}' podman secret — recreate it before "
            f"the next empty-datadir bootstrap (re-run this rotation, or the provisioning "
            f"playbook)"
        )


def _rotate_db(runner: Runner, args: List[str]) -> int:
    """App-tier DB accounts (carlos/drugref/backup): same idempotent
    provisioning as db-users with fresh passwords. The app pod is bounced
    automatically afterwards: without it the running app keeps authenticating
    with the OLD password and fails as its pooled connections recycle."""
    from . import dbops

    s = runner.settings
    do_restart = True
    if args == ["--no-restart"]:
        do_restart = False
    elif args:
        raise CtlError("usage: carlos-ctl rotate db [--no-restart]")
    dbops.require_provisioning_prereqs(runner)
    from .util import first_match

    current = first_match(s.properties_file.read_text().splitlines(), "db_username")
    if current == "root":
        raise CtlError(
            "app still runs as db root — provision least-privilege accounts first: "
            "carlos-ctl db-users"
        )
    if not dbops.provision_db_accounts(runner):
        raise CtlError(
            "rotation aborted AFTER the DB accounts were re-passworded — see the warnings "
            "above for the recovery path"
        )
    if do_restart:
        dbops.restart_app_and_waf(runner)
    else:
        log(
            "--no-restart: apply the rotated credentials with 'carlos-ctl play' (or restart "
            "the app pod) BEFORE the app's pooled connections recycle"
        )
    return 0


def _rotate_db_root(runner: Runner) -> int:
    """MariaDB root: ALTER USER inside the db container, then refresh the
    podman secret (only consulted when bootstrapping an EMPTY datadir, so a
    deferred secret refresh is not urgent)."""
    from . import dbops

    s = runner.settings
    runner.require_db_running()
    # Sealed installs sync the new password into the bundle below — prove
    # that CAN succeed before ALTER USER runs (a bundle_set refusal after the
    # mutation could leave a generated password recorded nowhere).
    preflight_reseal(runner)
    old_pw = need_db_password(runner)
    # require_db_running only proves the container NAME is in `podman ps`.
    # `rotate db` RESTARTS the app pod, so the documented back-to-back
    # rotation (`rotate db` then `rotate db-root`) hit a db that was Up but
    # not yet accepting connections — and the ALTER's generic failure was
    # reported as "is the current CARLOS_DB_ROOT_PASSWORD correct?", sending
    # the operator to hunt a credential problem that did not exist (measured
    # live). Wait for the server to actually answer, and keep the probe's own
    # stderr so the two causes stay distinguishable.
    ready, probe_err = dbops.wait_db_accepting(
        runner, old_pw, s.get_int_or("CARLOS_DB_READY_SECONDS", 120)
    )
    if not ready:
        raise CtlError(
            "MariaDB is not accepting root connections"
            + (f" ({probe_err})" if probe_err else "")
            + " — nothing was changed. If the pod was just restarted (a preceding "
              "'rotate db' does that), wait for it to finish starting and re-run; "
              "if this is an authentication failure, the stored "
              "CARLOS_DB_ROOT_PASSWORD no longer matches the server."
        )
    new_pw = s.get("CARLOS_DB_NEW_ROOT_PASSWORD")
    show_pw = False
    if not new_pw:
        new_pw = pysecrets.token_hex(16)
        show_pw = True
    validate_db_password(new_pw, "the new MariaDB root password")
    sql_pw = sql_escape(new_pw)
    log("Changing the MariaDB root password")
    # sql_log_bin=0: the root ALTER USER must NOT enter the binlog chain, or a
    # windowed PITR restore (or the restore drill) replays it and rewinds root
    # to a stale generation — the credential store then holds the new password
    # while mysql.user holds the old, a root lockout.
    sql = (
        f"SET SESSION sql_log_bin = 0;\n"
        f"ALTER USER IF EXISTS 'root'@'localhost' IDENTIFIED BY '{sql_pw}';\n"
        f"ALTER USER IF EXISTS 'root'@'127.0.0.1' IDENTIFIED BY '{sql_pw}';\n"
        f"ALTER USER IF EXISTS 'root'@'%' IDENTIFIED BY '{sql_pw}';\n"
        f"FLUSH PRIVILEGES;\n"
    )
    # MYSQL_PWD forwarded by NAME (a bare `-e MYSQL_PWD`) — off the argv;
    # runuser preserves the environment across the rootless boundary.
    # quiet=True (matching the provisioning path): a client parse error
    # echoes the failing statement's `near '...'` context, which for an
    # operator-supplied CARLOS_DB_NEW_ROOT_PASSWORD could carry the NEW
    # plaintext root password into journald.
    cp = runner.podman_user(
        ["exec", "-i", "-e", "MYSQL_PWD", f"{s.app_pod}-db", "mariadb", "-uroot"],
        input_text=sql, env={"MYSQL_PWD": old_pw}, quiet=True,
    )
    if cp.returncode != 0:
        raise CtlError("ALTER USER failed — is the current CARLOS_DB_ROOT_PASSWORD correct?")
    # EMIT-EARLY: the instant ALTER USER succeeds, a GENERATED
    # password exists only in this process — any failure below (secret
    # refresh, an ENOSPC inside set_kv's staging, the bundle sync) would
    # otherwise strand MariaDB root on a value known to nobody, recoverable
    # only via a skip-grant-tables restart of the production DB. Surface it
    # FIRST; everything after is persistence best-effort on top.
    if show_pw:
        emit_secret(
            s,
            f"new MariaDB root password: {new_pw}", new_pw, "mariadb-root-password",
        )
        warn(
            "store it in your password manager NOW — it is kept nowhere on this host "
            "(only its hash is)"
        )
    if runner.ok(runner.podman_user_argv(["secret", "rm", s.db_secret])):
        # MUST NOT abort the rotation here: ALTER USER already ran, and the
        # new password is not yet persisted (env file / bundle) or emitted —
        # dying now would strand a root password that exists NOWHERE. The
        # secret is only consulted when bootstrapping an EMPTY datadir, so a
        # deferred re-create is recoverable; a lost password is not.
        try:
            create_db_secret(runner, native_password_hash(new_pw))
            log(f"db-root secret '{s.db_secret}' refreshed")
        except CtlError as e:
            warn(f"{e} — continuing the rotation so the new password is persisted")
    else:
        warn(
            f"db-root secret '{s.db_secret}' is in use and was NOT refreshed — after the "
            f"next 'carlos-ctl down', re-run the provisioning playbook to recreate it (it "
            f"only bootstraps an empty datadir, so this can wait)"
        )
    # Keep the env file coherent with the DB: a stale stored root password
    # desyncs every later provisioning/rotation/admin path.
    if s.env_file.is_file() and any(
        line.startswith("CARLOS_DB_ROOT_PASSWORD=") and len(line.split("=", 1)[1]) > 0
        for line in s.env_file.read_text().splitlines()
    ):
        set_kv(s.env_file, "CARLOS_DB_ROOT_PASSWORD", percent_q(new_pw))
        s.env_file.chmod(0o600)
        log(f"Updated CARLOS_DB_ROOT_PASSWORD in {s.env_file} to the new password")
        warn(
            f"{s.env_file.name} is PLAYBOOK-OWNED: update carlos_db_root_password in this "
            f"instance's host_vars (ansible-vault) too, or the next playbook run re-renders "
            f"the OLD password and desyncs every later provisioning/rotation/admin path"
        )
    # (The generated password was already emitted right after ALTER USER —
    # see the EMIT-EARLY block above.)
    # Keep the DR copy in the sealed bundle in sync so a disaster-recovery
    # restore never recovers a stale root password.
    if bundle_available(runner):
        bundle_set(runner, "carlos", "db_root_password", new_pw)
        log("Refreshed the db root password in the sealed bundle")
    return 0


def _rotate_caddy_password(runner: Runner, user: str, label: str, new_pw: str) -> int:
    """Caddy basic_auth credentials (log view): rewrite only the credential
    line for the given user inside a basic_auth block so local Caddyfile
    edits survive, then restart Caddy. The bcrypt hash is computed IN-PROCESS
    (python3-bcrypt) — the bash needed a one-shot caddy container with the
    plaintext on stdin; Caddy verifies $2b$ hashes fine."""
    import bcrypt

    s = runner.settings
    if not s.obs_enabled:
        raise CtlError(
            "the log view runs in the observability pod, which is disabled "
            "(OBS_ENABLED=0 / carlos_obs_enabled: false) — enable it in the playbook "
            "host_vars and re-provision first"
        )
    caddyfile = s.conf_dir / "caddy" / "Caddyfile"
    if not caddyfile.is_file():
        raise CtlError(f"no {caddyfile} — run the provisioning playbook first")
    show_pw = False
    if not new_pw:
        new_pw = base64.b64encode(pysecrets.token_bytes(18)).decode()
        show_pw = True
    log(f"Hashing new {label} password (bcrypt, in-process)")
    c_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt(14)).decode()
    lines = caddyfile.read_text().splitlines()
    out: List[str] = []
    in_block = False
    replaced = False
    for line in lines:
        if re.search(r"basic_auth\s*\{", line):
            in_block = True
            out.append(line)
            continue
        if in_block and "}" in line:
            in_block = False
            out.append(line)
            continue
        if in_block and line.split() and line.split()[0] == user:
            indent = line[: len(line) - len(line.lstrip())]
            out.append(f"{indent}{user} {c_hash}")
            replaced = True
            continue
        out.append(line)
    if not replaced:
        raise CtlError(
            f"no basic_auth entry for user '{user}' in {caddyfile} — set the user variable "
            f"to the name in the file, or update it manually"
        )
    # Preserve the file's owner: the Caddyfile is service-user-owned (the
    # rootless logview container reads it through the subuid mapping), so a
    # root:root 0600 replacement would crash-loop Caddy on its next start —
    # the rotate would LOCK OUT the log view instead of re-keying it. Stat
    # the original, fchown the staged file before replace (same discipline
    # as the unsealed rotate-restic path and util.set_kv).
    try:
        st = caddyfile.stat()
        uid, gid = st.st_uid, st.st_gid
    except OSError:
        uid = gid = -1
    new_file = Path(str(caddyfile) + ".new")
    new_file.unlink(missing_ok=True)
    fd = os.open(new_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(out) + "\n")
        f.flush()
        if uid != -1:
            with contextlib.suppress(OSError):
                os.fchown(f.fileno(), uid, gid)
    os.replace(new_file, caddyfile)
    names = runner.output(runner.podman_user_argv(["ps", "--format", "{{.Names}}"])).splitlines()
    if f"{s.obs_pod}-logview" in names:
        # A failed restart must be LOUD: the file already holds the new hash,
        # so a still-running Caddy would keep serving the OLD credential —
        # "rotated" would be a lie until the next play.
        if runner.podman_user(["restart", f"{s.obs_pod}-logview"], quiet=True).returncode == 0:
            log(f"{label} restarted with the new credential")
        else:
            warn(
                f"could not restart {s.obs_pod}-logview — the Caddyfile holds the NEW "
                f"hash but the running log view still serves the OLD credential; "
                f"apply with: carlos-ctl play"
            )
    else:
        log("apply with: carlos-ctl play")
    if show_pw:
        emit_secret(
            s,
            f"{label} login — user: {user}   password: {new_pw}", new_pw, "caddy-password",
        )
        warn(
            "store this password in your password manager NOW — only its bcrypt hash is "
            "kept on disk"
        )
    return 0


def _rotate_restic(runner: Runner) -> int:
    """restic repository password rotation, ordered so no step can strand the
    repository on a password that exists nowhere:
      1. `restic key add`   — the repo now opens with OLD and NEW passwords
      2. persist NEW        — bundle / restic.env updated
      3. verify             — re-open the repo with the STORED new password
      4. `restic key remove <old>` — only after the stored credential is proven"""
    from .util import first_match

    s = runner.settings
    env_file = s.conf_dir / "restic" / "restic.env"
    sealed = False
    tmp_env: Optional[str] = None
    try:
        if not env_file.is_file() and bundle_available(runner):
            env_content = bundle_get(runner, "restic", "env")
            if not env_content and not bundle_decrypts(runner):
                # Distinguish "bundle has no restic section" (fall through to
                # the provisioning message) from "the bundle CANNOT be
                # decrypted" — the latter is a key/corruption problem that a
                # 'run seal first' message would misdirect.
                raise CtlError(
                    f"the secrets bundle at {s.secrets_bundle} exists but CANNOT be "
                    f"decrypted with the available age key — fix the key/bundle before "
                    f"rotating (carlos-ctl secrets render shows the sops error)"
                )
            if env_content:
                tmp_env = _run_tmpfile(f"{s.cred_age}.", root_required=True)
                Path(tmp_env).write_text(env_content)
                # podman reads this as --env-file AS the service user.
                with contextlib.suppress(OSError, KeyError):
                    import pwd as pwd_mod

                    os.chown(tmp_env, pwd_mod.getpwnam(s.service_user).pw_uid, -1)
                env_file = Path(tmp_env)
                sealed = True
        if not env_file.is_file():
            raise CtlError("no restic credentials — run the provisioning playbook / 'seal' first")
        # PARSE, never source: the plaintext restic.env is service-user-owned
        # (rootless --env-file reads), so executing it as root would run
        # service-user-writable content as root.
        env_lines = env_file.read_text().splitlines()
        repository = first_match(env_lines, "RESTIC_REPOSITORY") or ""
        if not repository:
            raise CtlError(f"no RESTIC_REPOSITORY in {env_file} — cannot rotate")
        restic_image = first_match(env_lines, "RESTIC_IMAGE") or s.get("RESTIC_IMAGE")

        new_pw = s.get("RESTIC_NEW_PASSWORD")
        show_pw = False
        if not new_pw:
            new_pw = base64.b64encode(pysecrets.token_bytes(24)).decode()
            show_pw = True
        else:
            # An operator-supplied value renders into the RESTIC_PASSWORD= line
            # of restic.env (or the bundle's restic.env blob), a line-oriented
            # store: a newline splits the line and a CR is silently trimmed by
            # restic but kept in the file, so the stored password stops opening
            # the repo. The sibling rotations validate their operator values
            # (rotate db-root, rotate obs); this one did not.
            validate_db_password(new_pw, "RESTIC_NEW_PASSWORD")
        newpw_file = _run_tmpfile(f"{s.cred_restic}-new.", root_required=True)
        try:
            Path(newpw_file).write_text(new_pw)
            # Bind-mounted into the rootless restic container: it must map to
            # container-root, i.e. be owned by the service user on the host.
            with contextlib.suppress(OSError, KeyError):
                import pwd as pwd_mod

                os.chown(newpw_file, pwd_mod.getpwnam(s.service_user).pw_uid, -1)

            repo = repository
            repo_mount: List[str] = []
            repo_local = restic_local_path(repository)
            if repo_local:
                repo_mount = ["-v", f"{repo_local}:/repo"]
                repo = "/repo"

            import subprocess as sp

            def restic_run(
                *restic_args: str, use_new_pw: bool = False
            ) -> sp.CompletedProcess[str]:
                # The env-file carries the OLD password; -e RESTIC_PASSWORD
                # (forwarded by NAME from our environment, off-argv) lets the
                # verify/remove steps authenticate with the NEW one.
                # /tmp/restic-newpw is the IN-CONTAINER path of the 0600 host
                # tempfile (newpw_file) — not a host /tmp write.
                envargs = ["-e", "RESTIC_PASSWORD"] if use_new_pw else []
                # The -e RESTIC_REPOSITORY override exists ONLY for the
                # local-path case (value '/repo', no secret). A REMOTE URL may
                # embed credentials (rest:https://user:pw@...) and must never
                # ride the podman argv — the env-file already supplies it
                # (same policy as backup.py's repo_env).
                repo_args = (["-e", f"RESTIC_REPOSITORY={repo}"]
                             if repo_local else [])
                return runner.podman_user(
                    [
                        "run", "--rm", "-i", "--pull=missing",
                        "--env-file", str(env_file),
                        *envargs,
                        *repo_args,
                        "-v", f"{s.emr_home}/backup/restic-cache:/root/.cache/restic",
                        "-v", f"{newpw_file}:/tmp/restic-newpw:ro",  # noqa: S108
                        *repo_mount,
                        restic_image, *restic_args,
                    ],
                    env={"RESTIC_PASSWORD": new_pw}, capture=True,
                )

            # Current key id (the active key's row is marked '*' — either as
            # its own column or fused to the id, depending on restic version).
            # Best-effort: without it the old key is simply kept.
            old_key_id = ""
            listing = restic_run("key", "list")
            for line in (listing.stdout or "").splitlines():
                parts = line.split()
                if not parts:
                    continue
                if parts[0] == "*" and len(parts) > 1:
                    old_key_id = parts[1]
                    break
                if parts[0].startswith("*") and len(parts[0]) > 1:
                    old_key_id = parts[0][1:]
                    break

            log(f"Adding the new repository key (restic key add) — repo "
                f"{scrub_repo_creds(repository)}")
            cp = restic_run("key", "add", "--new-password-file", "/tmp/restic-newpw")  # noqa: S108
            if cp.returncode != 0:
                # restic_run captures output — surface restic's own diagnosis
                # (wrong password? unreachable backend?) or the operator flies
                # blind, but scrub any user:pw@ from a creds-in-URL repository.
                detail = scrub_repo_creds((cp.stderr or "").strip())
                raise CtlError(
                    "restic key add failed — nothing changed (repo still opens with the "
                    "current password only)" + (f": {detail}" if detail else "")
                )

            # Persist BEFORE removing the old key. Rewrite only the
            # RESTIC_PASSWORD line so extra variables (offsite backend
            # credentials etc.) survive.
            new_env = "\n".join(
                [ln for ln in env_lines if not ln.startswith("RESTIC_PASSWORD=")]
                + [f"RESTIC_PASSWORD={new_pw}"]
            ) + "\n"
            if sealed:
                bundle_set(runner, "restic", "env", new_env)
            else:
                target = s.conf_dir / "restic" / "restic.env"
                # Preserve the file's owner: restic.env is service-user-owned
                # (rootless podman reads it as --env-file AS the service user),
                # so a root:root 0600 replacement would break every subsequent
                # backup's --env-file read until the next playbook sweep. Stat
                # the original, fchown the replacement to it before replace
                # (same discipline as util.set_kv; the sealed tmp-env path
                # already chowns).
                try:
                    st = target.stat()
                    uid, gid = st.st_uid, st.st_gid
                except OSError:
                    uid = gid = -1
                staged = Path(str(target) + ".new")
                # O_EXCL+O_NOFOLLOW after an unlink: the staging name lives in
                # a service-user-writable dir, so never follow or reuse a
                # pre-existing (possibly symlinked) file there.
                staged.unlink(missing_ok=True)
                fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "w") as f:
                    f.write(new_env)
                    f.flush()
                    if uid != -1:
                        with contextlib.suppress(OSError):
                            os.fchown(f.fileno(), uid, gid)
                os.replace(staged, target)

            # Verify: the repo must open with the NEW password before the old
            # key may be removed. On failure BOTH keys stay valid and the
            # stored credential already holds the new password.
            cp = restic_run("cat", "config", use_new_pw=True)
            if cp.returncode != 0:
                detail = scrub_repo_creds((cp.stderr or "").strip())
                raise CtlError(
                    "could not open the repository with the NEW password — NOT removing the "
                    "old key (both keys remain valid; the stored credential holds the NEW "
                    "password). Investigate before re-running."
                    + (f" restic said: {detail}" if detail else "")
                )
            if old_key_id:
                cp = restic_run("key", "remove", old_key_id, use_new_pw=True)
                if cp.returncode != 0:
                    warn(
                        f"could not remove the old repository key ({old_key_id}) — the "
                        f"rotation is complete and safe, but the OLD password still opens "
                        f"the repo; remove it by hand: restic key remove {old_key_id}"
                    )
            else:
                warn(
                    "could not determine the old key id — the rotation is complete, but the "
                    "OLD password still opens the repo; list and remove it by hand "
                    "(restic key list / key remove)"
                )
            if show_pw:
                emit_secret(
                    s, f"new RESTIC_PASSWORD: {new_pw}", new_pw,
                    "restic-password",
                )
            warn(
                "the restic password now lives ONLY in the age-encrypted bundle, which rides "
                "inside the backup repo it unlocks — UPDATE your off-host restic.env escrow "
                "with the new password now (the age key alone cannot reach or open the repo "
                "after a host loss)"
            )
            return 0
        finally:
            with contextlib.suppress(OSError):
                os.unlink(newpw_file)
    finally:
        if tmp_env:
            with contextlib.suppress(OSError):
                os.unlink(tmp_env)


def _rotate_age_key(runner: Runner) -> int:
    """Rotate the age MASTER key — the single key that unlocks the whole
    bundle and is the off-host DR secret. Every downstream credential already
    rotates; the master had no compromise-response flow. Ordered so the
    bundle is NEVER left unrecoverable: generate the new keypair, re-encrypt
    a decrypted copy to the NEW recipient, PROVE it decrypts with the new
    key, and only THEN swap the key/recipient/TPM-blob and retire the old
    recipient. The escrow marker is deleted so the next seal re-confirms the
    (new) key is escrowed off-host."""
    s = runner.settings
    if not runner.have("age-keygen") or not runner.have("sops"):
        raise CtlError("rotate age-key needs age-keygen and sops on PATH")
    if not s.secrets_bundle.is_file():
        raise CtlError(
            f"no sealed bundle at {s.secrets_bundle} — nothing to re-key; "
            f"'carlos-ctl seal' creates it first"
        )
    have_tpm = runner.have("systemd-creds") and runner.ok(["systemd-creds", "has-tpm2"])
    if not have_tpm and not s.flag("CARLOS_SEAL_NO_TPM"):
        raise CtlError(
            "no usable TPM2 and CARLOS_SEAL_NO_TPM=1 not set — the re-keyed private key "
            "would rest as a 0600 file (LUKS-only at rest). Set CARLOS_SEAL_NO_TPM=1 to "
            "accept that, then re-run."
        )
    # 1. Decrypt the bundle with the CURRENT key into /run tmpfs. All four
    # transient staging paths are created INSIDE the try and initialized
    # empty here so the finally can sweep whichever of them exist at any
    # failure point — `staged` in particular used to be cleaned only on the
    # success path and the two explicit sops-failure branches, so an OSError
    # at the .new key staging (or a SIGTERM mid `sops -e`, which cli.py
    # converts to SystemExit so this finally RUNS) leaked
    # /run/rekey-staged.*.yaml — in the pre-encrypt window, the decrypted
    # bundle PLAINTEXT.
    plain = new_key = new_bundle = ""
    staged: Optional[Path] = None
    try:
        plain = _run_tmpfile("rekey-plain.", root_required=True)
        new_key = _run_tmpfile("rekey-key.", root_required=True)
        with age_key(runner) as key_path:
            cp = runner.run(["sops", "-d", str(s.secrets_bundle)],
                            env={"SOPS_AGE_KEY_FILE": key_path}, capture=True)
        if cp.returncode != 0:
            raise CtlError(
                f"cannot decrypt {s.secrets_bundle} with the CURRENT age key — refusing "
                f"to re-key (fix key access first)"
            )
        Path(plain).write_text(cp.stdout)
        # 2. New keypair. age-keygen -o opens O_EXCL (it refuses an existing
        # output file), so drop the mkstemp placeholder first — age-keygen
        # itself recreates the path 0600 in the root-owned /run.
        os.unlink(new_key)
        if runner.run(["age-keygen", "-o", new_key], quiet=True).returncode != 0:
            raise CtlError("age-keygen failed — no new keypair generated")
        new_pub = runner.output(["age-keygen", "-y", new_key]).strip()
        if not new_pub.startswith("age1"):
            raise CtlError("age-keygen produced no usable recipient")
        # 3. Re-encrypt the plaintext to the NEW recipient in /run tmpfs (0600).
        # Staging in conf/secrets would put the DECRYPTED bundle, umask-mode,
        # on a persistent world-traversable path until sops finishes — and the
        # .yaml suffix is LOAD-BEARING (see _run_tmpfile: a different suffix
        # silently selects sops' binary store; its raw-bytes round-trip would
        # even PASS the step-4 verify while corrupting the swapped-in bundle).
        staged = Path(_run_tmpfile("rekey-staged.", root_required=True, suffix=".yaml"))
        staged.write_text(Path(plain).read_text())
        if runner.run(["sops", "-e", "-i", str(staged)],
                      env={"SOPS_AGE_RECIPIENTS": new_pub}, quiet=True).returncode != 0:
            staged.unlink(missing_ok=True)
            raise CtlError("sops re-encryption to the new recipient failed — bundle unchanged")
        # 4. PROVE the staged bundle decrypts with the NEW key BEFORE any swap.
        verify = runner.run(["sops", "-d", str(staged)],
                            env={"SOPS_AGE_KEY_FILE": new_key}, capture=True)
        if verify.returncode != 0 or verify.stdout != Path(plain).read_text():
            staged.unlink(missing_ok=True)
            raise CtlError(
                "the re-keyed bundle did NOT decrypt back with the new key — REFUSING the "
                "swap; the original bundle and key are untouched"
            )
        # 5. PERSIST-BEFORE-SWAP. Stage the new private key and pub as `.new`
        # siblings on the SAME persistent dir FIRST, then swap the bundle, then
        # shred the old key, then move the new key/pub into place. This closes
        # the window where a crash after the bundle swap but before the key
        # write left the committed bundle decryptable only by a key that
        # existed nowhere durable — it lived solely in the /run tmpfs `new_key`
        # copy the `finally` below unlinks. These `.new` siblings are NOT in
        # that finally set, so on a crash between the swap and the key rename
        # the new key survives on disk: complete the rotation by hand with
        # `mv <age_key_file>.new <age_key_file>` (and the `.new` pub likewise).
        # (Unlinking any stale `.new` here is safe: a prior post-swap crash
        # leaves a bundle the CURRENT key can't open, so step 1 would already
        # have raised before reaching this point.)
        key_new = Path(str(s.age_key_file) + ".new")
        pub_new = Path(str(s.age_pub_file) + ".new")
        key_new.unlink(missing_ok=True)
        pub_new.unlink(missing_ok=True)
        kfd = os.open(key_new, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(kfd, "w") as f:
            f.write(Path(new_key).read_text())
            f.flush()
            os.fsync(f.fileno())
        with contextlib.suppress(OSError):
            os.chown(key_new, 0, 0)
        pfd = os.open(pub_new, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(pfd, "w") as f:
            f.write(new_pub + "\n")
            f.flush()
            os.fsync(f.fileno())
        # Commit the re-keyed bundle: write the CIPHERTEXT next to the bundle
        # (same filesystem — /run is tmpfs, so a cross-device rename cannot be
        # atomic), then swap.
        new_bundle = str(s.secrets_bundle) + ".new"
        fd = os.open(new_bundle, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        # umask-proof (see bundle_set): the encrypted bundle must stay
        # world-readable for the rootless `files` backup.
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "w") as f:
            f.write(staged.read_text())
        os.replace(new_bundle, s.secrets_bundle)
        staged.unlink(missing_ok=True)
        # Old key -> SHRED now: the new bundle no longer decrypts with it, and
        # the new key is already durable at key_new. Shredding here (not a
        # plain truncate-overwrite) makes the retired — and, since rotate IS
        # the compromise response, possibly compromised — master key
        # unrecoverable, as this comment has always claimed. Guard on is_file()
        # like the recovery-wrap shred below: on a TPM host `seal` already
        # shredded the on-disk key (it lives only in the TPM blob), so an
        # unconditional _shred here hit a missing file and emitted the scary
        # "plaintext may be recoverable" warning on every TPM-host rekey — a
        # false at-rest-leak claim in a compromise-response flow.
        if s.age_key_file.is_file():
            _shred(runner, s.age_key_file)
        os.replace(key_new, s.age_key_file)
        s.age_key_file.chmod(0o600)
        with contextlib.suppress(OSError):
            os.chown(s.age_key_file, 0, 0)
        os.replace(pub_new, s.age_pub_file)
        s.age_pub_file.chmod(0o644)
        if have_tpm:
            _seal_one(runner, s.cred_age, s.age_key_file)  # verifies + shreds the file copy
        # SHRED the attended-recovery wrap: it holds the OLD master key, which
        # (a) still unwraps cleanly with its passphrase, so at a later TPM
        # incident the render would "recover" to a key that no longer opens
        # the bundle — a recovery slot that LIES mid-incident — and (b) leaves
        # the retired (possibly compromised, since rotate IS the compromise
        # response) key recoverable behind only an offline passphrase crack
        # while pre-rotation bundle ciphertext persists in restic snapshots.
        # No new wrap is written here (we have no passphrase in this flow); the
        # next `seal` re-creates it.
        if s.age_key_recovery_file.is_file():
            _shred(runner, s.age_key_recovery_file)
        # Force escrow re-confirmation: the NEW key must be escrowed off-host.
        for marker in (s.secrets_private_dir / ".age-escrow-confirmed",
                       s.secrets_dir / ".age-escrow-confirmed"):
            with contextlib.suppress(OSError):
                marker.unlink()
    finally:
        # `staged`/`new_bundle` too (M1): ciphertext by the time they can
        # normally leak, plaintext in the narrow pre-`sops -e` window — either
        # way nothing transient survives this frame. The `.new` key/pub
        # siblings are deliberately NOT here: they are the crash-recovery
        # artifact the persist-before-swap comment above depends on.
        for tmp in (plain, new_key, new_bundle, staged):
            if not tmp:
                continue
            with contextlib.suppress(OSError):
                os.unlink(tmp)
    warn(
        "age MASTER key ROTATED. The OLD recipient no longer opens the bundle. You MUST "
        "re-escrow the NEW age private key off-host NOW (the old escrow copy is dead), and "
        "run 'carlos-ctl seal' to re-confirm escrow (which also re-creates the "
        "attended-recovery wrap — the old one was SHREDDED, as it held the retired key). "
        "Any external DR/escrow age recipient you had added via 'sops updatekeys' was "
        "DROPPED by this re-key — re-add it. If this run was interrupted after the bundle "
        f"swap but before the key install, finish it with: mv {s.age_key_file}.new "
        f"{s.age_key_file} (and {s.age_pub_file}.new {s.age_pub_file})."
    )
    return 0


def cmd_rotate(runner: Runner, args: List[str]) -> int:
    verb = args[0] if args else ""
    rest = args[1:]
    # `rotate db` is the ONLY sub-verb with a flag (--no-restart, validated in
    # _rotate_db); every other one took `rest` and DROPPED it. Each of those
    # is a one-way credential change on a PHI host — `rotate age-key` re-keys
    # the sealed-secrets master, `rotate restic` re-passwords the backup repo,
    # `rotate db-root` changes the MariaDB root credential — so a
    # silently-ignored `--dry-run`/`--help` performed the REAL rotation while
    # the operator believed they were previewing it. Same contract (and same
    # class of footgun) as the CLI's no-argument-verb guard, `db-backup`'s
    # one-positional rule, and the `backup <tier>` sub-verb guard.
    # Restricted to the KNOWN sub-verbs so an unknown one still reaches the
    # usage line below (naming the valid set beats complaining about its args).
    if verb in ("db-root", "log-view", "obs", "age-key", "restic") and rest:
        raise CtlError(
            f"'carlos-ctl rotate {verb}' takes no arguments (got: {' '.join(rest)}) — "
            f"only 'rotate db' accepts a flag (--no-restart); behavior knobs for the "
            f"other rotations are environment variables, see the README"
        )
    if verb == "db":
        return _rotate_db(runner, rest)
    if verb == "db-root":
        return _rotate_db_root(runner)
    if verb == "log-view":
        s = runner.settings
        return _rotate_caddy_password(
            runner, s.get("LOG_VIEW_USER"), "log view", s.get("LOG_VIEW_PASSWORD")
        )
    if verb == "obs":
        return _rotate_obs_http(runner)
    if verb == "age-key":
        return _rotate_age_key(runner)
    if verb == "restic":
        return _rotate_restic(runner)
    raise CtlError(
        "usage: carlos-ctl rotate <db|db-root|log-view|obs|age-key|restic> "
        "(rotate db also takes --no-restart)"
    )


def _rotate_obs_http(runner: Runner) -> int:
    """Rotate the obs-store basic-auth credential (VL/VM/vmalert + every
    client). Order matters for convergence, not for stranding — the
    credential is REGENERABLE (nothing durable is encrypted with it), so the
    worst mid-rotation failure is a 401ing pipeline until play, never data
    loss: 1. new value into the root-only canonical file; 2. recreate the
    podman secret (containers pick it up at the next pod start); 3. surgical
    rewrites of the two inline holders (vector toml, Caddyfile header_up);
    4. restart obs -> app+waf so every consumer moves together."""
    s = runner.settings
    if not s.obs_enabled:
        raise CtlError(
            "the obs stores run in the observability pod, which is disabled "
            "(OBS_ENABLED=0 / carlos_obs_enabled: false) — nothing to rotate"
        )
    if not s.obs_http_password_file.is_file():
        raise CtlError(
            f"no {s.obs_http_password_file} — store auth is not provisioned "
            f"(carlos_obs_http_auth: false, or the playbook has not run); nothing to rotate"
        )
    user = s.get("OBS_HTTP_USER") or "obs"
    # token_urlsafe: alnum plus -_ — inert in every holder (toml string,
    # Caddy b64 input, curl -K config, basic-auth userinfo).
    new_pw = s.get("OBS_HTTP_NEW_PASSWORD") or pysecrets.token_urlsafe(24)
    # An operator-supplied OBS_HTTP_NEW_PASSWORD (unlike the generated default)
    # rides three inline holders that all break on the wrong char: the TOML
    # basic string in journald-collector.toml, the `curl -K -` config the
    # store probes use, and the line-oriented password file. Validate BEFORE
    # any mutation so a bad value refuses cleanly instead of half-rotating.
    validate_db_password(new_pw, "OBS_HTTP_NEW_PASSWORD")
    curl_config_quote(new_pw, "OBS_HTTP_NEW_PASSWORD")  # rejects "/\\/control
    # 1. canonical root-only file (atomic, mode-preserving).
    new_file = Path(str(s.obs_http_password_file) + ".new")
    new_file.unlink(missing_ok=True)
    fd = os.open(new_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(new_pw + "\n")
    os.replace(new_file, s.obs_http_password_file)
    # 2. podman secret (name-referenced by the pod specs).
    runner.podman_user(["secret", "rm", f"{s.instance}-obs-http"], quiet=True)
    manifest = (
        f"apiVersion: v1\nkind: Secret\nmetadata:\n  name: {s.instance}-obs-http\n"
        f"data:\n  password: {base64.b64encode(new_pw.encode()).decode()}\n"
    )
    if runner.podman_user(["kube", "play", "-"], input_text=manifest,
                          quiet=True).returncode != 0:
        raise CtlError(
            f"could not recreate the {s.instance}-obs-http podman secret — the canonical "
            f"file already holds the NEW value; re-run 'carlos-ctl rotate obs' (the "
            f"credential is regenerable, nothing is stranded)"
        )
    # 3. the two inline holders. Regex-surgical so operator edits survive.
    vector_toml = s.conf_dir / "vector" / "journald-collector.toml"
    if vector_toml.is_file():
        body = vector_toml.read_text()
        new_body = re.sub(
            r'(?m)^(auth\.password\s*=\s*")[^"]*(")',
            lambda m: m.group(1) + new_pw + m.group(2),
            body,
        )
        if new_body != body:
            _replace_preserving_owner(vector_toml, new_body)
        else:
            warn(f"{vector_toml} carries no auth.password line — the log collector "
                 f"will 401 until the playbook re-renders it")
    caddyfile = s.conf_dir / "caddy" / "Caddyfile"
    if caddyfile.is_file():
        cred = base64.b64encode(f"{user}:{new_pw}".encode()).decode()
        body = caddyfile.read_text()
        new_body = re.sub(
            r'(header_up Authorization "Basic )[A-Za-z0-9+/=]*(")',
            lambda m: m.group(1) + cred + m.group(2),
            body,
        )
        if new_body != body:
            _replace_preserving_owner(caddyfile, new_body)
        else:
            warn(f"{caddyfile} carries no store Authorization header_up — the log view "
                 f"will 401 until it is added (see the playbook's Caddyfile advisory)")
    # 4. restart so every consumer moves together (pod-unit restarts: podman
    # secret volume content materializes at container creation).
    from . import dbops

    if runner.systemd_running() and (s.quadlet_dir() / f"{s.instance}.kube").is_file():
        if not runner.ok(runner.systemctl_user_argv(["restart", f"{s.obs_pod}.service"])):
            warn(f"could not restart {s.obs_pod}.service — the stores still hold the OLD "
                 f"credential; run 'carlos-ctl play'")
    elif s.rendered_obs_yaml.is_file():
        # No systemd (or no quadlet): the app+waf half below already has this
        # fallback (dbops.restart_app_and_waf), the obs half did NOT — so on a
        # no-systemd host this verb rotated every CLIENT while the STORES kept
        # the old credential and printed the success line below anyway. The
        # whole metrics/log pipeline then 401s until the operator happens to
        # run `play`. Same `kube play --replace` the fallback deploy uses.
        if runner.podman_user([
            "kube", "play", "--replace", "--network", s.net_name,
            str(s.rendered_obs_yaml),
        ], quiet=True).returncode != 0:
            warn(f"could not restart the {s.obs_pod} pod — the stores still hold the OLD "
                 f"credential and every client will 401; run 'carlos-ctl play'")
    dbops.restart_app_and_waf(runner)
    if not s.get("OBS_HTTP_NEW_PASSWORD"):
        emit_secret(
            s,
            f"obs store login — user: {user}   password: {new_pw}", new_pw,
            "obs-http-password",
        )
    log("Rotated the obs-store credential (stores, vmagent, vector, log view)")
    return 0


def _replace_preserving_owner(target: Path, content: str) -> None:
    """Atomic full-file replacement keeping the original owner (rootless
    containers read these through the subuid mapping — a root:root
    replacement would lock them out; same discipline as rotate log-view)."""
    try:
        st = target.stat()
        uid, gid = st.st_uid, st.st_gid
    except OSError:
        uid = gid = -1
    new_file = Path(str(target) + ".new")
    new_file.unlink(missing_ok=True)
    fd = os.open(new_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(content)
        f.flush()
        if uid != -1:
            with contextlib.suppress(OSError):
                os.fchown(f.fileno(), uid, gid)
    os.replace(new_file, target)
