# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Small shared primitives: logging, escaping, atomic file edits, size math.

Everything here is a direct behavioral port of the bash helpers it replaces;
where the bash carried a security rationale (atomicity, escaping rules, off-
argv discipline) the rationale is preserved as a comment because it is a
contract, not an implementation detail.
"""

from __future__ import annotations

import hashlib
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Iterable, Optional


class CtlError(Exception):
    """Fatal operator-facing error (bash `die`). The CLI prints it to stderr
    prefixed with ERROR: and exits 1 — callers raise, they never sys.exit."""


def log(msg: str) -> None:
    print(f"==> {msg}")


def warn(msg: str) -> None:
    print(f"WARNING: {msg}", file=sys.stderr)


def die(msg: str) -> CtlError:
    """Return (for `raise die(...)`) a CtlError. Kept as a helper so ported
    call sites read like the bash they came from."""
    return CtlError(msg)


# --- memory-size math ---------------------------------------------------------

_SIZE_RE = re.compile(r"^([0-9]+(?:\.[0-9]+)?)([A-Za-z]*)$")


def size_to_mib(value: str) -> Optional[int]:
    """Normalize a memory size to MiB (integer, approximate — enough for the
    non-heap margin sanity check). Accepts k8s units (Gi/Mi/Ki, G/M/K) and JVM
    units (g/m/k); Gi and JVM 'g' are both treated as 1024 MiB, which errs
    toward not false-alarming. Returns None on a value it cannot parse
    (bash returned nonzero)."""
    m = _SIZE_RE.match(value)
    if not m:
        return None
    num, unit = m.group(1), m.group(2)
    if "." in num:
        # Decimal sizes ("1.5Gi") are valid k8s quantities; keep the bash's
        # scaled-to-thousandths integer math so results match exactly.
        whole_s, frac_s = num.split(".", 1)
        if not (whole_s.isdigit() and frac_s.isdigit()):
            return None
        frac_s = (frac_s + "000")[:3]
        n = int(whole_s) * 1000 + int(frac_s)
        if unit in ("Gi", "G", "g"):
            return n * 1024 // 1000
        if unit in ("Mi", "M", "m"):
            return n // 1000
        if unit in ("Ki", "K", "k"):
            return n // 1024 // 1000
        return None
    n = int(num)
    if unit in ("Gi", "G", "g"):
        return n * 1024
    if unit in ("Mi", "M", "m"):
        return n
    if unit in ("Ki", "K", "k"):
        return n // 1024
    if unit == "":
        return n // 1048576  # bare bytes
    return None


# --- escaping -----------------------------------------------------------------


def sql_escape(value: str) -> str:
    """Escape a value for use inside a single-quoted SQL string literal.
    Single quotes are doubled ('') — correct under EVERY sql_mode — because a
    backslash-escaped \\' breaks (or injects) when the server runs with
    NO_BACKSLASH_ESCAPES. Backslashes are still doubled for the default mode
    this deployment uses (zz-carlos.cnf sets sql_mode=""); that is harmless
    under NO_BACKSLASH_ESCAPES because the value only ever sits inside a '...'
    literal, where the '' quoting is what matters for termination."""
    return value.replace("\\", "\\\\").replace("'", "''")


def curl_config_quote(value: str, label: str) -> str:
    """Return a double-quoted token for one `curl -K -` config line, REJECTING
    (never escaping) values that would corrupt or hijack the config. In curl's
    config format a `"` ends the quoted value, a `\\` starts an escape, and any
    newline/control char starts a NEW directive — so an unescaped value could
    truncate the URL or inject an arbitrary directive (e.g. `output = <file>`,
    executed with the caller's privileges). None of these characters belong in
    a webhook/heartbeat URL or an obs credential; reject them, mirroring
    validate_db_password's control-char contract."""
    bad = next((c for c in value if c in '"\\' or ord(c) < 0x20), None)
    if bad is not None:
        raise CtlError(
            f"{label} contains a character that cannot ride a curl config line "
            f"(0x{ord(bad):02x}): double quotes, backslashes and control characters are "
            f"refused, not escaped (they would truncate the value or inject a directive)"
        )
    return f'"{value}"'


# restic's remote backend schemes (restic 0.16-0.19). Anything else — a bare
# absolute path, a RELATIVE path, or the `local:` scheme restic treats
# identically to a bare path — lives on this host.
_RESTIC_REMOTE_SCHEMES = ("s3:", "sftp:", "rest:", "swift:", "b2:", "azure:", "gs:", "rclone:")


def restic_local_path(repo: str) -> str:
    """The filesystem path of a LOCAL restic repository, or '' for a remote
    backend. The DR-posture gates key on this instead of startswith('/') so an
    alternate spelling of local — `local:/mnt/backup` (the form restic's own
    docs use) or a relative path — cannot silently bypass them; the
    mount/exists plumbing gets the real path for those spellings too. An
    unknown scheme is treated as LOCAL (fail-closed for the posture gates —
    nagging about a genuinely-remote exotic backend beats silently treating a
    local repo as offsite)."""
    r = repo.strip()
    if not r:
        return ""
    if r.startswith("local:"):
        return r[len("local:"):]
    if any(r.startswith(s) for s in _RESTIC_REMOTE_SCHEMES):
        return ""
    return r


def properties_escape_value(value: str) -> str:
    """Escape a value for the VALUE side of a Java .properties line (and,
    compatibly, a MariaDB option-file value): a backslash starts an escape in
    both formats, so a password like 'pa\\ss' or one ending in '\\' would be
    mis-parsed — or, for a stray '\\u', throw from Properties.load and fail the
    whole file. Doubling the backslash makes it literal in both parsers."""
    return value.replace("\\", "\\\\")


def properties_unescape_value(value: str) -> str:
    """Inverse of properties_escape_value: halve doubled backslashes back to
    the raw value. Exact because escaping ONLY doubles backslashes."""
    return value.replace("\\\\", "\\")


# --- shell-value decoding (parse-don't-source) ---------------------------------

_ANSI_C_ESCAPES = {
    "a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f",
    "n": "\n", "r": "\r", "t": "\t", "v": "\v",
    "\\": "\\", "'": "'", '"': '"',
}


def shell_unquote_value(value: str) -> str:
    """Decode ONE bash printf-%q-encoded value. The env files store passwords
    %q-encoded because they used to be shell-sourced; sourcing decoded them for
    free, a parser does not. Handles the three forms %q emits: $'...' ANSI-C
    (non-printables), backslash-escaped printables, and raw single-quoted."""
    if value.startswith("$'") and value.endswith("'") and len(value) >= 3:
        body = value[2:-1]
        # Accumulate BYTES, not codepoints: bash printf %q octal-escapes
        # multibyte values BYTE-wise under the C locale the systemd units run
        # in (café -> $'caf\303\251'), so \NNN/\xHH are UTF-8 byte fragments.
        # Decoding each as chr() would corrupt every non-ASCII password a
        # bash-era install persisted (backup/root DB auth failures). The final
        # decode uses surrogateescape so even non-UTF-8 bytes round-trip into
        # the environment (POSIX os.environ uses the same error handler).
        out = bytearray()
        i = 0
        while i < len(body):
            ch = body[i]
            if ch != "\\" or i + 1 >= len(body):
                out.extend(ch.encode("utf-8"))
                i += 1
                continue
            nxt = body[i + 1]
            if nxt == "x" and re.match(r"[0-9a-fA-F]{1,2}", body[i + 2 : i + 4]):
                hexs = re.match(r"[0-9a-fA-F]{1,2}", body[i + 2 : i + 4]).group(0)  # type: ignore[union-attr]
                out.append(int(hexs, 16))
                i += 2 + len(hexs)
            elif nxt == "0" or nxt.isdigit():
                m = re.match(r"[0-7]{1,3}", body[i + 1 : i + 4])
                if m:
                    out.append(int(m.group(0), 8) & 0xFF)
                    i += 1 + len(m.group(0))
                else:
                    out.extend(nxt.encode("utf-8"))
                    i += 2
            elif nxt in _ANSI_C_ESCAPES:
                out.extend(_ANSI_C_ESCAPES[nxt].encode("utf-8"))
                i += 2
            else:
                out.extend(nxt.encode("utf-8"))
                i += 2
        return out.decode("utf-8", errors="surrogateescape")
    if len(value) >= 2 and value[0] == "'" and value[-1] == "'":
        return value[1:-1]
    # Backslash-escaped printables (%q's a\ b / \! / \\ form): drop one layer.
    return re.sub(r"\\(.)", r"\1", value)


# --- files ---------------------------------------------------------------------


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


_STRAY_TOKEN_RE = re.compile(r"@[A-Z0-9_]+@")


def stray_tokens(path: Path) -> str:
    """Space-joined, unique @TOKEN@ placeholders left in a rendered file (may
    be empty). ONE definition of "what is a stray token" for every render
    guard — kept even though Ansible now renders, because `play` preflights
    the installed files before starting the pods."""
    found = sorted(set(_STRAY_TOKEN_RE.findall(path.read_text())))
    return " ".join(found) + (" " if found else "")


def set_kv(path: Path, key: str, value: str) -> None:
    """Literal-safe "key=value" line replacement (every matching line), with
    APPEND when the key is absent — a replace-only edit silently no-ops when
    asked to set a new key, losing the caller's write.

    Atomic write-then-rename via a sibling .new: a crash leaves at most a
    stale .new (never a truncated primary), and a concurrent reader always
    sees either the old or the new complete file — no torn secret. The .new
    is forced 0600 before it becomes the (secret-bearing) primary, and it
    INHERITS the original file's owner (the bash used `cp -p`): several
    targets — carlos.properties, drugref2.properties — are service-user-owned
    so the rootless pod can subPath-mount and read them; a root:root 0600
    replacement written by a root-run rotate/seal would crash-loop the app on
    an unreadable config until the playbook's ownership sweep re-runs."""
    st = os.stat(path)
    lines = path.read_text().splitlines()
    found = False
    out: list[str] = []
    for line in lines:
        if line.startswith(f"{key}="):
            line = f"{key}={value}"
            found = True
        out.append(line)
    if not found:
        out.append(f"{key}={value}")
    new = path.with_name(path.name + ".new")
    # O_EXCL+O_NOFOLLOW after an unlink: several targets live in service-
    # user-writable dirs, so a root-run rotate must never follow or reuse a
    # pre-existing (possibly symlinked) staging file there.
    new.unlink(missing_ok=True)
    fd = os.open(new, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(out) + "\n")
            f.flush()
            os.fchown(f.fileno(), st.st_uid, st.st_gid)
            # fchmod on the OPEN fd, never a path chmod after close: in the
            # service-user-writable target dirs this function exists for, a
            # post-close path chmod races a rename+symlink swap — a root
            # chmod-to-0600 primitive on an attacker-chosen file. (The
            # O_CREAT 0o600 above is also umask-subject, so this pins the
            # mode besides closing the race.)
            os.fchmod(f.fileno(), 0o600)
    except Exception:
        new.unlink(missing_ok=True)
        raise
    os.replace(new, path)


def atomic_write(path: Path, content: str, mode: int = 0o600) -> None:
    """Write-then-rename with the target mode from birth (no world-readable
    window) — the pattern every secret-bearing render in the bash used."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# --- misc ----------------------------------------------------------------------


def native_password_hash(password: str) -> str:
    """mysql_native_password hash: '*' + UPPER(SHA1(SHA1(password))) — no
    mysql client needed on the host."""
    inner = hashlib.sha1(password.encode()).digest()  # noqa: S324 — MySQL protocol, not our choice
    outer = hashlib.sha1(inner).hexdigest().upper()  # noqa: S324
    return f"*{outer}"


def first_match(lines: Iterable[str], key: str) -> Optional[str]:
    """First value for a literal `key=` line (bash prop_first/env_first: no
    leading-whitespace handling, value returned RAW)."""
    prefix = f"{key}="
    for line in lines:
        if line.startswith(prefix):
            return line[len(prefix):]
    return None


def chown_to_service_user(path: Path, user: str) -> bool:
    """Hand `path` to the service user — BOTH uid AND gid. Returns False when
    the user does not exist or the chown fails (callers warn; never raises).

    Both the user and group must change. Files are subsequently passed to
    ``podman unshare chown``; host root IDs are outside the service user's
    namespace mapping and cause that operation to fail with ``EPERM``.
    """
    try:
        import pwd

        pw = pwd.getpwnam(user)
    except KeyError:
        return False
    try:
        os.chown(path, pw.pw_uid, pw.pw_gid)
    except OSError:
        return False
    return True
