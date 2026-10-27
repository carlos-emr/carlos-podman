# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
"""Process execution across the root → rootless-engine boundary.

carlos-ctl runs as root; the pods live in the SERVICE_USER's rootless podman
engine. Every pod-facing call crosses that boundary via `runuser` (NOT su/
sudo: runuser preserves the caller's environment, so the off-argv credential
pattern — MYSQL_PWD staged in the environment, forwarded with a bare
`-e MYSQL_PWD` — reaches the container without ever being an argv token).
XDG_RUNTIME_DIR is what rootless podman keys its runtime on; it exists
because provisioning enables lingering for the service user.

Everything funnels through Runner.run(): list argv only, never shell=True.
Tests inject a recording subclass; the e2e suite instead lets the real
subprocess hit PATH-stubbed binaries — both work because the boundary is one
method.
"""

from __future__ import annotations

import os
import selectors
import signal
import subprocess
import time
from types import FrameType
from typing import IO, Any, Dict, List, Mapping, Optional, Sequence, Union

from .config import Settings
from .util import CtlError

_Stdin = Union[None, int, IO[bytes], IO[str]]

# Working directory for every root -> SERVICE_USER crossing. `runuser` keeps
# the CALLER's cwd and hard-fails ("cannot chdir to /root: Permission denied",
# rc 1) when the target user cannot enter it — and /root, mode 0700, is the
# cwd of every `sudo -i` / root login shell, i.e. exactly where an operator
# runs these commands. Measured live: from /root, `carlos-ctl check` reported
# "carlos-net network missing — run the provisioning playbook" and every pod
# and container absent on a fully provisioned host, and `carlos-ctl down`
# exited 0 ("pods stopped") while every container kept running — the false
# green that `down && umount <datadir>` maintenance scripting is gated on.
# "/" is world-executable everywhere and no argv in this tree is
# cwd-relative, so pinning it costs nothing.
#
# Membership, not argv[0]: the crossing is also reached WRAPPED — `cmd_pma`
# builds `timeout -k 10 <ttl>m runuser -u <user> -- podman run …` — so an
# argv[0]-only rule would leave the break-glass verb broken from the same
# directories.
_CROSS_USER_CWD = "/"


def _crosses_user_boundary(argv: Sequence[str]) -> bool:
    return "runuser" in argv


class Runner:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    # -- primitive ------------------------------------------------------------

    def run(
        self,
        argv: Sequence[str],
        *,
        check: bool = False,
        capture: bool = False,
        input_text: Optional[str] = None,
        stdin: _Stdin = None,
        stdout: _Stdin = None,
        env: Optional[Mapping[str, str]] = None,
        quiet: bool = False,
        timeout: Optional[float] = None,
        capture_limit: Optional[int] = None,
        supervise: bool = False,
    ) -> subprocess.CompletedProcess:
        """One chokepoint for every external command. `env` entries are ADDED
        to the inherited environment (the off-argv secret channel); passing a
        full replacement environment is deliberately unsupported so PATH and
        the CARLOS_* test overrides always survive. `stdout` streams the
        child's output straight to a file object — multi-GB streams (db
        dumps) must never be buffered in RAM via capture.

        `timeout` bounds the wall clock for a call that MUST NOT hang (a
        network-facing MTA, a per-iteration readiness probe). It defaults to
        None so the long-running streams — db dumps, image pulls, restic
        restores — are never killed mid-flight. When a bounded call expires the
        child is killed and, unless check=True, a synthetic nonzero result is
        returned so ok()/output() report FAILURE and the caller's fail-closed
        path runs (a hang must read as a failure, not a crash)."""
        full_env = None
        if env:
            full_env = dict(os.environ)
            full_env.update(env)
        if capture_limit is not None:
            if not capture or input_text is not None or stdin is not None or stdout is not None \
                    or timeout is None or timeout <= 0 or capture_limit <= 0:
                raise CtlError("bounded capture requires explicit capture, limit and deadline")
            bounded = self._bounded(argv, full_env, capture_limit, timeout)
            if check and bounded.returncode != 0:
                raise CtlError("bounded protocol command failed")
            return bounded
        if supervise:
            if capture or quiet or stdout is not None or stdin is not None or timeout is not None:
                raise CtlError("supervised streams cannot capture output or inherit a timeout")
            if input_text is not None and len(input_text.encode("utf-8")) > 4096:
                raise CtlError("supervised control input exceeded its protocol limit")
            supervised = self._supervised(argv, full_env, input_text)
            if check and supervised.returncode != 0:
                raise CtlError("supervised command failed")
            return supervised
        try:
            return subprocess.run(  # noqa: S603
                list(argv),
                check=check,
                capture_output=(capture or quiet) and stdout is None,
                stdout=stdout,
                text=True,
                input=input_text,
                stdin=stdin if input_text is None else None,
                env=full_env,
                cwd=_CROSS_USER_CWD if _crosses_user_boundary(argv) else None,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as e:
            if check:
                raise CtlError(
                    f"command timed out after {timeout}s: {argv[0]}"
                ) from e
            return subprocess.CompletedProcess(list(argv), 124, stdout="", stderr="timed out")

    @staticmethod
    def _stop_group(process: subprocess.Popen[Any]) -> None:
        for signum in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(process.pid, signum)
            except ProcessLookupError:
                # The owned group has already exited; still reap the child.
                break
            if signum == signal.SIGTERM:
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    # Escalate below; no further work may run in this group.
                    pass
        process.wait(timeout=2)

    def _bounded(
        self, argv: Sequence[str], env: Optional[Mapping[str, str]], limit: int, timeout: float,
    ) -> subprocess.CompletedProcess:
        """Bound both pipes and time for protocol probes, not import output."""
        process = subprocess.Popen(
            list(argv), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, cwd=_CROSS_USER_CWD if _crosses_user_boundary(argv) else None,
            start_new_session=True,
        )
        data = {"stdout": bytearray(), "stderr": bytearray()}
        deadline = time.monotonic() + timeout
        try:
            with selectors.DefaultSelector() as selector:
                for name in data:
                    selector.register(getattr(process, name), selectors.EVENT_READ, name)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return subprocess.CompletedProcess(list(argv), 124, "", "timed out")
                    for key, _ in selector.select(remaining):
                        chunk = os.read(key.fd, 8192)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        if len(data[key.data]) + len(chunk) > limit:
                            return subprocess.CompletedProcess(
                                list(argv), 125, "", "protocol limit")
                        data[key.data].extend(chunk)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return subprocess.CompletedProcess(list(argv), 124, "", "timed out")
            rc = process.wait(timeout=remaining)
            try:
                out = data["stdout"].decode("utf-8")
                err = data["stderr"].decode("utf-8")
            except UnicodeError:
                return subprocess.CompletedProcess(list(argv), 125, "", "invalid protocol encoding")
            return subprocess.CompletedProcess(list(argv), rc, out, err)
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(list(argv), 124, "", "timed out")
        finally:
            self._stop_group(process)
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()

    def _supervised(
        self, argv: Sequence[str], env: Optional[Mapping[str, str]], input_text: Optional[str],
    ) -> subprocess.CompletedProcess:
        """Relay signals while streaming long-running output without capture."""
        process: Optional[subprocess.Popen[str]] = None
        requested: Optional[int] = None
        old_handlers: Dict[int, Any] = {}

        def forward(signum: int, frame: Optional[FrameType]) -> None:
            nonlocal requested
            repeat = requested is not None
            requested = signum
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGKILL if repeat else signum)
                except ProcessLookupError:
                    # Completion raced the signal; durable engine state remains authoritative.
                    pass

        try:
            for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
                old_handlers[signum] = signal.signal(signum, forward)
            if requested is not None:
                return subprocess.CompletedProcess(list(argv), 128 + requested)
            process = subprocess.Popen(
                list(argv), stdin=subprocess.PIPE if input_text is not None else None,
                text=True, encoding="utf-8", env=env,
                cwd=_CROSS_USER_CWD if _crosses_user_boundary(argv) else None,
                start_new_session=True,
            )
            if requested is not None:
                try:
                    os.killpg(process.pid, requested)
                except ProcessLookupError:
                    # The child completed during cancellation admission.
                    pass
            broken_input = False
            if input_text is not None:
                if process.stdin is None:
                    raise CtlError("supervised control pipe was not created")
                try:
                    process.stdin.write(input_text)
                    process.stdin.close()
                except BrokenPipeError:
                    broken_input = True
            rc = process.wait()
            rc = 128 - rc if rc < 0 else rc
            if rc == 0 and broken_input:
                rc = 2
            if rc == 0 and requested is not None:
                rc = 128 + requested
            return subprocess.CompletedProcess(list(argv), rc)
        finally:
            try:
                if process is not None:
                    if process.stdin is not None and not process.stdin.closed:
                        try:
                            process.stdin.close()
                        except BrokenPipeError:
                            # A child refusal can close the bounded metadata pipe first.
                            pass
                    if process.poll() is None:
                        self._stop_group(process)
            finally:
                for cleanup_signum, old_handler in old_handlers.items():
                    signal.signal(cleanup_signum, old_handler)

    def ok(self, argv: Sequence[str], **kw: object) -> bool:
        """Command succeeded? (bash `if cmd; then`) — output suppressed."""
        return self.run(argv, quiet=True, **kw).returncode == 0  # type: ignore[arg-type]

    def output(self, argv: Sequence[str], **kw: object) -> str:
        """Stdout of a command (empty string on failure — bash `$(cmd || true)`)."""
        cp = self.run(argv, capture=True, **kw)  # type: ignore[arg-type]
        return cp.stdout if cp.returncode == 0 and cp.stdout else ""

    def output_any_rc(self, argv: Sequence[str], **kw: object) -> str:
        """Stdout REGARDLESS of exit code — for commands whose printed answer
        is the point and whose rc encodes that answer: `systemctl is-active`
        prints 'failed'/'inactive' but exits 3 for any non-active unit, so
        the rc-gated output() would turn every failed unit into ''."""
        cp = self.run(argv, capture=True, **kw)  # type: ignore[arg-type]
        return cp.stdout or ""

    def have(self, tool: str) -> bool:
        """bash `command -v` — PATH lookup only."""
        from shutil import which

        return which(tool) is not None

    def systemd_running(self) -> bool:
        """Is systemd USABLE on this host — not merely installed?

        Every "does this host have systemd" decision in this tree must ask
        THIS, not `have("systemctl")`. The binary's presence proves nothing:
        Debian/Ubuntu ship systemctl in container images, WSL distributions
        and chroots where systemd never booted, and there every call exits
        nonzero with "System has not been booted with systemd as init system
        (PID 1). Can't operate." — so the no-systemd fallbacks that keyed on
        `have()` alone (README: play/down fall back to plain rootless
        `podman kube play`/`kube down`) never engaged, and the operator got
        the systemd branch's failure instead of the documented fallback.

        Measured on such a host: `carlos-ctl seal` ingested both DB
        credentials, rewrote carlos.properties/drugref2.properties to
        `__SEALED__`, SHREDDED the plaintext restic.env, then died on
        `systemctl daemon-reload` with zero /run fragments rendered and told
        the operator to "fix the unit (journalctl -u …)" — advice that cannot
        be followed there, and a re-run fails identically. The inline render
        that the no-systemctl path performs was never reached.

        The test is sd_booted(3)'s: systemd creates /run/systemd/system when
        it is the init system. Both halves are required — a missing binary is
        just as fatal to a `systemctl` call as a dead manager."""
        return self.have("systemctl") and self.settings.systemd_runtime_dir.is_dir()

    # -- rootless-engine plumbing ----------------------------------------------

    def podman_user_argv(self, args: Sequence[str]) -> List[str]:
        uid = self.settings.service_uid()
        return [
            "runuser", "-u", self.settings.service_user, "--",
            "env", f"XDG_RUNTIME_DIR=/run/user/{uid}", "podman", *args,
        ]

    def podman_user(
        self,
        args: Sequence[str],
        *,
        check: bool = False,
        capture: bool = False,
        input_text: Optional[str] = None,
        stdin: _Stdin = None,
        stdout: _Stdin = None,
        env: Optional[Mapping[str, str]] = None,
        quiet: bool = False,
        timeout: Optional[float] = None,
    ) -> subprocess.CompletedProcess:
        return self.run(
            self.podman_user_argv(args),
            check=check, capture=capture, input_text=input_text,
            stdin=stdin, stdout=stdout, env=env, quiet=quiet, timeout=timeout,
        )

    def systemctl_user_argv(self, args: Sequence[str]) -> List[str]:
        # Drive the service user's systemd --user manager (the pod .kube units
        # live there) from root. -M <user>@ needs systemd >= 248.
        return ["systemctl", "--user", "-M", f"{self.settings.service_user}@", *args]

    def systemctl_user(
        self,
        args: Sequence[str],
        *,
        check: bool = False,
        capture: bool = False,
        quiet: bool = False,
    ) -> subprocess.CompletedProcess:
        return self.run(self.systemctl_user_argv(args), check=check, capture=capture, quiet=quiet)

    def require_db_running(self) -> None:
        names = self.output(self.podman_user_argv(["ps", "--format", "{{.Names}}"]))
        if f"{self.settings.app_pod}-db" not in names.splitlines():
            raise CtlError("db container not running — 'carlos-ctl play' first")
