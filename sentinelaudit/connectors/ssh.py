"""SSH connector -- audits a remote host over one multiplexed, read-only session.

Design notes worth defending in the report:

* **One session, not one-per-command.** ``open()`` establishes an OpenSSH
  ControlMaster; every subsequent command multiplexes over that single TCP/auth
  session and ``close()`` tears it down. This is what "the connector opens one
  read-only session" actually means in practice, and it keeps a ~20-command run
  down to a single authentication.
* **Key-based auth only.** ``PasswordAuthentication`` and
  ``KbdInteractiveAuthentication`` are explicitly disabled, so the agent can
  never prompt for -- or hold -- a password. The key path arrives from a CLI
  flag or the ``SENTINEL_SSH_KEY`` environment variable; nothing sensitive is
  ever written into argv beyond a path, and the path is not echoed into logs.
* **Host-key verification is on by default.** ``--insecure-host-key`` exists for
  a throwaway workshop target only, and it prints a loud warning that is also
  recorded in the report's ``notes`` so a reader cannot miss it.
* **The remote shell sees a shell-quoted string** (unavoidable with ssh), which
  is precisely why :func:`allowlist.assert_read_only` asserts that every argv
  survives a ``shlex.quote`` -> ``shlex.split`` round-trip unchanged.
"""

from __future__ import annotations

import atexit
import os
import shutil
import subprocess
import tempfile

from ..allowlist import CommandSpec, render_ssh
from ..models import CommandResult
from .base import DEFAULT_TIMEOUT, Connector, ConnectorError, TargetInfo


class SSHConnector(Connector):
    transport = "ssh"

    def __init__(
        self,
        host: str,
        user: str | None = None,
        port: int = 22,
        key_path: str | None = None,
        insecure_host_key: bool = False,
        connect_timeout: int = 10,
    ) -> None:
        self.host = host
        self.user = user or os.environ.get("SENTINEL_SSH_USER") or ""
        self.port = port
        self.key_path = key_path or os.environ.get("SENTINEL_SSH_KEY") or None
        self.insecure_host_key = insecure_host_key
        self.connect_timeout = connect_timeout
        self._ctl_dir: str | None = None
        self._remote_user = ""
        self._opened = False

    # -- session -----------------------------------------------------------

    @property
    def _destination(self) -> str:
        return f"{self.user}@{self.host}" if self.user else self.host

    def _base_opts(self) -> list[str]:
        opts = [
            "-o", "BatchMode=yes",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", f"ConnectTimeout={self.connect_timeout}",
            "-o", "LogLevel=ERROR",
            "-p", str(self.port),
        ]
        if self.insecure_host_key:
            opts += [
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
            ]
        else:
            opts += ["-o", "StrictHostKeyChecking=yes"]
        if self.key_path:
            opts += ["-i", os.path.expanduser(self.key_path), "-o", "IdentitiesOnly=yes"]
        if self._ctl_dir:
            opts += [
                "-o", "ControlMaster=auto",
                "-o", f"ControlPath={self._ctl_dir}/cm-%C",
                "-o", "ControlPersist=60",
            ]
        return opts

    def open(self) -> None:
        if shutil.which("ssh") is None:
            raise ConnectorError("no ssh client found on PATH")
        self._ctl_dir = self._make_ctl_dir()
        atexit.register(self._cleanup_ctl_dir)

        probe = ["ssh", *self._base_opts(), self._destination, "id -un"]
        try:
            proc = subprocess.run(  # noqa: S603
                probe, capture_output=True, text=True,
                timeout=self.connect_timeout + 10, shell=False, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ConnectorError(
                f"ssh session to {self._destination} timed out during handshake"
            ) from exc
        except OSError as exc:
            raise ConnectorError(f"ssh could not be started: {exc}") from exc

        if proc.returncode != 0:
            raise ConnectorError(
                f"ssh session to {self._destination}:{self.port} could not be "
                f"established (exit {proc.returncode}): "
                f"{proc.stderr.strip() or 'no stderr'}"
            )
        self._remote_user = proc.stdout.strip()
        self._opened = True

    def run(self, spec: CommandSpec, timeout: int = DEFAULT_TIMEOUT) -> CommandResult:
        if not self._opened:
            raise ConnectorError("run() called before open()")
        self._guard(spec)
        remote = render_ssh(spec.argv)
        argv = ["ssh", *self._base_opts(), self._destination, remote]
        return self._exec(argv, spec, timeout, display=spec.display)

    def close(self) -> None:
        if self._opened and self._ctl_dir:
            subprocess.run(  # noqa: S603
                ["ssh", *self._base_opts(), "-O", "exit", self._destination],
                capture_output=True, text=True, timeout=10, shell=False, check=False,
            )
        self._opened = False
        self._cleanup_ctl_dir()

    @staticmethod
    def _make_ctl_dir() -> str:
        """A control-socket directory short enough for a UNIX socket path.

        ``sun_path`` is capped at ~104 bytes on macOS and ~108 on Linux, and
        ``ControlPath`` is a socket path. The default temp directory on macOS
        (``/var/folders/../T/``) plus a ``cm-%C`` hash already exceeds that, so
        prefer a short base and fall back to the platform default only if it is
        unavailable.
        """
        for base in ("/tmp", None):
            try:
                return tempfile.mkdtemp(prefix="sa-", dir=base)
            except OSError:
                continue
        raise ConnectorError("could not create a control-socket directory")

    def _cleanup_ctl_dir(self) -> None:
        if self._ctl_dir and os.path.isdir(self._ctl_dir):
            shutil.rmtree(self._ctl_dir, ignore_errors=True)
        self._ctl_dir = None

    def describe(self) -> TargetInfo:
        return TargetInfo(
            transport=self.transport,
            label=f"{self._destination}:{self.port}",
            detail={
                "host": self.host,
                "port": str(self.port),
                "remote_user": self._remote_user,
                # Key *path* only -- never key material.
                "key_path": self.key_path or "(ssh-agent / default identities)",
                "host_key_checking": "disabled" if self.insecure_host_key else "strict",
            },
        )
