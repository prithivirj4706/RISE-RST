"""Local connector -- audits the machine the agent is running on.

Useful for demos and for auditing a laptop/workstation directly. The session
"handshake" is a real command (``id -un``); if even that fails we raise
:class:`ConnectorError` so the run exits non-zero like any other transport.
"""

from __future__ import annotations

import platform as _platform
import shutil

from ..allowlist import CommandSpec
from ..models import CommandResult
from .base import DEFAULT_TIMEOUT, Connector, ConnectorError, TargetInfo


class LocalConnector(Connector):
    transport = "local"

    def __init__(self) -> None:
        self._user = ""
        self._opened = False

    def open(self) -> None:
        probe = ["id", "-un"] if _platform.system() != "Windows" else [
            "powershell", "-NoProfile", "-NonInteractive", "-Command", "$env:USERNAME"
        ]
        if shutil.which(probe[0]) is None:
            raise ConnectorError(
                f"local session probe unavailable: {probe[0]} not found on PATH"
            )
        import subprocess

        try:
            proc = subprocess.run(  # noqa: S603
                probe, capture_output=True, text=True, timeout=10, shell=False,
                check=False,
            )
        except OSError as exc:
            raise ConnectorError(f"local session could not be opened: {exc}") from exc
        if proc.returncode != 0:
            raise ConnectorError(
                f"local session probe failed (exit {proc.returncode}): "
                f"{proc.stderr.strip() or 'no stderr'}"
            )
        self._user = proc.stdout.strip()
        self._opened = True

    def run(self, spec: CommandSpec, timeout: int = DEFAULT_TIMEOUT) -> CommandResult:
        if not self._opened:
            raise ConnectorError("run() called before open()")
        self._guard(spec)
        return self._exec(list(spec.argv), spec, timeout)

    def describe(self) -> TargetInfo:
        return TargetInfo(
            transport=self.transport,
            label=f"localhost ({_platform.node()})",
            detail={"user": self._user, "node": _platform.node()},
        )
