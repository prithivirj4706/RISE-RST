"""Docker connector -- audits a local container via ``docker exec``.

``docker exec`` takes an argv vector directly, so unlike the SSH transport there
is no shell on the target at all: no quoting, no word splitting, no globbing.
That makes this the safest of the three transports and the easiest to hand to
another team ("point it at your container name, done").
"""

from __future__ import annotations

import shutil
import subprocess

from ..allowlist import CommandSpec
from ..models import CommandResult
from .base import DEFAULT_TIMEOUT, Connector, ConnectorError, TargetInfo


class DockerConnector(Connector):
    transport = "docker"

    def __init__(self, container: str, user: str | None = None) -> None:
        self.container = container
        self.user = user
        self._remote_user = ""
        self._image = ""
        self._opened = False

    def _exec_prefix(self) -> list[str]:
        prefix = ["docker", "exec"]
        if self.user:
            prefix += ["--user", self.user]
        return [*prefix, self.container]

    def open(self) -> None:
        if shutil.which("docker") is None:
            raise ConnectorError("no docker client found on PATH")

        try:
            inspect = subprocess.run(  # noqa: S603
                ["docker", "inspect", "--format", "{{.State.Running}} {{.Config.Image}}",
                 self.container],
                capture_output=True, text=True, timeout=15, shell=False, check=False,
            )
        except OSError as exc:
            raise ConnectorError(f"docker could not be started: {exc}") from exc

        if inspect.returncode != 0:
            raise ConnectorError(
                f"container {self.container!r} could not be inspected: "
                f"{inspect.stderr.strip() or 'no stderr'}"
            )
        running, _, image = inspect.stdout.strip().partition(" ")
        if running != "true":
            raise ConnectorError(f"container {self.container!r} is not running")
        self._image = image

        probe = subprocess.run(  # noqa: S603
            [*self._exec_prefix(), "id", "-un"],
            capture_output=True, text=True, timeout=15, shell=False, check=False,
        )
        if probe.returncode != 0:
            raise ConnectorError(
                f"docker exec session into {self.container!r} failed "
                f"(exit {probe.returncode}): {probe.stderr.strip() or 'no stderr'}"
            )
        self._remote_user = probe.stdout.strip()
        self._opened = True

    def run(self, spec: CommandSpec, timeout: int = DEFAULT_TIMEOUT) -> CommandResult:
        if not self._opened:
            raise ConnectorError("run() called before open()")
        self._guard(spec)
        return self._exec([*self._exec_prefix(), *spec.argv], spec, timeout,
                          display=spec.display)

    def describe(self) -> TargetInfo:
        return TargetInfo(
            transport=self.transport,
            label=f"docker://{self.container}",
            detail={
                "container": self.container,
                "image": self._image,
                "remote_user": self._remote_user,
            },
        )
