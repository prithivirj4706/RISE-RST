"""Connector interface.

One shared surface -- ``open()`` / ``run()`` / ``close()`` -- implemented by the
local, SSH and Docker transports. The collector, rule engine and prioritizer are
written against this interface only and never learn which transport is in use.

A connector may only execute :class:`CommandSpec` objects that came out of the
allowlist. It never accepts a raw string, so there is no code path through which
a rule, a config file or an LLM could get an arbitrary command onto the target.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

from ..allowlist import CommandSpec, assert_read_only
from ..models import CommandResult

# Commands are cheap reads; a hung target must not hang the audit.
DEFAULT_TIMEOUT = 20

# Shells report "command not found" as 127; execve failures surface as ENOENT.
NOT_FOUND_EXIT = 127


class ConnectorError(RuntimeError):
    """The transport could not establish or maintain a session.

    Requirement 9: this is fatal and the run must exit non-zero.
    """


@dataclass
class TargetInfo:
    transport: str
    label: str  # human-readable target identity, never contains a credential
    detail: dict[str, str]


class Connector:
    """Abstract read-only session against one target."""

    transport = "abstract"

    def open(self) -> None:
        raise NotImplementedError

    def run(self, spec: CommandSpec, timeout: int = DEFAULT_TIMEOUT) -> CommandResult:
        raise NotImplementedError

    def close(self) -> None:
        pass

    def describe(self) -> TargetInfo:
        raise NotImplementedError

    def __enter__(self) -> "Connector":
        self.open()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- shared helpers ----------------------------------------------------

    @staticmethod
    def _guard(spec: CommandSpec) -> None:
        """Re-validate at execution time, not just at import time."""
        assert_read_only(spec)

    @staticmethod
    def _exec(
        argv: list[str],
        spec: CommandSpec,
        timeout: int,
        *,
        display: str | None = None,
    ) -> CommandResult:
        """Run argv with no shell and wrap the outcome in a CommandResult."""
        result = CommandResult(
            command_id=spec.command_id,
            argv=list(spec.argv),
            display=display or spec.display,
        )
        try:
            proc = subprocess.run(  # noqa: S603 - argv list, shell=False
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,
                check=False,
            )
        except FileNotFoundError as exc:
            result.available = False
            result.exit_code = NOT_FOUND_EXIT
            result.error = f"binary not found on target: {exc.filename}"
            return result
        except subprocess.TimeoutExpired:
            result.available = True
            result.exit_code = 124
            result.error = f"command timed out after {timeout}s"
            return result
        except OSError as exc:
            result.available = False
            result.error = f"could not execute: {exc}"
            return result

        result.stdout = (proc.stdout or "").strip()
        result.stderr = (proc.stderr or "").strip()
        result.exit_code = proc.returncode
        if result.exit_code == NOT_FOUND_EXIT or "command not found" in result.stderr.lower():
            result.available = False
            result.error = "binary not available on target"
        return result
