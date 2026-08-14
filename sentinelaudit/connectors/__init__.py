"""Transports. One interface, three implementations: local, SSH, docker exec."""

from .base import Connector, ConnectorError, TargetInfo
from .docker import DockerConnector
from .local import LocalConnector
from .ssh import SSHConnector

__all__ = [
    "Connector", "ConnectorError", "TargetInfo",
    "LocalConnector", "SSHConnector", "DockerConnector",
]
