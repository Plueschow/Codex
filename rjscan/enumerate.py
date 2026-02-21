from dataclasses import dataclass, field
from typing import Dict, List, Optional
import socket


@dataclass
class EnumResult:
    registry_names: List[str] = field(default_factory=list)
    jmx_domains: List[str] = field(default_factory=list)
    jmx_mbeans: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


def _connect(host: str, port: int, timeout: float) -> Optional[socket.socket]:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        return sock
    except OSError:
        return None


def enumerate_rmi_registry(host: str, port: int, timeout: float) -> EnumResult:
    result = EnumResult()
    sock = _connect(host, port, timeout)
    if sock is None:
        result.notes.append("connection_failed")
        return result
    try:
        result.notes.append("registry_listing_not_supported")
    finally:
        sock.close()
    return result


def enumerate_jmx(host: str, port: int, timeout: float, username: Optional[str], password: Optional[str]) -> EnumResult:
    result = EnumResult()
    sock = _connect(host, port, timeout)
    if sock is None:
        result.notes.append("connection_failed")
        return result
    try:
        result.notes.append("jmx_listing_not_supported")
    finally:
        sock.close()
    return result
