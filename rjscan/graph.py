from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Tuple
import hashlib
import re


ENDPOINT_HINT = re.compile(r"(?P<host>(?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9_.-]+)[: ](?P<port>\d{1,5})")


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int
    kind: str

    @property
    def endpoint_id(self) -> str:
        raw = f"{self.host}:{self.port}:{self.kind}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


@dataclass
class Edge:
    source_id: str
    target_id: str
    evidence: List[Dict[str, str]] = field(default_factory=list)


def extract_hints(text: str) -> List[Tuple[str, int]]:
    hints: List[Tuple[str, int]] = []
    for match in ENDPOINT_HINT.finditer(text):
        host = match.group("host")
        port = int(match.group("port"))
        hints.append((host, port))
    return hints


def bfs_graph(
    seeds: Iterable[Endpoint],
    hint_provider: Dict[str, List[Tuple[str, int, List[Dict[str, str]]]]],
    max_depth: int,
) -> Tuple[List[Endpoint], List[Edge]]:
    queue = deque([(endpoint, 0) for endpoint in seeds])
    seen: Dict[str, Endpoint] = {endpoint.endpoint_id: endpoint for endpoint in seeds}
    edges: List[Edge] = []

    while queue:
        current, depth = queue.popleft()
        if depth >= max_depth:
            continue
        key = current.endpoint_id
        hints = hint_provider.get(key, [])
        for host, port, evidence in hints:
            derived = Endpoint(host=host, port=port, kind=current.kind)
            derived_id = derived.endpoint_id
            edge = Edge(source_id=key, target_id=derived_id, evidence=evidence)
            edges.append(edge)
            if derived_id not in seen:
                seen[derived_id] = derived
                queue.append((derived, depth + 1))
    ordered = sorted(seen.values(), key=lambda item: (item.host, item.port, item.kind))
    return ordered, edges
