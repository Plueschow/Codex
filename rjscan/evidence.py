import hashlib
import json
from pathlib import Path
from typing import Any, Dict


def sha256_bytes(data: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(data)
    return digest.hexdigest()


def write_evidence_text(evidence_dir: Path, name: str, content: str) -> Dict[str, str]:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    path = evidence_dir / name
    data = content.encode("utf-8")
    path.write_bytes(data)
    return {"path": str(path), "sha256": sha256_bytes(data)}


def write_evidence_json(evidence_dir: Path, name: str, payload: Dict[str, Any]) -> Dict[str, str]:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    path = evidence_dir / name
    data = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    path.write_bytes(data)
    return {"path": str(path), "sha256": sha256_bytes(data)}
