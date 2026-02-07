from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional
import hashlib
import time

from rjscan.callback import CallbackRegistry
from rjscan.evidence import write_evidence_json, write_evidence_text


@dataclass
class VerifyResult:
    verified: bool
    artifacts: Dict[str, Any]
    evidence_refs: list[Dict[str, str]]


@dataclass
class VerifierContext:
    evidence_dir: Path
    verifier: str
    callback_registry: Optional[CallbackRegistry]
    callback_timeout: float
    smb_share_path: Optional[Path]
    smb_share_subdir: Optional[str]


def _resolve_backend(verifier: str, callback_registry: Optional[CallbackRegistry], smb_share_path: Optional[Path]) -> str:
    if verifier != "auto":
        return verifier
    if callback_registry:
        return "callback_http"
    if smb_share_path:
        return "smb_share"
    return "inconclusive"


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_file_write(
    ctx: VerifierContext,
    exec_channel: Dict[str, Any],
    path: str,
    content: str,
    cleanup: bool,
) -> VerifyResult:
    backend = _resolve_backend(ctx.verifier, ctx.callback_registry, ctx.smb_share_path)
    artifacts: Dict[str, Any] = {"backend": backend, "path": path}
    evidence: list[Dict[str, str]] = []
    verified = False

    if backend == "callback_http" and ctx.callback_registry:
        token = exec_channel.get("callback_token")
        if token:
            event = ctx.callback_registry.wait_for(token, ctx.callback_timeout)
            if event:
                verified = True
                artifacts.update({"callback_path": event.path, "token": token})
                evidence.append(write_evidence_json(ctx.evidence_dir, f"callback-{token}.json", artifacts))
    elif backend == "smb_share" and ctx.smb_share_path:
        relpath = exec_channel.get("smb_relpath")
        candidate = None
        if relpath:
            candidate = ctx.smb_share_path / relpath
        elif ctx.smb_share_subdir:
            candidate = ctx.smb_share_path / ctx.smb_share_subdir / Path(path).name
        else:
            candidate = ctx.smb_share_path / Path(path).name
        if candidate and candidate.exists():
            verified = True
            artifacts.update({
                "smb_path": str(candidate),
                "size": candidate.stat().st_size,
                "sha256": _sha256_path(candidate),
            })
            evidence.append(write_evidence_json(ctx.evidence_dir, "smb-proof.json", artifacts))
            if cleanup:
                candidate.unlink()
    else:
        note = write_evidence_text(ctx.evidence_dir, "verify_file_write.txt", "verification unavailable")
        evidence.append(note)

    return VerifyResult(verified=verified, artifacts=artifacts, evidence_refs=evidence)


def verify_cmd(
    ctx: VerifierContext,
    exec_channel: Dict[str, Any],
    cmd: str,
) -> VerifyResult:
    backend = _resolve_backend(ctx.verifier, ctx.callback_registry, ctx.smb_share_path)
    artifacts: Dict[str, Any] = {"backend": backend, "cmd": cmd}
    evidence: list[Dict[str, str]] = []
    verified = False

    outputs = exec_channel.get("cmd_output")
    if isinstance(outputs, dict):
        whoami = outputs.get("whoami")
        hostname = outputs.get("hostname")
        if whoami or hostname:
            verified = True
            artifacts.update({"whoami": whoami, "hostname": hostname})
            evidence.append(write_evidence_json(ctx.evidence_dir, "cmd-output.json", artifacts))

    if not verified:
        note = write_evidence_text(ctx.evidence_dir, "verify_cmd.txt", "command proof not verified")
        evidence.append(note)

    return VerifyResult(verified=verified, artifacts=artifacts, evidence_refs=evidence)
