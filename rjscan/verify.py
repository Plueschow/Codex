from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from rjscan.evidence import write_evidence_text
from rjscan.kb import ChainSignature, GadgetSignature, match_chains, match_gadgets


@dataclass
class VerifyFinding:
    name: str
    status: str
    evidence: List[Dict[str, str]]
    details: Optional[Dict[str, List[str]]] = None


def _evidence_from_text(evidence_dir: Path, name: str, content: str) -> List[Dict[str, str]]:
    if not content:
        return []
    ref = write_evidence_text(evidence_dir, name, content)
    return [ref]


def check_auth_required(text: str, evidence_dir: Path) -> VerifyFinding:
    flag = "authentication" in text.lower()
    evidence = _evidence_from_text(
        evidence_dir,
        "auth_required.txt",
        text if flag else "",
    )
    status = "observed" if flag else "not_observed"
    return VerifyFinding(name="auth_required", status=status, evidence=evidence)


def check_tls_required(text: str, evidence_dir: Path) -> VerifyFinding:
    flag = "ssl" in text.lower() or "tls" in text.lower()
    evidence = _evidence_from_text(evidence_dir, "tls_required.txt", text if flag else "")
    status = "observed" if flag else "not_observed"
    return VerifyFinding(name="tls_required", status=status, evidence=evidence)


def check_error_oracle(text: str, evidence_dir: Path) -> VerifyFinding:
    flag = "exception" in text.lower() or "stack" in text.lower()
    evidence = _evidence_from_text(evidence_dir, "error_oracle.txt", text if flag else "")
    status = "observed" if flag else "not_observed"
    return VerifyFinding(name="error_oracle", status=status, evidence=evidence)


def check_sink_indicators(text: str, evidence_dir: Path) -> VerifyFinding:
    indicators = ["invocationtargetexception", "unmarshal", "objectinputstream"]
    flag = any(indicator in text.lower() for indicator in indicators)
    evidence = _evidence_from_text(evidence_dir, "sink_indicators.txt", text if flag else "")
    status = "observed" if flag else "not_observed"
    return VerifyFinding(name="sink_indicators", status=status, evidence=evidence)


def check_gadget_detect(
    text: str,
    evidence_dir: Path,
    gadgets: List[GadgetSignature],
    chains: List[ChainSignature],
) -> VerifyFinding:
    matches = match_gadgets(text, gadgets)
    chain_matches = match_chains(matches, chains)
    if matches:
        content = "\n".join(f"{match.name}:{match.confidence}" for match in matches)
        details = {
            "matches": [f"{match.name}:{match.confidence}" for match in matches],
            "chains": [f"{chain.name}:{chain.confidence}" for chain in chain_matches],
        }
    else:
        content = ""
        details = None
    evidence = _evidence_from_text(evidence_dir, "gadget_detect.txt", content)
    status = "observed" if matches else "not_observed"
    return VerifyFinding(name="gadget_detect", status=status, evidence=evidence, details=details)


def run_checks(
    text: str,
    evidence_dir: Path,
    gadgets: List[GadgetSignature],
    chains: List[ChainSignature],
) -> List[VerifyFinding]:
    return [
        check_auth_required(text, evidence_dir),
        check_tls_required(text, evidence_dir),
        check_error_oracle(text, evidence_dir),
        check_sink_indicators(text, evidence_dir),
        check_gadget_detect(text, evidence_dir, gadgets, chains),
    ]
