from dataclasses import dataclass
from typing import List
from pathlib import Path


@dataclass
class GadgetSignature:
    name: str
    confidence: str
    indicators: List[str]


def load_gadgets(path: Path) -> List[GadgetSignature]:
    gadgets: List[GadgetSignature] = []
    current: dict = {}
    indicators: List[str] = []
    for raw_line in path.read_text().splitlines():
        line = raw_line.rstrip()
        if not line or line.strip().startswith("#"):
            continue
        stripped = line.lstrip()
        if stripped.startswith("- name:"):
            if current:
                gadgets.append(
                    GadgetSignature(
                        name=current.get("name", ""),
                        confidence=current.get("confidence", "LOW"),
                        indicators=indicators,
                    )
                )
            current = {"name": stripped.split(":", 1)[1].strip()}
            indicators = []
        elif stripped.startswith("confidence:"):
            current["confidence"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("- ") and "indicators" in raw_line:
            continue
        elif stripped.startswith("- "):
            indicators.append(stripped.split("-", 1)[1].strip())
    if current:
        gadgets.append(
            GadgetSignature(
                name=current.get("name", ""),
                confidence=current.get("confidence", "LOW"),
                indicators=indicators,
            )
        )
    return gadgets


def match_gadgets(text: str, gadgets: List[GadgetSignature]) -> List[GadgetSignature]:
    matches: List[GadgetSignature] = []
    for gadget in gadgets:
        if all(indicator.lower() in text.lower() for indicator in gadget.indicators):
            matches.append(gadget)
    return matches
