from __future__ import annotations

from dataclasses import dataclass
from importlib import util
from pathlib import Path
from typing import Any, Callable, Dict, Optional


@dataclass
class PocResult:
    status: str
    details: Dict[str, Any]


def load_poc_plugin(path: Path) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    spec = util.spec_from_file_location(path.stem, str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load PoC plugin")
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    if not hasattr(module, "run"):
        raise RuntimeError("PoC plugin missing run(context) function")
    return getattr(module, "run")
