from __future__ import annotations

from dataclasses import dataclass
from importlib import util
from pathlib import Path
from typing import Any, Callable, Dict, List
import inspect


@dataclass
class RunnerResult:
    success: bool
    execution_channel: Dict[str, Any]
    evidence_refs: List[str]
    notes: List[str]


@dataclass
class RunnerPlugin:
    runner_id: str
    title: str
    run: Callable[..., Any]


def load_runner(path: Path) -> RunnerPlugin:
    spec = util.spec_from_file_location(path.stem, str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load runner: {path}")
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    if not hasattr(module, "RUNNER_ID") or not hasattr(module, "TITLE"):
        raise RuntimeError("Runner missing RUNNER_ID or TITLE")
    if not hasattr(module, "run") or not inspect.iscoroutinefunction(module.run):
        raise RuntimeError("Runner must define async def run(ctx, target, payload_spec)")
    return RunnerPlugin(runner_id=module.RUNNER_ID, title=module.TITLE, run=module.run)


def coerce_runner_result(result: Any) -> RunnerResult:
    if isinstance(result, RunnerResult):
        return result
    if isinstance(result, dict):
        return RunnerResult(
            success=bool(result.get("success", False)),
            execution_channel=result.get("execution_channel", {}) or {},
            evidence_refs=list(result.get("evidence_refs", []) or []),
            notes=list(result.get("notes", []) or []),
        )
    raise RuntimeError("Runner returned invalid result")
