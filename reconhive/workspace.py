from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from .constants import OUTPUTS_BY_STAGE, STAGE_ORDER, WORKSPACE_DIRS


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_workspace_layout(workspace: Path) -> None:
    workspace.mkdir(parents=True, exist_ok=True)
    for directory in WORKSPACE_DIRS:
        (workspace / directory).mkdir(parents=True, exist_ok=True)


def state_path(workspace: Path) -> Path:
    return workspace / "state.json"


def init_state(workspace: Path) -> dict[str, Any]:
    state = {
        "workspace": str(workspace),
        "created": now_iso(),
        "updated": now_iso(),
        "stages": {stage: {"done": False} for stage in STAGE_ORDER},
    }
    save_state(workspace, state)
    return state


def load_state(workspace: Path) -> dict[str, Any]:
    path = state_path(workspace)
    if not path.exists():
        return init_state(workspace)
    return json.loads(path.read_text(encoding="utf-8"))


def save_state(workspace: Path, state: dict[str, Any]) -> None:
    state["updated"] = now_iso()
    state_path(workspace).write_text(json.dumps(state, indent=2), encoding="utf-8")


def mark_stage_started(workspace: Path, state: dict[str, Any], stage: str) -> None:
    stage_state = state["stages"].setdefault(stage, {})
    stage_state["started"] = now_iso()
    stage_state["done"] = False
    stage_state["failed"] = False
    stage_state.pop("error", None)
    save_state(workspace, state)


def mark_stage_finished(workspace: Path, state: dict[str, Any], stage: str, outputs: list[str]) -> None:
    stage_state = state["stages"].setdefault(stage, {})
    stage_state["ended"] = now_iso()
    stage_state["done"] = True
    stage_state["failed"] = False
    stage_state.pop("error", None)

    counts: dict[str, int] = {}
    for relative in outputs:
        file_path = workspace / relative
        if file_path.exists() and file_path.is_file():
            counts[relative] = _count_lines(file_path)

    stage_state["output_counts"] = counts
    save_state(workspace, state)


def mark_stage_failed(
    workspace: Path,
    state: dict[str, Any],
    stage: str,
    error: str,
    outputs: list[str] | None = None,
) -> None:
    stage_state = state["stages"].setdefault(stage, {})
    stage_state["ended"] = now_iso()
    stage_state["done"] = False
    stage_state["failed"] = True
    stage_state["error"] = error

    counts: dict[str, int] = {}
    for relative in outputs or []:
        file_path = workspace / relative
        if file_path.exists() and file_path.is_file():
            counts[relative] = _count_lines(file_path)

    stage_state["output_counts"] = counts
    save_state(workspace, state)


def _count_lines(path: Path) -> int:
    with path.open("r", encoding="utf-8", errors="ignore") as stream:
        return sum(1 for _ in stream)


def stage_done(state: dict[str, Any], stage: str) -> bool:
    return bool(state.get("stages", {}).get(stage, {}).get("done"))


def stage_outputs(stage: str) -> list[str]:
    return OUTPUTS_BY_STAGE.get(stage, [])
