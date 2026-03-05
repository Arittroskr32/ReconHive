from __future__ import annotations

import json
import os
import shutil
import shlex
import subprocess
from pathlib import Path
from typing import Iterable

from .scope import ScopeData, in_scope


class CommandRunner:
    def __init__(self, dry_run: bool = False, strict: bool = False, log_path: Path | None = None):
        self.dry_run = dry_run
        self.strict = strict
        self.log_path = log_path
        self.failures: list[str] = []

    def run(
        self,
        command: list[str],
        cwd: Path | None = None,
        timeout: int | float | None = None,
    ) -> subprocess.CompletedProcess | None:
        self._log(f"$ {' '.join(command)}")
        if self.dry_run:
            return None
        try:
            result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False, timeout=timeout)
        except subprocess.TimeoutExpired:
            message = f"Command timed out ({timeout}s): {' '.join(command)}"
            self._log(message)
            if self.strict:
                raise RuntimeError(message)
            self.failures.append(message)
            return None
        except OSError as exc:
            message = f"Failed to execute command: {' '.join(command)} ({exc})"
            self._log(message)
            if self.strict:
                raise RuntimeError(message) from exc
            self.failures.append(message)
            return None
        if result.stdout:
            self._log(result.stdout.strip())
        if result.stderr:
            self._log(result.stderr.strip())
        if result.returncode != 0:
            message = f"Command failed ({result.returncode}): {' '.join(command)}"
            self._log(message)
            if self.strict:
                raise RuntimeError(message)
            self.failures.append(message)
        return result

    def _log(self, line: str) -> None:
        if not self.log_path:
            return
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def load_tool_overrides(workspace: Path) -> dict[str, list[str]]:
    config_dir = workspace / "config"
    yaml_path = config_dir / "tools.yaml"
    json_path = config_dir / "tools.json"

    if yaml_path.exists():
        parsed = _parse_simple_tools_yaml(yaml_path)
        if parsed:
            return parsed

    if json_path.exists():
        raw = json.loads(json_path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            out: dict[str, list[str]] = {}
            for name, value in raw.items():
                if isinstance(value, list) and value and all(isinstance(v, str) for v in value):
                    out[name] = value
            return out

    return {}


def resolve_tool_command(tool_name: str, workspace: Path, overrides: dict[str, list[str]] | None = None) -> list[str] | None:
    overrides = overrides or {}
    if tool_name in overrides and overrides[tool_name]:
        return overrides[tool_name]

    if shutil.which(tool_name):
        return [tool_name]

    script_names = [f"{tool_name}.py"]
    if tool_name == "linkfinder":
        script_names.extend(["LinkFinder.py", "linkfinder.py"])
    if tool_name == "secretfinder":
        script_names.extend(["SecretFinder.py", "secretfinder.py"])

    search_roots = [workspace, workspace / "tools", workspace / "third_party"]
    for root in search_roots:
        for script_name in script_names:
            candidate = root / script_name
            if candidate.exists():
                return [os.sys.executable, str(candidate)]

    return None


def _parse_simple_tools_yaml(path: Path) -> dict[str, list[str]]:
    mapping: dict[str, list[str]] = {}
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        text = line.strip()
        if not text or text.startswith("#") or ":" not in text:
            continue
        name, _, rest = text.partition(":")
        tool = name.strip()
        value = rest.strip()
        if not tool or not value:
            continue
        if value.startswith("[") and value.endswith("]"):
            inner = value[1:-1].strip()
            parts = [p.strip().strip("\"'") for p in inner.split(",") if p.strip()]
        else:
            parts = shlex.split(value)
        if parts:
            mapping[tool] = parts
    return mapping


def read_hosts(path: Path) -> list[str]:
    if not path.exists():
        return []
    hosts = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        hosts.append(text)
    return hosts


def write_lines(path: Path, lines: Iterable[str]) -> None:
    unique_sorted = sorted({line.strip() for line in lines if line and line.strip()})
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(unique_sorted) + ("\n" if unique_sorted else ""), encoding="utf-8")


def write_raw(path: Path, lines: Iterable[str]) -> None:
    kept = [line.rstrip("\n") for line in lines if line is not None and line != ""]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")


def filter_hosts(hosts: Iterable[str], scope_data: ScopeData) -> list[str]:
    return sorted({host for host in hosts if in_scope(host, scope_data)})
