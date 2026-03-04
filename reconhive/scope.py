from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse


@dataclass
class ScopeData:
    in_exact: set[str]
    in_wildcards: set[str]
    out_exact: set[str]
    out_wildcards: set[str]

    def to_dict(self) -> dict:
        return {
            "in_scope": {
                "exact": sorted(self.in_exact),
                "wildcards": sorted(self.in_wildcards),
            },
            "out_of_scope": {
                "exact": sorted(self.out_exact),
                "wildcards": sorted(self.out_wildcards),
            },
        }


def _strip_comment(line: str) -> str:
    idx = line.find("#")
    if idx == -1:
        return line.strip()
    return line[:idx].strip()


def _normalize_token(raw: str) -> str | None:
    token = _strip_comment(raw)
    if not token:
        return None

    token = token.strip().lower()

    if "://" in token:
        parsed = urlparse(token)
        host = (parsed.hostname or "").strip().lower()
        return host or None

    if token.startswith("*."):
        token = token.rstrip("/")
        return token

    if "/" in token:
        token = token.split("/", 1)[0]

    if ":" in token and token.count(":") == 1:
        host, _, port = token.partition(":")
        if port.isdigit():
            token = host

    token = token.strip().strip(".")
    return token or None


def parse_scope_lines(lines: Iterable[str]) -> tuple[set[str], set[str]]:
    exact: set[str] = set()
    wildcards: set[str] = set()

    for line in lines:
        normalized = _normalize_token(line)
        if not normalized:
            continue

        if normalized.startswith("*."):
            suffix = normalized[2:].strip(".")
            if suffix:
                wildcards.add(f"*.{suffix}")
        else:
            exact.add(normalized)

    return exact, wildcards


def parse_scope_files(in_scope_path: Path, out_scope_path: Path | None) -> tuple[ScopeData, dict[str, str]]:
    in_exact, in_wildcards = parse_scope_lines(in_scope_path.read_text(encoding="utf-8").splitlines())
    out_exact: set[str] = set()
    out_wildcards: set[str] = set()

    if out_scope_path and out_scope_path.exists():
        out_exact, out_wildcards = parse_scope_lines(out_scope_path.read_text(encoding="utf-8").splitlines())

    hashes = {
        "in_scope_sha256": _sha256_file(in_scope_path),
        "out_of_scope_sha256": _sha256_file(out_scope_path) if out_scope_path and out_scope_path.exists() else "",
    }

    return ScopeData(in_exact, in_wildcards, out_exact, out_wildcards), hashes


def _sha256_file(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(8192)
            if not chunk:
                break
            sha.update(chunk)
    return sha.hexdigest()


def in_scope(host: str, scope_data: ScopeData) -> bool:
    host = _normalize_token(host) or ""
    if not host:
        return False

    if _matches(host, scope_data.out_exact, scope_data.out_wildcards):
        return False

    return _matches(host, scope_data.in_exact, scope_data.in_wildcards)


def _matches(host: str, exact: set[str], wildcards: set[str]) -> bool:
    if host in exact:
        return True

    for pattern in wildcards:
        suffix = pattern[2:]
        if host.endswith(f".{suffix}"):
            return True

    return False


def save_scope_json(scope_data: ScopeData, target: Path, hashes: dict[str, str]) -> None:
    payload = {
        **scope_data.to_dict(),
        "hashes": hashes,
    }
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_scope_json(path: Path) -> ScopeData:
    data = json.loads(path.read_text(encoding="utf-8"))
    return ScopeData(
        in_exact=set(data.get("in_scope", {}).get("exact", [])),
        in_wildcards=set(data.get("in_scope", {}).get("wildcards", [])),
        out_exact=set(data.get("out_of_scope", {}).get("exact", [])),
        out_wildcards=set(data.get("out_of_scope", {}).get("wildcards", [])),
    )
