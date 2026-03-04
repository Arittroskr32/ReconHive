from __future__ import annotations

from urllib.parse import quote
from pathlib import Path

from .runner import (
    CommandRunner,
    filter_hosts,
    load_tool_overrides,
    read_hosts,
    resolve_tool_command,
    write_lines,
    write_raw,
)
from .scope import ScopeData


def run_enum(workspace: Path, scope_data: ScopeData, runner: CommandRunner) -> list[str]:
    targets = sorted(scope_data.in_exact | {w[2:] for w in scope_data.in_wildcards})
    passive_path = workspace / "subs/passive_raw.txt"
    ct_path = workspace / "subs/ct.txt"
    asn_path = workspace / "subs/asn_intel.txt"

    overrides = load_tool_overrides(workspace)
    discovered: set[str] = set()
    raw_passive: list[str] = []

    for target in targets:
        subfinder_cmd = resolve_tool_command("subfinder", workspace, overrides)
        if subfinder_cmd:
            result = runner.run([*subfinder_cmd, "-silent", "-d", target])
            if result and result.stdout:
                lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
                raw_passive.extend(lines)
                discovered.update(lines)

        assetfinder_cmd = resolve_tool_command("assetfinder", workspace, overrides)
        if assetfinder_cmd:
            result = runner.run([*assetfinder_cmd, "--subs-only", target])
            if result and result.stdout:
                lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
                raw_passive.extend(lines)
                discovered.update(lines)

        findomain_cmd = resolve_tool_command("findomain", workspace, overrides)
        if findomain_cmd:
            result = runner.run([*findomain_cmd, "-t", target, "-q"])
            if result and result.stdout:
                lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
                raw_passive.extend(lines)
                discovered.update(lines)

        amass_cmd = resolve_tool_command("amass", workspace, overrides)
        if amass_cmd:
            result = runner.run([*amass_cmd, "enum", "-passive", "-d", target, "-silent"])
            if result and result.stdout:
                lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
                raw_passive.extend(lines)
                discovered.update(lines)

        crtsh_cmd = resolve_tool_command("crtsh", workspace, overrides)
        if crtsh_cmd:
            result = runner.run([*crtsh_cmd, target])
            if result and result.stdout:
                lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
                discovered.update(lines)
                write_raw(ct_path, lines)
        else:
            result = runner.run([
                "curl",
                "-s",
                f"https://crt.sh/?q=%25.{quote(target)}&output=json",
            ])
            if result and result.stdout:
                write_raw(ct_path, [result.stdout.strip()])

    if not discovered:
        discovered.update(targets)

    filtered = filter_hosts(discovered, scope_data)
    write_lines(passive_path, filtered)
    if not ct_path.exists():
        write_raw(ct_path, [])
    write_raw(asn_path, [])
    write_lines(workspace / "subs/all_subs.txt", filtered)

    return ["subs/passive_raw.txt", "subs/ct.txt", "subs/asn_intel.txt", "subs/all_subs.txt"]


def run_resolve(workspace: Path, scope_data: ScopeData, runner: CommandRunner) -> list[str]:
    all_subs = read_hosts(workspace / "subs/all_subs.txt")
    permutations = read_hosts(workspace / "subs/permutations.txt")
    candidates = filter_hosts(all_subs + permutations, scope_data)

    resolved_path = workspace / "resolved/resolved.txt"
    unresolved_path = workspace / "resolved/unresolved.txt"

    overrides = load_tool_overrides(workspace)
    dnsx_cmd = resolve_tool_command("dnsx", workspace, overrides)

    if dnsx_cmd and candidates:
        temp_input = workspace / "resolved/.resolve_input.txt"
        write_lines(temp_input, candidates)
        result = runner.run([*dnsx_cmd, "-silent", "-l", str(temp_input)])
        resolved = []
        if result and result.stdout:
            resolved = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        resolved = filter_hosts(resolved, scope_data)
    else:
        resolved = candidates

    unresolved = sorted(set(candidates) - set(resolved))
    write_lines(resolved_path, resolved)
    write_lines(unresolved_path, unresolved)
    return ["resolved/resolved.txt", "resolved/unresolved.txt"]


def run_live(workspace: Path, scope_data: ScopeData, runner: CommandRunner, threads: int, timeout: int, rate: int) -> list[str]:
    resolved = filter_hosts(read_hosts(workspace / "resolved/resolved.txt"), scope_data)
    live_path = workspace / "live/live.txt"
    httpx_full_path = workspace / "live/httpx_full.txt"

    overrides = load_tool_overrides(workspace)
    httpx_cmd = resolve_tool_command("httpx", workspace, overrides)

    if httpx_cmd and resolved:
        temp_input = workspace / "live/.live_input.txt"
        write_lines(temp_input, resolved)
        cmd = [
            *httpx_cmd,
            "-silent",
            "-l",
            str(temp_input),
            "-threads",
            str(threads),
            "-timeout",
            str(timeout),
            "-rate-limit",
            str(rate),
            "-title",
            "-status-code",
            "-tech-detect",
            "-server",
        ]
        result = runner.run(cmd)
        raw = [line.strip() for line in (result.stdout.splitlines() if result and result.stdout else []) if line.strip()]
        hosts = [line.split()[0].strip() for line in raw]
        filtered_hosts = sorted({h for h in hosts if in_scope_candidate(h, scope_data)})
        filtered_full = [line for line in raw if in_scope_candidate(line.split()[0].strip(), scope_data)]
        write_lines(live_path, filtered_hosts)
        write_raw(httpx_full_path, filtered_full)
    else:
        write_lines(live_path, resolved)
        write_raw(httpx_full_path, resolved)

    return ["live/live.txt", "live/httpx_full.txt"]


def in_scope_candidate(candidate: str, scope_data: ScopeData) -> bool:
    candidate = candidate.replace("https://", "").replace("http://", "")
    candidate = candidate.split("/", 1)[0]
    return bool(filter_hosts([candidate], scope_data))


def check_stage_dependencies(workspace: Path, stage: str) -> tuple[bool, str]:
    requirements = {
        "resolve": [workspace / "subs/all_subs.txt"],
        "live": [workspace / "resolved/resolved.txt"],
        "ports": [workspace / "live/live.txt"],
        "tech": [workspace / "live/live.txt"],
        "crawl": [workspace / "live/live.txt"],
        "js": [workspace / "urls/all_urls.txt"],
        "params_content": [workspace / "live/live.txt", workspace / "urls/all_urls.txt"],
        "visual": [workspace / "live/live.txt"],
        "scan": [workspace / "live/live.txt"],
    }

    needed = requirements.get(stage, [])
    if not needed:
        return True, ""

    missing = [str(path.relative_to(workspace)) for path in needed if not path.exists()]
    if missing:
        return False, f"Missing inputs for {stage}: {', '.join(missing)}"

    empty = []
    for path in needed:
        try:
            if path.read_text(encoding="utf-8", errors="ignore").strip() == "":
                empty.append(str(path.relative_to(workspace)))
        except OSError:
            empty.append(str(path.relative_to(workspace)))

    if empty:
        return False, f"Input files empty for {stage}: {', '.join(empty)}"

    return True, ""
