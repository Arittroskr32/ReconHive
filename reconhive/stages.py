from __future__ import annotations

from urllib.parse import parse_qs, quote, urlparse
from pathlib import Path
import json
import re

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


HOST_TOKEN_PATTERN = re.compile(r"[a-z0-9]+")
DEFAULT_PERMUTE_WORDS = [
    "dev",
    "stage",
    "staging",
    "prod",
    "test",
    "internal",
    "beta",
    "old",
    "backup",
    "admin",
    "api",
    "v1",
    "v2",
]


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


def run_permute(workspace: Path, scope_data: ScopeData, runner: CommandRunner) -> list[str]:
    all_subs_path = workspace / "subs/all_subs.txt"
    permutations_path = workspace / "subs/permutations.txt"
    resolved_path = workspace / "resolved/permuted_resolved.txt"

    all_subs = filter_hosts(read_hosts(all_subs_path), scope_data)
    seed_hosts = [host for host in all_subs if "*" not in host]

    if not all_subs:
        raise RuntimeError("permute requires non-empty subs/all_subs.txt")
    if not seed_hosts:
        raise RuntimeError("permute could not find valid non-wildcard seeds in subs/all_subs.txt")

    words = _load_permutation_words(workspace, seed_hosts)
    candidates = _build_permutation_candidates(seed_hosts, words)
    candidates = filter_hosts(candidates, scope_data)

    # Keep only genuinely new guesses; existing subdomains are already known.
    all_subs_set = set(all_subs)
    new_candidates = sorted(set(candidates) - all_subs_set)
    write_lines(permutations_path, new_candidates)

    overrides = load_tool_overrides(workspace)
    advanced = _run_advanced_permuters(workspace, runner, overrides)
    if advanced:
        merged = filter_hosts(new_candidates + advanced, scope_data)
        new_candidates = sorted(set(merged) - all_subs_set)
        write_lines(permutations_path, new_candidates)

    resolved_new = _resolve_permutation_candidates(workspace, runner, overrides, new_candidates, scope_data)
    write_lines(resolved_path, resolved_new)

    if resolved_new:
        write_lines(all_subs_path, all_subs + resolved_new)

    return ["subs/permutations.txt", "resolved/permuted_resolved.txt", "subs/all_subs.txt"]


def _load_permutation_words(workspace: Path, seed_hosts: list[str]) -> list[str]:
    wordlist_path = workspace / "wordlists/permutations.txt"
    if not wordlist_path.exists():
        wordlist_path.parent.mkdir(parents=True, exist_ok=True)
        write_lines(wordlist_path, DEFAULT_PERMUTE_WORDS)

    file_words = [word.lower() for word in read_hosts(wordlist_path)]
    token_words = sorted({token for host in seed_hosts for token in _extract_host_tokens(host)})
    combined = sorted({*file_words, *token_words})
    return [word for word in combined if word]


def _extract_host_tokens(host: str) -> list[str]:
    labels = host.lower().split(".")
    if len(labels) < 3:
        return []

    subdomain_labels = labels[:-2]
    tokens: set[str] = set()
    for label in subdomain_labels:
        for token in HOST_TOKEN_PATTERN.findall(label):
            if token and token not in {"www"} and len(token) > 1:
                tokens.add(token)
    return sorted(tokens)


def _build_permutation_candidates(seed_hosts: list[str], words: list[str]) -> list[str]:
    candidates: set[str] = set()
    for host in seed_hosts:
        labels = host.split(".")
        if len(labels) < 3:
            continue

        prefix = labels[0]
        root = ".".join(labels[1:])

        for word in words:
            if not word:
                continue
            candidates.add(f"{prefix}-{word}.{root}")
            candidates.add(f"{word}-{prefix}.{root}")
            candidates.add(f"{word}.{root}")

    return sorted(candidates)


def _run_advanced_permuters(
    workspace: Path,
    runner: CommandRunner,
    overrides: dict[str, list[str]],
) -> list[str]:
    base_input = workspace / "subs/all_subs.txt"
    words_input = workspace / "wordlists/permutations.txt"
    generated: list[str] = []

    dnsgen_cmd = resolve_tool_command("dnsgen", workspace, overrides)
    if dnsgen_cmd:
        result = runner.run([*dnsgen_cmd, str(base_input)])
        if result and result.stdout:
            generated.extend([line.strip() for line in result.stdout.splitlines() if line.strip()])

    altdns_cmd = resolve_tool_command("altdns", workspace, overrides)
    if altdns_cmd:
        output_path = workspace / "subs/.altdns_raw.txt"
        runner.run([
            *altdns_cmd,
            "-i",
            str(base_input),
            "-w",
            str(words_input),
            "-o",
            str(output_path),
        ])
        if output_path.exists():
            generated.extend(read_hosts(output_path))

    return generated


def _resolve_permutation_candidates(
    workspace: Path,
    runner: CommandRunner,
    overrides: dict[str, list[str]],
    candidates: list[str],
    scope_data: ScopeData,
) -> list[str]:
    if not candidates:
        return []

    temp_input = workspace / "resolved/.permute_input.txt"
    write_lines(temp_input, candidates)

    for tool_name in ("dnsx", "puredns", "massdns"):
        cmd = resolve_tool_command(tool_name, workspace, overrides)
        if not cmd:
            continue

        if tool_name == "dnsx":
            result = runner.run([*cmd, "-silent", "-l", str(temp_input)])
            lines = [line.strip() for line in (result.stdout.splitlines() if result and result.stdout else []) if line.strip()]
            return filter_hosts(lines, scope_data)

        if tool_name == "puredns":
            result = runner.run([*cmd, "resolve", str(temp_input)])
            lines = [line.strip() for line in (result.stdout.splitlines() if result and result.stdout else []) if line.strip()]
            return filter_hosts(lines, scope_data)

        if tool_name == "massdns":
            # massdns usage varies heavily; this lightweight path supports wrappers that print names.
            result = runner.run([*cmd, str(temp_input)])
            lines = [line.strip() for line in (result.stdout.splitlines() if result and result.stdout else []) if line.strip()]
            hosts = [line.split()[0].rstrip(".") for line in lines]
            return filter_hosts(hosts, scope_data)

    return []


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


def run_ports(
    workspace: Path,
    scope_data: ScopeData,
    runner: CommandRunner,
    rate: int,
    timeout: int,
    deep_nmap: bool,
) -> list[str]:
    live_hosts = filter_hosts(read_hosts(workspace / "live/live.txt"), scope_data)
    scan_hosts = sorted({_normalize_scan_host(host) for host in live_hosts if _normalize_scan_host(host)})
    if not scan_hosts:
        raise RuntimeError("ports requires non-empty live/live.txt")

    naabu_path = workspace / "ports/naabu.txt"
    nmap_path = workspace / "ports/nmap_full.txt"
    overrides = load_tool_overrides(workspace)
    naabu_cmd = resolve_tool_command("naabu", workspace, overrides)
    nmap_cmd = resolve_tool_command("nmap", workspace, overrides)

    if not naabu_cmd and not nmap_cmd:
        raise RuntimeError("ports requires naabu or nmap (set tools in PATH or config/tools.yaml)")

    temp_live = workspace / "ports/.ports_input.txt"
    write_lines(temp_live, scan_hosts)

    naabu_lines: list[str] = []
    host_ports: dict[str, set[str]] = {}
    naabu_ok = False

    if naabu_cmd:
        cmd = [
            *naabu_cmd,
            "-silent",
            "-l",
            str(temp_live),
            "-rate",
            str(rate),
            "-timeout",
            str(timeout),
        ]
        result = runner.run(cmd)
        naabu_ok = bool(result and result.returncode == 0)
        if result and result.stdout:
            naabu_lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            for item in naabu_lines:
                host, sep, port = item.rpartition(":")
                if sep and host and port.isdigit():
                    host_ports.setdefault(host, set()).add(port)
    write_lines(naabu_path, naabu_lines)

    # If naabu ran successfully, keep nmap output empty by design.
    if naabu_ok:
        write_raw(nmap_path, [])
    elif nmap_cmd:
        nmap_targets = sorted(host_ports) if host_ports else scan_hosts
        temp_nmap_hosts = workspace / "ports/.nmap_hosts.txt"
        write_lines(temp_nmap_hosts, nmap_targets)

        cmd = [
            *nmap_cmd,
            "-iL",
            str(temp_nmap_hosts),
            "-Pn",
            "-sV",
            "-T4",
        ]
        if not deep_nmap:
            cmd.extend(["--top-ports", "100"])
        cmd.extend(["-oN", str(nmap_path)])
        runner.run(cmd)
    elif not nmap_path.exists():
        write_raw(nmap_path, [])

    return ["ports/naabu.txt", "ports/nmap_full.txt"]


def run_tech(workspace: Path, scope_data: ScopeData, runner: CommandRunner) -> list[str]:
    live_hosts = filter_hosts(read_hosts(workspace / "live/live.txt"), scope_data)
    targets = sorted({_normalize_scan_url(host) for host in live_hosts if _normalize_scan_url(host)})
    if not targets:
        raise RuntimeError("tech requires non-empty live/live.txt")

    whatweb_path = workspace / "tech/whatweb.txt"
    summary_path = workspace / "tech/stack_summary.json"

    overrides = load_tool_overrides(workspace)
    whatweb_cmd = resolve_tool_command("whatweb", workspace, overrides)
    if not whatweb_cmd:
        raise RuntimeError("tech requires whatweb (set tools in PATH or config/tools.yaml)")

    raw_lines: list[str] = []
    tech_counts: dict[str, int] = {}
    host_tech: dict[str, list[str]] = {}

    for target in targets:
        result = runner.run([*whatweb_cmd, target])
        output_lines = [line.strip() for line in (result.stdout.splitlines() if result and result.stdout else []) if line.strip()]
        if not output_lines:
            continue

        raw_lines.extend(output_lines)
        for line in output_lines:
            technologies = _extract_whatweb_technologies(line)
            if not technologies:
                continue

            host = line.split(" ", 1)[0].strip()
            host_tech.setdefault(host, [])
            for tech in technologies:
                if tech not in host_tech[host]:
                    host_tech[host].append(tech)
                tech_counts[tech] = tech_counts.get(tech, 0) + 1

    write_raw(whatweb_path, raw_lines)
    summary = {
        "targets": len(targets),
        "hosts_with_findings": len(host_tech),
        "technologies": sorted(
            ({"name": name, "count": count} for name, count in tech_counts.items()),
            key=lambda item: (-item["count"], item["name"]),
        ),
        "by_host": {host: sorted(values) for host, values in sorted(host_tech.items())},
    }
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    return ["tech/whatweb.txt", "tech/stack_summary.json"]


def run_crawl(
    workspace: Path,
    scope_data: ScopeData,
    runner: CommandRunner,
    threads: int,
    timeout: int,
) -> list[str]:
    live_urls = [line.strip() for line in read_hosts(workspace / "live/live.txt") if line.strip()]
    if not live_urls:
        raise RuntimeError("crawl requires non-empty live/live.txt")

    crawl_path = workspace / "urls/crawl.txt"
    historical_path = workspace / "urls/historical.txt"
    all_urls_path = workspace / "urls/all_urls.txt"

    overrides = load_tool_overrides(workspace)
    katana_cmd = resolve_tool_command("katana", workspace, overrides)
    gau_cmd = resolve_tool_command("gau", workspace, overrides)
    waybackurls_cmd = resolve_tool_command("waybackurls", workspace, overrides)

    if not katana_cmd and not gau_cmd and not waybackurls_cmd:
        raise RuntimeError("crawl requires katana, gau, or waybackurls (set tools in PATH or config/tools.yaml)")

    active_urls: list[str] = []
    historical_urls: list[str] = []
    tool_timeout = max(10, min(30, timeout * 2))

    if katana_cmd:
        temp_live = workspace / "urls/.crawl_live.txt"
        write_lines(temp_live, live_urls)
        result = runner.run([
            *katana_cmd,
            "-silent",
            "-list",
            str(temp_live),
            "-c",
            str(threads),
            "-timeout",
            str(timeout),
        ], timeout=tool_timeout)
        lines = [line.strip() for line in (result.stdout.splitlines() if result and result.stdout else []) if line.strip()]
        active_urls.extend(_extract_urls_from_lines(lines))

    hosts = sorted({_normalize_scan_host(url) for url in live_urls if _normalize_scan_host(url)})

    if gau_cmd:
        for index, host in enumerate(hosts, start=1):
            if index == 1 or index % 10 == 0:
                print(f"[crawl] gau {index}/{len(hosts)}")
            result = runner.run([*gau_cmd, host], timeout=tool_timeout)
            lines = [line.strip() for line in (result.stdout.splitlines() if result and result.stdout else []) if line.strip()]
            historical_urls.extend(_extract_urls_from_lines(lines))

    if waybackurls_cmd:
        for index, host in enumerate(hosts, start=1):
            if index == 1 or index % 10 == 0:
                print(f"[crawl] waybackurls {index}/{len(hosts)}")
            result = runner.run([*waybackurls_cmd, host], timeout=tool_timeout)
            lines = [line.strip() for line in (result.stdout.splitlines() if result and result.stdout else []) if line.strip()]
            historical_urls.extend(_extract_urls_from_lines(lines))

    active_urls = _filter_urls_in_scope(active_urls, scope_data)
    historical_urls = _filter_urls_in_scope(historical_urls, scope_data)
    all_urls = sorted(set(active_urls) | set(historical_urls))

    write_lines(crawl_path, active_urls)
    write_lines(historical_path, historical_urls)
    write_lines(all_urls_path, all_urls)

    return ["urls/crawl.txt", "urls/historical.txt", "urls/all_urls.txt"]


def run_js(workspace: Path, scope_data: ScopeData, runner: CommandRunner, timeout: int) -> list[str]:
    # JS stage must read from urls/all_urls.txt.
    all_urls = [line.strip() for line in read_hosts(workspace / "urls/all_urls.txt") if line.strip()]
    if not all_urls:
        raise RuntimeError("js requires non-empty urls/all_urls.txt")

    js_urls_path = workspace / "js/js_urls.txt"
    endpoints_path = workspace / "js/endpoints.txt"
    secrets_path = workspace / "js/secrets_findings.txt"

    js_urls = _collect_js_urls(all_urls)
    js_urls = _filter_urls_in_scope(js_urls, scope_data)
    write_lines(js_urls_path, js_urls)

    overrides = load_tool_overrides(workspace)
    linkfinder_cmd = resolve_tool_command("linkfinder", workspace, overrides)
    secretfinder_cmd = resolve_tool_command("secretfinder", workspace, overrides)

    endpoint_hits: set[str] = set()
    secret_hits: set[str] = set()
    tool_timeout = max(10, min(45, timeout * 3))

    if linkfinder_cmd:
        for index, js_url in enumerate(js_urls, start=1):
            if index == 1 or index % 10 == 0:
                print(f"[js] linkfinder {index}/{len(js_urls)}")
            result = runner.run([*linkfinder_cmd, "-i", js_url], timeout=tool_timeout)
            lines = [line.strip() for line in (result.stdout.splitlines() if result and result.stdout else []) if line.strip()]
            for line in lines:
                for endpoint in _extract_potential_endpoints(line):
                    endpoint_hits.add(endpoint)

    if secretfinder_cmd:
        for index, js_url in enumerate(js_urls, start=1):
            if index == 1 or index % 10 == 0:
                print(f"[js] secretfinder {index}/{len(js_urls)}")
            result = runner.run([*secretfinder_cmd, "-i", js_url, "-o", "cli"], timeout=tool_timeout)
            lines = [line.strip() for line in (result.stdout.splitlines() if result and result.stdout else []) if line.strip()]
            for line in lines:
                if _looks_like_secret_finding(line):
                    secret_hits.add(line)

    write_lines(endpoints_path, sorted(endpoint_hits))
    write_raw(secrets_path, sorted(secret_hits))

    return ["js/js_urls.txt", "js/endpoints.txt", "js/secrets_findings.txt"]


def run_params_content(workspace: Path, scope_data: ScopeData, runner: CommandRunner) -> list[str]:
    live_urls = [line.strip() for line in read_hosts(workspace / "live/live.txt") if line.strip()]
    all_urls = [line.strip() for line in read_hosts(workspace / "urls/all_urls.txt") if line.strip()]
    if not live_urls or not all_urls:
        raise RuntimeError("params_content requires non-empty live/live.txt and urls/all_urls.txt")

    params_path = workspace / "params/params.txt"
    dirs_path = workspace / "content/dirs.txt"
    findings_path = workspace / "content/findings.txt"

    urls_in_scope = _filter_urls_in_scope(all_urls, scope_data)
    param_names: set[str] = set()
    dirs: set[str] = set()
    findings: set[str] = set()

    interesting_keywords = {"admin", "login", "auth", "token", "graphql", "swagger", "debug", "internal", "backup"}
    sensitive_extensions = (".bak", ".old", ".sql", ".zip", ".tar", ".gz", ".env", ".log", ".config", ".yaml", ".yml")

    for url in urls_in_scope:
        parsed = urlparse(url)

        # Query keys become params stage output.
        query = parse_qs(parsed.query, keep_blank_values=True)
        for key in query:
            if key:
                param_names.add(key)

        # Directory candidates from URL paths.
        parts = [p for p in parsed.path.split("/") if p]
        current = ""
        for part in parts:
            current += f"/{part}"
            dirs.add(current + "/")

        lowered = url.lower()
        if any(keyword in lowered for keyword in interesting_keywords):
            findings.add(f"interesting-url {url}")
        if lowered.endswith(sensitive_extensions):
            findings.add(f"sensitive-extension {url}")
        if "=" in parsed.query and not query:
            findings.add(f"odd-query-format {url}")

    write_lines(params_path, sorted(param_names))
    write_lines(dirs_path, sorted(dirs))
    write_raw(findings_path, sorted(findings))

    return ["params/params.txt", "content/dirs.txt", "content/findings.txt"]


def run_visual(workspace: Path, scope_data: ScopeData, runner: CommandRunner, timeout: int) -> list[str]:
    live_urls = [line.strip() for line in read_hosts(workspace / "live/live.txt") if line.strip()]
    if not live_urls:
        raise RuntimeError("visual requires non-empty live/live.txt")

    urls_in_scope = _filter_urls_in_scope(live_urls, scope_data)
    if not urls_in_scope:
        raise RuntimeError("visual has no in-scope URLs from live/live.txt")

    screenshots_dir = workspace / "screenshots"
    index_path = screenshots_dir / "index.html"
    input_path = screenshots_dir / ".visual_input.txt"
    write_lines(input_path, urls_in_scope)

    overrides = load_tool_overrides(workspace)
    gowitness_cmd = resolve_tool_command("gowitness", workspace, overrides)
    if not gowitness_cmd:
        raise RuntimeError("visual requires gowitness (set tools in PATH or config/tools.yaml)")

    tool_timeout = max(30, min(180, timeout * 20))
    commands = [
        # Newer gowitness styles
        [*gowitness_cmd, "scan", "file", "--source", str(input_path), "--screenshot-path", str(screenshots_dir)],
        # Legacy gowitness styles
        [*gowitness_cmd, "file", "-f", str(input_path), "-P", str(screenshots_dir)],
        [*gowitness_cmd, "file", "-f", str(input_path)],
    ]

    for command in commands:
        result = runner.run(command, timeout=tool_timeout)
        if result and result.returncode == 0:
            break

    _ensure_visual_index(index_path, urls_in_scope)
    return ["screenshots/index.html"]


def run_scan(
    workspace: Path,
    scope_data: ScopeData,
    runner: CommandRunner,
    timeout: int,
    nuclei_severity: str,
) -> list[str]:
    live_urls = [line.strip() for line in read_hosts(workspace / "live/live.txt") if line.strip()]
    if not live_urls:
        raise RuntimeError("scan requires non-empty live/live.txt")

    urls_in_scope = _filter_urls_in_scope(live_urls, scope_data)
    if not urls_in_scope:
        raise RuntimeError("scan has no in-scope targets from live/live.txt")

    nuclei_path = workspace / "nuclei/results.txt"
    dalfox_path = workspace / "xss/dalfox.txt"
    overrides = load_tool_overrides(workspace)
    nuclei_cmd = resolve_tool_command("nuclei", workspace, overrides)
    dalfox_cmd = resolve_tool_command("dalfox", workspace, overrides)

    if not nuclei_cmd and not dalfox_cmd:
        raise RuntimeError("scan requires nuclei or dalfox (set tools in PATH or config/tools.yaml)")

    tool_timeout = max(30, min(240, timeout * 20))

    if nuclei_cmd:
        temp_live = workspace / "nuclei/.scan_live.txt"
        write_lines(temp_live, [_normalize_scan_url(url) for url in urls_in_scope])
        cmd = [*nuclei_cmd, "-silent", "-l", str(temp_live)]
        if nuclei_severity:
            cmd.extend(["-severity", nuclei_severity])
        result = runner.run(cmd, timeout=tool_timeout)
        nuclei_lines = [line.strip() for line in (result.stdout.splitlines() if result and result.stdout else []) if line.strip()]
        write_raw(nuclei_path, nuclei_lines)
    else:
        write_raw(nuclei_path, [])

    if dalfox_cmd:
        all_urls = [line.strip() for line in read_hosts(workspace / "urls/all_urls.txt") if line.strip()]
        xss_candidates = _filter_urls_in_scope(all_urls, scope_data)
        xss_candidates = [url for url in xss_candidates if "=" in url]
        if not xss_candidates:
            xss_candidates = [_normalize_scan_url(url) for url in urls_in_scope]

        temp_xss = workspace / "xss/.dalfox_input.txt"
        write_lines(temp_xss, xss_candidates)

        attempts = [
            [*dalfox_cmd, "file", str(temp_xss), "--silence", "--no-color", "-o", str(dalfox_path)],
            [*dalfox_cmd, "file", str(temp_xss), "-o", str(dalfox_path)],
            [*dalfox_cmd, "file", str(temp_xss)],
        ]

        wrote_file = False
        for attempt in attempts:
            result = runner.run(attempt, timeout=tool_timeout)
            if dalfox_path.exists() and dalfox_path.read_text(encoding="utf-8", errors="ignore").strip():
                wrote_file = True
                break
            if result and result.stdout:
                lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
                if lines:
                    write_raw(dalfox_path, lines)
                    wrote_file = True
                    break

        if not wrote_file and not dalfox_path.exists():
            write_raw(dalfox_path, [])
    else:
        write_raw(dalfox_path, [])

    return ["nuclei/results.txt", "xss/dalfox.txt"]


def _normalize_scan_host(candidate: str) -> str:
    host = candidate.strip()
    if not host:
        return ""
    host = host.replace("https://", "").replace("http://", "")
    host = host.split("/", 1)[0]
    return host.strip()


def _normalize_scan_url(candidate: str) -> str:
    target = candidate.strip()
    if not target:
        return ""
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"https://{target}"


def _extract_whatweb_technologies(line: str) -> list[str]:
    values = re.findall(r"\[([^\]]+)\]", line)
    if not values:
        return []

    technologies: set[str] = set()
    for group in values:
        for item in group.split(","):
            token = item.strip()
            if not token:
                continue
            name = token.split(":", 1)[0].strip()
            if name:
                technologies.add(name)
    return sorted(technologies)


def _extract_urls_from_lines(lines: list[str]) -> list[str]:
    out: list[str] = []
    for line in lines:
        match = re.search(r'https?://[^\s\]\)"]+', line)
        if match:
            out.append(match.group(0).rstrip("/"))
    return out


def _collect_js_urls(urls: list[str]) -> list[str]:
    js_urls = []
    for url in urls:
        lowered = url.lower().split("#", 1)[0]
        if ".js" not in lowered:
            continue
        path = lowered.split("?", 1)[0]
        if path.endswith(".js"):
            js_urls.append(url.strip())
    return sorted(set(js_urls))


def _extract_potential_endpoints(line: str) -> list[str]:
    hits = re.findall(r"(?:https?://[^\s\"'<>]+|/[a-zA-Z0-9_\-./?=&%]+)", line)
    cleaned = [h.strip().rstrip(",.;") for h in hits if h.strip()]
    return sorted(set(cleaned))


def _looks_like_secret_finding(line: str) -> bool:
    lowered = line.lower()
    keywords = ["api", "token", "secret", "key", "password", "bearer", "authorization"]
    return any(keyword in lowered for keyword in keywords)


def _ensure_visual_index(index_path: Path, urls: list[str]) -> None:
    if index_path.exists() and index_path.read_text(encoding="utf-8", errors="ignore").strip():
        return

    items = "\n".join(f'<li><a href="{url}">{url}</a></li>' for url in sorted(set(urls)))
    html = (
        "<html><head><meta charset=\"utf-8\"><title>ReconHive Visual</title></head>"
        "<body><h1>ReconHive Visual Targets</h1><ul>"
        f"{items}"
        "</ul></body></html>"
    )
    index_path.parent.mkdir(parents=True, exist_ok=True)
    index_path.write_text(html, encoding="utf-8")


def _filter_urls_in_scope(urls: list[str], scope_data: ScopeData) -> list[str]:
    kept = [url for url in urls if in_scope_candidate(url, scope_data)]
    return sorted(set(kept))


def in_scope_candidate(candidate: str, scope_data: ScopeData) -> bool:
    candidate = candidate.replace("https://", "").replace("http://", "")
    candidate = candidate.split("/", 1)[0]
    return bool(filter_hosts([candidate], scope_data))


def check_stage_dependencies(workspace: Path, stage: str) -> tuple[bool, str]:
    requirements = {
        "permute": [workspace / "subs/all_subs.txt"],
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
