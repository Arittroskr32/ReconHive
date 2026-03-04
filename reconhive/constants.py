from __future__ import annotations

from dataclasses import dataclass

STAGE_ORDER = [
    "enum",
    "permute",
    "resolve",
    "live",
    "ports",
    "tech",
    "crawl",
    "js",
    "params_content",
    "visual",
    "scan",
]

STAGE_DESCRIPTIONS = {
    "enum": "Passive subdomain + CT + ASN intel",
    "permute": "Permutation + bruteforce generation",
    "resolve": "DNS resolution",
    "live": "Live host detection + fingerprinting",
    "ports": "Port scanning (naabu/nmap)",
    "tech": "Technology fingerprinting",
    "crawl": "Crawling + historical URL collection",
    "js": "JavaScript harvesting + endpoint extraction",
    "params_content": "Parameter and content discovery",
    "visual": "Screenshots + panel discovery",
    "scan": "Automated vulnerability scanning",
}

WORKSPACE_DIRS = [
    "config",
    "subs",
    "resolved",
    "live",
    "ports",
    "tech",
    "urls",
    "js",
    "params",
    "content",
    "screenshots",
    "nuclei",
    "xss",
    "logs",
]

OUTPUTS_BY_STAGE = {
    "enum": ["subs/passive_raw.txt", "subs/ct.txt", "subs/asn_intel.txt", "subs/all_subs.txt"],
    "permute": ["subs/permutations.txt"],
    "resolve": ["resolved/resolved.txt", "resolved/unresolved.txt"],
    "live": ["live/live.txt", "live/httpx_full.txt"],
    "ports": ["ports/naabu.txt", "ports/nmap_full.txt"],
    "tech": ["tech/whatweb.txt", "tech/stack_summary.json"],
    "crawl": ["urls/crawl.txt", "urls/historical.txt", "urls/all_urls.txt"],
    "js": ["js/js_urls.txt", "js/endpoints.txt", "js/secrets_findings.txt"],
    "params_content": ["params/params.txt", "content/dirs.txt", "content/findings.txt"],
    "visual": ["screenshots/index.html"],
    "scan": ["nuclei/results.txt", "xss/dalfox.txt"],
}


@dataclass(frozen=True)
class ToolRequirement:
    stage: str
    tools: tuple[str, ...]


TOOL_REQUIREMENTS = [
    ToolRequirement("enum", ("subfinder", "assetfinder", "findomain", "amass")),
    ToolRequirement("permute", ("dnsgen", "altdns")),
    ToolRequirement("resolve", ("dnsx", "shuffledns", "puredns")),
    ToolRequirement("live", ("httpx",)),
    ToolRequirement("ports", ("naabu", "nmap")),
    ToolRequirement("tech", ("whatweb",)),
    ToolRequirement("crawl", ("katana", "hakrawler", "gospider", "gau", "waybackurls")),
    ToolRequirement("js", ("linkfinder", "secretfinder")),
    ToolRequirement("params_content", ("gf", "arjun", "paramspider", "ffuf", "dirsearch", "feroxbuster")),
    ToolRequirement("visual", ("gowitness",)),
    ToolRequirement("scan", ("nuclei", "dalfox")),
]
