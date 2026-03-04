# ReconHive

ReconHive is a resumable reconnaissance CLI where **one workspace folder = one recon run**.

You initialize scope once, run stages incrementally, stop anytime, and continue later with the same workspace.

---

## 1) What this project does

- Parses in-scope and out-of-scope files safely (domains, URLs, ports, wildcards)
- Normalizes and stores scope in `config/scope.json`
- Executes recon in stage order
- Saves per-stage completion and output counts in `state.json`
- Allows resume without re-running completed stages (unless `--force`)
- Logs executed commands to `logs/reconhive.log`
- Preserves raw tool output order for rich output files (no forced sorting)

---

## 2) Installation

### Requirements

- Python 3.10+
- Recon tools you want to use (`subfinder`, `dnsx`, `httpx`, etc.)

### Install in editable mode

```bash
pip install -e .
```

### Verify CLI

```bash
python reconhive -h
```

If you prefer module style, use:

```bash
python -m reconhive -h
```

---

## 3) Core workflow (recommended)

### Step 1: Initialize workspace

```bash
python reconhive init -i in-scope.txt -o out-of-scope.txt -w recon_runs/acme
```

### Step 2: Run stages

```bash
python reconhive run --stage enum -w recon_runs/acme
python reconhive run --stage resolve -w recon_runs/acme
python reconhive run --stage live -w recon_runs/acme
```

### Step 3: Check status

```bash
python reconhive status -w recon_runs/acme
```

### Step 4: Resume later (next day)

```bash
python reconhive run --stage live -w recon_runs/acme
```

If `live` is already complete, ReconHive skips it automatically. Use `--force` to rerun.

---

## 4) Command reference

## Global help

```bash
python reconhive -h
```

## `init`

Create workspace and ingest scope files.

```bash
python reconhive init -h
python reconhive init -i in-scope.txt -o out-of-scope.txt -w recon_runs/acme
```

Options:

- `-i, --in-scope` (required): path to in-scope file
- `-o, --out-of-scope`: path to out-of-scope file
- `-w, --workspace` (required): workspace folder

## `run`

Run one stage or all stages.

```bash
python reconhive run -h
python reconhive run --stage enum -w recon_runs/acme
python reconhive run --stage all -w recon_runs/acme
```

Options:

- `-w, --workspace` (required)
- `--stage` (required):
  - `enum`, `permute`, `resolve`, `live`, `ports`, `tech`, `crawl`, `js`, `params_content`, `visual`, `scan`, `all`
- `--force`: rerun completed stage
- `--dry-run`: print commands only
- `--threads`: default `20`
- `--rate`: default `50`
- `--timeout`: default `10`
- `--retries`: default `1` (reserved)
- `--deep-nmap`: reserved for `ports`
- `--nuclei-severity`: reserved for `scan`
- `--strict`: fail fast on tool command errors (default is non-strict)
- `--resolvers`: resolver list path (stored in workspace config)
- `--wordlist`: wordlist path (stored in workspace config)
- `--nuclei-templates`: nuclei templates path (stored in workspace config)

## `stages`

List stage names and descriptions.

```bash
python reconhive stages
```

## `status`

Show stage completion, timestamps, and output counts.

```bash
python reconhive status -w recon_runs/acme
```

## `check`

Check whether expected tools are available.

```bash
python reconhive check
python reconhive check --json
```

## `menu`

Interactive stage runner for manual operation.

```bash
python reconhive menu -w recon_runs/acme
```

---

## 5) Scope file format and behavior

### Accepted line formats

- `example.com`
- `api.example.com`
- `https://example.com/login`
- `http://sub.example.com:8080`
- `*.example.com`

### Normalization rules

For each line:

1. Strip whitespace
2. Ignore empty lines
3. Ignore comments (`# ...`)
4. If URL contains `://`, parse and extract hostname
5. Strip port from `host:port`
6. Preserve wildcard patterns like `*.example.com`
7. Convert to lowercase

### Matching and filtering logic

When an asset is discovered:

1. If it matches out-of-scope exact/wildcard => **exclude**
2. Else if it matches in-scope exact/wildcard => **include**
3. Else => **exclude**

This prevents accidental out-of-scope scanning.

### Wildcard behavior (important)

- `*.example.com` matches `a.example.com`, `b.c.example.com`, etc.
- `*.example.com` **does not** match apex `example.com`
- To include apex, add `example.com` explicitly in scope

---

## 6) Stage model

Stages are defined in this order:

1. `enum`
2. `permute`
3. `resolve`
4. `live`
5. `ports`
6. `tech`
7. `crawl`
8. `js`
9. `params_content`
10. `visual`
11. `scan`

### Current implementation status

Fully wired in MVP:

- `enum`
- `resolve`
- `live`

Implemented behavior details:

- `enum` now attempts available passive tools: `subfinder`, `assetfinder`, `findomain`, `amass`
- `resolve` uses `dnsx` when available, with fallback behavior
- `live` uses `httpx` when available and preserves `httpx_full.txt` output order

Scaffolded (tracked and output placeholders created):

- `permute`, `ports`, `tech`, `crawl`, `js`, `params_content`, `visual`, `scan`

---

## 7) Workspace layout

```text
workspace/
  config/
    scope.json
    tools.json
  subs/
    passive_raw.txt
    ct.txt
    asn_intel.txt
    all_subs.txt
    permutations.txt
  resolved/
    resolved.txt
    unresolved.txt
  live/
    live.txt
    httpx_full.txt
  ports/
    naabu.txt
    nmap_full.txt
  tech/
    whatweb.txt
    stack_summary.json
  urls/
    crawl.txt
    historical.txt
    all_urls.txt
  js/
    js_urls.txt
    endpoints.txt
    secrets_findings.txt
  params/
    params.txt
  content/
    dirs.txt
    findings.txt
  screenshots/
    index.html
  nuclei/
    results.txt
  xss/
    dalfox.txt
  logs/
    reconhive.log
  state.json
```

---

## 8) Resume and state tracking

`state.json` stores:

- workspace metadata
- per-stage `done` status
- stage start/end timestamps
- output line counts per stage
- failed state + error message when a stage errors

Example behavior:

- Stage already done + no `--force` => skipped
- Stage done + `--force` => reruns and refreshes outputs/state
- Missing dependency input (for example running `live` before `resolve`) => skipped with guidance
- Tool returns non-zero:
  - default: stage is marked failed and execution continues safely
  - with `--strict`: command failure raises immediately

Runtime options used for a run are saved into:

- `config/run_config.json`

---

## 9) Tool detection behavior

- ReconHive checks known tool availability via `check`
- During MVP stages, if a specific binary is missing, fallback behavior is used where possible (for smooth local testing)
- `config/tools.json` is written at `init` time as a snapshot
- Optional `config/tools.yaml` allows explicit command mapping for tools that are scripts

Example `config/tools.yaml`:

```yaml
subfinder: subfinder
dnsx: dnsx
httpx: httpx
linkfinder: python C:/tools/LinkFinder.py
secretfinder: python C:/tools/SecretFinder.py
```

`check` can use workspace overrides:

```bash
python reconhive check -w recon_runs/acme
```

---

## 10) Safety defaults

- Scope filtering applied before active stages
- Conservative active defaults:
  - `threads=20`
  - `rate=50`
  - `timeout=10`
- Commands are logged to `logs/reconhive.log`

---

## 11) Example full run

```bash
python reconhive init -i in-scope.txt -o out-of-scope.txt -w recon_runs/acme
python reconhive check
python reconhive stages
python reconhive run --stage enum -w recon_runs/acme
python reconhive run --stage resolve -w recon_runs/acme
python reconhive run --stage live -w recon_runs/acme
python reconhive status -w recon_runs/acme
```

Continue later:

```bash
python reconhive run --stage all -w recon_runs/acme
```

Rerun a single stage:

```bash
python reconhive run --stage resolve -w recon_runs/acme --force
```

---

## 12) Notes and legal

- Run only against targets you are explicitly authorized to test.
- Keep `out-of-scope.txt` strict and updated.
- Treat sensitive findings (`js/secrets_findings.txt`) carefully.

---

## 13) Clean packaging (no pycache/junk)

To build a clean zip archive without `__pycache__`, `*.pyc`, `recon_runs`, or `*.egg-info`:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/package.ps1
```

This creates:

- `release/ReconHive.zip`
