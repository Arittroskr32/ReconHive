from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil

from .constants import OUTPUTS_BY_STAGE, STAGE_DESCRIPTIONS, STAGE_ORDER, TOOL_REQUIREMENTS
from .runner import CommandRunner, command_exists, load_tool_overrides, resolve_tool_command
from .scope import load_scope_json, parse_scope_files, save_scope_json
from .stages import (
    check_stage_dependencies,
    run_crawl,
    run_enum,
    run_js,
    run_live,
    run_params_content,
    run_permute,
    run_ports,
    run_resolve,
    run_scan,
    run_tech,
    run_visual,
)
from .workspace import (
    ensure_workspace_layout,
    init_state,
    load_state,
    mark_stage_failed,
    mark_stage_finished,
    mark_stage_started,
    stage_done,
    stage_outputs,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reconhive",
        description="Resumable recon workspace CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_p = subparsers.add_parser("init", help="Create workspace and ingest scope files")
    init_p.add_argument("-i", "--in-scope", required=True, help="Path to in-scope file")
    init_p.add_argument("-o", "--out-of-scope", help="Path to out-of-scope file")
    init_p.add_argument("-w", "--workspace", required=True, help="Workspace folder path")

    run_p = subparsers.add_parser("run", help="Run one or more stages")
    run_p.add_argument("-w", "--workspace", required=True, help="Workspace folder path")
    run_p.add_argument("--stage", choices=STAGE_ORDER + ["all"], required=True, help="Stage name or all")
    run_p.add_argument("--force", action="store_true", help="Rerun stage even if already done")
    run_p.add_argument("--dry-run", action="store_true", help="Print commands without execution")
    run_p.add_argument("--threads", type=int, default=20, help="Threads for active tools")
    run_p.add_argument("--rate", type=int, default=50, help="Request rate limit")
    run_p.add_argument("--timeout", type=int, default=10, help="Timeout seconds")
    run_p.add_argument("--retries", type=int, default=1, help="Reserved for future stages")
    run_p.add_argument("--deep-nmap", action="store_true", help="Reserved for ports stage")
    run_p.add_argument("--nuclei-severity", default="medium,high,critical", help="Reserved for scan stage")
    run_p.add_argument("--strict", action="store_true", help="Fail immediately when a tool command exits non-zero")
    run_p.add_argument("--resolvers", help="Resolvers file path for DNS-heavy stages")
    run_p.add_argument("--wordlist", help="Wordlist file path for content discovery stages")
    run_p.add_argument("--nuclei-templates", help="Nuclei templates path")

    subparsers.add_parser("stages", help="List stages and descriptions")

    status_p = subparsers.add_parser("status", help="Show stage completion and output counts")
    status_p.add_argument("-w", "--workspace", required=True, help="Workspace folder path")

    check_p = subparsers.add_parser("check", help="Check tool availability")
    check_p.add_argument("-w", "--workspace", help="Workspace folder path (to use config/tools.yaml overrides)")
    check_p.add_argument("--json", action="store_true", help="Output as JSON")

    menu_p = subparsers.add_parser("menu", help="Interactive stage menu")
    menu_p.add_argument("-w", "--workspace", required=True, help="Workspace folder path")

    return parser


def cmd_init(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace)
    in_scope_path = Path(args.in_scope)
    out_scope_path = Path(args.out_of_scope) if args.out_of_scope else None

    ensure_workspace_layout(workspace)
    scope_data, hashes = parse_scope_files(in_scope_path, out_scope_path)
    save_scope_json(scope_data, workspace / "config/scope.json", hashes)

    tools_status = {tool: bool(command_exists(tool)) for req in TOOL_REQUIREMENTS for tool in req.tools}
    (workspace / "config/tools.json").write_text(json.dumps(tools_status, indent=2), encoding="utf-8")

    run_config = {
        "threads": 20,
        "rate": 50,
        "timeout": 10,
        "retries": 1,
        "deep_nmap": False,
        "nuclei_severity": "medium,high,critical",
        "strict": False,
        "resolvers": "",
        "wordlist": "",
        "nuclei_templates": "",
    }
    (workspace / "config/run_config.json").write_text(json.dumps(run_config, indent=2), encoding="utf-8")

    tools_yaml = workspace / "config/tools.yaml"
    if not tools_yaml.exists():
        tools_yaml.write_text(
            "# Optional custom tool commands\n"
            "# Example:\n"
            "# subfinder: subfinder\n"
            "# linkfinder: python C:/tools/LinkFinder.py\n",
            encoding="utf-8",
        )

    init_state(workspace)
    print(f"Workspace initialized: {workspace}")
    print("Scope saved: config/scope.json")
    return 0


def _save_run_config(workspace: Path, args: argparse.Namespace) -> None:
    run_config = {
        "threads": args.threads,
        "rate": args.rate,
        "timeout": args.timeout,
        "retries": args.retries,
        "deep_nmap": args.deep_nmap,
        "nuclei_severity": args.nuclei_severity,
        "strict": args.strict,
        "resolvers": args.resolvers or "",
        "wordlist": args.wordlist or "",
        "nuclei_templates": args.nuclei_templates or "",
    }
    (workspace / "config/run_config.json").write_text(json.dumps(run_config, indent=2), encoding="utf-8")


def _run_stage(workspace: Path, stage: str, args: argparse.Namespace) -> bool:
    scope_data = load_scope_json(workspace / "config/scope.json")
    state = load_state(workspace)

    if stage_done(state, stage) and not args.force:
        print(f"Skipping {stage}: already completed (use --force to rerun).")
        return True

    dep_ok, dep_message = check_stage_dependencies(workspace, stage)
    if not dep_ok:
        print(f"Skipping {stage}: {dep_message}. Run previous stage first.")
        return False

    runner = CommandRunner(dry_run=args.dry_run, strict=args.strict, log_path=workspace / "logs/reconhive.log")
    mark_stage_started(workspace, state, stage)
    outputs = stage_outputs(stage)

    try:
        if stage == "enum":
            outputs = run_enum(workspace, scope_data, runner)
        elif stage == "permute":
            outputs = run_permute(workspace, scope_data, runner)
        elif stage == "resolve":
            outputs = run_resolve(workspace, scope_data, runner)
        elif stage == "live":
            outputs = run_live(workspace, scope_data, runner, args.threads, args.timeout, args.rate)
        elif stage == "ports":
            outputs = run_ports(workspace, scope_data, runner, args.rate, args.timeout, args.deep_nmap)
        elif stage == "tech":
            outputs = run_tech(workspace, scope_data, runner)
        elif stage == "crawl":
            outputs = run_crawl(workspace, scope_data, runner, args.threads, args.timeout)
        elif stage == "js":
            outputs = run_js(workspace, scope_data, runner, args.timeout)
        elif stage == "params_content":
            outputs = run_params_content(workspace, scope_data, runner)
        elif stage == "visual":
            outputs = run_visual(workspace, scope_data, runner, args.timeout)
        elif stage == "scan":
            outputs = run_scan(workspace, scope_data, runner, args.timeout, args.nuclei_severity)
        else:
            outputs = stage_outputs(stage)
            for rel in outputs:
                path = workspace / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                if not path.exists():
                    path.write_text("", encoding="utf-8")

        state = load_state(workspace)
        if runner.failures:
            mark_stage_failed(
                workspace,
                state,
                stage,
                f"{len(runner.failures)} tool failures. See logs/reconhive.log",
                outputs,
            )
            print(f"Stage completed with failures: {stage}")
            return False
        mark_stage_finished(workspace, state, stage, outputs)
        print(f"Stage completed: {stage}")
        return True
    except KeyboardInterrupt:
        state = load_state(workspace)
        mark_stage_failed(workspace, state, stage, "Interrupted by user", outputs)
        print(f"Stage interrupted: {stage}")
        raise
    except Exception as exc:
        state = load_state(workspace)
        mark_stage_failed(workspace, state, stage, str(exc), outputs)
        print(f"Stage failed: {stage} -> {exc}")
        if args.strict:
            raise
        return False


def cmd_run(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace)
    if not (workspace / "config/scope.json").exists():
        raise SystemExit("Workspace not initialized. Run: reconhive init ...")

    _save_run_config(workspace, args)

    try:
        if args.stage == "all":
            all_ok = True
            for stage in STAGE_ORDER:
                all_ok = _run_stage(workspace, stage, args) and all_ok
            return 0 if all_ok else 1

        ok = _run_stage(workspace, args.stage, args)
        return 0 if ok else 1
    except KeyboardInterrupt:
        return 130


def cmd_stages() -> int:
    for index, stage in enumerate(STAGE_ORDER, start=1):
        print(f"{index:>2}. {stage:<15} {STAGE_DESCRIPTIONS.get(stage, '')}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace)
    state = load_state(workspace)

    print(f"Workspace: {workspace}")
    print(f"Created:   {state.get('created', '-')}")
    print("")

    for stage in STAGE_ORDER:
        stage_state = state.get("stages", {}).get(stage, {})
        done = "✅" if stage_state.get("done") else ("⚠️" if stage_state.get("failed") else "❌")
        ended = stage_state.get("ended", "-")
        counts = stage_state.get("output_counts", {})
        error = stage_state.get("error", "")
        count_summary = ", ".join(f"{Path(k).name}:{v}" for k, v in counts.items()) if counts else "-"
        suffix = f" error={error}" if error else ""
        print(f"{done} {stage:<15} ended={ended} outputs={count_summary}{suffix}")
    return 0


def cmd_check(as_json: bool, workspace_path: str | None) -> int:
    workspace = Path(workspace_path) if workspace_path else Path.cwd()
    overrides = load_tool_overrides(workspace)
    tool_map = {
        tool: bool(resolve_tool_command(tool, workspace, overrides))
        for req in TOOL_REQUIREMENTS
        for tool in req.tools
    }
    if as_json:
        print(json.dumps(tool_map, indent=2))
    else:
        for tool, available in sorted(tool_map.items()):
            status = "OK" if available else "MISSING"
            print(f"{tool:<14} {status}")
    return 0


def cmd_menu(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace)
    while True:
        state = load_state(workspace)
        print("\nReconHive Menu")
        for idx, stage in enumerate(STAGE_ORDER, start=1):
            stage_state = state.get("stages", {}).get(stage, {})
            icon = "✅" if stage_state.get("done") else "⏳"
            print(f"{idx:>2}. {icon} {stage}")
        print(f"{len(STAGE_ORDER)+1:>2}. exit")

        choice = input("Select stage: ").strip().lower()
        if choice in {"exit", "q", str(len(STAGE_ORDER) + 1)}:
            return 0

        if choice.isdigit() and 1 <= int(choice) <= len(STAGE_ORDER):
            stage = STAGE_ORDER[int(choice) - 1]
        elif choice in STAGE_ORDER:
            stage = choice
        else:
            print("Invalid selection.")
            continue

        run_args = argparse.Namespace(
            workspace=str(workspace),
            stage=stage,
            force=False,
            dry_run=False,
            strict=False,
            threads=20,
            rate=50,
            timeout=10,
            retries=1,
            deep_nmap=False,
            nuclei_severity="medium,high,critical",
            resolvers=None,
            wordlist=None,
            nuclei_templates=None,
        )
        _run_stage(workspace, stage, run_args)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "init":
        return cmd_init(args)
    if args.command == "run":
        return cmd_run(args)
    if args.command == "stages":
        return cmd_stages()
    if args.command == "status":
        return cmd_status(args)
    if args.command == "check":
        return cmd_check(args.json, args.workspace)
    if args.command == "menu":
        return cmd_menu(args)

    parser.print_help()
    return 1
