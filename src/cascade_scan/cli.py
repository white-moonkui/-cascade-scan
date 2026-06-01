"""
cascade-scan CLI — run security scans, generate reports, check scores.

Usage::

    cascade-scan run                        # run all probes
    cascade-scan run --probes injection     # run specific probes
    cascade-scan report --format html       # generate HTML report
    cascade-scan score                      # show security score
    cascade-scan list-scenarios             # list available scenarios
    cascade-scan run --scenario file-deletion  # run a specific scenario
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Optional

from cascade import DecisionPipeline

from cascade_scan import ScanEngine, SecurityScorer, export_html, export_json
from cascade_scan.probes import InjectionProbe, ToolAbuseProbe
from cascade_scan.scenarios import get_scenario, list_scenarios, AttackScenario


def _build_pipeline(args: argparse.Namespace) -> DecisionPipeline:
    """Construct a DecisionPipeline from CLI args."""
    pipe = DecisionPipeline(
        enable_injection_detection=not args.no_injection,
    )

    # Apply rules if specified
    rules = _parse_rules(args)
    if rules:
        for r in rules:
            if "field" in r and "op" in r:
                pipe.set_gate_rules([r])

    return pipe


def _parse_rules(args: argparse.Namespace) -> list[dict]:
    """Parse --rule options into a list of rule dicts."""
    rules: list[dict] = []
    for r in args.rule or []:
        parts = r.split(":", 2)
        if len(parts) == 3:
            field, op, value = parts
            # Try numeric
            try:
                v = int(value)
            except ValueError:
                try:
                    v = float(value)
                except ValueError:
                    v = value
            rules.append({"field": field, "op": op, "value": v})
        elif len(parts) == 2:
            # name:value shorthand → op=nin
            rules.append({"field": "name", "op": "nin", "value": [parts[1]]})
    return rules


def _get_probes(args: argparse.Namespace) -> list:
    """Return the list of probe instances to run."""
    all_probes = {
        "injection": InjectionProbe(),
        "tool-abuse": ToolAbuseProbe(),
    }

    if args.probes:
        selected: list = []
        for name in args.probes:
            if name in all_probes:
                selected.append(all_probes[name])
            else:
                print(f"Warning: unknown probe {name!r}, skipping", file=sys.stderr)
        if not selected:
            print("No valid probes specified, using all", file=sys.stderr)
            return list(all_probes.values())
        return selected
    return list(all_probes.values())


# ── subcommands ─────────────────────────────────────────────────────


def cmd_run(args: argparse.Namespace) -> int:
    """Run security probes against a cascade pipeline."""
    pipe = _build_pipeline(args)

    engine = ScanEngine()
    for probe in _get_probes(args):
        engine.add_probe(probe)

    print(f"Scanning with {len(engine.probes)} probe(s): "
          f"{', '.join(p.name for p in engine.probes)}")
    print()

    result = engine.run(pipe, min_score=args.min_score)

    print(result.summary())
    print()

    # Optionally save report
    if args.output:
        output_path = Path(args.output)
        if output_path.suffix == ".json":
            export_json(result, output=output_path)
        else:
            export_html(result, output=output_path)
        print(f"Report saved to {output_path}")

    return 0 if result.passed else 1


def cmd_report(args: argparse.Namespace) -> int:
    """Generate a report from a previous scan result file."""
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: input file not found: {input_path}", file=sys.stderr)
        return 1

    # This is limited — full report generation requires ScanResult object.
    # For now, we support re-exporting from JSON result files.
    import json
    data = json.loads(input_path.read_text())

    print(f"Report from: {input_path}")
    print(f"  Score : {data.get('scan', {}).get('score', '?')}")
    print(f"  Passed: {data.get('scan', {}).get('passed', '?')}")
    print()

    if args.output:
        print(f"Report re-export is limited from JSON input.")
        print(f"Run 'cascade-scan run --output {args.output}' for a full report.")

    return 0


def cmd_score(args: argparse.Namespace) -> int:
    """Run probes and show the security score."""
    pipe = _build_pipeline(args)

    engine = ScanEngine()
    for probe in _get_probes(args):
        engine.add_probe(probe)

    result = engine.run(pipe, min_score=args.min_score)

    summary = SecurityScorer.summary(result.probe_results)
    print(f"Security Score: {summary['score']:.1f}/100  (Grade: {summary['grade']})")
    print(f"Probes: {summary['probes_passed']}/{summary['probes_total']} passed")
    print(f"Vectors: {summary['vectors_blocked']}/{summary['vectors_total']} blocked")
    print()
    for bd in summary["breakdown"]:
        print(f"  {bd['probe']:20s}  {bd['pass_rate']*100:3.0f}%  ({bd['blocked']}/{bd['total']})  severity={bd['severity']}")

    return 0 if result.passed else 1


def cmd_list_scenarios(args: argparse.Namespace) -> int:
    """List available attack scenarios."""
    scenarios = list_scanners()
    if not scenarios:
        print("No scenarios registered.")
        return 0

    print(f"{'Name':25s} {'Severity':12s} {'Calls':6s} {'Expected Blocked':18s} Description")
    print("-" * 90)
    for s in scenarios:
        print(f"{s['name']:25s} {s['severity']:12s} {s['n_tool_calls']:<6d} {s['expected_blocked']:<18d} {s['description']}")
    return 0


# backward compat alias
list_scanners = list_scenarios


# ── CLI entry point ─────────────────────────────────────────────────


def _add_common_args(sub: argparse.ArgumentParser) -> None:
    """Add common pipeline arguments to a subparser."""
    sub.add_argument("--no-injection", action="store_true",
                     help="Disable injection detection on the pipeline")
    sub.add_argument("--rule", "-r", action="append", default=[],
                     help="Add a rule (format: field:op:value or name:blocked_tool)")
    sub.add_argument("--min-score", type=float, default=70.0,
                     help="Minimum score to pass (default: 70)")
    sub.add_argument("--output", "-o", default="",
                     help="Output file for reports (.json or .html)")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cascade-scan",
        description="AI Agent security evaluation framework",
    )

    sub = parser.add_subparsers(dest="command", help="Subcommand")

    # run
    p_run = sub.add_parser("run", help="Run security probes")
    _add_common_args(p_run)
    p_run.add_argument("--probes", "-p", nargs="*", default=[],
                       help="Probes to run (injection, tool-abuse)")
    p_run.add_argument("--scenario", type=str, default="",
                       help="Run a specific attack scenario")
    p_run.set_defaults(func=cmd_run)

    # report
    p_rep = sub.add_parser("report", help="Generate report from scan results")
    p_rep.add_argument("input", type=str, help="Input JSON result file")
    p_rep.set_defaults(func=cmd_report)

    # score
    p_score = sub.add_parser("score", help="Run probes and show security score")
    _add_common_args(p_score)
    p_score.add_argument("--probes", "-p", nargs="*", default=[],
                         help="Probes to run (injection, tool-abuse)")
    p_score.set_defaults(func=cmd_score)

    # list-scenarios
    p_list = sub.add_parser("list-scenarios", help="List available attack scenarios")
    p_list.set_defaults(func=cmd_list_scenarios)

    args = parser.parse_args(argv)

    if not hasattr(args, "func"):
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
