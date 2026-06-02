"""
cascade-scan CLI — run security scans, generate reports, check scores.

Usage::

    cascade-scan run                        # run all probes
    cascade-scan run --probes injection     # run specific probes
    cascade-scan report --format html       # generate HTML report
    cascade-scan score                      # show security score
    cascade-scan run --fail-below 80        # exit 1 if score < 80 (CI)
    cascade-scan list-scenarios             # list available scenarios
    cascade-scan run --scenario file-deletion  # run a specific scenario
    cascade-scan evolve --iterations 5      # iterative evaluation
    cascade-scan baseline save ./baseline.json
    cascade-scan baseline compare ./baseline.json
    cascade-scan import-scenario ./custom.json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Optional

from cascade import DecisionPipeline

from cascade_scan import ScanEngine, SecurityScorer, export_html, export_json
from cascade_scan.probes import (
    InjectionProbe,
    ToolAbuseProbe,
    XSSProbe,
    SQLIProbe,
    PromptLeakProbe,
    RCEProbe,
    ToolChainProbe,
    DataFlowProbe,
    EscalationProbe,
    LoopDoSProbe,
    MCPPoisoningProbe,
    PolicyComplianceProbe,
    StrategyEvalProbe,
)
from cascade_scan.scenarios import get_scenario, list_scenarios, AttackScenario
from cascade_scan.baseline import BaselineManager
from cascade_scan.evolve import Evolver


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
        "xss": XSSProbe(),
        "sqli": SQLIProbe(),
        "prompt-leak": PromptLeakProbe(),
        "rce": RCEProbe(),
        "tool-chain": ToolChainProbe(),
        "data-flow": DataFlowProbe(),
        "escalation": EscalationProbe(),
        "loop-dos": LoopDoSProbe(),
        "mcp-poisoning": MCPPoisoningProbe(),
        "policy-compliance": PolicyComplianceProbe(),
        "strategy-eval": StrategyEvalProbe(),
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

    # --fail-below check
    score = SecurityScorer.score(result.probe_results)
    if args.fail_below is not None and score < args.fail_below:
        print(f"FAIL-BELOW: score {score:.1f} < {args.fail_below} (exit code 1)")
        return 1

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

    score = summary["score"]
    if args.fail_below is not None and score < args.fail_below:
        print(f"FAIL-BELOW: score {score:.1f} < {args.fail_below} (exit code 1)")
        return 1

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


def cmd_evolve(args: argparse.Namespace) -> int:
    """Run iterative security evaluation."""
    pipe = _build_pipeline(args)

    engine = ScanEngine()
    for probe in _get_probes(args):
        engine.add_probe(probe)

    def build_pipe():
        return _build_pipeline(args)

    evolver = Evolver(engine, build_pipe, iterations=args.iterations)
    result = evolver.run()
    summary = Evolver.summary(result)

    print(f"Evolution: {summary['iterations']} iterations")
    print(f"  Scores: {', '.join(f'{s:.1f}' for s in summary['scores'])}")
    print(f"  Min: {summary['min']:.1f}   Max: {summary['max']:.1f}")
    print(f"  Avg: {summary['avg']:.1f}   Std: {summary['std']:.2f}")
    print(f"  Grade: {summary['grade']}")
    print()

    if args.fail_below is not None and summary["avg"] < args.fail_below:
        print(f"FAIL-BELOW: avg score {summary['avg']:.1f} < {args.fail_below} (exit code 1)")
        return 1

    # Optionally save results
    if args.output:
        import json
        output_path = Path(args.output)
        output_path.write_text(
            json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"Evolution results saved to {output_path}")

    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    """Manage scan baselines."""
    pipe = _build_pipeline(args)

    engine = ScanEngine()
    for probe in _get_probes(args):
        engine.add_probe(probe)

    result = engine.run(pipe, min_score=args.min_score)

    if args.baseline_action == "save":
        BaselineManager.save(result.probe_results, args.path)
        score = SecurityScorer.score(result.probe_results)
        print(f"Baseline saved to {args.path} (score: {score:.1f})")
        return 0

    if args.baseline_action == "compare":
        cr = BaselineManager.compare(result.probe_results, args.path)
        s = BaselineManager.summarize(cr)

        print(f"Baseline: {s['baseline_score']:.1f} ({s['baseline_grade']})")
        print(f"Current:  {s['current_score']:.1f} ({s['current_grade']})")
        print(f"Diff:     {s['score_diff']:+.1f}")
        print(f"Verdict:  {s['verdict']}")

        if s["regressions"]:
            print(f"\nRegressions ({s['n_regressions']}):")
            for r in s["regressions"]:
                print(f"  {r['probe']:20s}  {r['baseline_pass_rate']*100:3.0f}% -> {r['current_pass_rate']*100:3.0f}%  ({r['diff']:+.0%})")

        if s["improvements"]:
            print(f"\nImprovements ({s['n_improvements']}):")
            for r in s["improvements"]:
                print(f"  {r['probe']:20s}  {r['baseline_pass_rate']*100:3.0f}% -> {r['current_pass_rate']*100:3.0f}%  ({r['diff']:+.0%})")

        return 0 if s["verdict"] != "REGRESSION" else 1

    print("Unknown baseline action. Use: save <path> or compare <path>")
    return 1


def cmd_import_scenario(args: argparse.Namespace) -> int:
    """Import attack scenarios from a JSON/YAML file."""
    from cascade_scan.scenarios.registry import load_scenarios_from_file, custom_scenarios_dir

    if args.init_dir:
        custom_scenarios_dir(args.init_dir)
        print(f"Scenario template directory created at {args.init_dir}")
        return 0

    try:
        loaded = load_scenarios_from_file(args.path)
        print(f"Loaded {len(loaded)} scenario(s) from {args.path}:")
        for s in loaded:
            print(f"  {s.name:25s}  severity={s.severity}  {len(s.tool_calls)} call(s)")
        return 0
    except Exception as e:
        print(f"Error importing scenarios: {e}", file=sys.stderr)
        return 1


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
    sub.add_argument("--fail-below", type=float, default=None,
                     help="Exit code 1 if score is below this threshold")
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

    # evolve
    p_ev = sub.add_parser("evolve", help="Iterative security evaluation")
    _add_common_args(p_ev)
    p_ev.add_argument("--probes", "-p", nargs="*", default=[],
                      help="Probes to run (injection, tool-abuse, xss, sqli, ...)")
    p_ev.add_argument("--iterations", type=int, default=5,
                      help="Number of scan iterations (default: 5)")
    p_ev.set_defaults(func=cmd_evolve)

    # baseline
    p_base = sub.add_parser("baseline", help="Manage scan baselines")
    p_base.add_argument("baseline_action", choices=["save", "compare"],
                        help="Action: save new baseline or compare against existing")
    p_base.add_argument("path", type=str,
                        help="Path to the baseline JSON file")
    _add_common_args(p_base)
    p_base.add_argument("--probes", "-p", nargs="*", default=[],
                        help="Probes to run (injection, tool-abuse, xss, sqli, ...)")
    p_base.set_defaults(func=cmd_baseline)

    # import-scenario
    p_imp = sub.add_parser("import-scenario", help="Import custom attack scenarios")
    p_imp.add_argument("path", type=str, nargs="?",
                       help="Path to scenario JSON/YAML file")
    p_imp.add_argument("--init-dir", type=str, default=None,
                       help="Create a scenario template directory")
    p_imp.set_defaults(func=cmd_import_scenario)

    args = parser.parse_args(argv)

    if not hasattr(args, "func"):
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
