# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.4.0] — 2026-06 — Escalation & Loop/DoS Probes

### Added
- **Escalation probe** (`escalation`): 4 multi-step privilege-escalation
  attack chains (shadow read→su, cron persistence, docker escape) —
  verifies pipeline breaks the chain
- **Loop/DoS probe** (`loop-dos`): 3 attack modes — 100-call burst
  throughput test, self-referential tool call detection, deeply nested
  argument parsing resilience
- `ConditionVerifier.deny_by_default` support in pipeline (requires
  `agent-armour>=0.9.0`)

### Changed
- `cascade-scan` CLI now auto-registers `escalation` and `loop-dos`
  probes in `--probes` and `run`/`score` commands
- Version bumped to 0.4.0

## [0.3.0] — 2026-06 — CI/CD & Evolution Platform

### Added
- **GitHub Actions CI workflow**: Python 3.10–3.12, ruff lint, pytest
- **`--fail-below` threshold**: `cascade-scan run --fail-below 80` exits 1 if score below threshold (CI integration)
- **Evolve mode**: `cascade-scan evolve --iterations 5` — iterative security evaluation with min/max/avg/std deviation tracking
- **Baseline management**: `cascade-scan baseline save|compare <path>` — save and compare scan results across versions
- **Custom scenario import**: `cascade-scan import-scenario <file>` — load attack scenarios from JSON/YAML files
- **20 new tests** for evolve, baseline, and scenario import (78 total)

### Changed
- **CLI**: all 8 probes accessible via `--probes`; `run`/`score` support `--fail-below`
- **78 tests** (up from 58)

## [0.2.0] — 2026-06 — Probe Matrix Expansion

### Added
- **6 new probes** (2→8 total, 120+ attack vectors):
  - **XSS probe** (`xss`): 16 vectors — script tags, event handlers,
    ``javascript:`` / ``data:`` URIs, DOM-based XSS
  - **SQLi probe** (`sqli`): 20 vectors — tautologies, UNION, blind,
    time-based, stacked queries, out-of-band
  - **Prompt-leak probe** (`prompt-leak`): 16 vectors — instruction
    override, role reversal, jailbreak, encoding bypass
  - **RCE probe** (`rce`): 18 vectors — shell commands, reverse shells,
    PowerShell, Python eval/exec, curl/wget weaponised
  - **Tool-chain probe** (`tool-chain`): 8 multi-step attack chains —
    credential exfil, privesc, persistence, data theft
  - **Data-flow probe** (`data-flow`): 20 vectors — email, HTTP, S3, DNS
    tunnel, clipboard, SCP/rsync, database export
- **`_models.py`**: shared data models (`AttackVector`, `ScanConfig`)

### Changed
- **58 tests** (up from 31) covering all 8 probes, engine, scorer, reports

## [0.1.0] — 2026-06 — Initial Release

### Added
- **Scan engine**: `ScanEngine` orchestrates security probes against a cascade pipeline
- **Injection probe**: 20+ injection patterns (eval, exec, os.system, rm -rf, pickle, …) tested against cascade's runtime injection detection
- **Tool-abuse probe**: 10 dangerous tool types tested against cascade's C₁ rule engine
- **Security scoring**: Weighted 0–100 scoring with letter grades (A+ through F)
- **HTML reports**: Self-contained (inline CSS, zero JS) with summary cards, pass bars, and detail tables
- **JSON export**: Structured JSON for CI integration
- **CLI**: `cascade-scan run` / `score` / `report` / `list-scenarios`
- **Attack scenarios**: 5 built-in scenarios (file-deletion, code-execution, privilege-escalation, data-exfiltration, injection-lite)
- **31 tests** covering engine, probes, scorer, reports, and scenarios
