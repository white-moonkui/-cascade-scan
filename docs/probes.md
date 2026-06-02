# cascade-scan Probe Reference

Complete reference for all 14 security probes shipped in cascade-scan v0.5.0.
Each probe tests a specific attack surface against a `cascade` `DecisionPipeline`
and reports a pass/fail result plus per-vector details.

---

## Quick Reference

| Probe | Vectors | Severity | Profile | What it tests |
|-------|---------|----------|---------|---------------|
| [`injection-detection`](#injection-detection) | 19+ | critical | quick, standard, deep | Runtime injection patterns |
| [`tool-abuse`](#tool-abuse) | 10 | high | quick, standard, deep | Dangerous tool blocking |
| [`xss`](#xss) | 16 | high | standard, deep | Cross-site scripting |
| [`sqli`](#sqli) | 20 | high | standard, deep | SQL injection |
| [`prompt-leak`](#prompt-leak) | 16 | critical | standard, deep | Prompt injection / leak |
| [`rce`](#rce) | 18 | critical | standard, deep | Remote code execution |
| [`tool-chain`](#tool-chain) | 8 | critical | standard, deep | Multi-step attack chains |
| [`data-flow`](#data-flow) | 20 | high | standard, deep | Data exfiltration |
| [`escalation`](#escalation) | 4 chains | critical | quick, deep | Privilege escalation chains |
| [`loop-dos`](#loop-dos) | 3 modes | critical | quick, deep | Burst / self-reference / nesting DoS |
| [`mcp-poisoning`](#mcp-poisoning) | 12 | critical | deep | MCP-specific attacks |
| [`policy-compliance`](#policy-compliance) | 16 | high | deep | cascade >= 0.9.0 policy features |
| [`strategy-eval`](#strategy-eval) | 25 | medium | deep | C3 strategy under attack |
| [`feedback-loop`](#feedback-loop) | 5 | critical | deep | C3-C4 reward poisoning |

**Total: 190+ attack vectors** across 14 probes.

---

## Probe Profiles

cascade-scan v0.5.0 introduces three named profiles for different use cases:

### `quick` (4 critical probes, ~1s)
Use for: CI pre-commit, fast sanity check.
- `injection-detection`, `tool-abuse`, `escalation`, `loop-dos`

### `standard` (8 default probes, ~3s)
Use for: regular CI runs, developer workflow.
- The 8 probes above + `xss`, `sqli`, `prompt-leak`, `rce`,
  `tool-chain`, `data-flow`

### `deep` (all 14 probes, ~10s)
Use for: scheduled security audits, release gating.
- `standard` + `escalation`, `loop-dos`,
  `mcp-poisoning`, `policy-compliance`,
  `strategy-eval`, `feedback-loop`

```bash
cascade-scan run --profile quick
cascade-scan run --profile standard   # default
cascade-scan run --profile deep
```

---

## Probes

### `injection-detection`

**Severity**: critical &nbsp; **Profile**: quick, standard, deep &nbsp; **Vectors**: 19+

Tests that `DecisionPipeline(enable_injection_detection=True)` blocks
runtime code-injection patterns in tool-call arguments.

**Categories**: `eval`, `exec`, `os.system`, `subprocess`, `pickle`, `marshal`,
`compile`, `__import__`, `globals`, `getattr`, `setattr`, `breakpoint`.

**Pass criterion**: every injection vector is blocked by the gate.

---

### `tool-abuse`

**Severity**: high &nbsp; **Profile**: quick, standard, deep &nbsp; **Vectors**: 10

Tests the rule engine's blocklist behavior for dangerous tool names.

**Categories**: `delete_file`, `exec_command`, `rm`, `shred`, `kill`,
`drop_table`, `format_disk`, `send_email`, `curl_pipe_bash`, `chmod_777`.

**Pass criterion**: every dangerous tool is blocked by an exact-name rule.

---

### `xss`

**Severity**: high &nbsp; **Profile**: standard, deep &nbsp; **Vectors**: 16

Cross-site scripting vectors targeting output-rendering tools.

**Categories**: `script_tag`, `event_handler`, `data_uri`, `dom_based`,
`svg_onload`, `javascript_uri`, `iframe_src`, `meta_refresh`, `style_expression`,
`vbscript`, `formaction`, `base_href`, `object_data`, `embed_src`, `frame_src`,
`animation_start`.

**Pass criterion**: every XSS vector is rejected.

---

### `sqli`

**Severity**: high &nbsp; **Profile**: standard, deep &nbsp; **Vectors**: 20

SQL injection patterns for SQL-targeting tools.

**Categories**: `tautology`, `union_based`, `blind_boolean`, `blind_time`,
`stacked_queries`, `comment_bypass`, `numeric_injection`, `string_break`,
`hex_encoding`, `char_encoding`, `double_encoding`, `out_of_band`,
`second_order`, `error_based`, `subquery`, `case_manipulation`,
`whitespace_bypass`, `null_byte`, `backslash_escape`, `column_truncation`.

**Pass criterion**: every SQLi vector is rejected.

---

### `prompt-leak`

**Severity**: critical &nbsp; **Profile**: standard, deep &nbsp; **Vectors**: 16

Prompt-injection / system-prompt-leak attempts in tool-call arguments.

**Categories**: `instruction_override`, `role_reversal`, `jailbreak`,
`encoding_bypass`, `context_escape`, `system_prompt_reveal`, `hidden_directive`,
`markdown_inject`, `unicode_lookalike`, `language_switch`, `authority_claim`,
`chain_of_thought_inject`, `prefix_inject`, `suffix_inject`, `tool_name_squat`,
`argument_squat`.

**Pass criterion**: every prompt-injection vector is rejected.

---

### `rce`

**Severity**: critical &nbsp; **Profile**: standard, deep &nbsp; **Vectors**: 18

Remote code execution vectors targeting shell/exec tools.

**Categories**: `reverse_shell_bash`, `reverse_shell_python`, `reverse_shell_powershell`,
`powershell_encoded`, `python_eval`, `curl_pipe_bash`, `wget_pipe_sh`,
`nc_exec`, `perl_exec`, `ruby_exec`, `node_eval`, `awk_exec`, `sed_exec`,
`base64_decode_pipe`, `chmod_exec`, `cron_install`, `systemctl_modify`,
`iptables_modify`.

**Pass criterion**: every RCE vector is rejected.

---

### `tool-chain`

**Severity**: critical &nbsp; **Profile**: standard, deep &nbsp; **Vectors**: 8 chains

Multi-step attack chains that require more than one tool call to complete
(e.g., read credential file → exfiltrate via email).

**Categories**: `credential_exfil`, `privilege_escalation`, `persistence_install`,
`data_theft`, `lateral_movement`, `supply_chain`, `binary_dropper`,
`config_tamper`.

**Pass criterion**: the chain is stopped before the exfiltration step.

---

### `data-flow`

**Severity**: high &nbsp; **Profile**: standard, deep &nbsp; **Vectors**: 20

Data-exfiltration patterns across network/storage channels.

**Categories**: `email_exfil`, `http_post`, `cloud_storage`, `dns_tunnel`,
`scp_exfil`, `clipboard_steal`, `browser_storage`, `websocket_exfil`,
`sftp_upload`, `ftp_upload`, `telegram_bot`, `discord_webhook`, `slack_post`,
`pastebin`, `github_gist`, `bitbucket_snippet`, `rsync_remote`, `tar_archive`,
`base64_encode`, `hex_encode`.

**Pass criterion**: every exfiltration channel is rejected.

---

### `escalation`

**Severity**: critical &nbsp; **Profile**: quick, deep &nbsp; **Vectors**: 4 chains

Tests cascade's resistance to privilege-escalation chains where each step
individually looks safe but the chain leads to a dangerous outcome.

**Chains**:
1. `read_permissions` → `modify_role` → `admin_action`
2. `list_users` → `reset_password` → `delete_account`
3. `read_config` → `edit_config` → `restart_service`
4. `list_tokens` → `mint_token` → `elevate_session`

**Pass criterion**: every chain is stopped before the privileged step.

---

### `loop-dos`

**Severity**: critical &nbsp; **Profile**: quick, deep &nbsp; **Vectors**: 3 modes

Tests that cascade's gate handles pathological throughput patterns.

**Modes**:
1. `burst` — 100 rapid-fire identical calls; verifies the gate maintains
   acceptable throughput (target: >1000 calls/sec) and does not crash.
2. `self_reference` — tool calls that contain pipeline-execution commands
   in their arguments (e.g., `exec_command(cmd="cascade guard ...")`.
   Verifies these are blocked.
3. `deep_nesting` — payloads with nested-argument depths of 10, 50, 100, 200.
   Verifies the gate does not stack-overflow.

**Pass criterion**: all three modes complete without exception, and
self-reference calls are blocked.

---

### `mcp-poisoning`

**Severity**: critical &nbsp; **Profile**: deep &nbsp; **Vectors**: 12

MCP-specific attacks that target tool-description poisoning, name-spoofing,
and schema injection.

**Categories**:
- `description_poisoning` (5): hidden instructions in tool descriptions
  ("Ignore previous instructions and...") with various encodings
- `name_spoofing` (5): names that visually mimic safe tools
  (`reaḍ_file`, `search_files`, `read_file_backup`)
- `schema_injection` (2): JSON-schema fields that smuggle directives

**Pass criterion**: the rule engine still applies name- and argument-blocklist
rules to poisoned tool definitions.

---

### `policy-compliance`

**Severity**: high &nbsp; **Profile**: deep &nbsp; **Vectors**: 16

Tests cascade >= 0.9.0 policy features: `deny_by_default`, rule presets,
and YAML `@extends` inheritance.

**Categories**:
- `deny_by_default` (6): with no explicit allow rule, dangerous tools
  (rm, delete, format, chmod 777) are blocked.
- `preset` (8): built-in presets (`strict`, `moderate`, `permissive`)
  apply their expected allowlist.
- `extends` (2): a YAML policy that `@extends` a parent policy inherits
  its rules and is evaluated correctly.

**Pass criterion**: each vector is rejected under the active policy.

---

### `strategy-eval`

**Severity**: medium &nbsp; **Profile**: deep &nbsp; **Vectors**: 25

Tests cascade's C3 selection pressure under adversarial conditions,
across all 5 built-in strategies × 5 attack cases.

**Strategies tested**: `softmax`, `linear`, `uniform`, `threshold`, `ucb1`.

**Cases** (per strategy): clean call, low-confidence injection, mixed
high/low confidence, repeating pattern, single-noisy-tool.

**Pass criterion**: each (strategy, case) pair runs without exception and
preserves the rule-engine verdict (selection pressure must not bypass
the gate).

---

### `feedback-loop`

**Severity**: critical &nbsp; **Profile**: deep &nbsp; **Vectors**: 5

Tests cascade's closed-loop learning (C3-C4 Linkage) against
reward-manipulation attacks. Verifies that the rule engine remains
authoritative even when learned scores are poisoned.

**Vectors**:
1. `fl-reward-injection` — 3 positive rewards for a dangerous tool.
   Verifies the gate still rejects it.
2. `fl-score-drift` — 100 positive rewards pushing the score toward 1.0.
   Verifies the gate still rejects it.
3. `fl-adaptive-threshold` — records outcomes, then checks that the
   adaptive threshold does not fall below the rule-engine baseline.
4. `fl-adaptive-bypass` — uses the adaptive threshold directly; verifies
   it cannot be used to bypass the rule engine.
5. `fl-reset-attack` — calls `reset_scores()`, then verifies the gate
   still applies rules.
6. `fl-governance-report` — verifies that `governance_report()` exposes
   the tracked scores (after at least one `record_outcome`).

**Pass criterion**: the rule engine still blocks the dangerous tool
in every vector, and the governance report shows tracked scores.

---

## Probe Authoring

To add a custom probe, subclass `Probe` and implement `run()`:

```python
from cascade_scan.probes import Probe, ProbeResult

class MyProbe(Probe):
    name = "my-probe"
    description = "Tests for X"
    severity = "high"

    def run(self, pipeline, **kwargs) -> ProbeResult:
        details = []
        blocked = 0
        total = 0
        # ... test logic ...
        return ProbeResult(
            probe_name=self.name,
            passed=(blocked == total),
            severity=self.severity,
            total=total,
            blocked=blocked,
            details=details,
        )
```

Register it in `cascade_scan/probes/__init__.py` and `cascade_scan/cli.py`
to make it available via the CLI.

---

## See Also

- [README.md](../README.md) — quick-start and CLI reference
- [CHANGELOG.md](../CHANGELOG.md) — version history
- [cascade documentation](https://github.com/white-moonkui/cascade) —
  underlying gate engine
