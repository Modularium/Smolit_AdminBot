# AdminBot Agent Tool Mapping

## Purpose

This document defines the first safe tool surface for `Agent-NN`.

The goal is a small, reviewable set of named tools. This is not a generic AdminBot action gateway.

## Design Rules

- tool names are fixed
- each tool has a typed input contract
- each tool maps to exactly one AdminBot action or one fixed local control-plane command
- no raw action passthrough
- no raw params passthrough
- mutating tools are stricter than read-only tools

## Initial Tool Set

| Tool | Purpose | Inputs | Expected Output | Mapping | Required Capability / Control | Risk | Access |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `adminbot_get_status` | Compact host status | `detail = basic|extended` | Hostname, kernel, uptime, load, memory | `system.status` | `read_basic` | `R0` | `agent_allowed` |
| `adminbot_get_health` | Stable health summary | `include_checks[]` from fixed enum | Overall status, checks, warnings | `system.health` | `read_basic` | `R0` | `agent_allowed` |
| `adminbot_get_service_status` | Status of one allowed unit | `unit` | Unit state and unit-file state | `service.status` | `service_read` | `R1` | `agent_allowed` |
| `adminbot_tail_audit` | Short audit or journald view for one unit | `unit`, `priority_min`, `since_seconds`, `limit`, `show_message = false|true` | Structured log list | `journal.query` | `journal_read` preferred, or `read_sensitive` only if broader exposure is intended | `R1` | `agent_restricted` |
| `adminbot_restart_service` | Preview or execute a restart of one allowed unit | `unit`, `reason`, `preview_only` | Preview result or restart result with audit reference | `service.restart` | `service_restart` or `service_control` | `R2` | `restricted` |
| `adminbot_validate_policy` | Validate the local Policy artifact | `path` with fixed default and strict path validation | `PASS` or `FAIL`, plus validation details | fixed local control-plane command `adminbotctl policy validate` | local operator or CI control, not daemon capability | `R0` | `human_only` |
| `adminbot_run_gate` | Run the security release gate in `artifact` or `live` mode | `mode`, optional fixed artifact paths | `PASS` or `FAIL`, plus per-check details | fixed local control-plane command `adminbotctl gate run` | local operator or CI control, not daemon capability | `R1` | `human_only` |

## Per-Tool Boundaries

### `adminbot_get_status`

- read-only
- no hidden side effects
- no free host selection

### `adminbot_get_health`

- read-only
- only the documented check enum is accepted
- no dynamic custom probes

### `adminbot_get_service_status`

- only one unit per call
- no wildcard units
- unit must pass AdminBot validation and Policy whitelist

### `adminbot_tail_audit`

- intended for narrow, recent diagnostics
- default unit should remain `adminbotd.service`
- `limit` is hard-capped in code and must stay small
- raw messages should remain redacted by default
- agent access should use `journal_read` where possible instead of broad `read_sensitive`
- `since_seconds` is hard-capped to a bounded recent window

### `adminbot_restart_service`

- only one unit per call
- no batch restarts
- mode is fixed to AdminBot `safe`
- the adapter maps preview to `dry_run = true`
- the adapter may map execution to `dry_run = false` only for this one tool
- the adapter must require `reason`
- the adapter must send a stable `correlation_id`
- non-dry-run execution is rejected unless a prior successful preview with the same `correlation_id` exists in the preview window
- this tool is not part of the default Agent-NN capability set
- replayed `request_id` values are rejected inside the replay window
- restart attempts are additionally subject to rate limiting and service cooldown protection

### `adminbot_validate_policy`

- intended for human operators, CI, or deployment automation
- not part of the first agent-allowed tool surface
- does not mutate the policy
- must not accept unbounded path traversal or shell interpolation

### `adminbot_run_gate`

- intended for human operators, CI, or deployment automation
- not part of the first agent-allowed tool surface
- does not modify deployment artifacts
- must not be converted into a generic local command runner

## Default Agent-NN Surface

Default agent-allowed tools for the first secure integration step:

- `adminbot_get_status`
- `adminbot_get_health`
- `adminbot_get_service_status`

Conditionally allowed after explicit review:

- `adminbot_tail_audit`

Not default agent tools in Phase 4:

- `adminbot_restart_service`
- `adminbot_validate_policy`
- `adminbot_run_gate`

## Hardening Defaults

The first Agent-NN integration step assumes these runtime defaults inside AdminBot:

- rate limiting enabled by default
- replay protection enabled by default for mutating requests
- preview-before-execute enabled by default for `service.restart`
- hard input limits enforced in code for journal query size and request metadata strings

## Deferred Tools

These existing AdminBot actions are intentionally not exposed in the first dedicated tool set:

- `resource.snapshot`
- `disk.usage`
- `network.interface_status`
- `process.snapshot`

They can be added later, but only via a separate issue with explicit scope and review.
