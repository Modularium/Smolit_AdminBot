# Dedicated AdminBot Agent Model

## Purpose

This document defines the shape of the dedicated AdminBot adapter used by `Agent-NN`.

The adapter is a bounded worker or service, not a general plugin.

## Deployment Model

Recommended model:

- a dedicated local worker or service account
- one narrow runtime responsibility: AdminBot tool translation
- no new network listener
- no direct root execution
- no direct systemd or polkit client logic outside AdminBot

Preferred placement:

- inside the `Agent-NN` runtime as a dedicated worker-service
- or as a local MCP-like adapter with a fixed tool registry

Not acceptable:

- a generic plugin container
- arbitrary script execution
- open-ended command dispatch
- a second independent authorization layer

## Accepted Inputs

The adapter accepts only:

- a fixed `tool_name` from a small enum
- tool-specific typed arguments
- optional `correlation_id` or run identifier
- an execution intent that is explicit for mutating paths

Examples of acceptable input:

- `adminbot_get_status(detail = "basic")`
- `adminbot_get_service_status(unit = "nginx.service")`
- `adminbot_restart_service(unit = "nginx.service", reason = "...", preview_only = true)`

Not acceptable as adapter input:

- arbitrary AdminBot `action`
- arbitrary JSON `params`
- shell fragments
- filesystem paths except where the tool contract explicitly allows a fixed validated path
- systemd method names
- polkit action IDs

## Mapping Model

Each adapter tool must have one of these mapping shapes:

- one tool to one AdminBot IPC action
- one tool to one fixed local control-plane command such as `adminbotctl policy validate`

No tool may dynamically choose an AdminBot action from user or model input.

No tool may alter the semantic mode of a privileged backend. For example, `service.restart` remains fixed to AdminBot mode `safe` and systemd mode `"replace"`.

## Request Construction Rules

When the adapter builds an AdminBot IPC request:

- `requested_by.type` is set to `agent`
- `requested_by.id` is set to a stable adapter identity string such as `agentnn-adminbot-agent`
- `action` comes only from the static tool mapping
- `params` come only from tool-specific validation
- `dry_run` follows tool rules, not model freedom
- `timeout_ms` remains bounded by conservative defaults

Important:

- these request fields improve audit and correlation
- they do not authorize anything by themselves
- real authorization still comes from peer credentials and AdminBot policy

## Mutating Paths

Mutating tools must remain rarer and stricter than read-only tools.

For Phase 4:

- the default agent capability set is read-only
- `service.restart` is defined as a restricted tool, not a broad default
- dry-run or preview must happen first
- the tool never exposes free restart modes, batch restarts, or wildcard unit selection

## Explicitly Forbidden Behaviors

The adapter must not:

- expose `adminbot_execute_anything`
- proxy raw JSON to the socket
- expose a shell, REPL, or script runner
- edit Policy, polkit, or systemd artifacts
- call `systemctl`
- call D-Bus directly for service control
- infer higher privileges from a human session
- silently retry mutating actions until they succeed

## Output Model

The adapter should return:

- AdminBot success payloads with minimal reshaping
- AdminBot error payloads without hiding error codes
- audit references and warnings where available

It should not:

- suppress AdminBot denials
- translate one error class into another security class
- invent success for partial or blocked mutations

## Minimal Reference Contract

The adapter remains intentionally small:

- fixed tool enum
- strict per-tool input validation
- no second policy engine
- no business logic beyond safe mapping and response forwarding

If future expansion is needed, each new tool requires a separate issue and review.
