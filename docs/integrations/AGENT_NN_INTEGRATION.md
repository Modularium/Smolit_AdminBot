# Agent-NN Integration with AdminBot

## Purpose

This document defines the Phase 4 integration shape between `Agent-NN` and `AdminBot`.

The integration goal is narrow:

- `Agent-NN` may use AdminBot through a dedicated adapter path
- AdminBot remains the technical and policy authority
- no new generic execution surface is introduced

This document is architecture, not an approval to widen the runtime surface.

## Roles

### Agent-NN

`Agent-NN` is responsible for:

- understanding user intent
- planning and orchestration
- selecting one of a small set of dedicated AdminBot tools
- interpreting structured AdminBot results

`Agent-NN` is not responsible for:

- local authorization
- privilege decisions
- direct systemd or polkit control
- raw IPC request construction from arbitrary prompt text
- any shell or generic command execution path

### AdminBot

`AdminBot` remains responsible for:

- request validation
- peer identity binding via `SO_PEERCRED`
- policy and capability enforcement
- audit logging
- execution of the fixed backend path for each action

`AdminBot` remains the technical and business boundary for local administration.

### Dedicated AdminBot Agent / Adapter

The integration component between `Agent-NN` and `AdminBot` is a dedicated local worker or service.

Its job is limited to:

- exposing a fixed tool surface to `Agent-NN`
- validating tool-specific input
- mapping each tool to one AdminBot action or one fixed local control-plane command
- forwarding the structured result back to `Agent-NN`

It is not a generic plugin host and not a second policy engine.

## Trust Boundary

The trust boundary does not move into `Agent-NN`.

The effective boundary remains:

1. local adapter process
2. `adminbotd` IPC boundary
3. AdminBot policy and capability checks
4. AdminBot audit trail
5. fixed backend path such as systemd D-Bus plus polkit

Security-relevant trust anchors remain:

- peer UID/GID/PID from `SO_PEERCRED`
- policy mapping to `unix_user` and `unix_group`
- static action registry
- AdminBot-side validation and audit

Not trusted as an authorization source:

- `requested_by.type`
- `requested_by.id`
- model output
- prompt text

## Why Agent-NN Must Not Rule the Host

`Agent-NN` output is not a security credential.

If the model could send arbitrary action names, arbitrary JSON params, shell commands, or direct D-Bus calls, the integration would bypass the core AdminBot design:

- deterministic actions
- minimal privilege surface
- single local policy authority
- reviewable audit trail

That is explicitly forbidden.

## Request Flow

The allowed flow is:

1. a user or automation asks `Agent-NN` for an admin task
2. `Agent-NN` selects a dedicated AdminBot tool
3. the AdminBot adapter validates the tool input against a fixed contract
4. the adapter maps the tool to a fixed AdminBot request
5. the adapter sends the request over the existing Unix socket
6. `adminbotd` validates the request, resolves peer credentials, applies policy, and audits
7. `adminbotd` either rejects the request or executes the fixed backend path
8. the adapter returns the structured response to `Agent-NN`

The adapter may enrich metadata for correlation, but it must not override AdminBot authorization semantics.

## Design Rules

The integration contract is only acceptable under these rules:

- no generic `run_action` or `call_any_action`
- no raw `params` passthrough from model output
- no shell wrapper
- no direct systemd or polkit API from `Agent-NN`
- no duplicate capability logic outside AdminBot
- no implicit privilege carry-over from human operator context
- mutating flows stay explicit and auditable

## Default Scope for Phase 4

Phase 4 prepares the integration boundary. It does not add a large Agent-NN subsystem to this repository.

The expected result is:

- canonical integration documentation
- a small fixed tool model
- explicit human-versus-agent identity rules
- optional minimal reference artifacts that do not widen the trust boundary

Further details are split into:

- [ADMINBOT_AGENT_MODEL.md](/home/dev/Documents/Smolit_AdminBot/docs/integrations/ADMINBOT_AGENT_MODEL.md)
- [TOOL_MAPPING.md](/home/dev/Documents/Smolit_AdminBot/docs/integrations/TOOL_MAPPING.md)
- [AGENT_SECURITY_BOUNDARY.md](/home/dev/Documents/Smolit_AdminBot/docs/integrations/AGENT_SECURITY_BOUNDARY.md)
