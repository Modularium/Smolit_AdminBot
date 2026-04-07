# Agent Security Boundary for AdminBot

## Purpose

This document defines how `Agent-NN` stays below the local AdminBot security boundary.

The key rule is simple:

- `Agent-NN` may ask
- AdminBot decides

## What Agent-NN May Do

`Agent-NN`, through the dedicated AdminBot adapter, may:

- call only fixed AdminBot tools
- receive structured read-only system data that Policy explicitly allows
- request a preview for restricted mutating operations
- attach correlation metadata for audit and run tracking

## What Agent-NN May Not Do

`Agent-NN` may not:

- submit arbitrary AdminBot action names
- submit arbitrary AdminBot params
- execute shell commands
- call `systemctl`
- call systemd D-Bus directly
- call polkit directly
- edit Policy, polkit, or systemd artifacts
- inherit a human operator identity
- turn `requested_by.*` into an authorization claim

## Enforcement Anchors

Security enforcement stays bound to:

- local Unix peer identity from `SO_PEERCRED`
- AdminBot Policy mapping on `unix_user` and `unix_group`
- AdminBot capability checks
- AdminBot audit records
- AdminBot rate limits and replay protection
- AdminBot mutation safety guard for preview-before-execute flows

The adapter may label a request as agent-originated, but it must not be able to self-authorize.

## Human vs Agent Separation

The recommended default model is:

| Component | Unix identity | Purpose |
| --- | --- | --- |
| `adminbotd` | `adminbot` | daemon and local policy authority |
| Human operator | local human user or dedicated operator group | interactive operator use |
| Agent adapter | dedicated user such as `agentnn` | non-human automation path |

Preferred separation rule:

- use a dedicated Unix user for the agent adapter
- keep human and agent Policy selectors non-overlapping
- do not rely on `requested_by.type = agent` for real separation

## Group Strategy

One detail is critical for this repository:

- AdminBot Policy unions capabilities across all matching client entries

That means:

- if the agent user matches its own `unix_user` entry and also a broader human `unix_group` entry, it inherits the union of both capability sets

This creates a concrete safety rule:

- any group shared only to open the socket must not also be used as a higher-privilege Policy selector for humans

Practical consequence:

- the socket access group may be shared for connectivity
- privileged human permissions should be granted through a dedicated human `unix_user` mapping or a group the agent user does not belong to

## `requested_by` and Peer Identity

For agent calls, the adapter should set:

- `requested_by.type = agent`
- `requested_by.id = agentnn-adminbot-agent`

For human calls, a human-oriented value is fine.

But in both cases:

- `requested_by.*` is audit and correlation metadata only
- the authoritative identity remains the Unix peer credential seen by `adminbotd`

This prevents the agent from becoming a human just by changing request JSON.

## Audit Marking

Agent calls should be visible in audit through two layers:

1. true peer identity:
   - peer UID
   - peer GID
   - peer PID
   - resolved Unix user
2. declared request metadata:
   - `requested_by.type`
   - `requested_by.id`
   - correlation or run identifier

The first layer is security-relevant. The second layer is operationally useful.

## Maximum Agent Capability Sets

Recommended default capability set for the base agent identity:

- `read_basic`
- optional `service_read`
- optional `journal_read` only when audit or journald visibility is really needed

Avoid by default:

- `read_sensitive` unless the broader exposure is explicitly required
- `service_restart`
- `service_control`

If a future workflow needs restricted mutation, use a separate stronger identity such as `agentnn-ops`, with a separate issue and review, instead of silently widening the base agent identity.

## Runtime Hardening

The Agent-NN path is additionally constrained at runtime:

- rate limiting is active by default
- requests are limited per effective Unix identity
- an optional second bucket limits repeated calls per tool name
- replay protection is active by default for mutating requests
- repeated `request_id` values are rejected inside the replay window
- `service.restart` execution requires a prior successful preview with the same `correlation_id`

These controls are enforced in AdminBot, not in the adapter.

## Linux Capability Sets

The agent adapter should not receive Linux kernel capabilities.

Recommended runtime stance:

- non-root
- `NoNewPrivileges=yes`
- empty `CapabilityBoundingSet=`
- no direct access to privileged backends

AdminBot already provides the only intended privileged bridge through its fixed local architecture.

## Minimal Integration Artifact

The repository includes a companion example Policy under:

- `config/policy.agentnn.example.toml`

It demonstrates:

- a dedicated `agentnn` identity
- non-overlapping Policy matches for human and agent
- a read-mostly default capability set for the agent path
- room for explicit `rate_limit`, `replay_protection`, and `mutation_safety` configuration
