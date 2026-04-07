# Agent-NN Integration for AdminBot v2

This document remains as the high-level v2 reference entry for Agent-NN integration.

The canonical Phase 4 integration contract now lives under:

- [AGENT_NN_INTEGRATION.md](/home/dev/Documents/Smolit_AdminBot/docs/integrations/AGENT_NN_INTEGRATION.md)
- [ADMINBOT_AGENT_MODEL.md](/home/dev/Documents/Smolit_AdminBot/docs/integrations/ADMINBOT_AGENT_MODEL.md)
- [TOOL_MAPPING.md](/home/dev/Documents/Smolit_AdminBot/docs/integrations/TOOL_MAPPING.md)
- [AGENT_SECURITY_BOUNDARY.md](/home/dev/Documents/Smolit_AdminBot/docs/integrations/AGENT_SECURITY_BOUNDARY.md)

## High-Level Summary

- `Agent-NN` plans and orchestrates, but does not become a local authority
- `AdminBot` remains the technical and policy boundary
- integration is only acceptable through a dedicated adapter with fixed tools
- no generic action passthrough, no shell, and no direct systemd or polkit control are allowed
- human-versus-agent separation must be anchored in Unix identity and Policy mapping, not in `requested_by.*`

For the active security interpretation, also see:

- [TRUST_BOUNDARIES.md](/home/dev/Documents/Smolit_AdminBot/docs/security/TRUST_BOUNDARIES.md)
- [SECURITY_SIGNOFF_V1.md](/home/dev/Documents/Smolit_AdminBot/docs/security/SECURITY_SIGNOFF_V1.md)
