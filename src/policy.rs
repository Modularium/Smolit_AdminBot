use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use serde::Deserialize;

use crate::actions::ActionMetadata;
use crate::error::{AppError, AppResult, ErrorCode};
use crate::peer::{gid_from_group_name, PeerCredentials};
use crate::types::{Request, RequestOriginType};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    ReadBasic,
    ReadSensitive,
    ServiceRead,
    ServiceControl,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    version: u32,
    #[serde(default)]
    clients: HashMap<String, ClientRule>,
    actions: ActionPolicy,
    #[serde(default)]
    filesystem: FilesystemPolicy,
    #[serde(default)]
    service_control: ServiceControlPolicy,
    #[serde(default)]
    constraints: ConstraintsPolicy,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientRule {
    unix_user: Option<String>,
    unix_group: Option<String>,
    #[serde(default)]
    allowed_request_types: Vec<RequestOriginType>,
    #[serde(default)]
    allowed_capabilities: Vec<Capability>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionPolicy {
    #[serde(default)]
    allowed: Vec<String>,
    #[serde(default)]
    denied: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FilesystemPolicy {
    #[serde(default)]
    allowed_mounts: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceControlPolicy {
    #[serde(default)]
    allowed_units: Vec<String>,
    restart_cooldown_seconds: Option<u64>,
    max_restarts_per_hour: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConstraintsPolicy {
    default_timeout_ms: Option<u64>,
    max_timeout_ms: Option<u64>,
    journal_limit_max: Option<u32>,
    process_limit_max: Option<u32>,
    max_parallel_mutations: Option<u32>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Constraints {
    pub default_timeout_ms: u64,
    pub max_timeout_ms: u64,
    pub journal_limit_max: u32,
    pub process_limit_max: u32,
    pub max_parallel_mutations: u32,
}

impl Default for Constraints {
    fn default() -> Self {
        Self {
            default_timeout_ms: 3000,
            max_timeout_ms: 30_000,
            journal_limit_max: 200,
            process_limit_max: 50,
            max_parallel_mutations: 1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    actions_allowed: HashSet<String>,
    actions_denied: HashSet<String>,
    filesystem_allowed_mounts: HashSet<String>,
    service_allowed_units: HashSet<String>,
    restart_cooldown_seconds: u64,
    max_restarts_per_hour: u32,
    constraints: Constraints,
    clients: Vec<ClientEntry>,
}

#[derive(Debug, Clone)]
struct ClientEntry {
    unix_user: Option<String>,
    unix_group: Option<String>,
    group_gid: Option<u32>,
    allowed_capabilities: HashSet<Capability>,
}

#[derive(Debug, Default)]
struct CooldownTracker {
    last_restart: HashMap<String, SystemTime>,
    recent_restarts: HashMap<String, Vec<SystemTime>>,
}

#[derive(Debug)]
pub struct PolicyEngine {
    snapshot: PolicySnapshot,
    cooldowns: Mutex<CooldownTracker>,
}

impl PolicyEngine {
    pub fn load_from_path(path: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let parsed: PolicyFile = toml::from_str(&content)?;
        if parsed.version != 1 {
            return Err(Box::new(AppError::new(
                ErrorCode::UnsupportedVersion,
                "policy version must be 1",
            )));
        }

        let mut clients = Vec::new();
        for (client_name, client) in parsed.clients {
            if !client.allowed_request_types.is_empty() {
                return Err(Box::new(
                    AppError::new(
                        ErrorCode::ValidationError,
                        "allowed_request_types is not trusted for authorization; use separate unix_user or unix_group bindings",
                    )
                    .with_detail("client", client_name)
                    .with_detail("field", "clients.*.allowed_request_types"),
                ));
            }

            let group_gid = match client.unix_group.as_deref() {
                Some(group_name) => gid_from_group_name(group_name)?,
                None => None,
            };
            clients.push(ClientEntry {
                unix_user: client.unix_user,
                unix_group: client.unix_group,
                group_gid,
                allowed_capabilities: client.allowed_capabilities.into_iter().collect(),
            });
        }

        let constraints = Constraints {
            default_timeout_ms: parsed.constraints.default_timeout_ms.unwrap_or(3000),
            max_timeout_ms: parsed.constraints.max_timeout_ms.unwrap_or(30_000),
            journal_limit_max: parsed.constraints.journal_limit_max.unwrap_or(200),
            process_limit_max: parsed.constraints.process_limit_max.unwrap_or(50),
            max_parallel_mutations: parsed.constraints.max_parallel_mutations.unwrap_or(1),
        };

        Ok(Self {
            snapshot: PolicySnapshot {
                actions_allowed: parsed.actions.allowed.into_iter().collect(),
                actions_denied: parsed.actions.denied.into_iter().collect(),
                filesystem_allowed_mounts: parsed.filesystem.allowed_mounts.into_iter().collect(),
                service_allowed_units: parsed.service_control.allowed_units.into_iter().collect(),
                restart_cooldown_seconds: parsed
                    .service_control
                    .restart_cooldown_seconds
                    .unwrap_or(300),
                max_restarts_per_hour: parsed.service_control.max_restarts_per_hour.unwrap_or(3),
                constraints,
                clients,
            },
            cooldowns: Mutex::new(CooldownTracker::default()),
        })
    }

    pub fn constraints(&self) -> &Constraints {
        &self.snapshot.constraints
    }

    pub fn authorize(
        &self,
        request: &Request,
        metadata: &ActionMetadata,
        peer: &PeerCredentials,
    ) -> AppResult<()> {
        if self.snapshot.actions_denied.contains(&request.action) {
            return Err(
                AppError::new(ErrorCode::PolicyDenied, "action denied by policy")
                    .with_detail("action", request.action.clone()),
            );
        }

        if !self.snapshot.actions_allowed.contains(&request.action) {
            return Err(
                AppError::new(ErrorCode::PolicyDenied, "action not allowed by policy")
                    .with_detail("action", request.action.clone()),
            );
        }

        let capabilities = self.capabilities_for_request_peer(request, peer)?;
        if !capabilities.contains(&metadata.required_capability) {
            return Err(
                AppError::new(ErrorCode::CapabilityDenied, "required capability missing")
                    .with_detail("action", request.action.clone())
                    .with_detail(
                        "required_capability",
                        metadata.required_capability.to_string(),
                    ),
            );
        }

        Ok(())
    }

    pub fn check_service_restart_allowed(&self, unit: &str) -> AppResult<()> {
        self.check_service_unit_allowed(unit)?;

        let now = SystemTime::now();
        let mut guard = self.cooldowns.lock().expect("cooldown lock poisoned");
        let tracker = &mut *guard;

        if let Some(last_restart) = tracker.last_restart.get(unit) {
            if now
                .duration_since(*last_restart)
                .unwrap_or(Duration::from_secs(0))
                .as_secs()
                < self.snapshot.restart_cooldown_seconds
            {
                return Err(
                    AppError::new(ErrorCode::CooldownActive, "restart cooldown is active")
                        .with_detail("unit", unit.to_string()),
                );
            }
        }

        let entries = tracker.recent_restarts.entry(unit.to_string()).or_default();
        entries.retain(|timestamp| {
            now.duration_since(*timestamp)
                .unwrap_or(Duration::from_secs(0))
                .as_secs()
                < 3600
        });

        if entries.len() as u32 >= self.snapshot.max_restarts_per_hour {
            return Err(
                AppError::new(ErrorCode::RateLimited, "restart rate limit exceeded")
                    .with_detail("unit", unit.to_string()),
            );
        }

        Ok(())
    }

    pub fn check_service_unit_allowed(&self, unit: &str) -> AppResult<()> {
        if !self.snapshot.service_allowed_units.contains(unit) {
            return Err(
                AppError::new(ErrorCode::PolicyDenied, "unit not allowed by policy")
                    .with_detail("field", "params.unit")
                    .with_detail("unit", unit.to_string())
                    .with_detail("policy_section", "service_control.allowed_units"),
            );
        }

        Ok(())
    }

    pub fn check_mount_allowed(&self, mount: &str) -> AppResult<()> {
        if !self.snapshot.filesystem_allowed_mounts.contains(mount) {
            return Err(
                AppError::new(ErrorCode::PolicyDenied, "mount not allowed by policy")
                    .with_detail("field", "params.mounts")
                    .with_detail("mount", mount.to_string())
                    .with_detail("policy_section", "filesystem.allowed_mounts"),
            );
        }

        Ok(())
    }

    pub fn record_service_restart(&self, unit: &str) {
        let now = SystemTime::now();
        let mut guard = self.cooldowns.lock().expect("cooldown lock poisoned");
        guard.last_restart.insert(unit.to_string(), now);
        guard
            .recent_restarts
            .entry(unit.to_string())
            .or_default()
            .push(now);
    }

    fn capabilities_for_request_peer(
        &self,
        _request: &Request,
        peer: &PeerCredentials,
    ) -> AppResult<HashSet<Capability>> {
        let gids = peer.all_gids();
        let mut capabilities = HashSet::new();
        let mut matched = false;

        for client in &self.snapshot.clients {
            let mut current_match = false;

            if let Some(expected_user) = &client.unix_user {
                if peer.unix_user.as_deref() == Some(expected_user.as_str()) {
                    current_match = true;
                }
            }

            if let Some(expected_gid) = client.group_gid {
                if gids.contains(&expected_gid) {
                    current_match = true;
                }
            } else if client.unix_group.is_some() {
                current_match = false;
            }

            if current_match {
                matched = true;
                capabilities.extend(client.allowed_capabilities.iter().copied());
            }
        }

        if !matched {
            return Err(AppError::new(
                ErrorCode::Unauthorized,
                "peer is not mapped to any policy client",
            )
            .with_detail("uid", peer.uid as u64)
            .with_detail("gid", peer.gid as u64));
        }

        Ok(capabilities)
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Capability::ReadBasic => "read_basic",
            Capability::ReadSensitive => "read_sensitive",
            Capability::ServiceRead => "service_read",
            Capability::ServiceControl => "service_control",
        };
        f.write_str(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::path::PathBuf;
    use std::process;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::actions;
    use crate::error::ErrorCode;
    use crate::peer::PeerCredentials;
    use crate::types::{Request, RequestOriginType, RequestedBy};

    fn write_policy_file(contents: &str) -> PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "adminbot-policy-test-{}-{timestamp}.toml",
            process::id()
        ));
        fs::write(&path, contents).expect("write test policy");
        path
    }

    fn remove_policy_file(path: &PathBuf) {
        let _ = fs::remove_file(path);
    }

    #[test]
    fn loads_v1_policy_snapshot_from_toml() {
        let path = write_policy_file(
            r#"
version = 1

[clients.human_admin]
unix_user = "dev"
allowed_capabilities = ["read_basic", "service_read"]

[clients.service_operator]
unix_group = "root"
allowed_capabilities = ["service_control"]

[actions]
allowed = ["system.status", "service.status", "service.restart"]
denied = ["journal.query"]

[filesystem]
allowed_mounts = ["/", "/var"]

[service_control]
allowed_units = ["sshd.service", "nginx.service"]
restart_cooldown_seconds = 120
max_restarts_per_hour = 2

[constraints]
default_timeout_ms = 5000
max_timeout_ms = 15000
journal_limit_max = 50
process_limit_max = 25
max_parallel_mutations = 1
"#,
        );

        let engine = PolicyEngine::load_from_path(path.clone()).expect("load policy");
        remove_policy_file(&path);

        assert!(engine.snapshot.actions_allowed.contains("system.status"));
        assert!(engine.snapshot.actions_denied.contains("journal.query"));
        assert!(engine.snapshot.filesystem_allowed_mounts.contains("/"));
        assert!(engine.snapshot.filesystem_allowed_mounts.contains("/var"));
        assert!(engine
            .snapshot
            .service_allowed_units
            .contains("sshd.service"));
        assert_eq!(engine.snapshot.restart_cooldown_seconds, 120);
        assert_eq!(engine.snapshot.max_restarts_per_hour, 2);
        assert_eq!(engine.snapshot.constraints.default_timeout_ms, 5000);
        assert_eq!(engine.snapshot.constraints.max_timeout_ms, 15_000);
        assert_eq!(engine.snapshot.constraints.journal_limit_max, 50);
        assert_eq!(engine.snapshot.constraints.process_limit_max, 25);
        assert_eq!(engine.snapshot.constraints.max_parallel_mutations, 1);
        assert_eq!(engine.snapshot.clients.len(), 2);

        let service_operator = engine
            .snapshot
            .clients
            .iter()
            .find(|client| client.unix_group.as_deref() == Some("root"))
            .expect("service_operator client");
        assert!(service_operator.group_gid.is_some());
        assert!(service_operator
            .allowed_capabilities
            .contains(&Capability::ServiceControl));
    }

    #[test]
    fn rejects_policy_versions_other_than_v1() {
        let path = write_policy_file(
            r#"
version = 2

[actions]
allowed = ["system.status"]
"#,
        );

        let error = PolicyEngine::load_from_path(path.clone()).expect_err("unsupported version");
        remove_policy_file(&path);

        let app_error = error
            .downcast_ref::<AppError>()
            .expect("error should be AppError");
        assert_eq!(app_error.code, ErrorCode::UnsupportedVersion);
    }

    #[test]
    fn rejects_unknown_fields_in_policy_file() {
        let path = write_policy_file(
            r#"
version = 1
unexpected_field = true

[actions]
allowed = ["system.status"]
"#,
        );

        let error = PolicyEngine::load_from_path(path.clone()).expect_err("unknown field");
        remove_policy_file(&path);

        let message = error.to_string();
        assert!(message.contains("unknown field"));
        assert!(message.contains("unexpected_field"));
    }

    #[test]
    fn authorize_returns_capability_denied_when_capability_is_missing() {
        let path = write_policy_file(
            r#"
version = 1

[clients.local_cli]
unix_user = "dev"
allowed_capabilities = ["read_basic"]

[actions]
allowed = ["service.status"]
"#,
        );

        let engine = PolicyEngine::load_from_path(path.clone()).expect("load policy");
        remove_policy_file(&path);

        let request = Request {
            version: 1,
            request_id: "b398e7a0-ae50-4a60-aef1-8e7b38eb84cf".to_string(),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "local-cli".to_string(),
            },
            action: "service.status".to_string(),
            params: serde_json::Map::new(),
            dry_run: false,
            timeout_ms: 3000,
        };
        let metadata = actions::metadata(&request.action).expect("metadata");
        let peer = PeerCredentials {
            uid: 1000,
            gid: 1000,
            pid: 1,
            supplementary_gids: Vec::new(),
            unix_user: Some("dev".to_string()),
        };

        let error = engine
            .authorize(&request, &metadata, &peer)
            .expect_err("capability denied");
        assert_eq!(error.code, ErrorCode::CapabilityDenied);
    }

    #[test]
    fn load_rejects_allowed_request_types_for_authorization() {
        let path = write_policy_file(
            r#"
version = 1

[clients.human_cli]
unix_user = "dev"
allowed_request_types = ["human"]
allowed_capabilities = ["service_control"]

[actions]
allowed = ["service.restart"]

[service_control]
allowed_units = ["nginx.service"]
"#,
        );

        let error = PolicyEngine::load_from_path(path.clone()).expect_err("policy must fail");
        remove_policy_file(&path);

        let app_error = error
            .downcast_ref::<AppError>()
            .expect("error should be AppError");
        assert_eq!(app_error.code, ErrorCode::ValidationError);
        assert_eq!(
            app_error.message,
            "allowed_request_types is not trusted for authorization; use separate unix_user or unix_group bindings"
        );
        assert_eq!(
            app_error.details.get("client"),
            Some(&serde_json::json!("human_cli"))
        );
        assert_eq!(
            app_error.details.get("field"),
            Some(&serde_json::json!("clients.*.allowed_request_types"))
        );
    }

    #[test]
    fn authorize_ignores_requested_by_type_for_capability_decisions() {
        let path = write_policy_file(
            r#"
version = 1

[clients.local_cli]
unix_user = "dev"
allowed_capabilities = ["service_control"]

[actions]
allowed = ["service.restart"]

[service_control]
allowed_units = ["nginx.service"]
"#,
        );

        let engine = PolicyEngine::load_from_path(path.clone()).expect("load policy");
        remove_policy_file(&path);

        let metadata = actions::metadata("service.restart").expect("metadata");
        let peer = PeerCredentials {
            uid: 1000,
            gid: 1000,
            pid: 1,
            supplementary_gids: Vec::new(),
            unix_user: Some("dev".to_string()),
        };

        let human_request = Request {
            version: 1,
            request_id: "adf4db77-6f76-4ff2-aa21-3ef7f2d8ff92".to_string(),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "human-cli".to_string(),
            },
            action: "service.restart".to_string(),
            params: serde_json::Map::new(),
            dry_run: true,
            timeout_ms: 3000,
        };

        let agent_request = Request {
            version: 1,
            request_id: "5f507fc6-d61f-4c45-b40f-d9fd253d2052".to_string(),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Agent,
                id: "agentnn-adminbot-agent".to_string(),
            },
            action: "service.restart".to_string(),
            params: serde_json::Map::new(),
            dry_run: true,
            timeout_ms: 3000,
        };

        engine
            .authorize(&human_request, &metadata, &peer)
            .expect("human request should be allowed");
        engine
            .authorize(&agent_request, &metadata, &peer)
            .expect("agent request should be evaluated from the same peer identity");
    }

    #[test]
    fn authorize_ignores_requested_by_id_for_capability_decisions() {
        let path = write_policy_file(
            r#"
version = 1

[clients.local_cli]
unix_user = "dev"
allowed_capabilities = ["read_basic"]

[actions]
allowed = ["system.status"]
"#,
        );

        let engine = PolicyEngine::load_from_path(path.clone()).expect("load policy");
        remove_policy_file(&path);

        let metadata = actions::metadata("system.status").expect("metadata");
        let peer = PeerCredentials {
            uid: 1000,
            gid: 1000,
            pid: 1,
            supplementary_gids: Vec::new(),
            unix_user: Some("dev".to_string()),
        };

        let mut request = Request {
            version: 1,
            request_id: "5348f356-6c80-4c27-b93a-e4436a725663".to_string(),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "cli-a".to_string(),
            },
            action: "system.status".to_string(),
            params: serde_json::Map::new(),
            dry_run: false,
            timeout_ms: 3000,
        };

        engine
            .authorize(&request, &metadata, &peer)
            .expect("first request should be allowed");

        request.requested_by.id = "cli-b".to_string();
        engine
            .authorize(&request, &metadata, &peer)
            .expect("second request should be allowed with the same peer identity");
    }

    #[test]
    fn service_restart_cooldown_is_held_per_unit() {
        let path = write_policy_file(
            r#"
version = 1

[actions]
allowed = ["service.restart"]

[service_control]
allowed_units = ["nginx.service", "sshd.service"]
restart_cooldown_seconds = 300
max_restarts_per_hour = 3
"#,
        );

        let engine = PolicyEngine::load_from_path(path.clone()).expect("load policy");
        remove_policy_file(&path);

        engine.record_service_restart("nginx.service");

        let cooldown_error = engine
            .check_service_restart_allowed("nginx.service")
            .expect_err("nginx should be in cooldown");
        assert_eq!(cooldown_error.code, ErrorCode::CooldownActive);

        engine
            .check_service_restart_allowed("sshd.service")
            .expect("other unit should remain allowed");
    }

    #[test]
    fn service_restart_rate_limit_returns_rate_limited() {
        let path = write_policy_file(
            r#"
version = 1

[actions]
allowed = ["service.restart"]

[service_control]
allowed_units = ["nginx.service"]
restart_cooldown_seconds = 0
max_restarts_per_hour = 1
"#,
        );

        let engine = PolicyEngine::load_from_path(path.clone()).expect("load policy");
        remove_policy_file(&path);

        engine.record_service_restart("nginx.service");

        let error = engine
            .check_service_restart_allowed("nginx.service")
            .expect_err("rate limit should be enforced");
        assert_eq!(error.code, ErrorCode::RateLimited);
    }

    #[test]
    fn check_mount_allowed_rejects_mounts_outside_filesystem_whitelist() {
        let path = write_policy_file(
            r#"
version = 1

[actions]
allowed = ["disk.usage"]

[filesystem]
allowed_mounts = ["/", "/var"]
"#,
        );

        let engine = PolicyEngine::load_from_path(path.clone()).expect("load policy");
        remove_policy_file(&path);

        engine.check_mount_allowed("/").expect("root mount allowed");

        let error = engine
            .check_mount_allowed("/home")
            .expect_err("mount should be denied");
        assert_eq!(error.code, ErrorCode::PolicyDenied);
        assert_eq!(error.message, "mount not allowed by policy");
        assert_eq!(
            error.details.get("field"),
            Some(&serde_json::json!("params.mounts"))
        );
        assert_eq!(
            error.details.get("mount"),
            Some(&serde_json::json!("/home"))
        );
        assert_eq!(
            error.details.get("policy_section"),
            Some(&serde_json::json!("filesystem.allowed_mounts"))
        );
    }
}
