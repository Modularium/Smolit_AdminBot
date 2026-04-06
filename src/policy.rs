use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use serde::Deserialize;

use crate::actions::ActionMetadata;
use crate::error::{AppError, AppResult, ErrorCode};
use crate::peer::{gid_from_group_name, PeerCredentials};
use crate::types::Request;

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
        for (_, client) in parsed.clients {
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

        let capabilities = self.capabilities_for_peer(peer)?;
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
        if !self.snapshot.service_allowed_units.contains(unit) {
            return Err(
                AppError::new(ErrorCode::PolicyDenied, "unit not allowed by policy")
                    .with_detail("unit", unit.to_string()),
            );
        }

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

    fn capabilities_for_peer(&self, peer: &PeerCredentials) -> AppResult<HashSet<Capability>> {
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
