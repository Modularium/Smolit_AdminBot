use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::actions::ActionMetadata;
use crate::error::{AppError, AppResult, ErrorCode};
use crate::peer::{gid_from_group_name, PeerCredentials};
use crate::types::{Request, RequestOriginType};

pub const EXPECTED_POLICY_OWNER_UID: u32 = 0;
pub const POLICY_FORBIDDEN_MODE_BITS: u32 = 0o022;
#[cfg(not(test))]
pub const DEFAULT_RESTART_STATE_PATH: &str = "/var/lib/adminbot/restart_abuse_state.json";
pub const RESTART_STATE_FORBIDDEN_MODE_BITS: u32 = 0o077;
pub const RESTART_STATE_MODE: u32 = 0o600;

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
    read_rate_limit_window_ms: Option<u64>,
    read_requests_per_peer_per_window: Option<u32>,
    global_read_requests_per_window: Option<u32>,
    mutate_rate_limit_window_ms: Option<u64>,
    mutate_requests_per_peer_per_window: Option<u32>,
    global_mutate_requests_per_window: Option<u32>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Constraints {
    pub default_timeout_ms: u64,
    pub max_timeout_ms: u64,
    pub journal_limit_max: u32,
    pub process_limit_max: u32,
    pub max_parallel_mutations: u32,
    pub read_rate_limit_window_ms: u64,
    pub read_requests_per_peer_per_window: u32,
    pub global_read_requests_per_window: u32,
    pub mutate_rate_limit_window_ms: u64,
    pub mutate_requests_per_peer_per_window: u32,
    pub global_mutate_requests_per_window: u32,
}

impl Default for Constraints {
    fn default() -> Self {
        Self {
            default_timeout_ms: 3000,
            max_timeout_ms: 30_000,
            journal_limit_max: 200,
            process_limit_max: 50,
            max_parallel_mutations: 1,
            read_rate_limit_window_ms: 1_000,
            read_requests_per_peer_per_window: 30,
            global_read_requests_per_window: 120,
            mutate_rate_limit_window_ms: 60_000,
            mutate_requests_per_peer_per_window: 4,
            global_mutate_requests_per_window: 12,
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

#[derive(Debug, Default)]
struct RestartGuardState {
    tracker: CooldownTracker,
    persistence_error: Option<AppError>,
}

#[derive(Debug)]
struct RestartStateStore {
    path: PathBuf,
    expected_owner_uid: u32,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedCooldownTracker {
    #[serde(default)]
    last_restart: HashMap<String, u64>,
    #[serde(default)]
    recent_restarts: HashMap<String, Vec<u64>>,
}

#[derive(Debug)]
pub struct PolicyEngine {
    snapshot: PolicySnapshot,
    cooldowns: Mutex<RestartGuardState>,
    restart_state_store: RestartStateStore,
}

impl PolicyEngine {
    pub fn validate_policy_file(path: &std::path::Path) -> AppResult<()> {
        validate_policy_file_for_owner(path, EXPECTED_POLICY_OWNER_UID)
    }

    pub fn load_from_path(path: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        Self::load_from_paths(path.clone(), default_restart_state_path_for_policy(&path))
    }

    fn load_from_paths(
        path: PathBuf,
        restart_state_path: PathBuf,
    ) -> Result<Self, Box<dyn std::error::Error>> {
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
            read_rate_limit_window_ms: parsed
                .constraints
                .read_rate_limit_window_ms
                .unwrap_or(1_000),
            read_requests_per_peer_per_window: parsed
                .constraints
                .read_requests_per_peer_per_window
                .unwrap_or(30),
            global_read_requests_per_window: parsed
                .constraints
                .global_read_requests_per_window
                .unwrap_or(120),
            mutate_rate_limit_window_ms: parsed
                .constraints
                .mutate_rate_limit_window_ms
                .unwrap_or(60_000),
            mutate_requests_per_peer_per_window: parsed
                .constraints
                .mutate_requests_per_peer_per_window
                .unwrap_or(4),
            global_mutate_requests_per_window: parsed
                .constraints
                .global_mutate_requests_per_window
                .unwrap_or(12),
        };
        let restart_state_store =
            RestartStateStore::new(restart_state_path, current_effective_uid());
        let tracker = restart_state_store.load_or_initialize()?;

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
            cooldowns: Mutex::new(RestartGuardState {
                tracker,
                persistence_error: None,
            }),
            restart_state_store,
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
        if let Some(error) = &guard.persistence_error {
            return Err(error.clone());
        }
        let tracker = &mut guard.tracker;
        tracker.retain_recent_restarts(now);

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
        guard.tracker.last_restart.insert(unit.to_string(), now);
        guard.tracker.retain_recent_restarts(now);
        guard
            .tracker
            .recent_restarts
            .entry(unit.to_string())
            .or_default()
            .push(now);
        match self.restart_state_store.persist(&guard.tracker) {
            Ok(()) => guard.persistence_error = None,
            Err(error) => {
                guard.persistence_error = Some(
                    AppError::new(
                        ErrorCode::PreconditionFailed,
                        "restart abuse state persistence is unavailable",
                    )
                    .with_detail("path", self.restart_state_store.path.display().to_string())
                    .with_detail("source", error.to_string()),
                )
            }
        }
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

impl CooldownTracker {
    fn retain_recent_restarts(&mut self, now: SystemTime) {
        self.recent_restarts.retain(|_, entries| {
            entries.retain(|timestamp| {
                now.duration_since(*timestamp)
                    .unwrap_or(Duration::from_secs(0))
                    .as_secs()
                    < 3600
            });
            !entries.is_empty()
        });
        self.last_restart.retain(|_, timestamp| {
            now.duration_since(*timestamp)
                .unwrap_or(Duration::from_secs(0))
                .as_secs()
                < 3600
        });
    }
}

impl RestartStateStore {
    fn new(path: PathBuf, expected_owner_uid: u32) -> Self {
        Self {
            path,
            expected_owner_uid,
        }
    }

    fn load_or_initialize(&self) -> AppResult<CooldownTracker> {
        self.validate_parent_directory()?;
        if !self.path.exists() {
            let tracker = CooldownTracker::default();
            self.persist(&tracker)?;
            return Ok(tracker);
        }

        self.validate_existing_file()?;
        let content = fs::read_to_string(&self.path).map_err(|error| {
            AppError::new(
                ErrorCode::PreconditionFailed,
                "restart abuse state file is unreadable",
            )
            .with_detail("path", self.path.display().to_string())
            .with_detail("source", error.to_string())
        })?;
        let persisted: PersistedCooldownTracker =
            serde_json::from_str(&content).map_err(|error| {
                AppError::new(
                    ErrorCode::PreconditionFailed,
                    "restart abuse state file is invalid",
                )
                .with_detail("path", self.path.display().to_string())
                .with_detail("source", error.to_string())
            })?;
        let now = SystemTime::now();
        let mut tracker = persisted.into_tracker();
        tracker.retain_recent_restarts(now);
        self.persist(&tracker)?;
        Ok(tracker)
    }

    fn persist(&self, tracker: &CooldownTracker) -> AppResult<()> {
        self.validate_parent_directory()?;
        let now = SystemTime::now();
        let mut snapshot = CooldownTracker {
            last_restart: tracker.last_restart.clone(),
            recent_restarts: tracker.recent_restarts.clone(),
        };
        snapshot.retain_recent_restarts(now);
        let persisted = PersistedCooldownTracker::from_tracker(&snapshot)?;
        let serialized = serde_json::to_vec_pretty(&persisted).map_err(|error| {
            AppError::new(
                ErrorCode::PreconditionFailed,
                "restart abuse state could not be serialized",
            )
            .with_detail("path", self.path.display().to_string())
            .with_detail("source", error.to_string())
        })?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_nanos();
        let tmp_path = self.path.with_extension(format!("json.tmp-{timestamp}"));

        let write_result = (|| -> AppResult<()> {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(RESTART_STATE_MODE)
                .open(&tmp_path)
                .map_err(|error| {
                    AppError::new(
                        ErrorCode::PreconditionFailed,
                        "restart abuse state file could not be created",
                    )
                    .with_detail("path", tmp_path.display().to_string())
                    .with_detail("source", error.to_string())
                })?;
            file.write_all(&serialized).map_err(|error| {
                AppError::new(
                    ErrorCode::PreconditionFailed,
                    "restart abuse state file could not be written",
                )
                .with_detail("path", tmp_path.display().to_string())
                .with_detail("source", error.to_string())
            })?;
            file.sync_all().map_err(|error| {
                AppError::new(
                    ErrorCode::PreconditionFailed,
                    "restart abuse state file could not be synced",
                )
                .with_detail("path", tmp_path.display().to_string())
                .with_detail("source", error.to_string())
            })?;
            fs::rename(&tmp_path, &self.path).map_err(|error| {
                AppError::new(
                    ErrorCode::PreconditionFailed,
                    "restart abuse state file could not be installed atomically",
                )
                .with_detail("path", self.path.display().to_string())
                .with_detail("source", error.to_string())
            })?;
            Ok(())
        })();

        if write_result.is_err() {
            let _ = fs::remove_file(&tmp_path);
        }
        write_result?;
        self.validate_existing_file()
    }

    fn validate_parent_directory(&self) -> AppResult<()> {
        let parent = self.path.parent().ok_or_else(|| {
            AppError::new(
                ErrorCode::PreconditionFailed,
                "restart abuse state path must include a parent directory",
            )
            .with_detail("path", self.path.display().to_string())
        })?;
        let metadata = fs::symlink_metadata(parent).map_err(|error| {
            AppError::new(
                ErrorCode::PreconditionFailed,
                "restart abuse state directory is missing or unreadable",
            )
            .with_detail("path", parent.display().to_string())
            .with_detail("source", error.to_string())
        })?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(AppError::new(
                ErrorCode::PreconditionFailed,
                "restart abuse state directory must be a real directory",
            )
            .with_detail("path", parent.display().to_string()));
        }
        Ok(())
    }

    fn validate_existing_file(&self) -> AppResult<()> {
        let metadata = fs::symlink_metadata(&self.path).map_err(|error| {
            AppError::new(
                ErrorCode::PreconditionFailed,
                "restart abuse state file is missing or unreadable",
            )
            .with_detail("path", self.path.display().to_string())
            .with_detail("source", error.to_string())
        })?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(AppError::new(
                ErrorCode::PreconditionFailed,
                "restart abuse state path must be a regular file",
            )
            .with_detail("path", self.path.display().to_string()));
        }

        let owner_uid = metadata.uid();
        if owner_uid != self.expected_owner_uid {
            return Err(AppError::new(
                ErrorCode::PreconditionFailed,
                "restart abuse state file owner is not trusted",
            )
            .with_detail("path", self.path.display().to_string())
            .with_detail("owner_uid", owner_uid as u64)
            .with_detail("expected_owner_uid", self.expected_owner_uid as u64));
        }

        let mode = metadata.mode() & 0o777;
        if mode & RESTART_STATE_FORBIDDEN_MODE_BITS != 0 {
            return Err(AppError::new(
                ErrorCode::PreconditionFailed,
                "restart abuse state file mode is too permissive",
            )
            .with_detail("path", self.path.display().to_string())
            .with_detail("mode", format!("{mode:o}"))
            .with_detail(
                "forbidden_mode_bits",
                format!("{:o}", RESTART_STATE_FORBIDDEN_MODE_BITS),
            ));
        }

        Ok(())
    }
}

impl PersistedCooldownTracker {
    fn from_tracker(tracker: &CooldownTracker) -> AppResult<Self> {
        let last_restart = tracker
            .last_restart
            .iter()
            .map(|(unit, timestamp)| Ok((unit.clone(), system_time_to_unix_seconds(*timestamp)?)))
            .collect::<AppResult<HashMap<_, _>>>()?;
        let recent_restarts = tracker
            .recent_restarts
            .iter()
            .map(|(unit, timestamps)| {
                let values = timestamps
                    .iter()
                    .map(|timestamp| system_time_to_unix_seconds(*timestamp))
                    .collect::<AppResult<Vec<_>>>()?;
                Ok((unit.clone(), values))
            })
            .collect::<AppResult<HashMap<_, _>>>()?;

        Ok(Self {
            last_restart,
            recent_restarts,
        })
    }

    fn into_tracker(self) -> CooldownTracker {
        CooldownTracker {
            last_restart: self
                .last_restart
                .into_iter()
                .map(|(unit, seconds)| (unit, UNIX_EPOCH + Duration::from_secs(seconds)))
                .collect(),
            recent_restarts: self
                .recent_restarts
                .into_iter()
                .map(|(unit, timestamps)| {
                    (
                        unit,
                        timestamps
                            .into_iter()
                            .map(|seconds| UNIX_EPOCH + Duration::from_secs(seconds))
                            .collect(),
                    )
                })
                .collect(),
        }
    }
}

fn current_effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

#[cfg(not(test))]
fn default_restart_state_path_for_policy(_policy_path: &PathBuf) -> PathBuf {
    PathBuf::from(DEFAULT_RESTART_STATE_PATH)
}

#[cfg(test)]
fn default_restart_state_path_for_policy(policy_path: &PathBuf) -> PathBuf {
    policy_path.with_extension("restart-state.json")
}

fn system_time_to_unix_seconds(timestamp: SystemTime) -> AppResult<u64> {
    timestamp
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| {
            AppError::new(
                ErrorCode::PreconditionFailed,
                "restart abuse timestamp predates unix epoch",
            )
            .with_detail("source", error.to_string())
        })
}

fn validate_policy_file_for_owner(path: &std::path::Path, expected_uid: u32) -> AppResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AppError::new(
            ErrorCode::PreconditionFailed,
            "policy file is missing or unreadable",
        )
        .with_detail("path", path.display().to_string())
        .with_detail("source", error.to_string())
    })?;

    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(AppError::new(
            ErrorCode::PreconditionFailed,
            "policy path must be a regular file",
        )
        .with_detail("path", path.display().to_string()));
    }

    let owner_uid = metadata.uid();
    if owner_uid != expected_uid {
        return Err(AppError::new(
            ErrorCode::PreconditionFailed,
            "policy file owner is not trusted",
        )
        .with_detail("path", path.display().to_string())
        .with_detail("owner_uid", owner_uid as u64)
        .with_detail("expected_owner_uid", expected_uid as u64));
    }

    let mode = metadata.mode() & 0o777;
    if mode & POLICY_FORBIDDEN_MODE_BITS != 0 {
        return Err(AppError::new(
            ErrorCode::PreconditionFailed,
            "policy file mode is too permissive",
        )
        .with_detail("path", path.display().to_string())
        .with_detail("mode", format!("{mode:o}"))
        .with_detail(
            "forbidden_mode_bits",
            format!("{:o}", POLICY_FORBIDDEN_MODE_BITS),
        ));
    }

    Ok(())
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
    use std::os::unix::fs::PermissionsExt;
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
        let _ = fs::remove_file(path.with_extension("restart-state.json"));
    }

    fn current_uid() -> u32 {
        unsafe { libc::geteuid() }
    }

    fn write_restart_state_file(contents: &str) -> PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "adminbot-restart-state-test-{}-{timestamp}.json",
            process::id()
        ));
        fs::write(&path, contents).expect("write restart state file");
        path
    }

    fn remove_restart_state_file(path: &PathBuf) {
        let _ = fs::remove_file(path);
    }

    fn load_policy_engine_with_restart_state(
        policy_path: PathBuf,
        restart_state_path: PathBuf,
    ) -> Result<PolicyEngine, Box<dyn std::error::Error>> {
        PolicyEngine::load_from_paths(policy_path, restart_state_path)
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
        assert_eq!(engine.snapshot.constraints.read_rate_limit_window_ms, 1_000);
        assert_eq!(
            engine.snapshot.constraints.read_requests_per_peer_per_window,
            30
        );
        assert_eq!(engine.snapshot.constraints.global_read_requests_per_window, 120);
        assert_eq!(engine.snapshot.constraints.mutate_rate_limit_window_ms, 60_000);
        assert_eq!(
            engine.snapshot.constraints.mutate_requests_per_peer_per_window,
            4
        );
        assert_eq!(
            engine.snapshot.constraints.global_mutate_requests_per_window,
            12
        );
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
    fn policy_file_validation_rejects_world_writable_mode() {
        let path = write_policy_file(
            r#"
version = 1

[actions]
allowed = ["system.status"]
"#,
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).expect("chmod");

        let error = validate_policy_file_for_owner(&path, current_uid())
            .expect_err("world-writable policy must fail");
        remove_policy_file(&path);

        assert_eq!(error.code, ErrorCode::PreconditionFailed);
        assert_eq!(error.message, "policy file mode is too permissive");
    }

    #[test]
    fn policy_file_validation_rejects_unexpected_owner() {
        let path = write_policy_file(
            r#"
version = 1

[actions]
allowed = ["system.status"]
"#,
        );

        let expected_uid = current_uid().saturating_add(1);
        let error =
            validate_policy_file_for_owner(&path, expected_uid).expect_err("wrong owner must fail");
        remove_policy_file(&path);

        assert_eq!(error.code, ErrorCode::PreconditionFailed);
        assert_eq!(error.message, "policy file owner is not trusted");
        assert_eq!(
            error.details.get("expected_owner_uid"),
            Some(&serde_json::json!(expected_uid as u64))
        );
    }

    #[test]
    fn policy_file_validation_accepts_trusted_owner_and_mode() {
        let path = write_policy_file(
            r#"
version = 1

[actions]
allowed = ["system.status"]
"#,
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");

        validate_policy_file_for_owner(&path, current_uid()).expect("trusted file must pass");
        remove_policy_file(&path);
    }

    #[test]
    fn restart_counters_persist_across_reload() {
        let policy_path = write_policy_file(
            r#"
version = 1

[actions]
allowed = ["service.restart"]

[service_control]
allowed_units = ["nginx.service"]
restart_cooldown_seconds = 300
max_restarts_per_hour = 3
"#,
        );
        let restart_state_path = write_restart_state_file("{}");
        fs::set_permissions(
            &restart_state_path,
            fs::Permissions::from_mode(RESTART_STATE_MODE),
        )
        .expect("chmod restart state");

        let engine =
            load_policy_engine_with_restart_state(policy_path.clone(), restart_state_path.clone())
                .expect("load policy with restart state");
        engine.record_service_restart("nginx.service");
        drop(engine);

        let reloaded =
            load_policy_engine_with_restart_state(policy_path.clone(), restart_state_path.clone())
                .expect("reload policy with restart state");
        let error = reloaded
            .check_service_restart_allowed("nginx.service")
            .expect_err("restart cooldown must survive reload");

        remove_policy_file(&policy_path);
        remove_restart_state_file(&restart_state_path);

        assert_eq!(error.code, ErrorCode::CooldownActive);
        assert_eq!(error.message, "restart cooldown is active");
    }

    #[test]
    fn load_rejects_restart_state_file_with_world_writable_mode() {
        let policy_path = write_policy_file(
            r#"
version = 1

[actions]
allowed = ["service.restart"]

[service_control]
allowed_units = ["nginx.service"]
"#,
        );
        let restart_state_path = write_restart_state_file("{}");
        fs::set_permissions(&restart_state_path, fs::Permissions::from_mode(0o666))
            .expect("chmod restart state");

        let error =
            load_policy_engine_with_restart_state(policy_path.clone(), restart_state_path.clone())
                .expect_err("world-writable restart state must fail");

        remove_policy_file(&policy_path);
        remove_restart_state_file(&restart_state_path);

        let app_error = error
            .downcast_ref::<AppError>()
            .expect("error should be AppError");
        assert_eq!(app_error.code, ErrorCode::PreconditionFailed);
        assert_eq!(
            app_error.message,
            "restart abuse state file mode is too permissive"
        );
    }

    #[test]
    fn persist_failure_blocks_future_restarts_fail_closed() {
        let policy_path = write_policy_file(
            r#"
version = 1

[actions]
allowed = ["service.restart"]

[service_control]
allowed_units = ["nginx.service"]
restart_cooldown_seconds = 0
max_restarts_per_hour = 3
"#,
        );
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        let restart_state_dir = std::env::temp_dir().join(format!(
            "adminbot-restart-state-dir-{}-{timestamp}",
            process::id()
        ));
        fs::create_dir_all(&restart_state_dir).expect("create restart state dir");
        let restart_state_path = restart_state_dir.join("restart_abuse_state.json");

        let engine =
            load_policy_engine_with_restart_state(policy_path.clone(), restart_state_path.clone())
                .expect("load policy with restart state");

        fs::set_permissions(&restart_state_dir, fs::Permissions::from_mode(0o500))
            .expect("chmod dir read-only");
        engine.record_service_restart("nginx.service");
        let error = engine
            .check_service_restart_allowed("nginx.service")
            .expect_err("restart checks must fail closed when persistence breaks");

        fs::set_permissions(&restart_state_dir, fs::Permissions::from_mode(0o700))
            .expect("restore dir permissions");
        remove_policy_file(&policy_path);
        remove_restart_state_file(&restart_state_path);
        let _ = fs::remove_dir(&restart_state_dir);

        assert_eq!(error.code, ErrorCode::PreconditionFailed);
        assert_eq!(
            error.message,
            "restart abuse state persistence is unavailable"
        );
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
