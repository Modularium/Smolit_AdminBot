use std::collections::{BTreeSet, HashMap};
use std::ffi::CString;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::OwnedObjectPath;

use crate::app::App;
use crate::error::{AppError, AppResult, ErrorCode};
use crate::policy::Capability;
use crate::types::Request;

#[derive(Debug, Clone, Copy)]
pub enum RiskLevel {
    R0,
    R1,
    R2,
}

#[derive(Debug, Clone, Copy)]
pub enum PrivilegeRequirement {
    None,
    Elevated,
    PrivilegedBackend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionHandler {
    SystemStatus,
    SystemHealth,
    ResourceSnapshot,
    DiskUsage,
    NetworkInterfaceStatus,
    ServiceStatus,
    JournalQuery,
    ProcessSnapshot,
    ServiceRestart,
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct ActionMetadata {
    pub name: &'static str,
    pub required_capability: Capability,
    pub risk: RiskLevel,
    pub privilege_requirement: PrivilegeRequirement,
    pub handler: ActionHandler,
}

const ACTIONS: &[ActionMetadata] = &[
    ActionMetadata {
        name: "system.status",
        required_capability: Capability::ReadBasic,
        risk: RiskLevel::R0,
        privilege_requirement: PrivilegeRequirement::None,
        handler: ActionHandler::SystemStatus,
    },
    ActionMetadata {
        name: "system.health",
        required_capability: Capability::ReadBasic,
        risk: RiskLevel::R0,
        privilege_requirement: PrivilegeRequirement::None,
        handler: ActionHandler::SystemHealth,
    },
    ActionMetadata {
        name: "resource.snapshot",
        required_capability: Capability::ReadBasic,
        risk: RiskLevel::R0,
        privilege_requirement: PrivilegeRequirement::None,
        handler: ActionHandler::ResourceSnapshot,
    },
    ActionMetadata {
        name: "disk.usage",
        required_capability: Capability::ReadBasic,
        risk: RiskLevel::R0,
        privilege_requirement: PrivilegeRequirement::None,
        handler: ActionHandler::DiskUsage,
    },
    ActionMetadata {
        name: "network.interface_status",
        required_capability: Capability::ReadBasic,
        risk: RiskLevel::R0,
        privilege_requirement: PrivilegeRequirement::None,
        handler: ActionHandler::NetworkInterfaceStatus,
    },
    ActionMetadata {
        name: "service.status",
        required_capability: Capability::ServiceRead,
        risk: RiskLevel::R1,
        privilege_requirement: PrivilegeRequirement::Elevated,
        handler: ActionHandler::ServiceStatus,
    },
    ActionMetadata {
        name: "journal.query",
        required_capability: Capability::ReadSensitive,
        risk: RiskLevel::R1,
        privilege_requirement: PrivilegeRequirement::Elevated,
        handler: ActionHandler::JournalQuery,
    },
    ActionMetadata {
        name: "process.snapshot",
        required_capability: Capability::ReadSensitive,
        risk: RiskLevel::R1,
        privilege_requirement: PrivilegeRequirement::Elevated,
        handler: ActionHandler::ProcessSnapshot,
    },
    ActionMetadata {
        name: "service.restart",
        required_capability: Capability::ServiceControl,
        risk: RiskLevel::R2,
        privilege_requirement: PrivilegeRequirement::PrivilegedBackend,
        handler: ActionHandler::ServiceRestart,
    },
];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum DetailLevel {
    Basic,
    Extended,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SystemStatusParams {
    detail: Option<DetailLevel>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum HealthCheckName {
    Cpu,
    Memory,
    DiskRoot,
    Swap,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SystemHealthParams {
    include_checks: Option<Vec<HealthCheckName>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum ResourceKind {
    Cpu,
    Memory,
    Swap,
    Disk,
    Net,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceSnapshotParams {
    include: Option<Vec<ResourceKind>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskUsageParams {
    mounts: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceStatusParams {
    unit: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum PriorityMin {
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalQueryParams {
    unit: Option<String>,
    priority_min: Option<PriorityMin>,
    since_seconds: Option<u64>,
    limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum ProcessTopBy {
    Cpu,
    Memory,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessSnapshotParams {
    top_by: ProcessTopBy,
    limit: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum ServiceRestartMode {
    Safe,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceRestartParams {
    unit: String,
    mode: ServiceRestartMode,
    reason: String,
}

#[derive(Debug)]
struct ServiceStatusView {
    unit: String,
    active_state: String,
    sub_state: String,
    load_state: String,
    unit_file_state: String,
}

#[derive(Debug, Clone)]
struct ProcessSnapshotEntry {
    pid: u32,
    name: String,
    cpu_percent: f64,
    memory_percent: f64,
    started_at: String,
}

#[derive(Debug)]
struct ProcessSystemContext {
    uptime_secs: f64,
    total_memory_bytes: u64,
    boot_time_unix_secs: i64,
    clock_ticks_per_second: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JournalPriority {
    Emergency,
    Alert,
    Critical,
    Error,
    Warning,
    Notice,
    Info,
    Debug,
}

impl JournalPriority {
    fn from_raw(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Emergency),
            1 => Some(Self::Alert),
            2 => Some(Self::Critical),
            3 => Some(Self::Error),
            4 => Some(Self::Warning),
            5 => Some(Self::Notice),
            6 => Some(Self::Info),
            7 => Some(Self::Debug),
            _ => None,
        }
    }

    fn code(self) -> u8 {
        match self {
            Self::Emergency => 0,
            Self::Alert => 1,
            Self::Critical => 2,
            Self::Error => 3,
            Self::Warning => 4,
            Self::Notice => 5,
            Self::Info => 6,
            Self::Debug => 7,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Emergency => "emergency",
            Self::Alert => "alert",
            Self::Critical => "critical",
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Notice => "notice",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }
}

#[derive(Debug, Clone)]
struct JournalRecord {
    timestamp_usec: u64,
    unit: String,
    priority: JournalPriority,
    message: String,
}

#[repr(C)]
struct SdJournal {
    _private: [u8; 0],
}

#[link(name = "systemd")]
unsafe extern "C" {
    fn sd_journal_open(ret: *mut *mut SdJournal, flags: libc::c_int) -> libc::c_int;
    fn sd_journal_close(j: *mut SdJournal);
    fn sd_journal_seek_tail(j: *mut SdJournal) -> libc::c_int;
    fn sd_journal_previous(j: *mut SdJournal) -> libc::c_int;
    fn sd_journal_get_realtime_usec(j: *mut SdJournal, ret: *mut u64) -> libc::c_int;
    fn sd_journal_get_data(
        j: *mut SdJournal,
        field: *const libc::c_char,
        data: *mut *const libc::c_void,
        length: *mut usize,
    ) -> libc::c_int;
    fn sd_journal_add_match(
        j: *mut SdJournal,
        data: *const libc::c_void,
        size: usize,
    ) -> libc::c_int;
}

struct JournalHandle {
    raw: *mut SdJournal,
}

impl Drop for JournalHandle {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { sd_journal_close(self.raw) };
        }
    }
}

pub fn metadata(action: &str) -> Option<ActionMetadata> {
    ACTIONS.iter().find(|entry| entry.name == action).copied()
}

pub fn validate_request_shape(request: &Request, app: &App) -> AppResult<ActionMetadata> {
    if request.version != 1 {
        return Err(AppError::new(
            ErrorCode::UnsupportedVersion,
            "unsupported protocol version",
        )
        .with_detail("version", request.version as u64));
    }

    Uuid::parse_str(&request.request_id).map_err(|_| {
        AppError::new(
            ErrorCode::ValidationError,
            "request_id must be a valid UUID",
        )
    })?;

    let metadata = metadata(&request.action).ok_or_else(|| {
        AppError::new(ErrorCode::ValidationError, "unknown action")
            .with_detail("action", request.action.clone())
    })?;

    if request.timeout_ms == 0 || request.timeout_ms > app.policy().constraints().max_timeout_ms {
        return Err(AppError::new(
            ErrorCode::ValidationError,
            "timeout_ms is out of allowed range",
        )
        .with_detail("timeout_ms", request.timeout_ms));
    }

    validate_params(&request.action, &request.params_value(), app)?;
    Ok(metadata)
}

pub fn execute(app: &App, request: &Request) -> AppResult<Value> {
    let metadata = metadata(&request.action)
        .ok_or_else(|| AppError::new(ErrorCode::ValidationError, "unknown action"))?;
    execute_handler(app, request, metadata.handler)
}

fn execute_handler(app: &App, request: &Request, handler: ActionHandler) -> AppResult<Value> {
    match handler {
        ActionHandler::SystemStatus => system_status(request),
        ActionHandler::SystemHealth => system_health(),
        ActionHandler::ResourceSnapshot => resource_snapshot(),
        ActionHandler::DiskUsage => disk_usage(request),
        ActionHandler::NetworkInterfaceStatus => network_interface_status(request),
        ActionHandler::ServiceStatus => service_status(request),
        ActionHandler::JournalQuery => journal_query(app, request),
        ActionHandler::ProcessSnapshot => process_snapshot(request),
        ActionHandler::ServiceRestart => service_restart(app, request),
    }
}

fn validate_params(action: &str, params: &Value, app: &App) -> AppResult<()> {
    match action {
        "system.status" => {
            let _ = from_params::<SystemStatusParams>(params)?;
        }
        "system.health" => {
            let parsed = from_params::<SystemHealthParams>(params)?;
            if let Some(checks) = parsed.include_checks {
                if checks.len() > 8 {
                    return Err(AppError::new(
                        ErrorCode::ValidationError,
                        "include_checks exceeds maximum length",
                    ));
                }
            }
        }
        "resource.snapshot" => {
            let parsed = from_params::<ResourceSnapshotParams>(params)?;
            if let Some(include) = parsed.include {
                if include.len() > 8 {
                    return Err(AppError::new(
                        ErrorCode::ValidationError,
                        "include exceeds maximum length",
                    ));
                }
            }
        }
        "disk.usage" => {
            let parsed = from_params::<DiskUsageParams>(params)?;
            if parsed.mounts.is_empty() || parsed.mounts.len() > 16 {
                return Err(AppError::new(
                    ErrorCode::ValidationError,
                    "mounts must contain between 1 and 16 entries",
                ));
            }
            for mount in parsed.mounts {
                validate_mount(&mount)?;
                app.policy().check_mount_allowed(&mount)?;
            }
        }
        "service.status" => {
            let parsed = from_params::<ServiceStatusParams>(params)?;
            validate_unit(&parsed.unit)?;
        }
        "journal.query" => {
            let parsed = from_params::<JournalQueryParams>(params)?;
            if let Some(unit) = parsed.unit {
                validate_unit(&unit)?;
                app.policy().check_service_unit_allowed(&unit)?;
            }
            let _ = parsed.priority_min;
            let limit = parsed.limit.unwrap_or(50);
            if limit == 0 || limit > app.policy().constraints().journal_limit_max {
                return Err(AppError::new(
                    ErrorCode::ValidationError,
                    "journal limit exceeds policy maximum",
                ));
            }
            if parsed.since_seconds.unwrap_or(3600) > 86_400 {
                return Err(AppError::new(
                    ErrorCode::ValidationError,
                    "since_seconds exceeds maximum range",
                ));
            }
        }
        "process.snapshot" => {
            let parsed = from_params::<ProcessSnapshotParams>(params)?;
            let _ = parsed.top_by;
            if parsed.limit == 0 || parsed.limit > app.policy().constraints().process_limit_max {
                return Err(AppError::new(
                    ErrorCode::ValidationError,
                    "process limit exceeds policy maximum",
                ));
            }
        }
        "network.interface_status" => {
            let interfaces = extract_interface_names(params)?;
            if interfaces.is_empty() || interfaces.len() > 16 {
                return Err(AppError::new(
                    ErrorCode::ValidationError,
                    "interfaces must contain between 1 and 16 entries",
                ));
            }
            for interface in interfaces {
                validate_interface_name(&interface)?;
            }
        }
        "service.restart" => {
            let parsed = from_params::<ServiceRestartParams>(params)?;
            validate_unit(&parsed.unit)?;
            if parsed.reason.trim().is_empty() {
                return Err(AppError::new(
                    ErrorCode::ValidationError,
                    "restart reason must not be empty",
                ));
            }
        }
        _ => return Err(AppError::new(ErrorCode::ValidationError, "unknown action")),
    }

    Ok(())
}

fn system_status(request: &Request) -> AppResult<Value> {
    let params = from_params::<SystemStatusParams>(&request.params_value())?;
    let hostname = fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| fs::read_to_string("/etc/hostname"))
        .map_err(|_| AppError::new(ErrorCode::ExecutionFailed, "unable to read hostname"))?
        .trim()
        .to_string();
    let kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map_err(|_| AppError::new(ErrorCode::ExecutionFailed, "unable to read kernel version"))?
        .trim()
        .to_string();
    let uptime = read_uptime_seconds()?;
    let load_average = read_load_average()?;
    let memory = read_memory_stats()?;

    let mut result = json!({
        "hostname": hostname,
        "kernel": kernel,
        "uptime_seconds": uptime,
        "load_average": load_average,
        "memory": memory,
    });

    if matches!(params.detail, Some(DetailLevel::Extended)) {
        let cpu_count = std::thread::available_parallelism()
            .map(|value| value.get())
            .unwrap_or(1);
        if let Some(object) = result.as_object_mut() {
            object.insert("cpu_count".to_string(), json!(cpu_count));
        }
    }

    Ok(result)
}

fn system_health() -> AppResult<Value> {
    let load = read_load_average()?;
    let memory = read_memory_stats()?;
    let disk = mount_usage("/")?;
    let swap_used = memory["swap_used_bytes"].as_u64().unwrap_or(0);
    let swap_total = memory["swap_total_bytes"].as_u64().unwrap_or(0);

    let cpu_status = if load[0] > 8.0 {
        "critical"
    } else if load[0] > 4.0 {
        "warning"
    } else {
        "ok"
    };
    let memory_ratio = ratio(
        memory["used_bytes"].as_u64().unwrap_or(0),
        memory["total_bytes"].as_u64().unwrap_or(0),
    );
    let memory_status = if memory_ratio > 0.95 {
        "critical"
    } else if memory_ratio > 0.85 {
        "warning"
    } else {
        "ok"
    };
    let disk_status = if disk.percent_used > 95.0 {
        "critical"
    } else if disk.percent_used > 85.0 {
        "warning"
    } else {
        "ok"
    };
    let swap_ratio = ratio(swap_used, swap_total);
    let swap_status = if swap_total == 0 {
        "ok"
    } else if swap_ratio > 0.80 {
        "warning"
    } else {
        "ok"
    };

    let statuses = [cpu_status, memory_status, disk_status, swap_status];
    let overall_status = if statuses.contains(&"critical") {
        "critical"
    } else if statuses.contains(&"warning") {
        "degraded"
    } else {
        "ok"
    };

    Ok(json!({
        "overall_status": overall_status,
        "checks": [
            {"name": "cpu", "status": cpu_status, "current": load[0], "threshold": 4.0},
            {"name": "memory", "status": memory_status, "current": memory_ratio, "threshold": 0.85},
            {"name": "disk_root", "status": disk_status, "current": disk.percent_used / 100.0, "threshold": 0.85},
            {"name": "swap", "status": swap_status, "current": swap_ratio, "threshold": 0.80}
        ],
        "warnings": []
    }))
}

fn resource_snapshot() -> AppResult<Value> {
    let memory = read_memory_stats()?;
    let load_average = read_load_average()?;
    let root_disk = mount_usage("/")?;
    let net = read_network_totals()?;

    Ok(json!({
        "timestamp": now_rfc3339()?,
        "cpu": {
            "load_average": load_average
        },
        "memory": {
            "total_bytes": memory["total_bytes"],
            "used_bytes": memory["used_bytes"],
            "available_bytes": memory["available_bytes"]
        },
        "swap": {
            "total_bytes": memory["swap_total_bytes"],
            "used_bytes": memory["swap_used_bytes"]
        },
        "disk": {
            "root": {
                "total_bytes": root_disk.total_bytes,
                "used_bytes": root_disk.used_bytes,
                "available_bytes": root_disk.available_bytes,
                "percent_used": root_disk.percent_used
            }
        },
        "net": net
    }))
}

fn disk_usage(request: &Request) -> AppResult<Value> {
    let params = from_params::<DiskUsageParams>(&request.params_value())?;
    let mut mounts = Vec::new();
    for mount in params.mounts {
        let usage = mount_usage(&mount)?;
        mounts.push(json!({
            "path": usage.path,
            "total_bytes": usage.total_bytes,
            "used_bytes": usage.used_bytes,
            "available_bytes": usage.available_bytes,
            "percent_used": usage.percent_used
        }));
    }
    Ok(json!({ "mounts": mounts }))
}

fn network_interface_status(request: &Request) -> AppResult<Value> {
    let interfaces = extract_interface_names(&request.params_value())?;
    let stats = read_network_device_stats()?;
    let mut result = Vec::new();

    for interface in interfaces {
        let addresses = read_interface_addresses(&interface)?;
        let (rx_bytes, tx_bytes) = stats.get(&interface).copied().unwrap_or((0, 0));
        result.push(json!({
            "name": interface,
            "state": read_interface_state(&interface),
            "addresses": addresses,
            "rx_bytes": rx_bytes,
            "tx_bytes": tx_bytes
        }));
    }

    Ok(json!({ "interfaces": result }))
}

fn service_status(request: &Request) -> AppResult<Value> {
    let params = from_params::<ServiceStatusParams>(&request.params_value())?;
    let status = fetch_service_status(&params.unit)?;
    Ok(json!({
        "unit": status.unit,
        "active_state": status.active_state,
        "sub_state": status.sub_state,
        "load_state": status.load_state,
        "unit_file_state": status.unit_file_state,
    }))
}

fn journal_query(app: &App, request: &Request) -> AppResult<Value> {
    let params = from_params::<JournalQueryParams>(&request.params_value())?;
    if let Some(unit) = params.unit.as_deref() {
        app.policy().check_service_unit_allowed(unit)?;
    }

    let cutoff_usec = cutoff_realtime_usec(params.since_seconds.unwrap_or(3600))?;
    let mut journal = JournalHandle::open()?;
    if let Some(unit) = params.unit.as_deref() {
        journal.add_match(&format!("_SYSTEMD_UNIT={unit}"))?;
    }
    journal.seek_tail()?;

    let limit = params.limit.unwrap_or(50) as usize;
    let mut entries = Vec::new();
    let mut truncated = false;

    while journal.previous()? {
        let Some(record) = journal.read_record()? else {
            continue;
        };
        if record.timestamp_usec < cutoff_usec {
            break;
        }
        if !priority_matches_filter(record.priority, params.priority_min.as_ref()) {
            continue;
        }
        if entries.len() >= limit {
            truncated = true;
            break;
        }
        entries.push(journal_record_to_value(&record)?);
    }

    entries.reverse();
    Ok(json!({
        "entries": entries,
        "truncated": truncated
    }))
}

fn process_snapshot(request: &Request) -> AppResult<Value> {
    let params = from_params::<ProcessSnapshotParams>(&request.params_value())?;
    let context = read_process_system_context()?;
    let mut processes = collect_process_snapshots(&context)?;

    processes.sort_by(|left, right| {
        let ordering = match params.top_by {
            ProcessTopBy::Cpu => right
                .cpu_percent
                .partial_cmp(&left.cpu_percent)
                .unwrap_or(std::cmp::Ordering::Equal),
            ProcessTopBy::Memory => right
                .memory_percent
                .partial_cmp(&left.memory_percent)
                .unwrap_or(std::cmp::Ordering::Equal),
        };

        ordering
            .then_with(|| {
                right
                    .memory_percent
                    .partial_cmp(&left.memory_percent)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| {
                right
                    .cpu_percent
                    .partial_cmp(&left.cpu_percent)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| left.pid.cmp(&right.pid))
    });

    processes.truncate(params.limit as usize);
    let processes = processes
        .into_iter()
        .map(|entry| {
            json!({
                "pid": entry.pid,
                "name": entry.name,
                "cpu_percent": entry.cpu_percent,
                "memory_percent": entry.memory_percent,
                "started_at": entry.started_at
            })
        })
        .collect::<Vec<_>>();

    Ok(json!({ "processes": processes }))
}

fn service_restart(app: &App, request: &Request) -> AppResult<Value> {
    let params = from_params::<ServiceRestartParams>(&request.params_value())?;
    app.policy().check_service_restart_allowed(&params.unit)?;
    let pre_state = fetch_service_status(&params.unit)?;
    if pre_state.load_state == "not-found" {
        return Err(
            AppError::new(ErrorCode::PreconditionFailed, "service is not loaded")
                .with_detail("unit", params.unit.clone()),
        );
    }

    if request.dry_run {
        return Ok(json!({
            "unit": params.unit,
            "mode": restart_mode_name(&params.mode),
            "pre_state": {
                "active_state": pre_state.active_state,
                "sub_state": pre_state.sub_state,
                "load_state": pre_state.load_state,
                "unit_file_state": pre_state.unit_file_state
            },
            "would_restart": true
        }));
    }

    let connection = Connection::system().map_err(|error| {
        AppError::new(
            ErrorCode::BackendUnavailable,
            "unable to connect to system bus",
        )
        .with_detail("source", error.to_string())
        .retryable(true)
    })?;

    let proxy = Proxy::new(
        &connection,
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
    )
    .map_err(|error| {
        AppError::new(
            ErrorCode::BackendUnavailable,
            "unable to create systemd manager proxy",
        )
        .with_detail("source", error.to_string())
        .retryable(true)
    })?;

    let job_path: OwnedObjectPath = proxy
        .call("RestartUnit", &(params.unit.as_str(), "replace"))
        .map_err(|error| {
            AppError::new(ErrorCode::ExecutionFailed, "systemd restart failed")
                .with_detail("source", error.to_string())
        })?;

    app.policy().record_service_restart(&params.unit);
    let post_state = poll_post_restart_status(&params.unit, request.timeout_ms)?;

    Ok(json!({
        "unit": params.unit,
        "mode": restart_mode_name(&params.mode),
        "job_object_path": job_path.to_string(),
        "pre_state": {
            "active_state": pre_state.active_state,
            "sub_state": pre_state.sub_state,
            "load_state": pre_state.load_state,
            "unit_file_state": pre_state.unit_file_state
        },
        "post_state": {
            "active_state": post_state.active_state,
            "sub_state": post_state.sub_state,
            "load_state": post_state.load_state,
            "unit_file_state": post_state.unit_file_state
        }
    }))
}

fn fetch_service_status(unit: &str) -> AppResult<ServiceStatusView> {
    validate_unit(unit)?;

    let connection = Connection::system().map_err(|error| {
        AppError::new(
            ErrorCode::BackendUnavailable,
            "unable to connect to system bus",
        )
        .with_detail("source", error.to_string())
        .retryable(true)
    })?;

    let manager = Proxy::new(
        &connection,
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
    )
    .map_err(|error| {
        AppError::new(
            ErrorCode::BackendUnavailable,
            "unable to create systemd manager proxy",
        )
        .with_detail("source", error.to_string())
        .retryable(true)
    })?;

    let path: OwnedObjectPath = manager.call("LoadUnit", &(unit,)).map_err(|error| {
        AppError::new(ErrorCode::ExecutionFailed, "unable to load unit")
            .with_detail("source", error.to_string())
    })?;

    let unit_proxy = Proxy::new(
        &connection,
        "org.freedesktop.systemd1",
        path.as_str(),
        "org.freedesktop.systemd1.Unit",
    )
    .map_err(|error| {
        AppError::new(ErrorCode::BackendUnavailable, "unable to create unit proxy")
            .with_detail("source", error.to_string())
            .retryable(true)
    })?;

    let active_state = unit_proxy
        .get_property::<String>("ActiveState")
        .map_err(|error| property_error("ActiveState", error.to_string()))?;
    let sub_state = unit_proxy
        .get_property::<String>("SubState")
        .map_err(|error| property_error("SubState", error.to_string()))?;
    let load_state = unit_proxy
        .get_property::<String>("LoadState")
        .map_err(|error| property_error("LoadState", error.to_string()))?;
    let unit_file_state = unit_proxy
        .get_property::<String>("UnitFileState")
        .unwrap_or_else(|_| "unknown".to_string());

    Ok(ServiceStatusView {
        unit: unit.to_string(),
        active_state,
        sub_state,
        load_state,
        unit_file_state,
    })
}

fn poll_post_restart_status(unit: &str, timeout_ms: u64) -> AppResult<ServiceStatusView> {
    let poll_deadline =
        std::time::Instant::now() + Duration::from_millis(timeout_ms.min(5_000).max(250));

    loop {
        let status = fetch_service_status(unit)?;
        if status.active_state != "activating" {
            return Ok(status);
        }

        if std::time::Instant::now() >= poll_deadline {
            return Err(AppError::new(
                ErrorCode::Timeout,
                "post-restart status check timed out",
            ));
        }

        thread::sleep(Duration::from_millis(250));
    }
}

fn property_error(property: &str, source: String) -> AppError {
    AppError::new(
        ErrorCode::ExecutionFailed,
        format!("unable to read systemd property {property}"),
    )
    .with_detail("property", property.to_string())
    .with_detail("source", source)
}

impl JournalHandle {
    fn open() -> AppResult<Self> {
        let mut raw = std::ptr::null_mut();
        let status = unsafe { sd_journal_open(&mut raw, 0) };
        if status < 0 || raw.is_null() {
            return Err(AppError::new(
                ErrorCode::BackendUnavailable,
                "unable to open journald reader",
            )
            .with_detail("status", status as i64)
            .retryable(true));
        }

        Ok(Self { raw })
    }

    fn add_match(&mut self, expression: &str) -> AppResult<()> {
        let data = expression.as_bytes();
        let status = unsafe {
            sd_journal_add_match(self.raw, data.as_ptr().cast::<libc::c_void>(), data.len())
        };
        if status < 0 {
            return Err(AppError::new(
                ErrorCode::ExecutionFailed,
                "unable to apply journal filter",
            )
            .with_detail("filter", expression.to_string())
            .with_detail("status", status as i64));
        }

        Ok(())
    }

    fn seek_tail(&mut self) -> AppResult<()> {
        let status = unsafe { sd_journal_seek_tail(self.raw) };
        if status < 0 {
            return Err(AppError::new(
                ErrorCode::BackendUnavailable,
                "unable to seek journald tail",
            )
            .with_detail("status", status as i64)
            .retryable(true));
        }

        Ok(())
    }

    fn previous(&mut self) -> AppResult<bool> {
        let status = unsafe { sd_journal_previous(self.raw) };
        if status < 0 {
            return Err(AppError::new(
                ErrorCode::ExecutionFailed,
                "unable to read previous journal entry",
            )
            .with_detail("status", status as i64));
        }

        Ok(status > 0)
    }

    fn read_record(&mut self) -> AppResult<Option<JournalRecord>> {
        let timestamp_usec = self.read_timestamp_usec()?;
        let Some(unit) = self.read_field("_SYSTEMD_UNIT")? else {
            return Ok(None);
        };
        let Some(priority) = self.read_priority()? else {
            return Ok(None);
        };
        let Some(message) = self.read_field("MESSAGE")? else {
            return Ok(None);
        };

        Ok(Some(JournalRecord {
            timestamp_usec,
            unit,
            priority,
            message,
        }))
    }

    fn read_timestamp_usec(&mut self) -> AppResult<u64> {
        let mut value = 0_u64;
        let status = unsafe { sd_journal_get_realtime_usec(self.raw, &mut value) };
        if status < 0 {
            return Err(AppError::new(
                ErrorCode::ExecutionFailed,
                "unable to read journal entry timestamp",
            )
            .with_detail("status", status as i64));
        }

        Ok(value)
    }

    fn read_priority(&mut self) -> AppResult<Option<JournalPriority>> {
        let Some(value) = self.read_field("PRIORITY")? else {
            return Ok(None);
        };
        let parsed = value.parse::<u8>().ok().and_then(JournalPriority::from_raw);
        Ok(parsed)
    }

    fn read_field(&mut self, field: &str) -> AppResult<Option<String>> {
        let c_field = CString::new(field).map_err(|_| {
            AppError::new(ErrorCode::ExecutionFailed, "journal field name is invalid")
                .with_detail("field", field.to_string())
        })?;
        let mut data = std::ptr::null();
        let mut length = 0_usize;
        let status =
            unsafe { sd_journal_get_data(self.raw, c_field.as_ptr(), &mut data, &mut length) };
        if status < 0 {
            return Ok(None);
        }
        if data.is_null() || length == 0 {
            return Ok(None);
        }

        let bytes = unsafe { std::slice::from_raw_parts(data.cast::<u8>(), length) };
        let Some(separator_index) = bytes.iter().position(|byte| *byte == b'=') else {
            return Ok(None);
        };
        let key = &bytes[..separator_index];
        let value = &bytes[separator_index + 1..];
        if key != field.as_bytes() {
            return Ok(None);
        }

        let text = std::str::from_utf8(value)
            .map_err(|_| {
                AppError::new(
                    ErrorCode::ExecutionFailed,
                    "journal field is not valid UTF-8",
                )
                .with_detail("field", field.to_string())
            })?
            .trim_end_matches('\0')
            .trim()
            .to_string();
        if text.is_empty() {
            return Ok(None);
        }

        Ok(Some(text))
    }
}

fn read_process_system_context() -> AppResult<ProcessSystemContext> {
    let uptime_secs = read_uptime_seconds_precise()?;
    let total_memory_bytes = read_mem_total_bytes()?;
    let boot_time_unix_secs = read_boot_time_unix_secs()?;
    let clock_ticks_per_second = clock_ticks_per_second()?;

    Ok(ProcessSystemContext {
        uptime_secs,
        total_memory_bytes,
        boot_time_unix_secs,
        clock_ticks_per_second,
    })
}

fn collect_process_snapshots(
    context: &ProcessSystemContext,
) -> AppResult<Vec<ProcessSnapshotEntry>> {
    let proc_entries = fs::read_dir("/proc")
        .map_err(|_| AppError::new(ErrorCode::ExecutionFailed, "unable to enumerate processes"))?;
    let mut snapshots = Vec::new();

    for proc_entry in proc_entries {
        let Ok(proc_entry) = proc_entry else {
            continue;
        };
        let Some(file_name) = proc_entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let Ok(pid) = file_name.parse::<u32>() else {
            continue;
        };

        let stat_path = format!("/proc/{pid}/stat");
        let Ok(stat_content) = fs::read_to_string(stat_path) else {
            continue;
        };
        let Ok((name, total_cpu_ticks, start_ticks, rss_pages)) =
            parse_proc_stat_line(&stat_content)
        else {
            continue;
        };

        let entry =
            process_snapshot_entry(pid, &name, total_cpu_ticks, start_ticks, rss_pages, context)?;
        snapshots.push(entry);
    }

    Ok(snapshots)
}

fn process_snapshot_entry(
    pid: u32,
    name: &str,
    total_cpu_ticks: u64,
    start_ticks: u64,
    rss_pages: i64,
    context: &ProcessSystemContext,
) -> AppResult<ProcessSnapshotEntry> {
    let clock_ticks = context.clock_ticks_per_second as f64;
    let total_cpu_seconds = total_cpu_ticks as f64 / clock_ticks;
    let started_after_boot_secs = start_ticks as f64 / clock_ticks;
    let elapsed_secs = (context.uptime_secs - started_after_boot_secs).max(0.001);
    let cpu_percent = round_percent((total_cpu_seconds / elapsed_secs) * 100.0);

    let page_size = page_size_bytes()?;
    let rss_pages = rss_pages.max(0) as u64;
    let rss_bytes = rss_pages.saturating_mul(page_size);
    let memory_percent = if context.total_memory_bytes == 0 {
        0.0
    } else {
        round_percent((rss_bytes as f64 / context.total_memory_bytes as f64) * 100.0)
    };

    let started_at = started_at_rfc3339(
        context.boot_time_unix_secs,
        start_ticks,
        context.clock_ticks_per_second,
    )?;

    Ok(ProcessSnapshotEntry {
        pid,
        name: name.to_string(),
        cpu_percent,
        memory_percent,
        started_at,
    })
}

fn parse_proc_stat_line(line: &str) -> AppResult<(String, u64, u64, i64)> {
    let open_paren = line
        .find('(')
        .ok_or_else(|| AppError::new(ErrorCode::ExecutionFailed, "invalid process stat format"))?;
    let close_paren = line
        .rfind(')')
        .ok_or_else(|| AppError::new(ErrorCode::ExecutionFailed, "invalid process stat format"))?;
    if close_paren <= open_paren {
        return Err(AppError::new(
            ErrorCode::ExecutionFailed,
            "invalid process stat format",
        ));
    }

    let name = line[open_paren + 1..close_paren].to_string();
    let remainder = line[close_paren + 1..].trim();
    let fields = remainder.split_whitespace().collect::<Vec<_>>();
    if fields.len() <= 21 {
        return Err(AppError::new(
            ErrorCode::ExecutionFailed,
            "incomplete process stat fields",
        ));
    }

    let utime = fields[11]
        .parse::<u64>()
        .map_err(|_| AppError::new(ErrorCode::ExecutionFailed, "invalid process utime"))?;
    let stime = fields[12]
        .parse::<u64>()
        .map_err(|_| AppError::new(ErrorCode::ExecutionFailed, "invalid process stime"))?;
    let start_ticks = fields[19]
        .parse::<u64>()
        .map_err(|_| AppError::new(ErrorCode::ExecutionFailed, "invalid process start time"))?;
    let rss_pages = fields[21]
        .parse::<i64>()
        .map_err(|_| AppError::new(ErrorCode::ExecutionFailed, "invalid process rss"))?;

    Ok((name, utime.saturating_add(stime), start_ticks, rss_pages))
}

fn from_params<T>(value: &Value) -> AppResult<T>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(value.clone()).map_err(|error| {
        AppError::new(ErrorCode::ValidationError, "invalid action params")
            .with_detail("source", error.to_string())
    })
}

fn validate_mount(mount: &str) -> AppResult<()> {
    if !mount.starts_with('/') || mount.len() > 255 {
        return Err(
            AppError::new(ErrorCode::ValidationError, "mount path is invalid")
                .with_detail("mount", mount.to_string()),
        );
    }

    Ok(())
}

fn validate_unit(unit: &str) -> AppResult<()> {
    if !unit.ends_with(".service")
        || unit.is_empty()
        || !unit.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_' | '@')
        })
    {
        return Err(
            AppError::new(ErrorCode::ValidationError, "unit name is invalid")
                .with_detail("unit", unit.to_string()),
        );
    }

    Ok(())
}

fn extract_interface_names(value: &Value) -> AppResult<Vec<String>> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct NetworkInterfaceStatusParams {
        interfaces: Vec<String>,
    }

    Ok(from_params::<NetworkInterfaceStatusParams>(value)?.interfaces)
}

fn validate_interface_name(name: &str) -> AppResult<()> {
    if name.is_empty()
        || name.len() > 32
        || !name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return Err(
            AppError::new(ErrorCode::ValidationError, "interface name is invalid")
                .with_detail("interface", name.to_string()),
        );
    }

    Ok(())
}

fn read_uptime_seconds() -> AppResult<u64> {
    let content = fs::read_to_string("/proc/uptime")
        .map_err(|_| AppError::new(ErrorCode::ExecutionFailed, "unable to read uptime"))?;
    let value = content
        .split_whitespace()
        .next()
        .ok_or_else(|| AppError::new(ErrorCode::ExecutionFailed, "invalid uptime format"))?;
    let seconds = value
        .split('.')
        .next()
        .unwrap_or("0")
        .parse::<u64>()
        .map_err(|_| AppError::new(ErrorCode::ExecutionFailed, "invalid uptime value"))?;
    Ok(seconds)
}

fn read_uptime_seconds_precise() -> AppResult<f64> {
    let content = fs::read_to_string("/proc/uptime")
        .map_err(|_| AppError::new(ErrorCode::ExecutionFailed, "unable to read uptime"))?;
    let value = content
        .split_whitespace()
        .next()
        .ok_or_else(|| AppError::new(ErrorCode::ExecutionFailed, "invalid uptime format"))?;
    value
        .parse::<f64>()
        .map_err(|_| AppError::new(ErrorCode::ExecutionFailed, "invalid uptime value"))
}

fn read_load_average() -> AppResult<[f64; 3]> {
    let content = fs::read_to_string("/proc/loadavg")
        .map_err(|_| AppError::new(ErrorCode::ExecutionFailed, "unable to read load average"))?;
    let values = content
        .split_whitespace()
        .take(3)
        .map(|value| value.parse::<f64>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AppError::new(ErrorCode::ExecutionFailed, "invalid load average value"))?;

    if values.len() != 3 {
        return Err(AppError::new(
            ErrorCode::ExecutionFailed,
            "unexpected load average format",
        ));
    }

    Ok([values[0], values[1], values[2]])
}

fn read_memory_stats() -> AppResult<Value> {
    let content = fs::read_to_string("/proc/meminfo")
        .map_err(|_| AppError::new(ErrorCode::ExecutionFailed, "unable to read meminfo"))?;
    let mut mem_total_kib = 0_u64;
    let mut mem_available_kib = 0_u64;
    let mut swap_total_kib = 0_u64;
    let mut swap_free_kib = 0_u64;

    for line in content.lines() {
        if let Some(value) = parse_meminfo_value(line, "MemTotal:") {
            mem_total_kib = value;
        } else if let Some(value) = parse_meminfo_value(line, "MemAvailable:") {
            mem_available_kib = value;
        } else if let Some(value) = parse_meminfo_value(line, "SwapTotal:") {
            swap_total_kib = value;
        } else if let Some(value) = parse_meminfo_value(line, "SwapFree:") {
            swap_free_kib = value;
        }
    }

    let total_bytes = mem_total_kib * 1024;
    let available_bytes = mem_available_kib * 1024;
    let used_bytes = total_bytes.saturating_sub(available_bytes);
    let swap_total_bytes = swap_total_kib * 1024;
    let swap_used_bytes = swap_total_bytes.saturating_sub(swap_free_kib * 1024);

    Ok(json!({
        "total_bytes": total_bytes,
        "used_bytes": used_bytes,
        "available_bytes": available_bytes,
        "swap_total_bytes": swap_total_bytes,
        "swap_used_bytes": swap_used_bytes
    }))
}

fn parse_meminfo_value(line: &str, key: &str) -> Option<u64> {
    line.strip_prefix(key)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|value| value.parse::<u64>().ok())
}

fn read_mem_total_bytes() -> AppResult<u64> {
    let content = fs::read_to_string("/proc/meminfo")
        .map_err(|_| AppError::new(ErrorCode::ExecutionFailed, "unable to read meminfo"))?;
    for line in content.lines() {
        if let Some(value) = parse_meminfo_value(line, "MemTotal:") {
            return Ok(value.saturating_mul(1024));
        }
    }

    Err(AppError::new(
        ErrorCode::ExecutionFailed,
        "meminfo does not contain MemTotal",
    ))
}

fn read_boot_time_unix_secs() -> AppResult<i64> {
    let content = fs::read_to_string("/proc/stat")
        .map_err(|_| AppError::new(ErrorCode::ExecutionFailed, "unable to read proc stat"))?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("btime ") {
            return rest
                .trim()
                .parse::<i64>()
                .map_err(|_| AppError::new(ErrorCode::ExecutionFailed, "invalid btime value"));
        }
    }

    Err(AppError::new(
        ErrorCode::ExecutionFailed,
        "proc stat does not contain btime",
    ))
}

fn clock_ticks_per_second() -> AppResult<u64> {
    let value = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if value <= 0 {
        return Err(AppError::new(
            ErrorCode::ExecutionFailed,
            "unable to read clock tick size",
        ));
    }

    Ok(value as u64)
}

fn page_size_bytes() -> AppResult<u64> {
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if value <= 0 {
        return Err(AppError::new(
            ErrorCode::ExecutionFailed,
            "unable to read page size",
        ));
    }

    Ok(value as u64)
}

#[derive(Debug)]
struct MountUsage {
    path: String,
    total_bytes: u64,
    used_bytes: u64,
    available_bytes: u64,
    percent_used: f64,
}

fn mount_usage(path: &str) -> AppResult<MountUsage> {
    use std::ffi::CString;

    let c_path = CString::new(path)
        .map_err(|_| AppError::new(ErrorCode::ValidationError, "invalid mount path"))?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    let result = unsafe { libc::statvfs(c_path.as_ptr(), stats.as_mut_ptr()) };
    if result != 0 {
        return Err(
            AppError::new(ErrorCode::ExecutionFailed, "statvfs failed for mount")
                .with_detail("mount", path.to_string()),
        );
    }

    let stats = unsafe { stats.assume_init() };
    let total_bytes = stats.f_blocks as u64 * stats.f_frsize as u64;
    let available_bytes = stats.f_bavail as u64 * stats.f_frsize as u64;
    let free_bytes = stats.f_bfree as u64 * stats.f_frsize as u64;
    let used_bytes = total_bytes.saturating_sub(free_bytes);
    let percent_used = if total_bytes == 0 {
        0.0
    } else {
        (used_bytes as f64 / total_bytes as f64) * 100.0
    };

    Ok(MountUsage {
        path: path.to_string(),
        total_bytes,
        used_bytes,
        available_bytes,
        percent_used,
    })
}

fn read_network_totals() -> AppResult<Value> {
    let content = fs::read_to_string("/proc/net/dev")
        .map_err(|_| AppError::new(ErrorCode::ExecutionFailed, "unable to read network stats"))?;
    let mut rx_bytes = 0_u64;
    let mut tx_bytes = 0_u64;

    for line in content.lines().skip(2) {
        let Some((_, rest)) = line.split_once(':') else {
            continue;
        };
        let columns: Vec<&str> = rest.split_whitespace().collect();
        if columns.len() < 16 {
            continue;
        }
        rx_bytes = rx_bytes.saturating_add(columns[0].parse::<u64>().unwrap_or(0));
        tx_bytes = tx_bytes.saturating_add(columns[8].parse::<u64>().unwrap_or(0));
    }

    Ok(json!({
        "rx_bytes": rx_bytes,
        "tx_bytes": tx_bytes
    }))
}

fn read_network_device_stats() -> AppResult<HashMap<String, (u64, u64)>> {
    let content = fs::read_to_string("/proc/net/dev")
        .map_err(|_| AppError::new(ErrorCode::ExecutionFailed, "unable to read network stats"))?;
    let mut stats = HashMap::new();

    for line in content.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let columns: Vec<&str> = rest.split_whitespace().collect();
        if columns.len() < 16 {
            continue;
        }
        let interface = name.trim().to_string();
        let rx_bytes = columns[0].parse::<u64>().unwrap_or(0);
        let tx_bytes = columns[8].parse::<u64>().unwrap_or(0);
        stats.insert(interface, (rx_bytes, tx_bytes));
    }

    Ok(stats)
}

fn read_interface_state(interface: &str) -> &'static str {
    let path = format!("/sys/class/net/{interface}/operstate");
    match fs::read_to_string(path) {
        Ok(state) => match state.trim() {
            "up" => "up",
            "down" => "down",
            _ => "unknown",
        },
        Err(_) => "unknown",
    }
}

fn read_interface_addresses(interface: &str) -> AppResult<Vec<String>> {
    let mut addresses = BTreeSet::new();
    let mut addrs = std::ptr::null_mut();
    let result = unsafe { libc::getifaddrs(&mut addrs) };
    if result != 0 {
        return Ok(Vec::new());
    }

    let mut current = addrs;
    while !current.is_null() {
        let ifaddr = unsafe { &*current };
        if !ifaddr.ifa_name.is_null() {
            let name = unsafe { std::ffi::CStr::from_ptr(ifaddr.ifa_name) }
                .to_string_lossy()
                .into_owned();
            if name == interface && !ifaddr.ifa_addr.is_null() {
                let family = unsafe { (*ifaddr.ifa_addr).sa_family as i32 };
                match family {
                    libc::AF_INET => {
                        let sockaddr = unsafe { &*(ifaddr.ifa_addr as *const libc::sockaddr_in) };
                        let addr = Ipv4Addr::from(u32::from_be(sockaddr.sin_addr.s_addr));
                        addresses.insert(addr.to_string());
                    }
                    libc::AF_INET6 => {
                        let sockaddr = unsafe { &*(ifaddr.ifa_addr as *const libc::sockaddr_in6) };
                        let addr = Ipv6Addr::from(sockaddr.sin6_addr.s6_addr);
                        addresses.insert(addr.to_string());
                    }
                    _ => {}
                }
            }
        }

        current = unsafe { (*current).ifa_next };
    }

    unsafe { libc::freeifaddrs(addrs) };
    Ok(addresses.into_iter().collect())
}

fn now_rfc3339() -> AppResult<String> {
    OffsetDateTime::from(SystemTime::now())
        .format(&Rfc3339)
        .map_err(|_| AppError::new(ErrorCode::ExecutionFailed, "unable to format timestamp"))
}

fn started_at_rfc3339(
    boot_time_unix_secs: i64,
    start_ticks: u64,
    clock_ticks_per_second: u64,
) -> AppResult<String> {
    let start_offset_nanos =
        (start_ticks as i128).saturating_mul(1_000_000_000) / clock_ticks_per_second as i128;
    let base_nanos = (boot_time_unix_secs as i128).saturating_mul(1_000_000_000);
    OffsetDateTime::from_unix_timestamp_nanos(base_nanos.saturating_add(start_offset_nanos))
        .map_err(|_| {
            AppError::new(
                ErrorCode::ExecutionFailed,
                "unable to convert process start time",
            )
        })?
        .format(&Rfc3339)
        .map_err(|_| {
            AppError::new(
                ErrorCode::ExecutionFailed,
                "unable to format process start time",
            )
        })
}

fn ratio(used: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        used as f64 / total as f64
    }
}

fn round_percent(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

fn restart_mode_name(mode: &ServiceRestartMode) -> &'static str {
    match mode {
        ServiceRestartMode::Safe => "safe",
    }
}

fn cutoff_realtime_usec(since_seconds: u64) -> AppResult<u64> {
    let cutoff = SystemTime::now()
        .checked_sub(Duration::from_secs(since_seconds))
        .unwrap_or(UNIX_EPOCH);
    let duration = cutoff.duration_since(UNIX_EPOCH).map_err(|_| {
        AppError::new(
            ErrorCode::ExecutionFailed,
            "unable to compute journal query time window",
        )
    })?;
    Ok(duration.as_secs().saturating_mul(1_000_000) + u64::from(duration.subsec_micros()))
}

fn priority_matches_filter(priority: JournalPriority, minimum: Option<&PriorityMin>) -> bool {
    match minimum {
        Some(PriorityMin::Warning) => priority.code() <= JournalPriority::Warning.code(),
        Some(PriorityMin::Error) => priority.code() <= JournalPriority::Error.code(),
        Some(PriorityMin::Critical) => priority.code() <= JournalPriority::Critical.code(),
        None => true,
    }
}

fn journal_record_to_value(record: &JournalRecord) -> AppResult<Value> {
    let timestamp =
        OffsetDateTime::from_unix_timestamp_nanos(record.timestamp_usec as i128 * 1_000)
            .map_err(|_| {
                AppError::new(
                    ErrorCode::ExecutionFailed,
                    "unable to convert journal timestamp",
                )
            })?
            .format(&Rfc3339)
            .map_err(|_| {
                AppError::new(
                    ErrorCode::ExecutionFailed,
                    "unable to format journal timestamp",
                )
            })?;

    Ok(json!({
        "timestamp": timestamp,
        "unit": record.unit,
        "priority": record.priority.as_str(),
        "message": record.message
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyEngine;
    use crate::types::{Request, RequestOriginType, RequestedBy};
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn metadata_covers_all_v1_actions_with_handler_mapping() {
        let expected = [
            (
                "system.status",
                Capability::ReadBasic,
                ActionHandler::SystemStatus,
            ),
            (
                "system.health",
                Capability::ReadBasic,
                ActionHandler::SystemHealth,
            ),
            (
                "resource.snapshot",
                Capability::ReadBasic,
                ActionHandler::ResourceSnapshot,
            ),
            (
                "disk.usage",
                Capability::ReadBasic,
                ActionHandler::DiskUsage,
            ),
            (
                "network.interface_status",
                Capability::ReadBasic,
                ActionHandler::NetworkInterfaceStatus,
            ),
            (
                "service.status",
                Capability::ServiceRead,
                ActionHandler::ServiceStatus,
            ),
            (
                "journal.query",
                Capability::ReadSensitive,
                ActionHandler::JournalQuery,
            ),
            (
                "process.snapshot",
                Capability::ReadSensitive,
                ActionHandler::ProcessSnapshot,
            ),
            (
                "service.restart",
                Capability::ServiceControl,
                ActionHandler::ServiceRestart,
            ),
        ];

        assert_eq!(ACTIONS.len(), expected.len());

        for (name, capability, handler) in expected {
            let metadata = metadata(name).expect("action must be registered");
            assert_eq!(metadata.name, name);
            assert_eq!(metadata.required_capability, capability);
            assert_eq!(metadata.handler, handler);
        }
    }

    #[test]
    fn metadata_returns_none_for_unknown_action() {
        assert!(metadata("unknown.action").is_none());
    }

    #[test]
    fn validate_request_shape_rejects_unknown_action() {
        let app = App::new(policy_for_current_user());
        let request = Request {
            version: 1,
            request_id: "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62571".to_string(),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "registry-test".to_string(),
            },
            action: "unknown.action".to_string(),
            params: serde_json::from_value(json!({})).expect("params"),
            dry_run: false,
            timeout_ms: 3000,
        };

        let error = validate_request_shape(&request, &app).expect_err("unknown action");
        assert_eq!(error.code, ErrorCode::ValidationError);
        assert_eq!(error.message, "unknown action");
        assert_eq!(error.details.get("action"), Some(&json!("unknown.action")));
    }

    #[test]
    fn validate_request_shape_rejects_unsupported_version() {
        let app = App::new(policy_for_current_user());
        let request = Request {
            version: 2,
            request_id: "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62572".to_string(),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "validator-test".to_string(),
            },
            action: "system.status".to_string(),
            params: serde_json::from_value(json!({})).expect("params"),
            dry_run: false,
            timeout_ms: 3000,
        };

        let error = validate_request_shape(&request, &app).expect_err("unsupported version");
        assert_eq!(error.code, ErrorCode::UnsupportedVersion);
        assert_eq!(error.message, "unsupported protocol version");
        assert_eq!(error.details.get("version"), Some(&json!(2)));
    }

    #[test]
    fn validate_request_shape_rejects_timeout_out_of_range() {
        let app = App::new(policy_for_current_user());
        let request = Request {
            version: 1,
            request_id: "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62573".to_string(),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "validator-test".to_string(),
            },
            action: "system.status".to_string(),
            params: serde_json::from_value(json!({})).expect("params"),
            dry_run: false,
            timeout_ms: 30_001,
        };

        let error = validate_request_shape(&request, &app).expect_err("timeout out of range");
        assert_eq!(error.code, ErrorCode::ValidationError);
        assert_eq!(error.message, "timeout_ms is out of allowed range");
        assert_eq!(error.details.get("timeout_ms"), Some(&json!(30_001)));
    }

    #[test]
    fn validate_request_shape_rejects_unknown_param_fields() {
        let app = App::new(policy_for_current_user());
        let request = Request {
            version: 1,
            request_id: "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62574".to_string(),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "validator-test".to_string(),
            },
            action: "system.status".to_string(),
            params: serde_json::from_value(json!({"unexpected": true})).expect("params"),
            dry_run: false,
            timeout_ms: 3000,
        };

        let error = validate_request_shape(&request, &app).expect_err("unknown field");
        assert_eq!(error.code, ErrorCode::ValidationError);
        assert_eq!(error.message, "invalid action params");
    }

    #[test]
    fn validate_request_shape_rejects_invalid_enum_values() {
        let app = App::new(policy_for_current_user());
        let request = Request {
            version: 1,
            request_id: "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62575".to_string(),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "validator-test".to_string(),
            },
            action: "service.restart".to_string(),
            params: serde_json::from_value(json!({
                "unit": "nginx.service",
                "mode": "unsafe",
                "reason": "test"
            }))
            .expect("params"),
            dry_run: false,
            timeout_ms: 3000,
        };

        let error = validate_request_shape(&request, &app).expect_err("invalid enum");
        assert_eq!(error.code, ErrorCode::ValidationError);
        assert_eq!(error.message, "invalid action params");
    }

    #[test]
    fn validate_request_shape_rejects_limit_violations_before_execution() {
        let app = App::new(policy_for_current_user());
        let request = Request {
            version: 1,
            request_id: "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62576".to_string(),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "validator-test".to_string(),
            },
            action: "disk.usage".to_string(),
            params: serde_json::from_value(json!({"mounts": []})).expect("params"),
            dry_run: false,
            timeout_ms: 3000,
        };

        let error = validate_request_shape(&request, &app).expect_err("limit violation");
        assert_eq!(error.code, ErrorCode::ValidationError);
        assert_eq!(
            error.message,
            "mounts must contain between 1 and 16 entries"
        );
    }

    #[test]
    fn validate_request_shape_rejects_zero_journal_limit() {
        let app = App::new(policy_for_current_user());
        let request = Request {
            version: 1,
            request_id: "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62577".to_string(),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "validator-test".to_string(),
            },
            action: "journal.query".to_string(),
            params: serde_json::from_value(json!({
                "limit": 0
            }))
            .expect("params"),
            dry_run: false,
            timeout_ms: 3000,
        };

        let error = validate_request_shape(&request, &app).expect_err("journal limit violation");
        assert_eq!(error.code, ErrorCode::ValidationError);
        assert_eq!(error.message, "journal limit exceeds policy maximum");
    }

    #[test]
    fn validate_request_shape_rejects_zero_process_limit() {
        let app = App::new(policy_for_current_user());
        let request = Request {
            version: 1,
            request_id: "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62578".to_string(),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "validator-test".to_string(),
            },
            action: "process.snapshot".to_string(),
            params: serde_json::from_value(json!({
                "top_by": "cpu",
                "limit": 0
            }))
            .expect("params"),
            dry_run: false,
            timeout_ms: 3000,
        };

        let error = validate_request_shape(&request, &app).expect_err("process limit violation");
        assert_eq!(error.code, ErrorCode::ValidationError);
        assert_eq!(error.message, "process limit exceeds policy maximum");
    }

    #[test]
    fn priority_matches_filter_respects_thresholds() {
        assert!(priority_matches_filter(
            JournalPriority::Warning,
            Some(&PriorityMin::Warning)
        ));
        assert!(priority_matches_filter(
            JournalPriority::Error,
            Some(&PriorityMin::Warning)
        ));
        assert!(!priority_matches_filter(
            JournalPriority::Notice,
            Some(&PriorityMin::Warning)
        ));
        assert!(priority_matches_filter(
            JournalPriority::Critical,
            Some(&PriorityMin::Error)
        ));
        assert!(!priority_matches_filter(
            JournalPriority::Warning,
            Some(&PriorityMin::Error)
        ));
    }

    #[test]
    fn journal_record_to_value_returns_documented_schema() {
        let value = journal_record_to_value(&JournalRecord {
            timestamp_usec: 1_710_000_000_000_000,
            unit: "nginx.service".to_string(),
            priority: JournalPriority::Warning,
            message: "upstream connection slow".to_string(),
        })
        .expect("journal record value");

        assert!(value["timestamp"].as_str().is_some());
        assert_eq!(value["unit"], json!("nginx.service"));
        assert_eq!(value["priority"], json!("warning"));
        assert_eq!(value["message"], json!("upstream connection slow"));
    }

    #[test]
    fn parse_proc_stat_line_extracts_required_fields() {
        let line = "1234 (kworker/0:1) S 1 2 3 4 5 6 7 8 9 10 120 30 14 15 16 17 18 19 1900 2000 400 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0";
        let (name, total_cpu_ticks, start_ticks, rss_pages) =
            parse_proc_stat_line(line).expect("parse proc stat");

        assert_eq!(name, "kworker/0:1");
        assert_eq!(total_cpu_ticks, 150);
        assert_eq!(start_ticks, 1900);
        assert_eq!(rss_pages, 400);
    }

    fn policy_for_current_user() -> PolicyEngine {
        let user = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());
        let content = format!(
            r#"
version = 1

[clients.local_cli]
unix_user = "{user}"
allowed_capabilities = ["read_basic", "read_sensitive", "service_read", "service_control"]

[actions]
allowed = ["system.status", "system.health", "resource.snapshot", "disk.usage", "network.interface_status", "service.status", "journal.query", "process.snapshot", "service.restart"]
denied = []

[service_control]
allowed_units = ["nginx.service"]
restart_cooldown_seconds = 300
max_restarts_per_hour = 3
"#
        );

        let mut path = std::env::temp_dir();
        path.push(unique_policy_name());
        fs::write(&path, content).expect("write policy");
        let engine = PolicyEngine::load_from_path(PathBuf::from(&path)).expect("load policy");
        let _ = fs::remove_file(path);
        engine
    }

    fn unique_policy_name() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        format!("adminbot-actions-policy-{nanos}.toml")
    }
}
