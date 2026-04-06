use std::fs;
use std::thread;
use std::time::{Duration, SystemTime};

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

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct ActionMetadata {
    pub name: &'static str,
    pub required_capability: Capability,
    pub risk: RiskLevel,
    pub privilege_requirement: PrivilegeRequirement,
}

const ACTIONS: &[ActionMetadata] = &[
    ActionMetadata {
        name: "system.status",
        required_capability: Capability::ReadBasic,
        risk: RiskLevel::R0,
        privilege_requirement: PrivilegeRequirement::None,
    },
    ActionMetadata {
        name: "system.health",
        required_capability: Capability::ReadBasic,
        risk: RiskLevel::R0,
        privilege_requirement: PrivilegeRequirement::None,
    },
    ActionMetadata {
        name: "resource.snapshot",
        required_capability: Capability::ReadBasic,
        risk: RiskLevel::R0,
        privilege_requirement: PrivilegeRequirement::None,
    },
    ActionMetadata {
        name: "disk.usage",
        required_capability: Capability::ReadBasic,
        risk: RiskLevel::R0,
        privilege_requirement: PrivilegeRequirement::None,
    },
    ActionMetadata {
        name: "network.interface_status",
        required_capability: Capability::ReadBasic,
        risk: RiskLevel::R0,
        privilege_requirement: PrivilegeRequirement::None,
    },
    ActionMetadata {
        name: "service.status",
        required_capability: Capability::ServiceRead,
        risk: RiskLevel::R1,
        privilege_requirement: PrivilegeRequirement::Elevated,
    },
    ActionMetadata {
        name: "journal.query",
        required_capability: Capability::ReadSensitive,
        risk: RiskLevel::R1,
        privilege_requirement: PrivilegeRequirement::Elevated,
    },
    ActionMetadata {
        name: "process.snapshot",
        required_capability: Capability::ReadSensitive,
        risk: RiskLevel::R1,
        privilege_requirement: PrivilegeRequirement::Elevated,
    },
    ActionMetadata {
        name: "service.restart",
        required_capability: Capability::ServiceControl,
        risk: RiskLevel::R2,
        privilege_requirement: PrivilegeRequirement::PrivilegedBackend,
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
    match request.action.as_str() {
        "system.status" => system_status(request),
        "system.health" => system_health(),
        "resource.snapshot" => resource_snapshot(),
        "disk.usage" => disk_usage(request),
        "service.status" => service_status(request),
        "service.restart" => service_restart(app, request),
        "network.interface_status" | "journal.query" | "process.snapshot" => Err(AppError::new(
            ErrorCode::BackendUnavailable,
            "action is registered but not implemented in this minimal build",
        )),
        _ => Err(AppError::new(ErrorCode::ValidationError, "unknown action")),
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
            }
            let _ = parsed.priority_min;
            if parsed.limit.unwrap_or(50) > app.policy().constraints().journal_limit_max {
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

fn now_rfc3339() -> AppResult<String> {
    OffsetDateTime::from(SystemTime::now())
        .format(&Rfc3339)
        .map_err(|_| AppError::new(ErrorCode::ExecutionFailed, "unable to format timestamp"))
}

fn ratio(used: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        used as f64 / total as f64
    }
}

fn restart_mode_name(mode: &ServiceRestartMode) -> &'static str {
    match mode {
        ServiceRestartMode::Safe => "safe",
    }
}
