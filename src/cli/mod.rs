pub mod gate;

use std::io::{self, BufRead, IsTerminal, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::ipc::{read_frame, write_json_frame, IPC_READ_TIMEOUT, IPC_WRITE_TIMEOUT};
use crate::policy::PolicyEngine;
use crate::types::{Request, RequestOriginType, RequestedBy, Response, SuccessResponse};
use crate::{DEFAULT_POLICY_PATH, DEFAULT_SOCKET_PATH};

use self::gate::{run_gate, GateMode, GateOptions, GateReport};

const CLI_ID: &str = "adminbotctl";
const DEFAULT_TIMEOUT_MS: u64 = 3_000;
const DEFAULT_AUDIT_UNIT: &str = "adminbotd.service";
const DEFAULT_AUDIT_SINCE_SECONDS: u64 = 900;
const DEFAULT_AUDIT_LIMIT: u32 = 20;

#[derive(Debug, Clone)]
struct ParsedCli {
    socket_path: PathBuf,
    command: Command,
}

#[derive(Debug, Clone)]
enum Command {
    Status {
        json: bool,
    },
    Health {
        json: bool,
    },
    PolicyValidate {
        path: PathBuf,
        json: bool,
    },
    GateRun {
        options: GateOptions,
        json: bool,
    },
    AuditTail {
        unit: String,
        priority_min: Option<String>,
        since_seconds: u64,
        limit: u32,
        show_message: bool,
        json: bool,
    },
    Restart {
        unit: String,
        reason: String,
        dry_run: bool,
        confirm: bool,
        json: bool,
    },
}

#[derive(Debug)]
struct CliError {
    message: String,
    json: Option<Value>,
}

impl CliError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            json: None,
        }
    }

    fn with_json(mut self, json: Value) -> Self {
        self.json = Some(json);
        self
    }
}

pub fn run<I, S>(args: I) -> i32
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    let mut stdin = io::stdin().lock();
    run_with(
        args,
        &mut stdin,
        &mut stdout,
        &mut stderr,
        io::stdin().is_terminal(),
    )
}

fn run_with<I, S, R, W, E>(
    args: I,
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
    stdin_is_terminal: bool,
) -> i32
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
    R: BufRead,
    W: Write,
    E: Write,
{
    let parsed = match parse_args(args) {
        Ok(parsed) => parsed,
        Err(error) => {
            let _ = writeln!(stderr, "{error}");
            return 2;
        }
    };

    let json_output = parsed.command.json_output();
    match execute_command(parsed, stdin, stdout, stdin_is_terminal) {
        Ok(()) => 0,
        Err(error) => {
            if json_output {
                let payload = error.json.unwrap_or_else(
                    || json!({"status": "error", "error": {"message": error.message}}),
                );
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&payload).unwrap_or_else(|_| {
                        "{\"status\":\"error\",\"error\":{\"message\":\"failed to encode error\"}}"
                            .to_string()
                    })
                );
            } else {
                let _ = writeln!(stderr, "adminbotctl failed: {}", error.message);
            }
            1
        }
    }
}

fn execute_command<R: BufRead, W: Write>(
    parsed: ParsedCli,
    stdin: &mut R,
    stdout: &mut W,
    stdin_is_terminal: bool,
) -> Result<(), CliError> {
    match parsed.command {
        Command::Status { json } => {
            let success = execute_ipc(parsed.socket_path.as_path(), "system.status", Map::new())?;
            output_result(stdout, json, &success, render_status_human(&success.result))
        }
        Command::Health { json } => {
            let success = execute_ipc(parsed.socket_path.as_path(), "system.health", Map::new())?;
            output_result(stdout, json, &success, render_health_human(&success.result))
        }
        Command::PolicyValidate { path, json } => {
            let report = validate_policy(path.as_path())?;
            if json {
                writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&report).map_err(|error| {
                        CliError::new(format!(
                            "unable to encode policy validation output: {error}"
                        ))
                    })?
                )
                .map_err(|error| CliError::new(format!("unable to write stdout: {error}")))?;
            } else {
                writeln!(stdout, "{}", render_policy_report_human(&report))
                    .map_err(|error| CliError::new(format!("unable to write stdout: {error}")))?;
            }
            Ok(())
        }
        Command::GateRun { options, json } => {
            let report = run_gate(&options);
            if json {
                writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&report).map_err(|error| {
                        CliError::new(format!("unable to encode gate report: {error}"))
                    })?
                )
                .map_err(|error| CliError::new(format!("unable to write stdout: {error}")))?;
            } else {
                writeln!(stdout, "{}", render_gate_report_human(&report))
                    .map_err(|error| CliError::new(format!("unable to write stdout: {error}")))?;
            }
            if report.is_pass() {
                Ok(())
            } else {
                Err(
                    CliError::new("security release gate failed").with_json(json!({
                        "status": "error",
                        "error": {"message": "security release gate failed"},
                        "report": report
                    })),
                )
            }
        }
        Command::AuditTail {
            unit,
            priority_min,
            since_seconds,
            limit,
            show_message,
            json,
        } => {
            let mut params = Map::new();
            params.insert("unit".to_string(), json!(unit));
            params.insert("since_seconds".to_string(), json!(since_seconds));
            params.insert("limit".to_string(), json!(limit));
            if let Some(priority_min) = priority_min {
                params.insert("priority_min".to_string(), json!(priority_min));
            }
            let success = execute_ipc(parsed.socket_path.as_path(), "journal.query", params)?;
            output_result(
                stdout,
                json,
                &success,
                render_audit_tail_human(&success.result, show_message),
            )
        }
        Command::Restart {
            unit,
            reason,
            dry_run,
            confirm,
            json,
        } => {
            ensure_restart_confirmation(stdin, stdout, stdin_is_terminal, confirm, &unit, dry_run)?;

            let mut params = Map::new();
            params.insert("unit".to_string(), json!(unit));
            params.insert("mode".to_string(), json!("safe"));
            params.insert("reason".to_string(), json!(reason));
            let success = execute_ipc_with_dry_run(
                parsed.socket_path.as_path(),
                "service.restart",
                params,
                dry_run,
            )?;
            output_result(
                stdout,
                json,
                &success,
                render_restart_human(&success.result, dry_run),
            )
        }
    }
}

fn output_result<W: Write>(
    stdout: &mut W,
    json_output: bool,
    success: &SuccessResponse,
    human: String,
) -> Result<(), CliError> {
    if json_output {
        writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&Response::Success(success.clone())).map_err(|error| {
                CliError::new(format!("unable to encode command output: {error}"))
            })?
        )
        .map_err(|error| CliError::new(format!("unable to write stdout: {error}")))?;
    } else {
        writeln!(stdout, "{human}")
            .map_err(|error| CliError::new(format!("unable to write stdout: {error}")))?;
    }
    Ok(())
}

fn execute_ipc(
    socket_path: &Path,
    action: &str,
    params: Map<String, Value>,
) -> Result<SuccessResponse, CliError> {
    execute_ipc_with_dry_run(socket_path, action, params, false)
}

fn execute_ipc_with_dry_run(
    socket_path: &Path,
    action: &str,
    params: Map<String, Value>,
    dry_run: bool,
) -> Result<SuccessResponse, CliError> {
    let request = Request {
        version: 1,
        request_id: Uuid::new_v4().to_string(),
        requested_by: RequestedBy {
            origin_type: RequestOriginType::Human,
            id: CLI_ID.to_string(),
        },
        action: action.to_string(),
        params,
        dry_run,
        timeout_ms: DEFAULT_TIMEOUT_MS,
    };

    let response = send_request(socket_path, &request)?;
    match response {
        Response::Success(success) => Ok(success),
        Response::Error(error) => Err(CliError::new(format!(
            "{} ({})",
            error.error.message, error.error.code
        ))
        .with_json(json!(Response::Error(error)))),
    }
}

fn send_request(socket_path: &Path, request: &Request) -> Result<Response, CliError> {
    let mut stream = UnixStream::connect(socket_path).map_err(|error| {
        CliError::new(format!(
            "unable to connect to {}: {error}",
            socket_path.display()
        ))
    })?;
    stream
        .set_read_timeout(Some(IPC_READ_TIMEOUT))
        .map_err(|error| CliError::new(format!("unable to configure IPC read timeout: {error}")))?;
    stream
        .set_write_timeout(Some(IPC_WRITE_TIMEOUT))
        .map_err(|error| {
            CliError::new(format!("unable to configure IPC write timeout: {error}"))
        })?;
    write_json_frame(&mut stream, request)
        .map_err(|error| CliError::new(format!("unable to send IPC request: {error}")))?;
    let payload = read_frame(&mut stream)
        .map_err(|error| CliError::new(format!("unable to read IPC response: {error}")))?;
    serde_json::from_slice::<Response>(&payload)
        .map_err(|error| CliError::new(format!("unable to decode IPC response: {error}")))
}

#[derive(Debug, serde::Serialize)]
struct PolicyValidationReport {
    path: String,
    syntax_semantics_valid: bool,
    deployment_checks_applied: bool,
    deployment_checks_valid: Option<bool>,
}

fn validate_policy(path: &Path) -> Result<PolicyValidationReport, CliError> {
    PolicyEngine::load_from_path(path.to_path_buf())
        .map_err(|error| CliError::new(format!("policy syntax/semantics invalid: {error}")))?;

    let deployment_checks_applied = path == Path::new(DEFAULT_POLICY_PATH);
    let deployment_checks_valid = if deployment_checks_applied {
        PolicyEngine::validate_policy_file(path)
            .map_err(|error| CliError::new(format!("deployment validation failed: {error}")))?;
        Some(true)
    } else {
        None
    };

    Ok(PolicyValidationReport {
        path: path.display().to_string(),
        syntax_semantics_valid: true,
        deployment_checks_applied,
        deployment_checks_valid,
    })
}

fn render_policy_report_human(report: &PolicyValidationReport) -> String {
    if report.deployment_checks_applied {
        format!(
            "PASS: {} syntax/semantics valid; deployment owner/mode valid",
            report.path
        )
    } else {
        format!(
            "PASS: {} syntax/semantics valid; deployment owner/mode skipped for custom path",
            report.path
        )
    }
}

fn render_gate_report_human(report: &GateReport) -> String {
    let mut lines = vec![format!(
        "Security release gate mode: {}",
        match report.mode {
            GateMode::Artifact => "artifact",
            GateMode::Live => "live",
        }
    )];
    for check in &report.checks {
        let prefix = match check.status {
            gate::GateCheckStatus::Pass => "PASS",
            gate::GateCheckStatus::Fail => "FAIL",
        };
        lines.push(format!("{prefix}: {}", check.message));
    }
    lines.push(format!(
        "SECURITY RELEASE GATE: {}",
        if report.is_pass() { "PASS" } else { "FAIL" }
    ));
    lines.join("\n")
}

fn render_status_human(result: &Value) -> String {
    let hostname = result["hostname"].as_str().unwrap_or("unknown");
    let kernel = result["kernel"].as_str().unwrap_or("unknown");
    let uptime_seconds = result["uptime_seconds"].as_u64().unwrap_or(0);
    let memory_used = result["memory"]["used_bytes"].as_u64().unwrap_or(0);
    let memory_total = result["memory"]["total_bytes"].as_u64().unwrap_or(0);
    format!(
        "Hostname: {hostname}\nKernel: {kernel}\nUptime: {uptime_seconds}s\nMemory: {memory_used}/{memory_total} bytes"
    )
}

fn render_health_human(result: &Value) -> String {
    let overall = result["overall_status"].as_str().unwrap_or("unknown");
    let mut lines = vec![format!("Overall: {overall}")];
    if let Some(checks) = result["checks"].as_array() {
        for check in checks {
            let name = check["name"].as_str().unwrap_or("unknown");
            let status = check["status"].as_str().unwrap_or("unknown");
            lines.push(format!("- {name}: {status}"));
        }
    }
    lines.join("\n")
}

fn render_audit_tail_human(result: &Value, show_message: bool) -> String {
    let mut lines = Vec::new();
    if let Some(entries) = result["entries"].as_array() {
        for entry in entries {
            let timestamp = entry["timestamp"].as_str().unwrap_or("unknown");
            let unit = entry["unit"].as_str().unwrap_or("unknown");
            let priority = entry["priority"].as_str().unwrap_or("unknown");
            let message = if show_message {
                entry["message"].as_str().unwrap_or("")
            } else {
                "<redacted>"
            };
            let redacted = if show_message {
                ""
            } else {
                " message_redacted=true"
            };
            lines.push(format!(
                "{timestamp} {unit} priority={priority}{redacted} {message}"
            ));
        }
    }
    if result["truncated"].as_bool().unwrap_or(false) {
        lines.push("truncated=true".to_string());
    }
    if lines.is_empty() {
        "no entries".to_string()
    } else {
        lines.join("\n")
    }
}

fn render_restart_human(result: &Value, dry_run: bool) -> String {
    let unit = result["unit"].as_str().unwrap_or("unknown");
    let mode = result["mode"].as_str().unwrap_or("unknown");
    if dry_run {
        return format!(
            "Dry-run: would restart {unit} with mode {mode}\nPre-state: {}",
            serde_json::to_string_pretty(&result["pre_state"]).unwrap_or_else(|_| "{}".to_string())
        );
    }
    format!(
        "Restarted: {unit}\nMode: {mode}\nJob: {}\nPre-state: {}\nPost-state: {}",
        result["job_object_path"].as_str().unwrap_or("unknown"),
        serde_json::to_string_pretty(&result["pre_state"]).unwrap_or_else(|_| "{}".to_string()),
        serde_json::to_string_pretty(&result["post_state"]).unwrap_or_else(|_| "{}".to_string()),
    )
}

fn ensure_restart_confirmation<R: BufRead, W: Write>(
    stdin: &mut R,
    stdout: &mut W,
    stdin_is_terminal: bool,
    confirm: bool,
    unit: &str,
    dry_run: bool,
) -> Result<(), CliError> {
    if dry_run || confirm {
        return Ok(());
    }
    if !stdin_is_terminal {
        return Err(CliError::new(
            "restart requires --confirm when stdin is not interactive",
        ));
    }

    write!(stdout, "Type YES to restart {unit}: ")
        .and_then(|_| stdout.flush())
        .map_err(|error| CliError::new(format!("unable to prompt for confirmation: {error}")))?;
    let mut line = String::new();
    stdin
        .read_line(&mut line)
        .map_err(|error| CliError::new(format!("unable to read confirmation: {error}")))?;
    if line.trim() == "YES" {
        Ok(())
    } else {
        Err(CliError::new("restart confirmation declined"))
    }
}

fn parse_args<I, S>(args: I) -> Result<ParsedCli, String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut values = args.into_iter().map(Into::into).collect::<Vec<_>>();
    if !values.is_empty() {
        values.remove(0);
    }

    let mut socket_path = PathBuf::from(DEFAULT_SOCKET_PATH);
    while values.first().is_some_and(|value| value == "--socket") {
        if values.len() < 2 {
            return Err("--socket requires a path".to_string());
        }
        socket_path = PathBuf::from(values[1].clone());
        values.drain(0..2);
    }

    let Some(command) = values.first().cloned() else {
        return Err(usage());
    };

    let command = match command.as_str() {
        "status" => Command::Status {
            json: parse_flag_only_command("status", &values[1..])?,
        },
        "health" => Command::Health {
            json: parse_flag_only_command("health", &values[1..])?,
        },
        "policy" => parse_policy_command(&values[1..])?,
        "gate" => parse_gate_command(&values[1..])?,
        "audit" => parse_audit_command(&values[1..])?,
        "restart" => parse_restart_command(&values[1..])?,
        "--help" | "-h" => return Err(usage()),
        _ => return Err(format!("unknown command: {command}\n\n{}", usage())),
    };

    Ok(ParsedCli {
        socket_path,
        command,
    })
}

fn parse_policy_command(args: &[String]) -> Result<Command, String> {
    if args.first().map(String::as_str) != Some("validate") {
        return Err("usage: adminbotctl policy validate [--path PATH] [--json]".to_string());
    }
    let mut path = PathBuf::from(DEFAULT_POLICY_PATH);
    let mut json = false;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--path" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err("--path requires a value".to_string());
                };
                path = PathBuf::from(value);
            }
            "--json" => json = true,
            other => return Err(format!("unknown option for policy validate: {other}")),
        }
        index += 1;
    }

    Ok(Command::PolicyValidate { path, json })
}

fn parse_flag_only_command(command: &str, args: &[String]) -> Result<bool, String> {
    let mut remaining = args.to_vec();
    let json = consume_flag(&mut remaining, "--json");
    if let Some(unexpected) = remaining.first() {
        return Err(format!("unknown option for {command}: {unexpected}"));
    }
    Ok(json)
}

fn parse_gate_command(args: &[String]) -> Result<Command, String> {
    if args.first().map(String::as_str) != Some("run") {
        return Err("usage: adminbotctl gate run --mode artifact|live [options]".to_string());
    }

    let mut json = false;
    let mut mode = None;
    let mut options = GateOptions::defaults(GateMode::Artifact);
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--mode" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err("--mode requires artifact or live".to_string());
                };
                let parsed_mode = parse_gate_mode(value)?;
                mode = Some(parsed_mode);
                options = GateOptions::defaults(parsed_mode);
            }
            "--policy" => {
                index += 1;
                options.policy_path = PathBuf::from(
                    args.get(index)
                        .ok_or_else(|| "--policy requires a value".to_string())?,
                );
            }
            "--polkit" => {
                index += 1;
                options.polkit_path = PathBuf::from(
                    args.get(index)
                        .ok_or_else(|| "--polkit requires a value".to_string())?,
                );
            }
            "--unit" => {
                index += 1;
                options.unit_path = PathBuf::from(
                    args.get(index)
                        .ok_or_else(|| "--unit requires a value".to_string())?,
                );
            }
            "--runtime-dir" => {
                index += 1;
                options.runtime_dir = PathBuf::from(
                    args.get(index)
                        .ok_or_else(|| "--runtime-dir requires a value".to_string())?,
                );
            }
            "--socket" => {
                index += 1;
                options.socket_path = PathBuf::from(
                    args.get(index)
                        .ok_or_else(|| "--socket requires a value".to_string())?,
                );
            }
            "--expected-polkit-template" => {
                index += 1;
                options.expected_polkit_template =
                    PathBuf::from(args.get(index).ok_or_else(|| {
                        "--expected-polkit-template requires a value".to_string()
                    })?);
            }
            "--json" => json = true,
            other => return Err(format!("unknown option for gate run: {other}")),
        }
        index += 1;
    }

    options.mode = mode.ok_or_else(|| "gate run requires --mode artifact|live".to_string())?;
    Ok(Command::GateRun { options, json })
}

fn parse_audit_command(args: &[String]) -> Result<Command, String> {
    if args.first().map(String::as_str) != Some("tail") {
        return Err(
            "usage: adminbotctl audit tail [--unit UNIT] [--priority-min warning|error|critical] [--since-seconds N] [--limit N] [--show-message] [--json]".to_string(),
        );
    }
    let mut unit = DEFAULT_AUDIT_UNIT.to_string();
    let mut priority_min = None;
    let mut since_seconds = DEFAULT_AUDIT_SINCE_SECONDS;
    let mut limit = DEFAULT_AUDIT_LIMIT;
    let mut show_message = false;
    let mut json = false;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--unit" => {
                index += 1;
                unit = args
                    .get(index)
                    .ok_or_else(|| "--unit requires a value".to_string())?
                    .clone();
            }
            "--priority-min" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--priority-min requires a value".to_string())?;
                match value.as_str() {
                    "warning" | "error" | "critical" => priority_min = Some(value.clone()),
                    _ => {
                        return Err("--priority-min must be warning, error or critical".to_string())
                    }
                }
            }
            "--since-seconds" => {
                index += 1;
                since_seconds = args
                    .get(index)
                    .ok_or_else(|| "--since-seconds requires a value".to_string())?
                    .parse::<u64>()
                    .map_err(|_| "--since-seconds must be an integer".to_string())?;
            }
            "--limit" => {
                index += 1;
                limit = args
                    .get(index)
                    .ok_or_else(|| "--limit requires a value".to_string())?
                    .parse::<u32>()
                    .map_err(|_| "--limit must be an integer".to_string())?;
            }
            "--show-message" => show_message = true,
            "--json" => json = true,
            other => return Err(format!("unknown option for audit tail: {other}")),
        }
        index += 1;
    }

    Ok(Command::AuditTail {
        unit,
        priority_min,
        since_seconds,
        limit,
        show_message,
        json,
    })
}

fn parse_restart_command(args: &[String]) -> Result<Command, String> {
    let mut unit = None;
    let mut reason = None;
    let mut dry_run = false;
    let mut confirm = false;
    let mut json = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--unit" => {
                index += 1;
                unit = Some(
                    args.get(index)
                        .ok_or_else(|| "--unit requires a value".to_string())?
                        .clone(),
                );
            }
            "--reason" => {
                index += 1;
                reason = Some(
                    args.get(index)
                        .ok_or_else(|| "--reason requires a value".to_string())?
                        .clone(),
                );
            }
            "--dry-run" => dry_run = true,
            "--confirm" => confirm = true,
            "--json" => json = true,
            other => return Err(format!("unknown option for restart: {other}")),
        }
        index += 1;
    }

    Ok(Command::Restart {
        unit: unit.ok_or_else(|| "restart requires --unit".to_string())?,
        reason: reason.ok_or_else(|| "restart requires --reason".to_string())?,
        dry_run,
        confirm,
        json,
    })
}

fn parse_gate_mode(value: &str) -> Result<GateMode, String> {
    match value {
        "artifact" => Ok(GateMode::Artifact),
        "live" => Ok(GateMode::Live),
        _ => Err("--mode must be artifact or live".to_string()),
    }
}

fn consume_flag(args: &mut Vec<String>, flag: &str) -> bool {
    if let Some(position) = args.iter().position(|arg| arg == flag) {
        args.remove(position);
        true
    } else {
        false
    }
}

fn usage() -> String {
    [
        "Usage:",
        "  adminbotctl [--socket PATH] status [--json]",
        "  adminbotctl [--socket PATH] health [--json]",
        "  adminbotctl policy validate [--path PATH] [--json]",
        "  adminbotctl gate run --mode artifact|live [--policy PATH] [--polkit PATH] [--unit PATH] [--runtime-dir PATH] [--socket PATH] [--expected-polkit-template PATH] [--json]",
        "  adminbotctl [--socket PATH] audit tail [--unit UNIT] [--priority-min warning|error|critical] [--since-seconds N] [--limit N] [--show-message] [--json]",
        "  adminbotctl [--socket PATH] restart --unit UNIT --reason TEXT [--dry-run] [--confirm] [--json]",
    ]
    .join("\n")
}

impl Command {
    fn json_output(&self) -> bool {
        match self {
            Command::Status { json }
            | Command::Health { json }
            | Command::PolicyValidate { json, .. }
            | Command::GateRun { json, .. }
            | Command::AuditTail { json, .. }
            | Command::Restart { json, .. } => *json,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::io::Cursor;
    use std::path::PathBuf;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::app::App;
    use crate::ipc::IpcServer;
    use crate::policy::PolicyEngine;

    #[test]
    fn status_json_smoke_works_against_test_server() {
        let socket_path = temp_socket_path("status");
        let policy_path = temp_policy_path();
        let policy = PolicyEngine::load_from_path(policy_path.clone()).expect("load policy");
        let app = App::new(policy);
        let server = IpcServer::bind_for_test(socket_path.clone()).expect("bind test server");
        let handle = thread::spawn(move || server.run_once(&app));

        let mut stdin = Cursor::new(Vec::<u8>::new());
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run_with(
            vec![
                "adminbotctl".to_string(),
                "--socket".to_string(),
                socket_path.display().to_string(),
                "status".to_string(),
                "--json".to_string(),
            ],
            &mut stdin,
            &mut stdout,
            &mut stderr,
            false,
        );

        assert_eq!(exit_code, 0);
        let output = String::from_utf8(stdout).expect("utf8 stdout");
        assert!(output.contains("\"status\": \"ok\""));
        assert!(output.contains("\"hostname\""));
        handle.join().expect("join").expect("server run_once");
        let _ = fs::remove_file(policy_path);
    }

    #[test]
    fn health_human_smoke_works_against_test_server() {
        let socket_path = temp_socket_path("health");
        let policy_path = temp_policy_path();
        let policy = PolicyEngine::load_from_path(policy_path.clone()).expect("load policy");
        let app = App::new(policy);
        let server = IpcServer::bind_for_test(socket_path.clone()).expect("bind test server");
        let handle = thread::spawn(move || server.run_once(&app));

        let mut stdin = Cursor::new(Vec::<u8>::new());
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run_with(
            vec![
                "adminbotctl".to_string(),
                "--socket".to_string(),
                socket_path.display().to_string(),
                "health".to_string(),
            ],
            &mut stdin,
            &mut stdout,
            &mut stderr,
            false,
        );

        assert_eq!(exit_code, 0);
        let output = String::from_utf8(stdout).expect("utf8 stdout");
        assert!(output.contains("Overall:"));
        handle.join().expect("join").expect("server run_once");
        let _ = fs::remove_file(policy_path);
    }

    #[test]
    fn policy_validate_rejects_invalid_policy_file() {
        let policy_path = write_temp_file("invalid-policy", "version = 2\n");
        let mut stdin = Cursor::new(Vec::<u8>::new());
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_with(
            vec![
                "adminbotctl".to_string(),
                "policy".to_string(),
                "validate".to_string(),
                "--path".to_string(),
                policy_path.display().to_string(),
            ],
            &mut stdin,
            &mut stdout,
            &mut stderr,
            false,
        );

        assert_eq!(exit_code, 1);
        let error = String::from_utf8(stderr).expect("utf8 stderr");
        assert!(error.contains("policy syntax/semantics invalid"));
        let _ = fs::remove_file(policy_path);
    }

    #[test]
    fn gate_run_reports_fail_for_broken_artifact_policy() {
        let temp_dir = temp_dir("gate");
        let broken_policy = temp_dir.join("policy.toml");
        fs::write(&broken_policy, "version = 1\n").expect("write broken policy");

        let mut stdin = Cursor::new(Vec::<u8>::new());
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run_with(
            vec![
                "adminbotctl".to_string(),
                "gate".to_string(),
                "run".to_string(),
                "--mode".to_string(),
                "artifact".to_string(),
                "--policy".to_string(),
                broken_policy.display().to_string(),
            ],
            &mut stdin,
            &mut stdout,
            &mut stderr,
            false,
        );

        assert_eq!(exit_code, 1);
        let output = String::from_utf8(stdout).expect("utf8 stdout");
        assert!(output.contains("SECURITY RELEASE GATE: FAIL"));
        let _ = fs::remove_file(broken_policy);
        let _ = fs::remove_dir(temp_dir);
    }

    #[test]
    fn restart_requires_confirm_without_tty() {
        let mut stdin = Cursor::new(Vec::<u8>::new());
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_with(
            vec![
                "adminbotctl".to_string(),
                "restart".to_string(),
                "--unit".to_string(),
                "nginx.service".to_string(),
                "--reason".to_string(),
                "manual restart".to_string(),
            ],
            &mut stdin,
            &mut stdout,
            &mut stderr,
            false,
        );

        assert_eq!(exit_code, 1);
        let error = String::from_utf8(stderr).expect("utf8 stderr");
        assert!(error.contains("restart requires --confirm"));
    }

    #[test]
    fn audit_tail_human_output_redacts_messages_by_default() {
        let result = json!({
            "entries": [{
                "timestamp": "2026-04-06T21:00:00Z",
                "unit": "adminbotd.service",
                "priority": "warning",
                "message": "secret details"
            }],
            "truncated": false
        });

        let rendered = render_audit_tail_human(&result, false);
        assert!(rendered.contains("message_redacted=true"));
        assert!(!rendered.contains("secret details"));
    }

    #[test]
    fn status_rejects_unknown_option() {
        let mut stdin = Cursor::new(Vec::<u8>::new());
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code = run_with(
            vec![
                "adminbotctl".to_string(),
                "status".to_string(),
                "--bogus".to_string(),
            ],
            &mut stdin,
            &mut stdout,
            &mut stderr,
            false,
        );

        assert_eq!(exit_code, 2);
        let error = String::from_utf8(stderr).expect("utf8 stderr");
        assert!(error.contains("unknown option for status: --bogus"));
    }

    fn temp_socket_path(label: &str) -> PathBuf {
        let base = temp_dir(label);
        base.join("adminbot.sock")
    }

    fn temp_policy_path() -> PathBuf {
        let path = write_temp_file(
            "policy",
            r#"
version = 1

[clients.local_cli]
unix_user = "dev"
allowed_capabilities = ["read_basic", "read_sensitive", "service_read", "service_control"]

[actions]
allowed = ["system.status", "system.health", "journal.query", "service.restart"]
denied = []

[service_control]
allowed_units = ["adminbotd.service", "nginx.service"]
restart_cooldown_seconds = 300
max_restarts_per_hour = 3

[constraints]
default_timeout_ms = 3000
max_timeout_ms = 30000
journal_limit_max = 200
process_limit_max = 50
max_parallel_mutations = 1
"#,
        );
        path
    }

    fn write_temp_file(label: &str, contents: &str) -> PathBuf {
        let path = temp_dir(label).join(format!("{label}.tmp"));
        fs::write(&path, contents).expect("write temp file");
        path
    }

    fn temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "adminbotctl-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }
}
