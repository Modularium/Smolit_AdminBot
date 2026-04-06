use std::collections::HashMap;
use std::ffi::CString;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use libc::iovec;
use serde_json::json;
use serde_json::Value;

use crate::error::AppError;
use crate::peer::PeerCredentials;
use crate::types::Request;

pub const AUDIT_REPETITIVE_ERROR_WINDOW: Duration = Duration::from_secs(1);
pub const AUDIT_REPETITIVE_ERROR_BURST_LIMIT: usize = 4;

#[derive(Debug)]
pub struct AuditLogger {
    flood_control: Mutex<AuditFloodControl>,
}

#[derive(Debug, Clone, Copy)]
enum AuditDecision {
    Pending,
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy)]
enum AuditStage {
    Received,
    Completed,
}

#[derive(Debug)]
struct AuditEvent<'a> {
    request: &'a Request,
    peer: &'a PeerCredentials,
    stage: AuditStage,
    decision: AuditDecision,
    result: &'a str,
    error: Option<&'a AppError>,
}

#[derive(Debug)]
enum AuditEmission {
    Emit { suppression_notice: bool },
    Suppress,
}

#[derive(Debug, Default)]
struct AuditFloodControl {
    repetitive_error_windows: HashMap<AuditFloodKey, AuditFloodWindow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AuditFloodKey {
    peer_uid: u32,
    peer_gid: u32,
    action: String,
    error_code: String,
}

#[derive(Debug)]
struct AuditFloodWindow {
    window_started: Instant,
    emitted_events: usize,
    suppression_notice_emitted: bool,
}

#[link(name = "systemd")]
unsafe extern "C" {
    fn sd_journal_sendv(iov: *const iovec, n: libc::c_int) -> libc::c_int;
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self {
            flood_control: Mutex::new(AuditFloodControl::default()),
        }
    }
}

impl AuditLogger {
    pub fn log_received(&self, request: &Request, peer: &PeerCredentials) {
        let event = AuditEvent {
            request,
            peer,
            stage: AuditStage::Received,
            decision: AuditDecision::Pending,
            result: "received",
            error: None,
        };
        self.log_event(&event, Instant::now());
    }

    pub fn log_success(&self, request: &Request, peer: &PeerCredentials) {
        let event = AuditEvent {
            request,
            peer,
            stage: AuditStage::Completed,
            decision: AuditDecision::Allow,
            result: success_result(request),
            error: None,
        };
        self.log_event(&event, Instant::now());
    }

    pub fn log_error(&self, request: &Request, peer: &PeerCredentials, error: &AppError) {
        let event = AuditEvent {
            request,
            peer,
            stage: AuditStage::Completed,
            decision: AuditDecision::Deny,
            result: "error",
            error: Some(error),
        };
        self.log_event(&event, Instant::now());
    }

    fn log_event(&self, event: &AuditEvent<'_>, now: Instant) {
        let emission = self.evaluate_flood_control(event, now);
        let suppression_notice = match emission {
            AuditEmission::Emit { suppression_notice } => suppression_notice,
            AuditEmission::Suppress => return,
        };

        let fields = build_journald_fields(event, suppression_notice);
        if send_to_journald(&fields).is_err() {
            eprintln!("{}", fallback_json(event, suppression_notice));
        }
    }

    fn evaluate_flood_control(&self, event: &AuditEvent<'_>, now: Instant) -> AuditEmission {
        if !is_repetitive_error_candidate(event) {
            return AuditEmission::Emit {
                suppression_notice: false,
            };
        }

        let key = repetitive_error_key(event);
        let mut guard = self
            .flood_control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let window = guard
            .repetitive_error_windows
            .entry(key)
            .or_insert_with(|| AuditFloodWindow {
                window_started: now,
                emitted_events: 0,
                suppression_notice_emitted: false,
            });

        if now.duration_since(window.window_started) >= AUDIT_REPETITIVE_ERROR_WINDOW {
            window.window_started = now;
            window.emitted_events = 0;
            window.suppression_notice_emitted = false;
        }

        if window.emitted_events < AUDIT_REPETITIVE_ERROR_BURST_LIMIT {
            window.emitted_events += 1;
            return AuditEmission::Emit {
                suppression_notice: false,
            };
        }

        if !window.suppression_notice_emitted {
            window.suppression_notice_emitted = true;
            return AuditEmission::Emit {
                suppression_notice: true,
            };
        }

        AuditEmission::Suppress
    }
}

fn build_journald_fields(event: &AuditEvent<'_>, suppression_notice: bool) -> Vec<CString> {
    let access = access_decisions(event);
    let mut fields = vec![
        cstring_field("MESSAGE", &format_message(event)),
        cstring_field("PRIORITY", priority_value(event)),
        cstring_field("SYSLOG_IDENTIFIER", "adminbotd"),
        cstring_field("ADMINBOT_EVENT_KIND", "audit"),
        cstring_field("ADMINBOT_REQUEST_ID", &event.request.request_id),
        cstring_field("ADMINBOT_ACTION", &event.request.action),
        cstring_field("ADMINBOT_STAGE", stage_value(event.stage)),
        cstring_field(
            "ADMINBOT_REQUESTED_BY_TYPE",
            requested_by_type(event.request),
        ),
        cstring_field("ADMINBOT_REQUESTED_BY_ID", &event.request.requested_by.id),
        cstring_field("ADMINBOT_PEER_UID", &event.peer.uid.to_string()),
        cstring_field("ADMINBOT_PEER_GID", &event.peer.gid.to_string()),
        cstring_field("ADMINBOT_PEER_PID", &event.peer.pid.to_string()),
        cstring_field("ADMINBOT_DRY_RUN", bool_value(event.request.dry_run)),
        cstring_field("ADMINBOT_DECISION", decision_value(event.decision)),
        cstring_field("ADMINBOT_POLICY_DECISION", access.policy),
        cstring_field("ADMINBOT_CAPABILITY_DECISION", access.capability),
        cstring_field("ADMINBOT_RESULT", event.result),
    ];

    if suppression_notice {
        fields.push(cstring_field("ADMINBOT_AUDIT_SUPPRESSION_ACTIVE", "true"));
        fields.push(cstring_field(
            "ADMINBOT_AUDIT_SUPPRESSION_WINDOW_MS",
            &AUDIT_REPETITIVE_ERROR_WINDOW.as_millis().to_string(),
        ));
        fields.push(cstring_field(
            "ADMINBOT_AUDIT_SUPPRESSION_BURST_LIMIT",
            &AUDIT_REPETITIVE_ERROR_BURST_LIMIT.to_string(),
        ));
    }

    if let Some(error) = event.error {
        fields.push(cstring_field(
            "ADMINBOT_ERROR_CODE",
            &error.code.to_string(),
        ));
        fields.push(cstring_field("ADMINBOT_ERROR_MESSAGE", &error.message));

        if let Some(policy_section) = string_detail(error, "policy_section") {
            fields.push(cstring_field("ADMINBOT_POLICY_SECTION", policy_section));
        }

        if let Some(required_capability) = string_detail(error, "required_capability") {
            fields.push(cstring_field(
                "ADMINBOT_REQUIRED_CAPABILITY",
                required_capability,
            ));
        }
    }

    fields
}

fn send_to_journald(fields: &[CString]) -> Result<(), ()> {
    let iovecs = fields
        .iter()
        .map(|field| iovec {
            iov_base: field.as_ptr().cast::<libc::c_void>() as *mut libc::c_void,
            iov_len: field.as_bytes().len(),
        })
        .collect::<Vec<_>>();
    let status = unsafe { sd_journal_sendv(iovecs.as_ptr(), iovecs.len() as libc::c_int) };
    if status < 0 {
        return Err(());
    }

    Ok(())
}

fn fallback_json(event: &AuditEvent<'_>, suppression_notice: bool) -> serde_json::Value {
    let access = access_decisions(event);
    let mut entry = json!({
        "request_id": event.request.request_id,
        "action": event.request.action,
        "stage": stage_value(event.stage),
        "requested_by": {
            "type": event.request.requested_by.origin_type,
            "id": event.request.requested_by.id
        },
        "peer": {
            "uid": event.peer.uid,
            "gid": event.peer.gid,
            "pid": event.peer.pid
        },
        "dry_run": event.request.dry_run,
        "decision": decision_value(event.decision),
        "policy": {
            "decision": access.policy
        },
        "capability": {
            "decision": access.capability
        },
        "result": event.result
    });

    if suppression_notice {
        entry["audit"] = json!({
            "suppression_active": true,
            "suppression_window_ms": AUDIT_REPETITIVE_ERROR_WINDOW.as_millis(),
            "suppression_burst_limit": AUDIT_REPETITIVE_ERROR_BURST_LIMIT
        });
    }

    if let Some(error) = event.error {
        entry["error"] = json!({
            "code": error.code,
            "message": error.message,
        });

        if let Some(policy_section) = string_detail(error, "policy_section") {
            entry["policy"]["section"] = json!(policy_section);
        }

        if let Some(required_capability) = string_detail(error, "required_capability") {
            entry["capability"]["required"] = json!(required_capability);
        }
    }

    entry
}

fn is_repetitive_error_candidate(event: &AuditEvent<'_>) -> bool {
    matches!(
        event.error.map(|error| error.code),
        Some(crate::error::ErrorCode::ValidationError)
            | Some(crate::error::ErrorCode::UnsupportedVersion)
            | Some(crate::error::ErrorCode::Unauthorized)
            | Some(crate::error::ErrorCode::Forbidden)
    )
}

fn repetitive_error_key(event: &AuditEvent<'_>) -> AuditFloodKey {
    let error_code = event
        .error
        .map(|error| error.code.to_string())
        .unwrap_or_else(|| "none".to_string());
    AuditFloodKey {
        peer_uid: event.peer.uid,
        peer_gid: event.peer.gid,
        action: event.request.action.clone(),
        error_code,
    }
}

fn cstring_field(key: &str, value: &str) -> CString {
    let sanitized = value.replace('\0', "");
    CString::new(format!("{key}={sanitized}")).expect("audit field must be valid cstring")
}

fn requested_by_type(request: &Request) -> &'static str {
    match request.requested_by.origin_type {
        crate::types::RequestOriginType::Human => "human",
        crate::types::RequestOriginType::Agent => "agent",
    }
}

fn decision_value(decision: AuditDecision) -> &'static str {
    match decision {
        AuditDecision::Pending => "pending",
        AuditDecision::Allow => "allow",
        AuditDecision::Deny => "deny",
    }
}

fn stage_value(stage: AuditStage) -> &'static str {
    match stage {
        AuditStage::Received => "received",
        AuditStage::Completed => "completed",
    }
}

fn priority_value(event: &AuditEvent<'_>) -> &'static str {
    match event.decision {
        AuditDecision::Pending => "6",
        AuditDecision::Allow => "6",
        AuditDecision::Deny => "4",
    }
}

fn format_message(event: &AuditEvent<'_>) -> String {
    match event.stage {
        AuditStage::Received => format!(
            "adminbot audit received action={} request_id={} dry_run={}",
            event.request.action, event.request.request_id, event.request.dry_run
        ),
        AuditStage::Completed => match event.error {
            Some(error) => format!(
                "adminbot audit deny action={} request_id={} error_code={}",
                event.request.action, event.request.request_id, error.code
            ),
            None => format!(
                "adminbot audit allow action={} request_id={}",
                event.request.action, event.request.request_id
            ),
        },
    }
}

fn success_result(request: &Request) -> &'static str {
    if request.dry_run {
        "dry_run_ok"
    } else {
        "ok"
    }
}

fn bool_value(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

struct AccessDecisions {
    policy: &'static str,
    capability: &'static str,
}

fn access_decisions(event: &AuditEvent<'_>) -> AccessDecisions {
    match event.stage {
        AuditStage::Received => AccessDecisions {
            policy: "pending",
            capability: "pending",
        },
        AuditStage::Completed => match event.error.map(|error| error.code) {
            None => AccessDecisions {
                policy: "allow",
                capability: "allow",
            },
            Some(crate::error::ErrorCode::PolicyDenied) => AccessDecisions {
                policy: "deny",
                capability: "not_evaluated",
            },
            Some(crate::error::ErrorCode::CapabilityDenied) => AccessDecisions {
                policy: "allow",
                capability: "deny",
            },
            Some(crate::error::ErrorCode::Unauthorized)
            | Some(crate::error::ErrorCode::Forbidden)
            | Some(crate::error::ErrorCode::ValidationError)
            | Some(crate::error::ErrorCode::UnsupportedVersion) => AccessDecisions {
                policy: "not_evaluated",
                capability: "not_evaluated",
            },
            Some(_) => AccessDecisions {
                policy: "allow",
                capability: "allow",
            },
        },
    }
}

fn string_detail<'a>(error: &'a AppError, key: &str) -> Option<&'a str> {
    match error.details.get(key) {
        Some(Value::String(value)) => Some(value.as_str()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;
    use crate::types::{RequestOriginType, RequestedBy};

    #[test]
    fn build_journald_fields_contains_expected_success_keys() {
        let request = test_request();
        let peer = test_peer();
        let event = AuditEvent {
            request: &request,
            peer: &peer,
            stage: AuditStage::Completed,
            decision: AuditDecision::Allow,
            result: "ok",
            error: None,
        };

        let fields = build_journald_fields(&event, false)
            .into_iter()
            .map(|field| field.into_string().expect("utf8"))
            .collect::<Vec<_>>();

        assert!(fields.contains(&"PRIORITY=6".to_string()));
        assert!(fields.contains(&"SYSLOG_IDENTIFIER=adminbotd".to_string()));
        assert!(fields.contains(&"ADMINBOT_REQUEST_ID=test-request-id".to_string()));
        assert!(fields.contains(&"ADMINBOT_ACTION=system.status".to_string()));
        assert!(fields.contains(&"ADMINBOT_STAGE=completed".to_string()));
        assert!(fields.contains(&"ADMINBOT_DRY_RUN=false".to_string()));
        assert!(fields.contains(&"ADMINBOT_DECISION=allow".to_string()));
        assert!(fields.contains(&"ADMINBOT_POLICY_DECISION=allow".to_string()));
        assert!(fields.contains(&"ADMINBOT_CAPABILITY_DECISION=allow".to_string()));
        assert!(fields.contains(&"ADMINBOT_RESULT=ok".to_string()));
    }

    #[test]
    fn build_journald_fields_marks_received_stage_for_incoming_request() {
        let request = test_request();
        let peer = test_peer();
        let event = AuditEvent {
            request: &request,
            peer: &peer,
            stage: AuditStage::Received,
            decision: AuditDecision::Pending,
            result: "received",
            error: None,
        };

        let fields = build_journald_fields(&event, false)
            .into_iter()
            .map(|field| field.into_string().expect("utf8"))
            .collect::<Vec<_>>();

        assert!(fields.contains(&"ADMINBOT_STAGE=received".to_string()));
        assert!(fields.contains(&"ADMINBOT_DECISION=pending".to_string()));
        assert!(fields.contains(&"ADMINBOT_POLICY_DECISION=pending".to_string()));
        assert!(fields.contains(&"ADMINBOT_CAPABILITY_DECISION=pending".to_string()));
        assert!(fields.contains(&"ADMINBOT_RESULT=received".to_string()));
    }

    #[test]
    fn build_journald_fields_contains_error_metadata() {
        let request = test_request();
        let peer = test_peer();
        let error = AppError::new(ErrorCode::PolicyDenied, "action denied");
        let event = AuditEvent {
            request: &request,
            peer: &peer,
            stage: AuditStage::Completed,
            decision: AuditDecision::Deny,
            result: "error",
            error: Some(&error),
        };

        let fields = build_journald_fields(&event, false)
            .into_iter()
            .map(|field| field.into_string().expect("utf8"))
            .collect::<Vec<_>>();

        assert!(fields.contains(&"PRIORITY=4".to_string()));
        assert!(fields.contains(&"ADMINBOT_DECISION=deny".to_string()));
        assert!(fields.contains(&"ADMINBOT_POLICY_DECISION=deny".to_string()));
        assert!(fields.contains(&"ADMINBOT_CAPABILITY_DECISION=not_evaluated".to_string()));
        assert!(fields.contains(&"ADMINBOT_ERROR_CODE=policy_denied".to_string()));
        assert!(fields.contains(&"ADMINBOT_ERROR_MESSAGE=action denied".to_string()));
    }

    #[test]
    fn build_journald_fields_includes_capability_decision_context() {
        let request = test_request();
        let peer = test_peer();
        let error = AppError::new(ErrorCode::CapabilityDenied, "required capability missing")
            .with_detail("required_capability", "service_control");
        let event = AuditEvent {
            request: &request,
            peer: &peer,
            stage: AuditStage::Completed,
            decision: AuditDecision::Deny,
            result: "error",
            error: Some(&error),
        };

        let fields = build_journald_fields(&event, false)
            .into_iter()
            .map(|field| field.into_string().expect("utf8"))
            .collect::<Vec<_>>();

        assert!(fields.contains(&"ADMINBOT_POLICY_DECISION=allow".to_string()));
        assert!(fields.contains(&"ADMINBOT_CAPABILITY_DECISION=deny".to_string()));
        assert!(fields.contains(&"ADMINBOT_REQUIRED_CAPABILITY=service_control".to_string()));
    }

    #[test]
    fn build_journald_fields_includes_policy_section_for_policy_denial() {
        let request = test_request();
        let peer = test_peer();
        let error = AppError::new(ErrorCode::PolicyDenied, "mount not allowed by policy")
            .with_detail("policy_section", "filesystem.allowed_mounts")
            .with_detail("mount", "/secret");
        let event = AuditEvent {
            request: &request,
            peer: &peer,
            stage: AuditStage::Completed,
            decision: AuditDecision::Deny,
            result: "error",
            error: Some(&error),
        };

        let fields = build_journald_fields(&event, false)
            .into_iter()
            .map(|field| field.into_string().expect("utf8"))
            .collect::<Vec<_>>();

        assert!(fields.contains(&"ADMINBOT_POLICY_SECTION=filesystem.allowed_mounts".to_string()));
        assert!(!fields.iter().any(|field| field.contains("/secret")));
    }

    #[test]
    fn success_result_marks_dry_run_requests_explicitly() {
        let mut request = test_request();
        request.dry_run = true;

        assert_eq!(success_result(&request), "dry_run_ok");
    }

    #[test]
    fn fallback_json_preserves_existing_error_shape() {
        let request = test_request();
        let peer = test_peer();
        let error = AppError::new(ErrorCode::ExecutionFailed, "write failed");
        let event = AuditEvent {
            request: &request,
            peer: &peer,
            stage: AuditStage::Completed,
            decision: AuditDecision::Deny,
            result: "error",
            error: Some(&error),
        };

        let json = fallback_json(&event, false);
        assert_eq!(json["request_id"], "test-request-id");
        assert_eq!(json["action"], "system.status");
        assert_eq!(json["stage"], "completed");
        assert_eq!(json["dry_run"], false);
        assert_eq!(json["decision"], "deny");
        assert_eq!(json["policy"]["decision"], "allow");
        assert_eq!(json["capability"]["decision"], "allow");
        assert_eq!(json["result"], "error");
        assert_eq!(json["error"]["code"], "execution_failed");
        assert_eq!(json["error"]["message"], "write failed");
    }

    #[test]
    fn repetitive_invalid_request_errors_are_suppressed_after_burst_limit() {
        let logger = AuditLogger::default();
        let request = test_request();
        let peer = test_peer();
        let error = AppError::new(ErrorCode::ValidationError, "invalid request payload");
        let event = AuditEvent {
            request: &request,
            peer: &peer,
            stage: AuditStage::Completed,
            decision: AuditDecision::Deny,
            result: "error",
            error: Some(&error),
        };
        let now = Instant::now();

        for offset in 0..AUDIT_REPETITIVE_ERROR_BURST_LIMIT {
            let emission =
                logger.evaluate_flood_control(&event, now + Duration::from_millis(offset as u64));
            assert!(matches!(
                emission,
                AuditEmission::Emit {
                    suppression_notice: false
                }
            ));
        }

        let suppression_notice = logger.evaluate_flood_control(
            &event,
            now + Duration::from_millis(AUDIT_REPETITIVE_ERROR_BURST_LIMIT as u64),
        );
        assert!(matches!(
            suppression_notice,
            AuditEmission::Emit {
                suppression_notice: true
            }
        ));

        let suppressed = logger.evaluate_flood_control(
            &event,
            now + Duration::from_millis((AUDIT_REPETITIVE_ERROR_BURST_LIMIT + 1) as u64),
        );
        assert!(matches!(suppressed, AuditEmission::Suppress));
    }

    #[test]
    fn repetitive_error_suppression_resets_after_window() {
        let logger = AuditLogger::default();
        let request = test_request();
        let peer = test_peer();
        let error = AppError::new(ErrorCode::ValidationError, "invalid request payload");
        let event = AuditEvent {
            request: &request,
            peer: &peer,
            stage: AuditStage::Completed,
            decision: AuditDecision::Deny,
            result: "error",
            error: Some(&error),
        };
        let now = Instant::now();

        for offset in 0..=AUDIT_REPETITIVE_ERROR_BURST_LIMIT {
            let _ =
                logger.evaluate_flood_control(&event, now + Duration::from_millis(offset as u64));
        }

        let emission = logger.evaluate_flood_control(&event, now + AUDIT_REPETITIVE_ERROR_WINDOW);
        assert!(matches!(
            emission,
            AuditEmission::Emit {
                suppression_notice: false
            }
        ));
    }

    #[test]
    fn success_events_are_never_subject_to_repetitive_error_suppression() {
        let logger = AuditLogger::default();
        let request = test_request();
        let peer = test_peer();
        let event = AuditEvent {
            request: &request,
            peer: &peer,
            stage: AuditStage::Completed,
            decision: AuditDecision::Allow,
            result: "ok",
            error: None,
        };

        for offset in 0..10_u64 {
            let emission = logger
                .evaluate_flood_control(&event, Instant::now() + Duration::from_millis(offset));
            assert!(matches!(
                emission,
                AuditEmission::Emit {
                    suppression_notice: false
                }
            ));
        }
    }

    #[test]
    fn suppression_notice_is_encoded_in_fallback_json() {
        let request = test_request();
        let peer = test_peer();
        let error = AppError::new(ErrorCode::ValidationError, "invalid request payload");
        let event = AuditEvent {
            request: &request,
            peer: &peer,
            stage: AuditStage::Completed,
            decision: AuditDecision::Deny,
            result: "error",
            error: Some(&error),
        };

        let json = fallback_json(&event, true);
        assert_eq!(json["audit"]["suppression_active"], true);
        assert_eq!(
            json["audit"]["suppression_burst_limit"],
            AUDIT_REPETITIVE_ERROR_BURST_LIMIT
        );
        assert_eq!(
            json["audit"]["suppression_window_ms"],
            json!(AUDIT_REPETITIVE_ERROR_WINDOW.as_millis())
        );
    }

    fn test_request() -> Request {
        Request {
            version: 1,
            request_id: "test-request-id".to_string(),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "local-cli".to_string(),
            },
            action: "system.status".to_string(),
            params: serde_json::Map::new(),
            dry_run: false,
            timeout_ms: 3000,
        }
    }

    fn test_peer() -> PeerCredentials {
        PeerCredentials {
            uid: 1000,
            gid: 1000,
            pid: 4242,
            supplementary_gids: Vec::new(),
            unix_user: Some("tester".to_string()),
        }
    }
}
