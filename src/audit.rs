use std::ffi::CString;

use libc::iovec;
use serde_json::json;

use crate::error::AppError;
use crate::peer::PeerCredentials;
use crate::types::Request;

#[derive(Debug, Default)]
pub struct AuditLogger;

#[derive(Debug, Clone, Copy)]
enum AuditDecision {
    Allow,
    Deny,
}

#[derive(Debug)]
struct AuditEvent<'a> {
    request: &'a Request,
    peer: &'a PeerCredentials,
    decision: AuditDecision,
    result: &'a str,
    error: Option<&'a AppError>,
}

#[link(name = "systemd")]
unsafe extern "C" {
    fn sd_journal_sendv(iov: *const iovec, n: libc::c_int) -> libc::c_int;
}

impl AuditLogger {
    pub fn log_success(&self, request: &Request, peer: &PeerCredentials) {
        let event = AuditEvent {
            request,
            peer,
            decision: AuditDecision::Allow,
            result: "ok",
            error: None,
        };
        self.log_event(&event);
    }

    pub fn log_error(&self, request: &Request, peer: &PeerCredentials, error: &AppError) {
        let event = AuditEvent {
            request,
            peer,
            decision: AuditDecision::Deny,
            result: "error",
            error: Some(error),
        };
        self.log_event(&event);
    }

    fn log_event(&self, event: &AuditEvent<'_>) {
        let fields = build_journald_fields(event);
        if send_to_journald(&fields).is_err() {
            eprintln!("{}", fallback_json(event));
        }
    }
}

fn build_journald_fields(event: &AuditEvent<'_>) -> Vec<CString> {
    let mut fields = vec![
        cstring_field("MESSAGE", &format_message(event)),
        cstring_field("PRIORITY", priority_value(event)),
        cstring_field("SYSLOG_IDENTIFIER", "adminbotd"),
        cstring_field("ADMINBOT_EVENT_KIND", "audit"),
        cstring_field("ADMINBOT_REQUEST_ID", &event.request.request_id),
        cstring_field("ADMINBOT_ACTION", &event.request.action),
        cstring_field(
            "ADMINBOT_REQUESTED_BY_TYPE",
            requested_by_type(event.request),
        ),
        cstring_field("ADMINBOT_REQUESTED_BY_ID", &event.request.requested_by.id),
        cstring_field("ADMINBOT_PEER_UID", &event.peer.uid.to_string()),
        cstring_field("ADMINBOT_PEER_GID", &event.peer.gid.to_string()),
        cstring_field("ADMINBOT_PEER_PID", &event.peer.pid.to_string()),
        cstring_field("ADMINBOT_DECISION", decision_value(event.decision)),
        cstring_field("ADMINBOT_RESULT", event.result),
    ];

    if let Some(error) = event.error {
        fields.push(cstring_field(
            "ADMINBOT_ERROR_CODE",
            &error.code.to_string(),
        ));
        fields.push(cstring_field("ADMINBOT_ERROR_MESSAGE", &error.message));
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

fn fallback_json(event: &AuditEvent<'_>) -> serde_json::Value {
    let mut entry = json!({
        "request_id": event.request.request_id,
        "action": event.request.action,
        "requested_by": {
            "type": event.request.requested_by.origin_type,
            "id": event.request.requested_by.id
        },
        "peer": {
            "uid": event.peer.uid,
            "gid": event.peer.gid,
            "pid": event.peer.pid
        },
        "decision": decision_value(event.decision),
        "result": event.result
    });

    if let Some(error) = event.error {
        entry["error"] = json!({
            "code": error.code,
            "message": error.message,
        });
    }

    entry
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
        AuditDecision::Allow => "allow",
        AuditDecision::Deny => "deny",
    }
}

fn priority_value(event: &AuditEvent<'_>) -> &'static str {
    match event.decision {
        AuditDecision::Allow => "6",
        AuditDecision::Deny => "4",
    }
}

fn format_message(event: &AuditEvent<'_>) -> String {
    match event.error {
        Some(error) => format!(
            "adminbot audit deny action={} request_id={} error_code={}",
            event.request.action, event.request.request_id, error.code
        ),
        None => format!(
            "adminbot audit allow action={} request_id={}",
            event.request.action, event.request.request_id
        ),
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
            decision: AuditDecision::Allow,
            result: "ok",
            error: None,
        };

        let fields = build_journald_fields(&event)
            .into_iter()
            .map(|field| field.into_string().expect("utf8"))
            .collect::<Vec<_>>();

        assert!(fields.contains(&"PRIORITY=6".to_string()));
        assert!(fields.contains(&"SYSLOG_IDENTIFIER=adminbotd".to_string()));
        assert!(fields.contains(&"ADMINBOT_REQUEST_ID=test-request-id".to_string()));
        assert!(fields.contains(&"ADMINBOT_ACTION=system.status".to_string()));
        assert!(fields.contains(&"ADMINBOT_DECISION=allow".to_string()));
        assert!(fields.contains(&"ADMINBOT_RESULT=ok".to_string()));
    }

    #[test]
    fn build_journald_fields_contains_error_metadata() {
        let request = test_request();
        let peer = test_peer();
        let error = AppError::new(ErrorCode::PolicyDenied, "action denied");
        let event = AuditEvent {
            request: &request,
            peer: &peer,
            decision: AuditDecision::Deny,
            result: "error",
            error: Some(&error),
        };

        let fields = build_journald_fields(&event)
            .into_iter()
            .map(|field| field.into_string().expect("utf8"))
            .collect::<Vec<_>>();

        assert!(fields.contains(&"PRIORITY=4".to_string()));
        assert!(fields.contains(&"ADMINBOT_DECISION=deny".to_string()));
        assert!(fields.contains(&"ADMINBOT_ERROR_CODE=policy_denied".to_string()));
        assert!(fields.contains(&"ADMINBOT_ERROR_MESSAGE=action denied".to_string()));
    }

    #[test]
    fn fallback_json_preserves_existing_error_shape() {
        let request = test_request();
        let peer = test_peer();
        let error = AppError::new(ErrorCode::ExecutionFailed, "write failed");
        let event = AuditEvent {
            request: &request,
            peer: &peer,
            decision: AuditDecision::Deny,
            result: "error",
            error: Some(&error),
        };

        let json = fallback_json(&event);
        assert_eq!(json["request_id"], "test-request-id");
        assert_eq!(json["action"], "system.status");
        assert_eq!(json["decision"], "deny");
        assert_eq!(json["result"], "error");
        assert_eq!(json["error"]["code"], "execution_failed");
        assert_eq!(json["error"]["message"], "write failed");
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
