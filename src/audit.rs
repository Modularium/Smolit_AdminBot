use serde_json::json;

use crate::error::AppError;
use crate::peer::PeerCredentials;
use crate::types::Request;

#[derive(Debug, Default)]
pub struct AuditLogger;

impl AuditLogger {
    pub fn log_success(&self, request: &Request, peer: &PeerCredentials) {
        let entry = json!({
            "request_id": request.request_id,
            "action": request.action,
            "requested_by": {
                "type": request.requested_by.origin_type,
                "id": request.requested_by.id
            },
            "peer": {
                "uid": peer.uid,
                "gid": peer.gid,
                "pid": peer.pid
            },
            "decision": "allow",
            "result": "ok"
        });
        eprintln!("{entry}");
    }

    pub fn log_error(&self, request: &Request, peer: &PeerCredentials, error: &AppError) {
        let entry = json!({
            "request_id": request.request_id,
            "action": request.action,
            "requested_by": {
                "type": request.requested_by.origin_type,
                "id": request.requested_by.id
            },
            "peer": {
                "uid": peer.uid,
                "gid": peer.gid,
                "pid": peer.pid
            },
            "decision": "deny",
            "error": {
                "code": error.code,
                "message": error.message,
            }
        });
        eprintln!("{entry}");
    }
}
