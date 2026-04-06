use serde_json::Value;

use crate::actions;
use crate::audit::AuditLogger;
use crate::error::AppError;
use crate::peer::PeerCredentials;
use crate::policy::PolicyEngine;
use crate::types::{Request, Response};

#[derive(Debug)]
pub struct App {
    policy: PolicyEngine,
    audit: AuditLogger,
}

impl App {
    pub fn new(policy: PolicyEngine) -> Self {
        Self {
            policy,
            audit: AuditLogger,
        }
    }

    pub fn policy(&self) -> &PolicyEngine {
        &self.policy
    }

    pub fn handle_request(&self, request: Request, peer: PeerCredentials) -> Response {
        match self.execute(&request, &peer) {
            Ok(result) => {
                self.audit.log_success(&request, &peer);
                Response::success(request.request_id, result)
            }
            Err(error) => {
                self.audit.log_error(&request, &peer, &error);
                Response::error(request.request_id, error.to_body())
            }
        }
    }

    fn execute(&self, request: &Request, peer: &PeerCredentials) -> Result<Value, AppError> {
        let metadata = actions::validate_request_shape(request, self)?;
        self.policy.authorize(request, &metadata, peer)?;
        actions::execute(self, request)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::json;

    use super::*;
    use crate::types::{RequestOriginType, RequestedBy};

    #[test]
    fn system_status_success_for_allowed_client() {
        let app = App::new(policy_for_current_user(
            r#"
version = 1

[clients.local_cli]
unix_user = "__USER__"
allowed_capabilities = ["read_basic"]

[actions]
allowed = ["system.status"]
denied = []
"#,
        ));

        let request = Request {
            version: 1,
            request_id: "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62571".to_string(),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            action: "system.status".to_string(),
            params: serde_json::from_value(json!({})).expect("params"),
            dry_run: false,
            timeout_ms: 3000,
        };

        let response = app.handle_request(request, current_peer());
        match response {
            Response::Success(success) => {
                assert_eq!(success.status, "ok");
                assert!(success.result.get("hostname").is_some());
            }
            Response::Error(error) => panic!("unexpected error response: {:?}", error),
        }
    }

    #[test]
    fn policy_denied_when_action_not_allowed() {
        let app = App::new(policy_for_current_user(
            r#"
version = 1

[clients.local_cli]
unix_user = "__USER__"
allowed_capabilities = ["read_basic", "service_control"]

[actions]
allowed = ["system.status"]
denied = []

[service_control]
allowed_units = ["nginx.service"]
restart_cooldown_seconds = 300
max_restarts_per_hour = 3
"#,
        ));

        let request = Request {
            version: 1,
            request_id: "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62572".to_string(),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            action: "service.restart".to_string(),
            params: serde_json::from_value(json!({
                "unit": "nginx.service",
                "mode": "safe",
                "reason": "test"
            }))
            .expect("params"),
            dry_run: true,
            timeout_ms: 3000,
        };

        let response = app.handle_request(request, current_peer());
        match response {
            Response::Error(error) => {
                assert_eq!(
                    serde_json::to_value(error.error.code).unwrap(),
                    json!("policy_denied")
                );
            }
            Response::Success(success) => panic!("unexpected success response: {:?}", success),
        }
    }

    fn current_peer() -> PeerCredentials {
        PeerCredentials {
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            pid: unsafe { libc::getpid() as u32 },
            supplementary_gids: Vec::new(),
            unix_user: std::env::var("USER").ok(),
        }
    }

    fn policy_for_current_user(template: &str) -> PolicyEngine {
        let user = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());
        let content = template.replace("__USER__", &user);
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
        format!("adminbot-policy-{nanos}.toml")
    }
}
