use std::sync::Mutex;

use serde_json::Value;

use crate::actions::{self, ActionHandler, ActionMetadata};
use crate::audit::AuditLogger;
use crate::error::{AppError, ErrorCode};
use crate::peer::PeerCredentials;
use crate::policy::PolicyEngine;
use crate::types::{Request, Response};

#[derive(Debug)]
struct MutationLimiter {
    max_parallel_mutations: usize,
    active_mutations: Mutex<usize>,
}

#[derive(Debug)]
struct MutationPermit<'a> {
    limiter: &'a MutationLimiter,
}

#[derive(Debug)]
pub struct App {
    policy: PolicyEngine,
    audit: AuditLogger,
    mutation_limiter: MutationLimiter,
}

impl MutationLimiter {
    fn new(max_parallel_mutations: u32) -> Self {
        Self {
            max_parallel_mutations: max_parallel_mutations.max(1) as usize,
            active_mutations: Mutex::new(0),
        }
    }

    fn try_acquire(&self) -> Result<MutationPermit<'_>, AppError> {
        let mut active = self
            .active_mutations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *active >= self.max_parallel_mutations {
            return Err(AppError::new(
                ErrorCode::RateLimited,
                "maximum parallel mutating actions exceeded",
            )
            .with_detail("max_parallel_mutations", self.max_parallel_mutations as u64)
            .retryable(true));
        }

        *active += 1;
        Ok(MutationPermit { limiter: self })
    }
}

impl Drop for MutationPermit<'_> {
    fn drop(&mut self) {
        let mut active = self
            .limiter
            .active_mutations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *active = active.saturating_sub(1);
    }
}

impl App {
    pub fn new(policy: PolicyEngine) -> Self {
        let mutation_limiter = MutationLimiter::new(policy.constraints().max_parallel_mutations);
        Self {
            policy,
            audit: AuditLogger,
            mutation_limiter,
        }
    }

    pub fn policy(&self) -> &PolicyEngine {
        &self.policy
    }

    pub fn handle_request(&self, request: Request, peer: PeerCredentials) -> Response {
        self.audit.log_received(&request, &peer);
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
        let _mutation_permit = self.try_acquire_mutation_permit(request, &metadata)?;
        actions::execute(self, request)
    }

    fn try_acquire_mutation_permit<'a>(
        &'a self,
        request: &Request,
        metadata: &ActionMetadata,
    ) -> Result<Option<MutationPermit<'a>>, AppError> {
        if requires_mutation_permit(request, metadata) {
            return self.mutation_limiter.try_acquire().map(Some);
        }

        Ok(None)
    }

    #[cfg(test)]
    fn hold_mutation_slot_for_test(&self) -> Result<MutationPermit<'_>, AppError> {
        self.mutation_limiter.try_acquire()
    }
}

fn requires_mutation_permit(request: &Request, metadata: &ActionMetadata) -> bool {
    !request.dry_run && matches!(metadata.handler, ActionHandler::ServiceRestart)
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::thread;
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

    #[test]
    fn service_restart_not_found_unit_reports_precondition_failed() {
        let unit = "adminbot-missing-integration.service";
        let app = App::new(service_restart_policy_for_current_user(unit));
        let request = service_restart_request(unit, false);

        let response = app.handle_request(request, current_peer());
        match response {
            Response::Error(error) => {
                assert_eq!(
                    serde_json::to_value(error.error.code).unwrap(),
                    json!("precondition_failed")
                );
                assert_eq!(error.error.details.get("unit"), Some(&json!(unit)));
            }
            Response::Success(success) => panic!("unexpected success response: {:?}", success),
        }
    }

    #[test]
    #[ignore = "requires ADMINBOT_TEST_SERVICE_UNIT and a polkit-authorized target setup"]
    fn service_restart_integration_uses_systemd_dbus_and_polkit() {
        let unit = integration_test_service_unit();
        let app = App::new(service_restart_policy_for_current_user(&unit));
        let request = service_restart_request(&unit, false);

        let response = app.handle_request(request, current_peer());
        match response {
            Response::Success(success) => {
                assert_eq!(success.result["unit"], json!(unit));
                assert_eq!(success.result["mode"], json!("safe"));
                assert!(success.result["job_object_path"].as_str().is_some());
                assert!(success.result["pre_state"]["active_state"].is_string());
                assert!(success.result["pre_state"]["sub_state"].is_string());
                assert!(success.result["pre_state"]["load_state"].is_string());
                assert!(success.result["post_state"]["active_state"].is_string());
                assert!(success.result["post_state"]["sub_state"].is_string());
                assert!(success.result["post_state"]["load_state"].is_string());
            }
            Response::Error(error) => panic!("unexpected error response: {:?}", error),
        }
    }

    #[test]
    fn mutation_limiter_allows_up_to_configured_parallel_limit() {
        let app = App::new(service_restart_policy_with_parallel_limit(
            "nginx.service",
            2,
        ));

        let first = app.hold_mutation_slot_for_test().expect("first slot");
        let second = app.hold_mutation_slot_for_test().expect("second slot");
        let error = app
            .hold_mutation_slot_for_test()
            .expect_err("third slot must fail");
        assert_eq!(error.code, crate::error::ErrorCode::RateLimited);
        assert_eq!(error.details.get("max_parallel_mutations"), Some(&json!(2)));

        drop(first);
        let third = app
            .hold_mutation_slot_for_test()
            .expect("slot should be released after drop");
        drop(third);
        drop(second);
    }

    #[test]
    fn service_restart_is_rejected_when_mutation_limit_is_exhausted() {
        let unit = "nginx.service";
        let app = App::new(service_restart_policy_with_parallel_limit(unit, 1));
        let _permit = app
            .hold_mutation_slot_for_test()
            .expect("hold mutation slot");

        let response = app.handle_request(service_restart_request(unit, false), current_peer());
        match response {
            Response::Error(error) => {
                assert_eq!(error.error.code, crate::error::ErrorCode::RateLimited);
                assert_eq!(
                    error.error.details.get("max_parallel_mutations"),
                    Some(&json!(1))
                );
                assert_eq!(error.error.retryable, true);
            }
            Response::Success(success) => panic!("unexpected success response: {:?}", success),
        }
    }

    #[test]
    fn parallel_mutation_requests_over_limit_are_rejected() {
        let unit = "nginx.service";
        let app = Arc::new(App::new(service_restart_policy_with_parallel_limit(
            unit, 1,
        )));
        let barrier = Arc::new(std::sync::Barrier::new(3));

        let mut handles = Vec::new();
        for _ in 0..2 {
            let app = Arc::clone(&app);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let _permit = app.hold_mutation_slot_for_test().ok();
                barrier.wait();
                let response =
                    app.handle_request(service_restart_request(unit, false), current_peer());
                barrier.wait();
                response
            }));
        }

        barrier.wait();
        barrier.wait();

        let mut codes = Vec::new();
        for handle in handles {
            match handle.join().expect("thread join") {
                Response::Error(error) => {
                    codes.push(error.error.code);
                }
                Response::Success(success) => panic!("unexpected success response: {:?}", success),
            }
        }

        assert_eq!(codes.len(), 2);
        assert!(codes
            .into_iter()
            .all(|code| code == crate::error::ErrorCode::RateLimited));
    }

    #[test]
    fn network_interface_status_returns_loopback() {
        let app = App::new(policy_for_current_user(
            r#"
version = 1

[clients.local_cli]
unix_user = "__USER__"
allowed_capabilities = ["read_basic"]

[actions]
allowed = ["network.interface_status"]
denied = []
"#,
        ));

        let request = Request {
            version: 1,
            request_id: "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62573".to_string(),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            action: "network.interface_status".to_string(),
            params: serde_json::from_value(json!({
                "interfaces": ["lo"]
            }))
            .expect("params"),
            dry_run: false,
            timeout_ms: 3000,
        };

        let response = app.handle_request(request, current_peer());
        match response {
            Response::Success(success) => {
                let interfaces = success.result["interfaces"]
                    .as_array()
                    .expect("interfaces array");
                assert_eq!(interfaces.len(), 1);
                assert_eq!(interfaces[0]["name"], "lo");
                assert!(interfaces[0]["state"].is_string());
            }
            Response::Error(error) => panic!("unexpected error response: {:?}", error),
        }
    }

    #[test]
    fn service_status_returns_structured_fields_for_existing_unit() {
        let app = App::new(policy_for_current_user(
            r#"
version = 1

[clients.local_cli]
unix_user = "__USER__"
allowed_capabilities = ["service_read"]

[actions]
allowed = ["service.status"]
denied = []
"#,
        ));

        let request = Request {
            version: 1,
            request_id: "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62574".to_string(),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            action: "service.status".to_string(),
            params: serde_json::from_value(json!({
                "unit": existing_service_unit()
            }))
            .expect("params"),
            dry_run: false,
            timeout_ms: 3000,
        };

        let response = app.handle_request(request, current_peer());
        match response {
            Response::Success(success) => {
                assert!(success.result["unit"].is_string());
                assert!(success.result["active_state"].is_string());
                assert!(success.result["sub_state"].is_string());
                assert!(success.result["load_state"].is_string());
                assert!(success.result["unit_file_state"].is_string());
            }
            Response::Error(error) => panic!("unexpected error response: {:?}", error),
        }
    }

    #[test]
    fn service_status_rejects_invalid_unit_name() {
        let app = App::new(policy_for_current_user(
            r#"
version = 1

[clients.local_cli]
unix_user = "__USER__"
allowed_capabilities = ["service_read"]

[actions]
allowed = ["service.status"]
denied = []
"#,
        ));

        let request = Request {
            version: 1,
            request_id: "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62575".to_string(),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            action: "service.status".to_string(),
            params: serde_json::from_value(json!({
                "unit": "invalid-unit"
            }))
            .expect("params"),
            dry_run: false,
            timeout_ms: 3000,
        };

        let response = app.handle_request(request, current_peer());
        match response {
            Response::Error(error) => {
                assert_eq!(
                    serde_json::to_value(error.error.code).unwrap(),
                    json!("validation_error")
                );
            }
            Response::Success(success) => panic!("unexpected success response: {:?}", success),
        }
    }

    #[test]
    fn journal_query_denies_unit_not_allowed_by_policy() {
        let app = App::new(policy_for_current_user(
            r#"
version = 1

[clients.local_cli]
unix_user = "__USER__"
allowed_capabilities = ["read_sensitive"]

[actions]
allowed = ["journal.query"]
denied = []

[service_control]
allowed_units = ["nginx.service"]
"#,
        ));

        let request = Request {
            version: 1,
            request_id: "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62575".to_string(),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            action: "journal.query".to_string(),
            params: serde_json::from_value(json!({
                "unit": "sshd.service",
                "limit": 10
            }))
            .expect("params"),
            dry_run: false,
            timeout_ms: 3000,
        };

        let response = app.handle_request(request, current_peer());
        match response {
            Response::Error(error) => {
                assert_eq!(
                    serde_json::to_value(error.error.code).unwrap(),
                    json!("policy_denied")
                );
                assert_eq!(
                    error.error.details.get("policy_section"),
                    Some(&json!("service_control.allowed_units"))
                );
            }
            Response::Success(success) => panic!("unexpected success response: {:?}", success),
        }
    }

    #[test]
    fn system_health_returns_expected_check_set() {
        let app = App::new(policy_for_current_user(
            r#"
version = 1

[clients.local_cli]
unix_user = "__USER__"
allowed_capabilities = ["read_basic"]

[actions]
allowed = ["system.health"]
denied = []
"#,
        ));

        let request = Request {
            version: 1,
            request_id: "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62576".to_string(),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            action: "system.health".to_string(),
            params: serde_json::from_value(json!({})).expect("params"),
            dry_run: false,
            timeout_ms: 3000,
        };

        let response = app.handle_request(request, current_peer());
        match response {
            Response::Success(success) => {
                assert!(success.result["overall_status"].is_string());
                let checks = success.result["checks"].as_array().expect("checks array");
                assert_eq!(checks.len(), 4);

                let names: Vec<&str> = checks
                    .iter()
                    .map(|check| check["name"].as_str().expect("check name"))
                    .collect();
                assert_eq!(names, vec!["cpu", "memory", "disk_root", "swap"]);

                assert!(success.result["warnings"].is_array());
            }
            Response::Error(error) => panic!("unexpected error response: {:?}", error),
        }
    }

    #[test]
    fn system_health_overall_status_is_deterministic() {
        let app = App::new(policy_for_current_user(
            r#"
version = 1

[clients.local_cli]
unix_user = "__USER__"
allowed_capabilities = ["read_basic"]

[actions]
allowed = ["system.health"]
denied = []
"#,
        ));

        let request = Request {
            version: 1,
            request_id: "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62577".to_string(),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            action: "system.health".to_string(),
            params: serde_json::from_value(json!({})).expect("params"),
            dry_run: false,
            timeout_ms: 3000,
        };

        let response = app.handle_request(request, current_peer());
        match response {
            Response::Success(success) => {
                let overall = success.result["overall_status"]
                    .as_str()
                    .expect("overall status");
                let checks = success.result["checks"].as_array().expect("checks array");

                let has_critical = checks
                    .iter()
                    .any(|check| check["status"].as_str() == Some("critical"));
                let has_warning = checks
                    .iter()
                    .any(|check| check["status"].as_str() == Some("warning"));

                if has_critical {
                    assert_eq!(overall, "critical");
                } else if has_warning {
                    assert_eq!(overall, "degraded");
                } else {
                    assert_eq!(overall, "ok");
                }
            }
            Response::Error(error) => panic!("unexpected error response: {:?}", error),
        }
    }

    #[test]
    fn resource_snapshot_returns_stable_typed_shape() {
        let app = App::new(policy_for_current_user(
            r#"
version = 1

[clients.local_cli]
unix_user = "__USER__"
allowed_capabilities = ["read_basic"]

[actions]
allowed = ["resource.snapshot"]
denied = []
"#,
        ));

        let request = Request {
            version: 1,
            request_id: "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62578".to_string(),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            action: "resource.snapshot".to_string(),
            params: serde_json::from_value(json!({})).expect("params"),
            dry_run: false,
            timeout_ms: 3000,
        };

        let response = app.handle_request(request, current_peer());
        match response {
            Response::Success(success) => {
                let timestamp = success.result["timestamp"].as_str().expect("timestamp");
                let (date, time) = timestamp.split_once('T').expect("rfc3339 separator");
                assert_eq!(date.len(), 10);
                assert!(date.chars().enumerate().all(|(idx, ch)| match idx {
                    4 | 7 => ch == '-',
                    _ => ch.is_ascii_digit(),
                }));
                assert!(time.ends_with('Z'));

                let load_average = success.result["cpu"]["load_average"]
                    .as_array()
                    .expect("cpu load_average");
                assert_eq!(load_average.len(), 3);
                assert!(load_average.iter().all(|value| value.is_number()));

                assert!(success.result["memory"]["total_bytes"].is_u64());
                assert!(success.result["memory"]["used_bytes"].is_u64());
                assert!(success.result["memory"]["available_bytes"].is_u64());

                assert!(success.result["swap"]["total_bytes"].is_u64());
                assert!(success.result["swap"]["used_bytes"].is_u64());

                assert!(success.result["disk"]["root"]["total_bytes"].is_u64());
                assert!(success.result["disk"]["root"]["used_bytes"].is_u64());
                assert!(success.result["disk"]["root"]["available_bytes"].is_u64());
                assert!(success.result["disk"]["root"]["percent_used"].is_number());

                assert!(success.result["net"]["rx_bytes"].is_u64());
                assert!(success.result["net"]["tx_bytes"].is_u64());
            }
            Response::Error(error) => panic!("unexpected error response: {:?}", error),
        }
    }

    #[test]
    fn resource_snapshot_rejects_invalid_include_values() {
        let app = App::new(policy_for_current_user(
            r#"
version = 1

[clients.local_cli]
unix_user = "__USER__"
allowed_capabilities = ["read_basic"]

[actions]
allowed = ["resource.snapshot"]
denied = []
"#,
        ));

        let request = Request {
            version: 1,
            request_id: "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62579".to_string(),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            action: "resource.snapshot".to_string(),
            params: serde_json::from_value(json!({
                "include": ["cpu", "history"]
            }))
            .expect("params"),
            dry_run: false,
            timeout_ms: 3000,
        };

        let response = app.handle_request(request, current_peer());
        match response {
            Response::Error(error) => {
                assert_eq!(
                    serde_json::to_value(error.error.code).unwrap(),
                    json!("validation_error")
                );
            }
            Response::Success(success) => panic!("unexpected success response: {:?}", success),
        }
    }

    #[test]
    fn disk_usage_returns_structured_fields_for_allowed_mount() {
        let app = App::new(policy_for_current_user(
            r#"
version = 1

[clients.local_cli]
unix_user = "__USER__"
allowed_capabilities = ["read_basic"]

[actions]
allowed = ["disk.usage"]
denied = []

[filesystem]
allowed_mounts = ["/"]
"#,
        ));

        let request = Request {
            version: 1,
            request_id: "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62580".to_string(),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            action: "disk.usage".to_string(),
            params: serde_json::from_value(json!({
                "mounts": ["/"]
            }))
            .expect("params"),
            dry_run: false,
            timeout_ms: 3000,
        };

        let response = app.handle_request(request, current_peer());
        match response {
            Response::Success(success) => {
                let mounts = success.result["mounts"].as_array().expect("mounts array");
                assert_eq!(mounts.len(), 1);
                assert_eq!(mounts[0]["path"], "/");
                assert!(mounts[0]["total_bytes"].is_u64());
                assert!(mounts[0]["used_bytes"].is_u64());
                assert!(mounts[0]["available_bytes"].is_u64());
                assert!(mounts[0]["percent_used"].is_number());
            }
            Response::Error(error) => panic!("unexpected error response: {:?}", error),
        }
    }

    #[test]
    fn disk_usage_rejects_mounts_outside_policy_whitelist() {
        let app = App::new(policy_for_current_user(
            r#"
version = 1

[clients.local_cli]
unix_user = "__USER__"
allowed_capabilities = ["read_basic"]

[actions]
allowed = ["disk.usage"]
denied = []

[filesystem]
allowed_mounts = ["/"]
"#,
        ));

        let request = Request {
            version: 1,
            request_id: "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62581".to_string(),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            action: "disk.usage".to_string(),
            params: serde_json::from_value(json!({
                "mounts": ["/var"]
            }))
            .expect("params"),
            dry_run: false,
            timeout_ms: 3000,
        };

        let response = app.handle_request(request, current_peer());
        match response {
            Response::Error(error) => {
                assert_eq!(
                    serde_json::to_value(error.error.code).unwrap(),
                    json!("policy_denied")
                );
                assert_eq!(error.error.details["field"], "params.mounts");
                assert_eq!(error.error.details["mount"], "/var");
                assert_eq!(
                    error.error.details["policy_section"],
                    "filesystem.allowed_mounts"
                );
            }
            Response::Success(success) => panic!("unexpected success response: {:?}", success),
        }
    }

    #[test]
    fn disk_usage_handles_missing_allowed_mount_cleanly() {
        let app = App::new(policy_for_current_user(
            r#"
version = 1

[clients.local_cli]
unix_user = "__USER__"
allowed_capabilities = ["read_basic"]

[actions]
allowed = ["disk.usage"]
denied = []

[filesystem]
allowed_mounts = ["/definitely-missing-adminbot-mount"]
"#,
        ));

        let request = Request {
            version: 1,
            request_id: "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62582".to_string(),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            action: "disk.usage".to_string(),
            params: serde_json::from_value(json!({
                "mounts": ["/definitely-missing-adminbot-mount"]
            }))
            .expect("params"),
            dry_run: false,
            timeout_ms: 3000,
        };

        let response = app.handle_request(request, current_peer());
        match response {
            Response::Error(error) => {
                assert_eq!(
                    serde_json::to_value(error.error.code).unwrap(),
                    json!("execution_failed")
                );
                assert_eq!(error.error.message, "statvfs failed for mount");
                assert_eq!(
                    error.error.details["mount"],
                    "/definitely-missing-adminbot-mount"
                );
            }
            Response::Success(success) => panic!("unexpected success response: {:?}", success),
        }
    }

    #[test]
    fn process_snapshot_returns_small_stable_shape() {
        let app = App::new(policy_for_current_user(
            r#"
version = 1

[clients.local_cli]
unix_user = "__USER__"
allowed_capabilities = ["read_sensitive"]

[actions]
allowed = ["process.snapshot"]
denied = []

[constraints]
process_limit_max = 10
"#,
        ));

        let request = Request {
            version: 1,
            request_id: "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62583".to_string(),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            action: "process.snapshot".to_string(),
            params: serde_json::from_value(json!({
                "top_by": "memory",
                "limit": 5
            }))
            .expect("params"),
            dry_run: false,
            timeout_ms: 3000,
        };

        let response = app.handle_request(request, current_peer());
        match response {
            Response::Success(success) => {
                let processes = success.result["processes"]
                    .as_array()
                    .expect("processes array");
                assert!(!processes.is_empty());
                assert!(processes.len() <= 5);

                for process in processes {
                    assert!(process["pid"].is_u64());
                    assert!(process["name"].as_str().is_some());
                    assert!(process["cpu_percent"].is_number());
                    assert!(process["memory_percent"].is_number());
                    assert!(process["started_at"].as_str().is_some());
                }
            }
            Response::Error(error) => panic!("unexpected error response: {:?}", error),
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

    fn service_restart_policy_for_current_user(unit: &str) -> PolicyEngine {
        service_restart_policy_with_parallel_limit(unit, 1)
    }

    fn service_restart_policy_with_parallel_limit(
        unit: &str,
        max_parallel_mutations: u32,
    ) -> PolicyEngine {
        let template = format!(
            r#"
version = 1

[clients.local_cli]
unix_user = "__USER__"
allowed_capabilities = ["service_control"]

[actions]
allowed = ["service.restart"]
denied = []

[service_control]
allowed_units = ["{unit}"]
restart_cooldown_seconds = 300
max_restarts_per_hour = 3

[constraints]
max_parallel_mutations = {max_parallel_mutations}
"#
        );

        policy_for_current_user(&template)
    }

    fn service_restart_request(unit: &str, dry_run: bool) -> Request {
        Request {
            version: 1,
            request_id: "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62572".to_string(),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            action: "service.restart".to_string(),
            params: serde_json::from_value(json!({
                "unit": unit,
                "mode": "safe",
                "reason": "integration test"
            }))
            .expect("params"),
            dry_run,
            timeout_ms: 3000,
        }
    }

    fn integration_test_service_unit() -> String {
        let unit = env::var("ADMINBOT_TEST_SERVICE_UNIT").expect(
            "ADMINBOT_TEST_SERVICE_UNIT must name a safe restartable *.service unit for the integration test",
        );
        assert!(
            unit.ends_with(".service"),
            "ADMINBOT_TEST_SERVICE_UNIT must end with .service"
        );
        unit
    }

    fn unique_policy_name() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        format!("adminbot-policy-{nanos}.toml")
    }

    fn existing_service_unit() -> &'static str {
        const CANDIDATES: [(&str, &str); 3] = [
            (
                "systemd-journald.service",
                "/lib/systemd/system/systemd-journald.service",
            ),
            ("dbus.service", "/lib/systemd/system/dbus.service"),
            ("ssh.service", "/lib/systemd/system/ssh.service"),
        ];

        for (unit, path) in CANDIDATES {
            if std::path::Path::new(path).exists() {
                return unit;
            }
        }

        panic!("no suitable local service unit found for test")
    }
}
