use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::ErrorBody;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestOriginType {
    Human,
    Agent,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedBy {
    #[serde(rename = "type")]
    pub origin_type: RequestOriginType,
    pub id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u32,
    pub request_id: String,
    pub requested_by: RequestedBy,
    pub action: String,
    pub params: Map<String, Value>,
    pub dry_run: bool,
    pub timeout_ms: u64,
}

impl Request {
    pub fn params_value(&self) -> Value {
        Value::Object(self.params.clone())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SuccessResponse {
    pub request_id: String,
    pub status: String,
    pub result: Value,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ErrorResponse {
    pub request_id: String,
    pub status: String,
    pub error: ErrorBody,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Response {
    Success(SuccessResponse),
    Error(ErrorResponse),
}

impl Response {
    pub fn success(request_id: impl Into<String>, result: Value) -> Self {
        Self::Success(SuccessResponse {
            request_id: request_id.into(),
            status: "ok".to_string(),
            result,
        })
    }

    pub fn error(request_id: impl Into<String>, error: ErrorBody) -> Self {
        Self::Error(ErrorResponse {
            request_id: request_id.into(),
            status: "error".to_string(),
            error,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{AppError, ErrorCode};

    #[test]
    fn request_roundtrip_preserves_required_fields() {
        let request = Request {
            version: 1,
            request_id: "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62571".to_string(),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "local-cli".to_string(),
            },
            action: "system.status".to_string(),
            params: Map::new(),
            dry_run: false,
            timeout_ms: 3000,
        };

        let encoded = serde_json::to_value(&request).expect("serialize request");
        assert_eq!(encoded["version"], 1);
        assert_eq!(encoded["request_id"], request.request_id);
        assert_eq!(encoded["requested_by"]["type"], "human");
        assert_eq!(encoded["requested_by"]["id"], "local-cli");
        assert_eq!(encoded["action"], "system.status");
        assert_eq!(encoded["dry_run"], false);
        assert_eq!(encoded["timeout_ms"], 3000);

        let decoded: Request = serde_json::from_value(encoded).expect("deserialize request");
        assert_eq!(decoded.version, 1);
        assert!(matches!(
            decoded.requested_by.origin_type,
            RequestOriginType::Human
        ));
    }

    #[test]
    fn request_rejects_unknown_fields() {
        let payload = serde_json::json!({
            "version": 1,
            "request_id": "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62571",
            "requested_by": {
                "type": "human",
                "id": "local-cli",
                "extra": true
            },
            "action": "system.status",
            "params": {},
            "dry_run": false,
            "timeout_ms": 3000
        });

        let error = serde_json::from_value::<Request>(payload).expect_err("unknown field");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn request_rejects_unknown_origin_type() {
        let payload = serde_json::json!({
            "version": 1,
            "request_id": "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62571",
            "requested_by": {
                "type": "service",
                "id": "local-cli"
            },
            "action": "system.status",
            "params": {},
            "dry_run": false,
            "timeout_ms": 3000
        });

        let error = serde_json::from_value::<Request>(payload).expect_err("invalid enum");
        assert!(error.to_string().contains("unknown variant"));
    }

    #[test]
    fn success_response_serializes_final_contract() {
        let response = Response::success(
            "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62571",
            serde_json::json!({"hostname": "node-1"}),
        );

        let encoded = serde_json::to_value(&response).expect("serialize response");
        assert_eq!(
            encoded["request_id"],
            "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62571"
        );
        assert_eq!(encoded["status"], "ok");
        assert_eq!(encoded["result"]["hostname"], "node-1");
    }

    #[test]
    fn error_response_serializes_final_contract() {
        let error = AppError::new(ErrorCode::ValidationError, "invalid request")
            .with_detail("field", "action")
            .retryable(false);
        let response = Response::error("2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62571", error.to_body());

        let encoded = serde_json::to_value(&response).expect("serialize error response");
        assert_eq!(
            encoded["request_id"],
            "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62571"
        );
        assert_eq!(encoded["status"], "error");
        assert_eq!(encoded["error"]["code"], "validation_error");
        assert_eq!(encoded["error"]["message"], "invalid request");
        assert_eq!(encoded["error"]["details"]["field"], "action");
        assert_eq!(encoded["error"]["retryable"], false);
    }
}
