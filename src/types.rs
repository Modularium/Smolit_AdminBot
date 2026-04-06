use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::ErrorBody;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestOriginType {
    Human,
    Agent,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedBy {
    #[serde(rename = "type")]
    pub origin_type: RequestOriginType,
    pub id: String,
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Serialize)]
pub struct SuccessResponse {
    pub request_id: String,
    pub status: &'static str,
    pub result: Value,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub request_id: String,
    pub status: &'static str,
    pub error: ErrorBody,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Response {
    Success(SuccessResponse),
    Error(ErrorResponse),
}

impl Response {
    pub fn success(request_id: impl Into<String>, result: Value) -> Self {
        Self::Success(SuccessResponse {
            request_id: request_id.into(),
            status: "ok",
            result,
        })
    }

    pub fn error(request_id: impl Into<String>, error: ErrorBody) -> Self {
        Self::Error(ErrorResponse {
            request_id: request_id.into(),
            status: "error",
            error,
        })
    }
}
