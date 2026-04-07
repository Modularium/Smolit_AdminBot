use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub enum ErrorCode {
    ValidationError,
    UnsupportedVersion,
    Unauthorized,
    Forbidden,
    CapabilityDenied,
    PolicyDenied,
    PreconditionFailed,
    CooldownActive,
    RateLimited,
    ReplayDetected,
    BackendUnavailable,
    ExecutionFailed,
    Timeout,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub message: String,
    pub details: Map<String, Value>,
    pub retryable: bool,
}

#[derive(Debug, Clone)]
pub struct AppError {
    pub code: ErrorCode,
    pub message: String,
    pub details: Map<String, Value>,
    pub retryable: bool,
}

pub type AppResult<T> = Result<T, AppError>;

impl AppError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: Map::new(),
            retryable: false,
        }
    }

    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    pub fn retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    pub fn to_body(&self) -> ErrorBody {
        ErrorBody {
            code: self.code,
            message: self.message.clone(),
            details: self.details.clone(),
            retryable: self.retryable,
        }
    }
}

impl Display for AppError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, self.code)
    }
}

impl std::error::Error for AppError {}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            ErrorCode::ValidationError => "validation_error",
            ErrorCode::UnsupportedVersion => "unsupported_version",
            ErrorCode::Unauthorized => "unauthorized",
            ErrorCode::Forbidden => "forbidden",
            ErrorCode::CapabilityDenied => "capability_denied",
            ErrorCode::PolicyDenied => "policy_denied",
            ErrorCode::PreconditionFailed => "precondition_failed",
            ErrorCode::CooldownActive => "cooldown_active",
            ErrorCode::RateLimited => "rate_limited",
            ErrorCode::ReplayDetected => "replay_detected",
            ErrorCode::BackendUnavailable => "backend_unavailable",
            ErrorCode::ExecutionFailed => "execution_failed",
            ErrorCode::Timeout => "timeout",
        };

        f.write_str(value)
    }
}
