use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::actions::{self, ActionHandler, ActionMetadata};
use crate::audit::AuditLogger;
use crate::error::{AppError, ErrorCode};
use crate::peer::PeerCredentials;
use crate::policy::{PolicyEngine, ReplayProtectionScope};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestClass {
    Read,
    Mutate,
}

#[derive(Debug, Clone, Copy)]
struct RateLimitConfig {
    window: Duration,
    per_peer_limit: usize,
    global_limit: usize,
}

#[derive(Debug, Clone, Copy)]
struct TokenBucketConfig {
    refill_per_second: f64,
    burst: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PeerRateKey {
    uid: u32,
    gid: u32,
}

#[derive(Debug, Default)]
struct RateLimitWindow {
    hits: VecDeque<Instant>,
}

#[derive(Debug, Clone, Copy)]
struct TokenBucketState {
    tokens: f64,
    last_refill: Instant,
}

#[derive(Debug, Default)]
struct RequestRateLimiterState {
    global_read: RateLimitWindow,
    global_mutate: RateLimitWindow,
    per_peer_read: HashMap<PeerRateKey, RateLimitWindow>,
    per_peer_mutate: HashMap<PeerRateKey, RateLimitWindow>,
    per_identity: HashMap<String, TokenBucketState>,
    per_identity_tool: HashMap<IdentityToolRateKey, TokenBucketState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct IdentityToolRateKey {
    identity: String,
    tool: String,
}

#[derive(Debug)]
struct RequestRateLimiter {
    read: RateLimitConfig,
    mutate: RateLimitConfig,
    identity: Option<TokenBucketConfig>,
    identity_tool: Option<TokenBucketConfig>,
    state: Mutex<RequestRateLimiterState>,
}

#[derive(Debug)]
struct ReplayProtector {
    entries: Mutex<HashMap<ReplayKey, ReplayEntry>>,
    replay_window: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ReplayKey {
    peer_uid: u32,
    peer_gid: u32,
    request_id: String,
}

#[derive(Debug)]
enum ReplayEntry {
    InFlight {
        fingerprint: Vec<u8>,
        started_at: Instant,
    },
    Completed {
        fingerprint: Vec<u8>,
        completed_at: Instant,
    },
}

#[derive(Debug)]
enum ReplayDecision {
    Execute(ReplayReservation),
}

#[derive(Debug)]
struct ReplayReservation {
    key: ReplayKey,
    fingerprint: Vec<u8>,
}

#[derive(Debug)]
struct PreviewProtector {
    entries: Mutex<HashMap<PreviewKey, PreviewEntry>>,
    preview_window: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PreviewKey {
    peer_uid: u32,
    peer_gid: u32,
    action: String,
    correlation_id: String,
}

#[derive(Debug)]
struct PreviewEntry {
    fingerprint: Vec<u8>,
    observed_at: Instant,
}

#[derive(Debug)]
pub struct App {
    policy: PolicyEngine,
    audit: AuditLogger,
    request_rate_limiter: RequestRateLimiter,
    mutation_limiter: MutationLimiter,
    replay_protector: ReplayProtector,
    preview_protector: PreviewProtector,
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

impl RequestRateLimiter {
    fn from_policy(policy: &PolicyEngine) -> Self {
        let constraints = policy.constraints();
        let hardening = policy.rate_limit();
        Self {
            read: RateLimitConfig {
                window: Duration::from_millis(constraints.read_rate_limit_window_ms.max(1)),
                per_peer_limit: constraints.read_requests_per_peer_per_window.max(1) as usize,
                global_limit: constraints.global_read_requests_per_window.max(1) as usize,
            },
            mutate: RateLimitConfig {
                window: Duration::from_millis(constraints.mutate_rate_limit_window_ms.max(1)),
                per_peer_limit: constraints.mutate_requests_per_peer_per_window.max(1) as usize,
                global_limit: constraints.global_mutate_requests_per_window.max(1) as usize,
            },
            identity: hardening.enabled.then_some(TokenBucketConfig {
                refill_per_second: hardening.identity_requests_per_second.max(1) as f64,
                burst: hardening.identity_burst.max(1) as f64,
            }),
            identity_tool: (hardening.enabled && hardening.per_tool_enabled).then_some(
                TokenBucketConfig {
                    refill_per_second: hardening.tool_requests_per_second.max(1) as f64,
                    burst: hardening.tool_burst.max(1) as f64,
                },
            ),
            state: Mutex::new(RequestRateLimiterState::default()),
        }
    }

    fn check(
        &self,
        request_class: RequestClass,
        request: &Request,
        peer: &PeerCredentials,
    ) -> Result<(), AppError> {
        let now = Instant::now();
        let key = PeerRateKey {
            uid: peer.uid,
            gid: peer.gid,
        };
        let identity = rate_limit_identity(peer);
        let tool = request.effective_tool_name().to_string();

        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match request_class {
            RequestClass::Read => {
                let state = &mut *guard;
                apply_rate_limit(
                    &mut state.global_read,
                    &mut state.per_peer_read,
                    self.read,
                    request_class,
                    key,
                    now,
                )?;
            }
            RequestClass::Mutate => {
                let state = &mut *guard;
                apply_rate_limit(
                    &mut state.global_mutate,
                    &mut state.per_peer_mutate,
                    self.mutate,
                    request_class,
                    key,
                    now,
                )?;
            }
        }

        if let Some(config) = self.identity {
            consume_token(
                guard
                    .per_identity
                    .entry(identity.clone())
                    .or_insert_with(|| TokenBucketState::new(config.burst, now)),
                config,
                now,
                request_class,
                "identity",
                &identity,
                request.effective_tool_name(),
            )?;
        }

        if let Some(config) = self.identity_tool {
            let tool_key = IdentityToolRateKey {
                identity: identity.clone(),
                tool: tool.clone(),
            };
            consume_token(
                guard
                    .per_identity_tool
                    .entry(tool_key)
                    .or_insert_with(|| TokenBucketState::new(config.burst, now)),
                config,
                now,
                request_class,
                "identity_tool",
                &identity,
                &tool,
            )?;
        }

        Ok(())
    }
}

impl ReplayProtector {
    fn new(replay_window: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            replay_window,
        }
    }

    fn begin(&self, request: &Request, peer: &PeerCredentials) -> Result<ReplayDecision, AppError> {
        let key = ReplayKey {
            peer_uid: peer.uid,
            peer_gid: peer.gid,
            request_id: request.request_id.clone(),
        };
        let fingerprint = replay_fingerprint(request)?;
        let now = Instant::now();

        let mut guard = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let replay_window = self.replay_window;
        guard.retain(|_, entry| !entry.is_expired(now, replay_window));

        match guard.get(&key) {
            Some(ReplayEntry::InFlight {
                fingerprint: existing,
                ..
            }) => {
                return Err(replay_detected_error(
                    request,
                    self.replay_window,
                    *existing != fingerprint,
                    "in_flight",
                ));
            }
            Some(ReplayEntry::Completed {
                fingerprint: existing,
                ..
            }) => {
                return Err(replay_detected_error(
                    request,
                    self.replay_window,
                    *existing != fingerprint,
                    "completed",
                ));
            }
            None => {}
        }

        guard.insert(
            key.clone(),
            ReplayEntry::InFlight {
                fingerprint: fingerprint.clone(),
                started_at: now,
            },
        );

        Ok(ReplayDecision::Execute(ReplayReservation {
            key,
            fingerprint,
        }))
    }

    fn abort(&self, reservation: &ReplayReservation) {
        let mut guard = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let should_remove = matches!(
            guard.get(&reservation.key),
            Some(ReplayEntry::InFlight { fingerprint, .. }) if *fingerprint == reservation.fingerprint
        );
        if should_remove {
            guard.remove(&reservation.key);
        }
    }

    fn complete(&self, reservation: ReplayReservation, _response: &Response) {
        let mut guard = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.insert(
            reservation.key,
            ReplayEntry::Completed {
                fingerprint: reservation.fingerprint,
                completed_at: Instant::now(),
            },
        );
    }
}

impl ReplayEntry {
    fn is_expired(&self, now: Instant, replay_window: Duration) -> bool {
        let timestamp = match self {
            ReplayEntry::InFlight { started_at, .. } => *started_at,
            ReplayEntry::Completed { completed_at, .. } => *completed_at,
        };
        now.duration_since(timestamp) >= replay_window
    }
}

impl PreviewProtector {
    fn new(preview_window: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            preview_window,
        }
    }

    fn record(&self, request: &Request, peer: &PeerCredentials) -> Result<(), AppError> {
        let key = preview_key(request, peer)?;
        let fingerprint = preview_fingerprint(request)?;
        let now = Instant::now();
        let mut guard = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let preview_window = self.preview_window;
        guard.retain(|_, entry| now.duration_since(entry.observed_at) < preview_window);
        guard.insert(
            key,
            PreviewEntry {
                fingerprint,
                observed_at: now,
            },
        );
        Ok(())
    }

    fn consume(&self, request: &Request, peer: &PeerCredentials) -> Result<(), AppError> {
        let key = preview_key(request, peer)?;
        let fingerprint = preview_fingerprint(request)?;
        let now = Instant::now();
        let mut guard = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let preview_window = self.preview_window;
        guard.retain(|_, entry| now.duration_since(entry.observed_at) < preview_window);

        let Some(existing) = guard.remove(&key) else {
            return Err(AppError::new(
                ErrorCode::PreconditionFailed,
                "mutating request requires a prior preview with the same correlation_id",
            )
            .with_detail("correlation_id", key.correlation_id)
            .with_detail("preview_required", true));
        };

        if existing.fingerprint != fingerprint {
            return Err(AppError::new(
                ErrorCode::PreconditionFailed,
                "preview does not match the requested mutation payload",
            )
            .with_detail("correlation_id", key.correlation_id)
            .with_detail("preview_required", true));
        }

        Ok(())
    }
}

impl App {
    pub fn new(policy: PolicyEngine) -> Self {
        let replay_window = Duration::from_secs(policy.replay_protection().window_seconds.max(1));
        let preview_window =
            Duration::from_secs(policy.mutation_safety().preview_window_seconds.max(1));
        let observability = policy.observability().clone();
        let request_rate_limiter = RequestRateLimiter::from_policy(&policy);
        let mutation_limiter = MutationLimiter::new(policy.constraints().max_parallel_mutations);
        Self {
            policy,
            audit: AuditLogger::new(observability),
            request_rate_limiter,
            mutation_limiter,
            replay_protector: ReplayProtector::new(replay_window),
            preview_protector: PreviewProtector::new(preview_window),
        }
    }

    pub fn policy(&self) -> &PolicyEngine {
        &self.policy
    }

    pub fn handle_request(&self, request: Request, peer: PeerCredentials) -> Response {
        match self.execute(&request, &peer) {
            Ok(response) => {
                self.log_response(&request, &peer, &response);
                response
            }
            Err(error) => {
                self.audit.log_error(&request, &peer, &error);
                Response::error(request.request_id, error.to_body())
            }
        }
    }

    fn execute(&self, request: &Request, peer: &PeerCredentials) -> Result<Response, AppError> {
        let metadata = actions::validate_request_shape(request, self)?;
        self.request_rate_limiter
            .check(classify_request(request, &metadata), request, peer)?;
        self.policy.authorize(request, &metadata, peer)?;

        if requires_replay_protection(&self.policy, request, &metadata) {
            return self.execute_replay_protected_request(request, peer, &metadata);
        }

        self.audit.log_received(request, peer);
        actions::execute(self, request)
            .map(|result| Response::success(request.request_id.clone(), result))
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

    fn execute_replay_protected_request(
        &self,
        request: &Request,
        peer: &PeerCredentials,
        metadata: &ActionMetadata,
    ) -> Result<Response, AppError> {
        if requires_preview_guard(&self.policy, request, metadata) {
            self.preview_protector.consume(request, peer)?;
        }

        let reservation = match self.replay_protector.begin(request, peer)? {
            ReplayDecision::Execute(reservation) => reservation,
        };

        let _mutation_permit = match self.try_acquire_mutation_permit(request, metadata) {
            Ok(Some(permit)) => permit,
            Ok(None) => {
                self.replay_protector.abort(&reservation);
                return Err(AppError::new(
                    ErrorCode::ExecutionFailed,
                    "mutation replay guard expected a mutation permit",
                ));
            }
            Err(error) => {
                self.replay_protector.abort(&reservation);
                return Err(error);
            }
        };

        self.audit.log_received(request, peer);
        match actions::execute(self, request) {
            Ok(result) => {
                if is_preview_request(request, metadata) {
                    self.preview_protector.record(request, peer)?;
                }
                let response = Response::success(request.request_id.clone(), result);
                self.replay_protector.complete(reservation, &response);
                Ok(response)
            }
            Err(error) => {
                let response = Response::error(request.request_id.clone(), error.to_body());
                self.replay_protector.complete(reservation, &response);
                Err(error)
            }
        }
    }

    fn log_response(&self, request: &Request, peer: &PeerCredentials, response: &Response) {
        match response {
            Response::Success(_) => self.audit.log_success(request, peer),
            Response::Error(error) => self.audit.log_error(
                request,
                peer,
                &AppError {
                    code: error.error.code,
                    message: error.error.message.clone(),
                    details: error.error.details.clone(),
                    retryable: error.error.retryable,
                },
            ),
        }
    }
}

fn classify_request(request: &Request, metadata: &ActionMetadata) -> RequestClass {
    if requires_mutation_permit(request, metadata) {
        RequestClass::Mutate
    } else {
        RequestClass::Read
    }
}

fn retain_recent_hits(hits: &mut VecDeque<Instant>, window: Duration, now: Instant) {
    while let Some(oldest) = hits.front().copied() {
        if now.duration_since(oldest) < window {
            break;
        }
        hits.pop_front();
    }
}

fn apply_rate_limit(
    global_window: &mut RateLimitWindow,
    per_peer_windows: &mut HashMap<PeerRateKey, RateLimitWindow>,
    config: RateLimitConfig,
    request_class: RequestClass,
    key: PeerRateKey,
    now: Instant,
) -> Result<(), AppError> {
    retain_recent_hits(&mut global_window.hits, config.window, now);
    if global_window.hits.len() >= config.global_limit {
        return Err(rate_limit_error(
            request_class,
            "global",
            config.global_limit,
            config.window,
        ));
    }

    let peer_window = per_peer_windows.entry(key).or_default();
    retain_recent_hits(&mut peer_window.hits, config.window, now);
    if peer_window.hits.len() >= config.per_peer_limit {
        return Err(rate_limit_error(
            request_class,
            "per_peer",
            config.per_peer_limit,
            config.window,
        ));
    }

    global_window.hits.push_back(now);
    peer_window.hits.push_back(now);
    per_peer_windows.retain(|_, window| !window.hits.is_empty());
    Ok(())
}

fn rate_limit_error(
    request_class: RequestClass,
    scope: &'static str,
    limit: usize,
    window: Duration,
) -> AppError {
    AppError::new(ErrorCode::RateLimited, "request rate limit exceeded")
        .with_detail(
            "request_class",
            match request_class {
                RequestClass::Read => "read",
                RequestClass::Mutate => "mutate",
            },
        )
        .with_detail("scope", scope)
        .with_detail("limit", limit as u64)
        .with_detail("window_ms", window.as_millis() as u64)
        .with_detail("rate_limit_hit", true)
        .retryable(true)
}

impl TokenBucketState {
    fn new(burst: f64, now: Instant) -> Self {
        Self {
            tokens: burst,
            last_refill: now,
        }
    }
}

fn consume_token(
    bucket: &mut TokenBucketState,
    config: TokenBucketConfig,
    now: Instant,
    request_class: RequestClass,
    scope: &'static str,
    identity: &str,
    tool_name: &str,
) -> Result<(), AppError> {
    let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
    bucket.tokens = (bucket.tokens + elapsed * config.refill_per_second).min(config.burst);
    bucket.last_refill = now;
    if bucket.tokens < 1.0 {
        return Err(
            AppError::new(ErrorCode::RateLimited, "request rate limit exceeded")
                .with_detail(
                    "request_class",
                    match request_class {
                        RequestClass::Read => "read",
                        RequestClass::Mutate => "mutate",
                    },
                )
                .with_detail("scope", scope)
                .with_detail("identity", identity)
                .with_detail("tool_name", tool_name)
                .with_detail("rate_limit_hit", true)
                .with_detail("refill_per_second", config.refill_per_second)
                .with_detail("burst", config.burst)
                .retryable(true),
        );
    }
    bucket.tokens -= 1.0;
    Ok(())
}

fn requires_mutation_permit(request: &Request, metadata: &ActionMetadata) -> bool {
    !request.dry_run && matches!(metadata.handler, ActionHandler::ServiceRestart)
}

fn requires_replay_protection(
    policy: &PolicyEngine,
    request: &Request,
    metadata: &ActionMetadata,
) -> bool {
    let config = policy.replay_protection();
    if !config.enabled {
        return false;
    }

    match config.scope {
        ReplayProtectionScope::Mutating => requires_mutation_permit(request, metadata),
        ReplayProtectionScope::All => true,
    }
}

fn is_preview_request(request: &Request, metadata: &ActionMetadata) -> bool {
    request.dry_run && matches!(metadata.handler, ActionHandler::ServiceRestart)
}

fn requires_preview_guard(
    policy: &PolicyEngine,
    request: &Request,
    metadata: &ActionMetadata,
) -> bool {
    policy.mutation_safety().require_preview
        && !request.dry_run
        && matches!(metadata.handler, ActionHandler::ServiceRestart)
}

fn replay_fingerprint(request: &Request) -> Result<Vec<u8>, AppError> {
    serde_json::to_vec(request).map_err(|error| {
        AppError::new(
            ErrorCode::ExecutionFailed,
            "unable to encode mutating request fingerprint",
        )
        .with_detail("source", error.to_string())
    })
}

fn preview_fingerprint(request: &Request) -> Result<Vec<u8>, AppError> {
    serde_json::to_vec(&serde_json::json!({
        "action": request.action,
        "tool_name": request.effective_tool_name(),
        "params": request.params_value(),
    }))
    .map_err(|error| {
        AppError::new(
            ErrorCode::ExecutionFailed,
            "unable to encode preview fingerprint",
        )
        .with_detail("source", error.to_string())
    })
}

fn preview_key(request: &Request, peer: &PeerCredentials) -> Result<PreviewKey, AppError> {
    let correlation_id = request.correlation_id.clone().ok_or_else(|| {
        AppError::new(
            ErrorCode::PreconditionFailed,
            "mutating request requires correlation_id for preview linkage",
        )
        .with_detail("preview_required", true)
    })?;

    Ok(PreviewKey {
        peer_uid: peer.uid,
        peer_gid: peer.gid,
        action: request.action.clone(),
        correlation_id,
    })
}

fn replay_detected_error(
    request: &Request,
    replay_window: Duration,
    fingerprint_mismatch: bool,
    replay_stage: &'static str,
) -> AppError {
    AppError::new(
        ErrorCode::ReplayDetected,
        "request_id was already observed within the replay protection window",
    )
    .with_detail("request_id", request.request_id.clone())
    .with_detail("replay_window_ms", replay_window.as_millis() as u64)
    .with_detail("replay_detected", true)
    .with_detail("replay_stage", replay_stage)
    .with_detail("fingerprint_mismatch", fingerprint_mismatch)
}

fn rate_limit_identity(peer: &PeerCredentials) -> String {
    peer.unix_user
        .as_ref()
        .map(|user| format!("unix_user:{user}"))
        .unwrap_or_else(|| format!("uid:{}:gid:{}", peer.uid, peer.gid))
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
            correlation_id: None,
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            tool_name: None,
            agent_run_id: None,
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
    fn read_requests_are_rate_limited_per_peer() {
        let app = App::new(policy_for_current_user(
            r#"
version = 1

[clients.local_cli]
unix_user = "__USER__"
allowed_capabilities = ["read_basic"]

[actions]
allowed = ["system.status"]
denied = []

[constraints]
read_rate_limit_window_ms = 60000
read_requests_per_peer_per_window = 2
global_read_requests_per_window = 10
"#,
        ));

        let first = app.handle_request(
            system_status_request("2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62593"),
            current_peer(),
        );
        let second = app.handle_request(
            system_status_request("2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62594"),
            current_peer(),
        );
        let third = app.handle_request(
            system_status_request("2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62595"),
            current_peer(),
        );

        assert!(matches!(first, Response::Success(_)));
        assert!(matches!(second, Response::Success(_)));
        match third {
            Response::Error(error) => {
                assert_eq!(error.error.code.to_string(), "rate_limited");
                assert_eq!(
                    error.error.details.get("request_class"),
                    Some(&json!("read"))
                );
                assert_eq!(error.error.details.get("scope"), Some(&json!("per_peer")));
            }
            Response::Success(success) => panic!("unexpected success response: {:?}", success),
        }
    }

    #[test]
    fn read_requests_are_rate_limited_globally_across_peers() {
        let app = App::new(policy_for_current_user(
            r#"
version = 1

[clients.local_cli]
unix_user = "__USER__"
allowed_capabilities = ["read_basic"]

[actions]
allowed = ["system.status"]
denied = []

[constraints]
read_rate_limit_window_ms = 60000
read_requests_per_peer_per_window = 10
global_read_requests_per_window = 2
"#,
        ));

        let first = app.handle_request(
            system_status_request("2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62596"),
            current_peer(),
        );
        let second = app.handle_request(
            system_status_request("2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62597"),
            peer_with_ids(4242, 2424),
        );
        let third = app.handle_request(
            system_status_request("2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62598"),
            peer_with_ids(4343, 3434),
        );

        assert!(matches!(first, Response::Success(_)));
        assert!(matches!(second, Response::Success(_)));
        match third {
            Response::Error(error) => {
                assert_eq!(error.error.code.to_string(), "rate_limited");
                assert_eq!(
                    error.error.details.get("request_class"),
                    Some(&json!("read"))
                );
                assert_eq!(error.error.details.get("scope"), Some(&json!("global")));
            }
            Response::Success(success) => panic!("unexpected success response: {:?}", success),
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
            correlation_id: None,
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            tool_name: None,
            agent_run_id: None,
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
    fn mutating_requests_are_rate_limited_per_peer() {
        let unit = "adminbot-rate-limit-mutate.service";
        let app = App::new(policy_for_current_user(&format!(
            r#"
version = 1

[clients.local_cli]
unix_user = "__USER__"
allowed_capabilities = ["service_control"]

[actions]
allowed = ["service.restart"]
denied = []

[service_control]
allowed_units = ["{unit}", "adminbot-rate-limit-mutate-2.service"]
restart_cooldown_seconds = 0
max_restarts_per_hour = 10

[constraints]
mutate_rate_limit_window_ms = 60000
mutate_requests_per_peer_per_window = 1
global_mutate_requests_per_window = 10
"#
        )));

        let first = app.handle_request(service_restart_request(unit, false), current_peer());
        let second = app.handle_request(
            service_restart_request_with_id(
                "adminbot-rate-limit-mutate-2.service",
                false,
                "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62590",
            ),
            current_peer(),
        );

        assert!(matches!(first, Response::Error(_)));
        match second {
            Response::Error(error) => {
                assert_eq!(error.error.code.to_string(), "rate_limited");
                assert_eq!(
                    error.error.details.get("request_class"),
                    Some(&json!("mutate"))
                );
                assert_eq!(error.error.details.get("scope"), Some(&json!("per_peer")));
            }
            Response::Success(success) => panic!("unexpected success response: {:?}", success),
        }
    }

    #[test]
    fn mutating_requests_are_rate_limited_globally_across_peers() {
        let units = [
            "adminbot-rate-limit-global-1.service",
            "adminbot-rate-limit-global-2.service",
            "adminbot-rate-limit-global-3.service",
        ];
        let allowed_units = units
            .iter()
            .map(|unit| format!("\"{unit}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let app = App::new(policy_for_current_user(&format!(
            r#"
version = 1

[clients.local_cli]
unix_user = "__USER__"
allowed_capabilities = ["service_control"]

[actions]
allowed = ["service.restart"]
denied = []

[service_control]
allowed_units = [{allowed_units}]
restart_cooldown_seconds = 0
max_restarts_per_hour = 10

[constraints]
mutate_rate_limit_window_ms = 60000
mutate_requests_per_peer_per_window = 10
global_mutate_requests_per_window = 2
"#
        )));

        let first = app.handle_request(service_restart_request(units[0], false), current_peer());
        let second = app.handle_request(
            service_restart_request_with_id(
                units[1],
                false,
                "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62591",
            ),
            peer_with_ids(5555, 6666),
        );
        let third = app.handle_request(
            service_restart_request_with_id(
                units[2],
                false,
                "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62592",
            ),
            peer_with_ids(7777, 8888),
        );

        assert!(matches!(first, Response::Error(_)));
        assert!(matches!(second, Response::Error(_)));
        match third {
            Response::Error(error) => {
                assert_eq!(error.error.code.to_string(), "rate_limited");
                assert_eq!(
                    error.error.details.get("request_class"),
                    Some(&json!("mutate"))
                );
                assert_eq!(error.error.details.get("scope"), Some(&json!("global")));
            }
            Response::Success(success) => panic!("unexpected success response: {:?}", success),
        }
    }

    #[test]
    fn completed_mutating_replay_is_rejected() {
        let unit = "adminbot-missing-replay.service";
        let app = App::new(service_restart_policy_for_current_user(unit));
        let request = service_restart_request(unit, false);

        let first = app.handle_request(request.clone(), current_peer());
        let _permit = app
            .hold_mutation_slot_for_test()
            .expect("hold mutation slot after first response");
        let second = app.handle_request(request, current_peer());

        assert!(matches!(first, Response::Error(_)));
        match second {
            Response::Error(error) => {
                assert_eq!(error.error.code, crate::error::ErrorCode::ReplayDetected);
                assert_eq!(
                    error.error.details.get("replay_detected"),
                    Some(&json!(true))
                );
                assert_eq!(
                    error.error.details.get("fingerprint_mismatch"),
                    Some(&json!(false))
                );
            }
            Response::Success(success) => panic!("unexpected success response: {:?}", success),
        }
    }

    #[test]
    fn mutating_request_id_reuse_with_different_payload_is_rejected() {
        let app = App::new(service_restart_policy_for_current_user_list(&[
            "adminbot-first-missing.service",
            "adminbot-second-missing.service",
        ]));
        let first = service_restart_request("adminbot-first-missing.service", false);
        let second = service_restart_request_with_id(
            "adminbot-second-missing.service",
            false,
            &first.request_id,
        );

        let _ = app.handle_request(first, current_peer());
        let response = app.handle_request(second, current_peer());

        match response {
            Response::Error(error) => {
                assert_eq!(error.error.code, crate::error::ErrorCode::ReplayDetected);
                assert_eq!(
                    error.error.message,
                    "request_id was already observed within the replay protection window"
                );
                assert_eq!(
                    error.error.details.get("request_id"),
                    Some(&json!("2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62572"))
                );
                assert_eq!(
                    error.error.details.get("fingerprint_mismatch"),
                    Some(&json!(true))
                );
            }
            Response::Success(success) => panic!("unexpected success response: {:?}", success),
        }
    }

    #[test]
    fn in_flight_mutating_replay_is_rejected() {
        let protector = ReplayProtector::new(Duration::from_millis(300_000));
        let peer = current_peer();
        let request = service_restart_request("adminbot-inflight-missing.service", false);

        let _reservation = match protector.begin(&request, &peer).expect("begin first") {
            ReplayDecision::Execute(reservation) => reservation,
        };

        let error = protector
            .begin(&request, &peer)
            .expect_err("in-flight duplicate must fail");
        assert_eq!(error.code, crate::error::ErrorCode::ReplayDetected);
        assert_eq!(
            error.message,
            "request_id was already observed within the replay protection window"
        );
        assert_eq!(error.details.get("replay_stage"), Some(&json!("in_flight")));
    }

    #[test]
    fn high_security_profile_reduces_reported_replay_window() {
        let protector = ReplayProtector::new(Duration::from_millis(60_000));
        let peer = current_peer();
        let request = service_restart_request("adminbot-inflight-missing.service", false);

        let _reservation = match protector.begin(&request, &peer).expect("begin first") {
            ReplayDecision::Execute(reservation) => reservation,
        };

        let error = protector
            .begin(&request, &peer)
            .expect_err("in-flight duplicate must fail");
        assert_eq!(error.code, crate::error::ErrorCode::ReplayDetected);
        assert_eq!(error.details.get("replay_window_ms"), Some(&json!(60_000)));
    }

    #[test]
    fn identity_tool_rate_limit_rejects_burst_above_token_bucket() {
        let app = App::new(policy_for_current_user(
            r#"
version = 1

[clients.local_cli]
unix_user = "__USER__"
allowed_capabilities = ["read_basic"]

[actions]
allowed = ["system.status"]
denied = []

[rate_limit]
enabled = true
identity_requests_per_second = 100
identity_burst = 100
per_tool_enabled = true
tool_requests_per_second = 1
tool_burst = 1
"#,
        ));

        let first = app.handle_request(
            system_status_request("2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62650"),
            current_peer(),
        );
        let second = app.handle_request(
            system_status_request("2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62651"),
            current_peer(),
        );

        assert!(matches!(first, Response::Success(_)));
        match second {
            Response::Error(error) => {
                assert_eq!(error.error.code, crate::error::ErrorCode::RateLimited);
                assert_eq!(
                    error.error.details.get("scope"),
                    Some(&json!("identity_tool"))
                );
                assert_eq!(
                    error.error.details.get("rate_limit_hit"),
                    Some(&json!(true))
                );
                assert_eq!(
                    error.error.details.get("tool_name"),
                    Some(&json!("system.status"))
                );
            }
            Response::Success(success) => panic!("unexpected success response: {:?}", success),
        }
    }

    #[test]
    fn service_restart_without_preview_is_rejected_when_guard_enabled() {
        let unit = existing_service_unit();
        let app = App::new(policy_for_current_user(&format!(
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

[mutation_safety]
require_preview = true
preview_window_seconds = 60
"#
        )));

        let request = service_restart_request(unit, false);
        let response = app.handle_request(request, current_peer());

        match response {
            Response::Error(error) => {
                assert_eq!(
                    error.error.code,
                    crate::error::ErrorCode::PreconditionFailed
                );
                assert_eq!(
                    error.error.details.get("preview_required"),
                    Some(&json!(true))
                );
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
                let request_id = uuid::Uuid::new_v4().to_string();
                let response = app.handle_request(
                    service_restart_request_with_id(unit, false, &request_id),
                    current_peer(),
                );
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
            correlation_id: None,
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            tool_name: None,
            agent_run_id: None,
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
            correlation_id: None,
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            tool_name: None,
            agent_run_id: None,
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
            correlation_id: None,
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            tool_name: None,
            agent_run_id: None,
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
            correlation_id: None,
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            tool_name: None,
            agent_run_id: None,
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
    fn journal_query_uses_journal_specific_allowlist_when_configured() {
        let app = App::new(policy_for_current_user(
            r#"
version = 1

[clients.local_cli]
unix_user = "__USER__"
allowed_capabilities = ["journal_read"]

[actions]
allowed = ["journal.query"]
denied = []

[service_control]
allowed_units = ["nginx.service"]

[journal]
allowed_units = ["adminbotd.service"]
"#,
        ));

        let denied = app.handle_request(
            Request {
                version: 1,
                request_id: "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62599".to_string(),
                correlation_id: None,
                requested_by: RequestedBy {
                    origin_type: RequestOriginType::Human,
                    id: "test-cli".to_string(),
                },
                tool_name: None,
                agent_run_id: None,
                action: "journal.query".to_string(),
                params: serde_json::from_value(json!({
                    "unit": "nginx.service",
                    "limit": 10
                }))
                .expect("params"),
                dry_run: false,
                timeout_ms: 3000,
            },
            current_peer(),
        );
        match denied {
            Response::Error(error) => {
                assert_eq!(
                    error.error.details.get("policy_section"),
                    Some(&json!("journal.allowed_units"))
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
            correlation_id: None,
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            tool_name: None,
            agent_run_id: None,
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
            correlation_id: None,
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            tool_name: None,
            agent_run_id: None,
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
            correlation_id: None,
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            tool_name: None,
            agent_run_id: None,
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
            correlation_id: None,
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            tool_name: None,
            agent_run_id: None,
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
            correlation_id: None,
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            tool_name: None,
            agent_run_id: None,
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
            correlation_id: None,
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            tool_name: None,
            agent_run_id: None,
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
            correlation_id: None,
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            tool_name: None,
            agent_run_id: None,
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
            correlation_id: None,
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            tool_name: None,
            agent_run_id: None,
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

    fn peer_with_ids(uid: u32, gid: u32) -> PeerCredentials {
        PeerCredentials {
            uid,
            gid,
            pid: unsafe { libc::getpid() as u32 },
            supplementary_gids: Vec::new(),
            unix_user: std::env::var("USER").ok(),
        }
    }

    fn system_status_request(request_id: &str) -> Request {
        Request {
            version: 1,
            request_id: request_id.to_string(),
            correlation_id: None,
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            tool_name: None,
            agent_run_id: None,
            action: "system.status".to_string(),
            params: serde_json::from_value(json!({})).expect("params"),
            dry_run: false,
            timeout_ms: 3000,
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

    fn service_restart_policy_for_current_user_list(units: &[&str]) -> PolicyEngine {
        service_restart_policy_with_parallel_limit_list(units, 1)
    }

    fn service_restart_policy_with_parallel_limit(
        unit: &str,
        max_parallel_mutations: u32,
    ) -> PolicyEngine {
        service_restart_policy_with_parallel_limit_list(&[unit], max_parallel_mutations)
    }

    fn service_restart_policy_with_parallel_limit_list(
        units: &[&str],
        max_parallel_mutations: u32,
    ) -> PolicyEngine {
        let allowed_units = units
            .iter()
            .map(|unit| format!("\"{unit}\""))
            .collect::<Vec<_>>()
            .join(", ");
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
allowed_units = [{allowed_units}]
restart_cooldown_seconds = 300
max_restarts_per_hour = 3

[mutation_safety]
require_preview = false

[constraints]
max_parallel_mutations = {max_parallel_mutations}
"#
        );

        policy_for_current_user(&template)
    }

    fn service_restart_request(unit: &str, dry_run: bool) -> Request {
        service_restart_request_with_id(unit, dry_run, "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62572")
    }

    fn service_restart_request_with_id(unit: &str, dry_run: bool, request_id: &str) -> Request {
        Request {
            version: 1,
            request_id: request_id.to_string(),
            correlation_id: Some(format!("test-correlation-{request_id}")),
            requested_by: RequestedBy {
                origin_type: RequestOriginType::Human,
                id: "test-cli".to_string(),
            },
            tool_name: None,
            agent_run_id: None,
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
