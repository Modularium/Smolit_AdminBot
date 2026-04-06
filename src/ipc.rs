use std::collections::VecDeque;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::app::App;
use crate::error::{AppError, ErrorCode};
use crate::peer::{get_peer_credentials, gid_from_group_name, set_socket_group};
use crate::types::{Request, Response};

pub const MAX_IPC_FRAME_SIZE: usize = 64 * 1024;
pub const IPC_READ_TIMEOUT: Duration = Duration::from_secs(1);
pub const IPC_WRITE_TIMEOUT: Duration = Duration::from_secs(1);
pub const IPC_ADMISSION_WINDOW: Duration = Duration::from_secs(1);
pub const IPC_MAX_CONNECTIONS_PER_WINDOW: usize = 8;
pub const RUNTIME_DIRECTORY_MODE: u32 = 0o750;
pub const SOCKET_FILE_MODE: u32 = 0o660;

#[derive(Debug)]
enum ReadFrameError {
    Io(io::Error),
    FrameTooLarge {
        announced_size: usize,
        max_size: usize,
    },
}

#[derive(Debug)]
pub struct IpcServer {
    listener: UnixListener,
    socket_path: PathBuf,
    admission_control: Mutex<AdmissionControl>,
}

impl IpcServer {
    pub fn bind(socket_path: PathBuf, socket_group: &str) -> io::Result<Self> {
        let expected_uid = current_effective_uid();
        let expected_runtime_gid = current_effective_gid();
        let expected_socket_gid = prepare_socket_path(
            &socket_path,
            socket_group,
            expected_uid,
            expected_runtime_gid,
        )?;

        let listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(SOCKET_FILE_MODE))?;
        set_socket_group(&socket_path, socket_group)?;
        validate_socket_file_for_ids(&socket_path, expected_uid, expected_socket_gid)?;

        Ok(Self {
            listener,
            socket_path,
            admission_control: Mutex::new(AdmissionControl::new(
                IPC_MAX_CONNECTIONS_PER_WINDOW,
                IPC_ADMISSION_WINDOW,
            )),
        })
    }

    pub fn run(self, app: &App) -> io::Result<()> {
        for stream in self.listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    self.handle_connection(app, &mut stream)?;
                }
                Err(error) => {
                    eprintln!("adminbotd socket accept failed: {error}");
                    return Err(error);
                }
            }
        }

        Ok(())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn run_once(self, app: &App) -> io::Result<()> {
        let (mut stream, _) = self.listener.accept()?;
        self.handle_connection(app, &mut stream)
    }

    fn handle_stream(&self, app: &App, stream: &mut UnixStream) -> Result<Response, AppError> {
        configure_read_timeout(stream).map_err(|error| {
            AppError::new(
                ErrorCode::ExecutionFailed,
                "failed to configure IPC read timeout",
            )
            .with_detail("source", error.to_string())
        })?;
        let payload = read_frame_checked(stream).map_err(map_read_frame_error)?;
        let peer = get_peer_credentials(stream).map_err(|error| {
            AppError::new(
                ErrorCode::Unauthorized,
                "unable to determine peer credentials",
            )
            .with_detail("source", error.to_string())
        })?;
        let request: Request = serde_json::from_slice(&payload).map_err(|error| {
            AppError::new(ErrorCode::ValidationError, "invalid request payload")
                .with_detail("source", error.to_string())
        })?;

        Ok(app.handle_request(request, peer))
    }

    #[allow(dead_code)]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    fn process_connection(&self, app: &App, stream: &mut UnixStream) -> io::Result<()> {
        let response = match self.handle_stream(app, stream) {
            Ok(response) => response,
            Err(error) => {
                let request_id = "00000000-0000-0000-0000-000000000000".to_string();
                Response::error(request_id, error.to_body())
            }
        };

        configure_write_timeout(stream)?;
        write_frame(stream, &response).map_err(|error| {
            eprintln!("adminbotd socket write failed: {error}");
            error
        })
    }

    fn handle_connection(&self, app: &App, stream: &mut UnixStream) -> io::Result<()> {
        if !self.try_admit_connection() {
            return self.write_admission_rejection(stream);
        }

        self.process_connection(app, stream)
    }

    fn try_admit_connection(&self) -> bool {
        let mut admission = self
            .admission_control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        admission.try_admit(Instant::now())
    }

    fn write_admission_rejection(&self, stream: &mut UnixStream) -> io::Result<()> {
        let response = Response::error(
            "00000000-0000-0000-0000-000000000000".to_string(),
            AppError::new(
                ErrorCode::RateLimited,
                "IPC admission control rejected connection",
            )
            .with_detail(
                "max_connections_per_window",
                IPC_MAX_CONNECTIONS_PER_WINDOW as u64,
            )
            .with_detail(
                "admission_window_ms",
                IPC_ADMISSION_WINDOW.as_millis() as u64,
            )
            .retryable(true)
            .to_body(),
        );

        configure_write_timeout(stream)?;
        write_frame(stream, &response).map_err(|error| {
            eprintln!("adminbotd admission rejection write failed: {error}");
            error
        })
    }

    #[cfg(test)]
    pub(crate) fn bind_for_test(socket_path: PathBuf) -> io::Result<Self> {
        if let Some(parent) = socket_path.parent() {
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(RUNTIME_DIRECTORY_MODE))?;
        }

        let expected_uid = current_effective_uid();
        let expected_gid = current_effective_gid();
        prepare_test_socket_path(&socket_path, expected_uid, expected_gid)?;

        let listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(SOCKET_FILE_MODE))?;
        validate_socket_file_for_ids(&socket_path, expected_uid, expected_gid)?;

        Ok(Self {
            listener,
            socket_path,
            admission_control: Mutex::new(AdmissionControl::new(
                IPC_MAX_CONNECTIONS_PER_WINDOW,
                IPC_ADMISSION_WINDOW,
            )),
        })
    }

    #[cfg(test)]
    fn run_n(self, app: &App, count: usize) -> io::Result<()> {
        for _ in 0..count {
            let (mut stream, _) = self.listener.accept()?;
            self.handle_connection(app, &mut stream)?;
        }

        Ok(())
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket_path);
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn read_frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    read_frame_checked(stream).map_err(ReadFrameError::into_io_error)
}

pub fn write_frame(stream: &mut UnixStream, response: &Response) -> io::Result<()> {
    write_json_frame(stream, response)
}

pub fn write_json_frame<T: Serialize>(writer: &mut impl Write, value: &T) -> io::Result<()> {
    write_frame_to_writer(writer, value)
}

#[cfg_attr(not(test), allow(dead_code))]
fn read_frame_from_reader<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    read_frame_checked(reader).map_err(ReadFrameError::into_io_error)
}

fn read_frame_checked<R: Read>(reader: &mut R) -> Result<Vec<u8>, ReadFrameError> {
    let mut length_bytes = [0_u8; 4];
    reader
        .read_exact(&mut length_bytes)
        .map_err(ReadFrameError::Io)?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length > MAX_IPC_FRAME_SIZE {
        return Err(ReadFrameError::FrameTooLarge {
            announced_size: length,
            max_size: MAX_IPC_FRAME_SIZE,
        });
    }
    let mut payload = vec![0_u8; length];
    reader
        .read_exact(&mut payload)
        .map_err(ReadFrameError::Io)?;
    Ok(payload)
}

fn map_read_frame_error(error: ReadFrameError) -> AppError {
    match error {
        ReadFrameError::FrameTooLarge {
            announced_size,
            max_size,
        } => AppError::new(ErrorCode::ValidationError, "IPC frame exceeds maximum size")
            .with_detail("announced_frame_size_bytes", announced_size as u64)
            .with_detail("max_frame_size_bytes", max_size as u64),
        ReadFrameError::Io(error) if is_timeout_error(&error) => {
            AppError::new(ErrorCode::Timeout, "IPC read timed out")
                .with_detail("read_timeout_ms", IPC_READ_TIMEOUT.as_millis() as u64)
                .retryable(true)
        }
        ReadFrameError::Io(error) => {
            AppError::new(ErrorCode::ValidationError, "failed to read IPC frame")
                .with_detail("source", error.to_string())
        }
    }
}

fn configure_read_timeout(stream: &UnixStream) -> io::Result<()> {
    stream.set_read_timeout(Some(IPC_READ_TIMEOUT))
}

fn configure_write_timeout(stream: &UnixStream) -> io::Result<()> {
    stream.set_write_timeout(Some(IPC_WRITE_TIMEOUT))
}

fn is_timeout_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

impl ReadFrameError {
    #[cfg_attr(not(test), allow(dead_code))]
    fn into_io_error(self) -> io::Error {
        match self {
            ReadFrameError::Io(error) => error,
            ReadFrameError::FrameTooLarge {
                announced_size,
                max_size,
            } => io::Error::new(
                io::ErrorKind::InvalidData,
                format!("IPC frame size {announced_size} exceeds maximum size {max_size}"),
            ),
        }
    }
}

#[derive(Debug)]
struct AdmissionControl {
    max_connections: usize,
    window: Duration,
    accepted_at: VecDeque<Instant>,
}

fn prepare_socket_path(
    socket_path: &Path,
    socket_group: &str,
    expected_uid: u32,
    expected_runtime_gid: u32,
) -> io::Result<u32> {
    let runtime_dir = socket_path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path must include a runtime directory",
        )
    })?;
    validate_runtime_directory_for_ids(runtime_dir, expected_uid, expected_runtime_gid)?;

    let expected_socket_gid = gid_from_group_name(socket_group)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("group {socket_group} not found"),
        )
    })?;

    prepare_existing_socket_artifact(socket_path, expected_uid, expected_socket_gid)?;
    Ok(expected_socket_gid)
}

#[cfg(test)]
fn prepare_test_socket_path(
    socket_path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> io::Result<()> {
    let runtime_dir = socket_path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path must include a runtime directory",
        )
    })?;
    validate_runtime_directory_for_ids(runtime_dir, expected_uid, expected_gid)?;
    prepare_existing_socket_artifact(socket_path, expected_uid, expected_gid)
}

fn prepare_existing_socket_artifact(
    socket_path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> io::Result<()> {
    if !socket_path.exists() {
        return Ok(());
    }

    validate_socket_file_for_ids(socket_path, expected_uid, expected_gid)?;
    fs::remove_file(socket_path)
}

fn validate_runtime_directory_for_ids(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("runtime directory is missing or unreadable: {error}"),
        )
    })?;

    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("runtime path {} must be a real directory", path.display()),
        ));
    }

    if metadata.uid() != expected_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "runtime directory owner mismatch for {}: expected uid {expected_uid}, got {}",
                path.display(),
                metadata.uid()
            ),
        ));
    }

    if metadata.gid() != expected_gid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "runtime directory group mismatch for {}: expected gid {expected_gid}, got {}",
                path.display(),
                metadata.gid()
            ),
        ));
    }

    let mode = metadata.mode() & 0o777;
    if mode != RUNTIME_DIRECTORY_MODE {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "runtime directory mode mismatch for {}: expected {:o}, got {:o}",
                path.display(),
                RUNTIME_DIRECTORY_MODE,
                mode
            ),
        ));
    }

    Ok(())
}

fn validate_socket_file_for_ids(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("socket path is missing or unreadable: {error}"),
        )
    })?;

    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("socket path {} must be a unix socket", path.display()),
        ));
    }

    if metadata.uid() != expected_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "socket owner mismatch for {}: expected uid {expected_uid}, got {}",
                path.display(),
                metadata.uid()
            ),
        ));
    }

    if metadata.gid() != expected_gid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "socket group mismatch for {}: expected gid {expected_gid}, got {}",
                path.display(),
                metadata.gid()
            ),
        ));
    }

    let mode = metadata.mode() & 0o777;
    if mode != SOCKET_FILE_MODE {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "socket mode mismatch for {}: expected {:o}, got {:o}",
                path.display(),
                SOCKET_FILE_MODE,
                mode
            ),
        ));
    }

    Ok(())
}

fn current_effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

fn current_effective_gid() -> u32 {
    unsafe { libc::getegid() }
}

impl AdmissionControl {
    fn new(max_connections: usize, window: Duration) -> Self {
        Self {
            max_connections,
            window,
            accepted_at: VecDeque::new(),
        }
    }

    fn try_admit(&mut self, now: Instant) -> bool {
        while let Some(&accepted_at) = self.accepted_at.front() {
            if now.duration_since(accepted_at) < self.window {
                break;
            }
            self.accepted_at.pop_front();
        }

        if self.accepted_at.len() >= self.max_connections {
            return false;
        }

        self.accepted_at.push_back(now);
        true
    }
}

fn write_frame_to_writer<T: Serialize, W: Write>(writer: &mut W, value: &T) -> io::Result<()> {
    let payload = serde_json::to_vec(value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let length = payload.len() as u32;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::App;
    use crate::peer::get_peer_credentials;
    use crate::policy::PolicyEngine;
    use std::io::Cursor;
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::time::{SystemTime, UNIX_EPOCH};
    use std::{env, fs, io::Write, path::PathBuf, thread};

    #[test]
    fn framing_roundtrip() {
        let response = Response::success(
            "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62571",
            serde_json::json!({"ok": true}),
        );

        let mut encoded = Vec::new();
        write_frame_to_writer(&mut encoded, &response).expect("write");
        let mut cursor = Cursor::new(encoded);
        let payload = read_frame_from_reader(&mut cursor).expect("read");
        let decoded: serde_json::Value = serde_json::from_slice(&payload).expect("decode");
        assert_eq!(decoded["status"], "ok");
    }

    #[test]
    fn framing_rejects_incomplete_length_prefix() {
        let mut cursor = Cursor::new(vec![0_u8, 0_u8, 0_u8]);
        let error = read_frame_from_reader(&mut cursor).expect_err("short prefix must fail");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn framing_rejects_incomplete_payload() {
        let mut cursor = Cursor::new(vec![0_u8, 0_u8, 0_u8, 5_u8, 1_u8, 2_u8]);
        let error = read_frame_from_reader(&mut cursor).expect_err("short payload must fail");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn framing_rejects_oversized_payload_before_allocation() {
        let oversized = (MAX_IPC_FRAME_SIZE + 1) as u32;
        let mut cursor = Cursor::new(oversized.to_be_bytes().to_vec());
        let error = read_frame_checked(&mut cursor).expect_err("oversized frame must fail");
        match error {
            ReadFrameError::FrameTooLarge {
                announced_size,
                max_size,
            } => {
                assert_eq!(announced_size, MAX_IPC_FRAME_SIZE + 1);
                assert_eq!(max_size, MAX_IPC_FRAME_SIZE);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn bind_creates_unix_socket_file() {
        let path = temp_socket_path("bind");
        let server = IpcServer::bind_for_test(path.clone()).expect("bind");
        let metadata = fs::metadata(server.socket_path()).expect("metadata");
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.permissions().mode() & 0o777, SOCKET_FILE_MODE);
        drop(server);
    }

    #[test]
    fn runtime_directory_validation_rejects_world_writable_directory() {
        let runtime_dir = temp_runtime_dir("runtime-world-writable");
        fs::set_permissions(&runtime_dir, fs::Permissions::from_mode(0o777)).expect("chmod");

        let error = validate_runtime_directory_for_ids(
            &runtime_dir,
            current_effective_uid(),
            current_effective_gid(),
        )
        .expect_err("world-writable runtime dir must fail");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("mode mismatch"));

        let _ = fs::remove_dir(&runtime_dir);
    }

    #[test]
    fn runtime_directory_validation_rejects_unexpected_owner() {
        let runtime_dir = temp_runtime_dir("runtime-owner");
        let error = validate_runtime_directory_for_ids(
            &runtime_dir,
            current_effective_uid().saturating_add(1),
            current_effective_gid(),
        )
        .expect_err("wrong owner must fail");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("owner mismatch"));

        let _ = fs::remove_dir(&runtime_dir);
    }

    #[test]
    fn runtime_directory_validation_accepts_expected_owner_and_mode() {
        let runtime_dir = temp_runtime_dir("runtime-valid");
        validate_runtime_directory_for_ids(
            &runtime_dir,
            current_effective_uid(),
            current_effective_gid(),
        )
        .expect("trusted runtime dir must pass");

        let _ = fs::remove_dir(&runtime_dir);
    }

    #[test]
    fn bind_rejects_stale_regular_file_at_socket_path() {
        let socket_path = temp_socket_path("stale-file");
        let runtime_dir = socket_path.parent().expect("runtime dir");
        fs::create_dir_all(runtime_dir).expect("create runtime dir");
        fs::set_permissions(
            runtime_dir,
            fs::Permissions::from_mode(RUNTIME_DIRECTORY_MODE),
        )
        .expect("chmod runtime dir");
        fs::write(&socket_path, "not-a-socket").expect("write stale file");

        let error = IpcServer::bind_for_test(socket_path.clone())
            .expect_err("regular file must block startup");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("must be a unix socket"));

        let _ = fs::remove_file(&socket_path);
        let _ = fs::remove_dir(runtime_dir);
    }

    #[test]
    fn socket_validation_rejects_unexpected_group() {
        let socket_path = temp_socket_path("socket-group");
        let server = IpcServer::bind_for_test(socket_path.clone()).expect("bind");

        let error = validate_socket_file_for_ids(
            server.socket_path(),
            current_effective_uid(),
            current_effective_gid().saturating_add(1),
        )
        .expect_err("wrong socket group must fail");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("group mismatch"));

        drop(server);
    }

    #[test]
    fn peer_credentials_can_be_read_from_local_connection() {
        let (server_stream, client_stream) = UnixStream::pair().expect("pair");
        let server_peer = get_peer_credentials(&server_stream).expect("server peer");
        let client_peer = get_peer_credentials(&client_stream).expect("client peer");

        let expected_uid = unsafe { libc::geteuid() };
        let expected_gid = unsafe { libc::getegid() };
        let expected_pid = unsafe { libc::getpid() as u32 };

        assert_eq!(server_peer.uid, expected_uid);
        assert_eq!(server_peer.gid, expected_gid);
        assert_eq!(server_peer.pid, expected_pid);
        assert_eq!(client_peer.uid, expected_uid);
        assert_eq!(client_peer.gid, expected_gid);
        assert_eq!(client_peer.pid, expected_pid);
        assert!(server_peer.unix_user.is_some());
    }

    #[test]
    fn run_once_accepts_single_connection() {
        let socket_path = temp_socket_path("accept");
        let policy_path = temp_policy_path();
        let policy = PolicyEngine::load_from_path(policy_path.clone()).expect("policy");
        let app = App::new(policy);
        let server = IpcServer::bind_for_test(socket_path.clone()).expect("bind");

        let handle = thread::spawn(move || server.run_once(&app));

        let mut client = connect_with_retry(&socket_path);
        let request = serde_json::json!({
            "version": 1,
            "request_id": "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62571",
            "requested_by": {
                "type": "human",
                "id": "ipc-test"
            },
            "action": "system.status",
            "params": {},
            "dry_run": false,
            "timeout_ms": 3000
        });
        let payload = serde_json::to_vec(&request).expect("encode request");
        client
            .write_all(&(payload.len() as u32).to_be_bytes())
            .expect("write length");
        client.write_all(&payload).expect("write payload");
        client.flush().expect("flush");

        let response_payload = read_frame(&mut client).expect("read response");
        let response: serde_json::Value =
            serde_json::from_slice(&response_payload).expect("decode response");
        assert_eq!(response["status"], "ok");
        assert!(response["result"]["hostname"].is_string());

        handle.join().expect("join").expect("server run_once");
        let _ = fs::remove_file(policy_path);
    }

    #[test]
    fn run_once_rejects_unmapped_peer_with_unauthorized_error() {
        let socket_path = temp_socket_path("unauthorized");
        let policy_path = temp_policy_path_for_user("definitely-not-the-current-user");
        let policy = PolicyEngine::load_from_path(policy_path.clone()).expect("policy");
        let app = App::new(policy);
        let server = IpcServer::bind_for_test(socket_path.clone()).expect("bind");

        let handle = thread::spawn(move || server.run_once(&app));

        let mut client = connect_with_retry(&socket_path);
        let request = serde_json::json!({
            "version": 1,
            "request_id": "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62573",
            "requested_by": {
                "type": "human",
                "id": "ipc-test"
            },
            "action": "system.status",
            "params": {},
            "dry_run": false,
            "timeout_ms": 3000
        });
        let payload = serde_json::to_vec(&request).expect("encode request");
        write_raw_frame(&mut client, &payload);

        let response_payload = read_frame(&mut client).expect("read response");
        let response: serde_json::Value =
            serde_json::from_slice(&response_payload).expect("decode response");
        assert_eq!(
            response["request_id"],
            "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62573"
        );
        assert_eq!(response["status"], "error");
        assert_eq!(response["error"]["code"], "unauthorized");
        assert_eq!(
            response["error"]["message"],
            "peer is not mapped to any policy client"
        );
        assert_eq!(response["error"]["retryable"], false);

        handle.join().expect("join").expect("server run_once");
        let _ = fs::remove_file(policy_path);
    }

    #[test]
    fn run_once_maps_invalid_json_to_validation_error_response() {
        let socket_path = temp_socket_path("invalid-json");
        let policy_path = temp_policy_path();
        let policy = PolicyEngine::load_from_path(policy_path.clone()).expect("policy");
        let app = App::new(policy);
        let server = IpcServer::bind_for_test(socket_path.clone()).expect("bind");

        let handle = thread::spawn(move || server.run_once(&app));

        let mut client = connect_with_retry(&socket_path);
        let payload = br#"{"version":1,"request_id":"broken""#.to_vec();
        write_raw_frame(&mut client, &payload);

        let response_payload = read_frame(&mut client).expect("read response");
        let response: serde_json::Value =
            serde_json::from_slice(&response_payload).expect("decode response");
        assert_eq!(
            response["request_id"],
            "00000000-0000-0000-0000-000000000000"
        );
        assert_eq!(response["status"], "error");
        assert_eq!(response["error"]["code"], "validation_error");
        assert_eq!(response["error"]["message"], "invalid request payload");
        assert!(response["error"]["details"]["source"].is_string());
        assert_eq!(response["error"]["retryable"], false);

        handle.join().expect("join").expect("server run_once");
        let _ = fs::remove_file(policy_path);
    }

    #[test]
    fn run_once_rejects_oversized_frame_with_validation_error_response() {
        let socket_path = temp_socket_path("oversized");
        let policy_path = temp_policy_path();
        let policy = PolicyEngine::load_from_path(policy_path.clone()).expect("policy");
        let app = App::new(policy);
        let server = IpcServer::bind_for_test(socket_path.clone()).expect("bind");

        let handle = thread::spawn(move || server.run_once(&app));

        let mut client = connect_with_retry(&socket_path);
        let oversized = (MAX_IPC_FRAME_SIZE as u32) + 1;
        client
            .write_all(&oversized.to_be_bytes())
            .expect("write length");
        client.flush().expect("flush");

        let response_payload = read_frame(&mut client).expect("read response");
        let response: serde_json::Value =
            serde_json::from_slice(&response_payload).expect("decode response");
        assert_eq!(
            response["request_id"],
            "00000000-0000-0000-0000-000000000000"
        );
        assert_eq!(response["status"], "error");
        assert_eq!(response["error"]["code"], "validation_error");
        assert_eq!(
            response["error"]["message"],
            "IPC frame exceeds maximum size"
        );
        assert_eq!(
            response["error"]["details"]["announced_frame_size_bytes"],
            serde_json::json!(MAX_IPC_FRAME_SIZE as u64 + 1)
        );
        assert_eq!(
            response["error"]["details"]["max_frame_size_bytes"],
            serde_json::json!(MAX_IPC_FRAME_SIZE as u64)
        );

        handle.join().expect("join").expect("server run_once");
        let _ = fs::remove_file(policy_path);
    }

    #[test]
    fn run_once_times_out_slow_client_reads() {
        let socket_path = temp_socket_path("slow-read");
        let policy_path = temp_policy_path();
        let policy = PolicyEngine::load_from_path(policy_path.clone()).expect("policy");
        let app = App::new(policy);
        let server = IpcServer::bind_for_test(socket_path.clone()).expect("bind");

        let handle = thread::spawn(move || server.run_once(&app));

        let mut client = connect_with_retry(&socket_path);
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("client read timeout");

        let started = std::time::Instant::now();
        let response_payload = read_frame(&mut client).expect("read timeout response");
        let elapsed = started.elapsed();
        let response: serde_json::Value =
            serde_json::from_slice(&response_payload).expect("decode response");

        assert!(elapsed >= IPC_READ_TIMEOUT);
        assert!(elapsed < Duration::from_secs(3));
        assert_eq!(
            response["request_id"],
            "00000000-0000-0000-0000-000000000000"
        );
        assert_eq!(response["status"], "error");
        assert_eq!(response["error"]["code"], "timeout");
        assert_eq!(response["error"]["message"], "IPC read timed out");
        assert_eq!(
            response["error"]["details"]["read_timeout_ms"],
            serde_json::json!(IPC_READ_TIMEOUT.as_millis() as u64)
        );
        assert_eq!(response["error"]["retryable"], true);

        handle.join().expect("join").expect("server run_once");
        let _ = fs::remove_file(policy_path);
    }

    #[test]
    fn write_frame_times_out_for_non_reading_peer() {
        let (mut server_stream, _client_stream) = UnixStream::pair().expect("pair");
        configure_write_timeout(&server_stream).expect("configure write timeout");
        set_socket_send_buffer(&server_stream, 4096).expect("set send buffer");

        let response = Response::success(
            "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62581",
            serde_json::json!({
                "payload": "x".repeat(MAX_IPC_FRAME_SIZE * 32)
            }),
        );

        let started = std::time::Instant::now();
        let error = write_frame(&mut server_stream, &response).expect_err("write must time out");
        let elapsed = started.elapsed();

        assert!(is_timeout_error(&error));
        assert!(elapsed >= IPC_WRITE_TIMEOUT);
        assert!(elapsed < Duration::from_secs(3));
    }

    #[test]
    fn admission_control_rejects_burst_above_window_limit() {
        let now = Instant::now();
        let mut control = AdmissionControl::new(2, Duration::from_secs(1));

        assert!(control.try_admit(now));
        assert!(control.try_admit(now + Duration::from_millis(100)));
        assert!(!control.try_admit(now + Duration::from_millis(200)));
        assert!(control.try_admit(now + Duration::from_millis(1100)));
    }

    #[test]
    fn run_n_rate_limits_flooded_connections() {
        let socket_path = temp_socket_path("flood");
        let policy_path = temp_policy_path();
        let policy = PolicyEngine::load_from_path(policy_path.clone()).expect("policy");
        let app = App::new(policy);
        let server = IpcServer::bind_for_test(socket_path.clone()).expect("bind");
        let connection_count = IPC_MAX_CONNECTIONS_PER_WINDOW + 2;

        let handle = thread::spawn(move || server.run_n(&app, connection_count));

        let mut ok_count = 0;
        let mut rate_limited_count = 0;

        for idx in 0..connection_count {
            let mut client = connect_with_retry(&socket_path);
            if idx < IPC_MAX_CONNECTIONS_PER_WINDOW {
                let request = serde_json::json!({
                    "version": 1,
                    "request_id": format!("2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a6259{idx}"),
                    "requested_by": {
                        "type": "human",
                        "id": "ipc-test"
                    },
                    "action": "system.status",
                    "params": {},
                    "dry_run": false,
                    "timeout_ms": 3000
                });
                let payload = serde_json::to_vec(&request).expect("encode request");
                write_raw_frame(&mut client, &payload);
            }

            let response_payload = read_frame(&mut client).expect("read response");
            let response: serde_json::Value =
                serde_json::from_slice(&response_payload).expect("decode response");

            match response["status"].as_str() {
                Some("ok") => ok_count += 1,
                Some("error") if response["error"]["code"] == "rate_limited" => {
                    rate_limited_count += 1;
                }
                other => panic!("unexpected response status: {other:?}"),
            }
        }

        assert_eq!(ok_count, IPC_MAX_CONNECTIONS_PER_WINDOW);
        assert_eq!(rate_limited_count, 2);

        handle.join().expect("join").expect("server run_n");
        let _ = fs::remove_file(policy_path);
    }

    fn temp_socket_path(name: &str) -> PathBuf {
        let runtime_dir = temp_runtime_dir(name);
        let mut path = runtime_dir;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        path.push(format!("adminbot-{nanos}.sock"));
        path
    }

    fn temp_runtime_dir(name: &str) -> PathBuf {
        let mut path = env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        path.push(format!("adminbot-runtime-{name}-{nanos}"));
        fs::create_dir_all(&path).expect("create runtime dir");
        fs::set_permissions(&path, fs::Permissions::from_mode(RUNTIME_DIRECTORY_MODE))
            .expect("chmod runtime dir");
        path
    }

    fn temp_policy_path() -> PathBuf {
        let user = env::var("USER").unwrap_or_else(|_| "unknown".to_string());
        temp_policy_path_for_user(&user)
    }

    fn temp_policy_path_for_user(user: &str) -> PathBuf {
        let mut path = env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        path.push(format!("adminbot-policy-{nanos}.toml"));
        let policy = format!(
            "version = 1\n\n[clients.local_cli]\nunix_user = \"{user}\"\nallowed_capabilities = [\"read_basic\"]\n\n[actions]\nallowed = [\"system.status\"]\ndenied = []\n"
        );
        fs::write(&path, policy).expect("write policy");
        path
    }
    fn connect_with_retry(path: &Path) -> UnixStream {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match UnixStream::connect(path) {
                Ok(stream) => return stream,
                Err(error) if std::time::Instant::now() < deadline => {
                    let _ = error;
                    thread::sleep(std::time::Duration::from_millis(25));
                }
                Err(error) => panic!("connect failed: {error}"),
            }
        }
    }

    fn write_raw_frame(stream: &mut UnixStream, payload: &[u8]) {
        stream
            .write_all(&(payload.len() as u32).to_be_bytes())
            .expect("write length");
        stream.write_all(payload).expect("write payload");
        stream.flush().expect("flush");
    }

    fn set_socket_send_buffer(stream: &UnixStream, size: usize) -> io::Result<()> {
        let size = size as libc::c_int;
        let result = unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &size as *const _ as *const libc::c_void,
                std::mem::size_of_val(&size) as libc::socklen_t,
            )
        };

        if result == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
