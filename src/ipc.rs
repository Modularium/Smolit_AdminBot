use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use crate::app::App;
use crate::error::{AppError, ErrorCode};
use crate::peer::{get_peer_credentials, set_socket_group};
use crate::types::{Request, Response};

pub const MAX_IPC_FRAME_SIZE: usize = 64 * 1024;

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
}

impl IpcServer {
    pub fn bind(socket_path: PathBuf, socket_group: &str) -> io::Result<Self> {
        if let Some(parent) = socket_path.parent() {
            fs::create_dir_all(parent)?;
        }

        if socket_path.exists() {
            fs::remove_file(&socket_path)?;
        }

        let listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o660))?;
        set_socket_group(&socket_path, socket_group)?;

        Ok(Self {
            listener,
            socket_path,
        })
    }

    pub fn run(self, app: &App) -> io::Result<()> {
        for stream in self.listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    self.process_connection(app, &mut stream)?;
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
        self.process_connection(app, &mut stream)
    }

    fn handle_stream(&self, app: &App, stream: &mut UnixStream) -> Result<Response, AppError> {
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

        write_frame(stream, &response).map_err(|error| {
            eprintln!("adminbotd socket write failed: {error}");
            error
        })
    }

    #[cfg(test)]
    fn bind_for_test(socket_path: PathBuf) -> io::Result<Self> {
        if let Some(parent) = socket_path.parent() {
            fs::create_dir_all(parent)?;
        }

        if socket_path.exists() {
            fs::remove_file(&socket_path)?;
        }

        let listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o660))?;

        Ok(Self {
            listener,
            socket_path,
        })
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
    write_frame_to_writer(stream, response)
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
        ReadFrameError::Io(error) => {
            AppError::new(ErrorCode::ValidationError, "failed to read IPC frame")
                .with_detail("source", error.to_string())
        }
    }
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

fn write_frame_to_writer<W: Write>(writer: &mut W, response: &Response) -> io::Result<()> {
    let payload = serde_json::to_vec(response)
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
        assert_eq!(metadata.permissions().mode() & 0o777, 0o660);
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

    fn temp_socket_path(name: &str) -> PathBuf {
        let mut path = env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        path.push(format!("adminbot-{name}-{nanos}.sock"));
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
}
