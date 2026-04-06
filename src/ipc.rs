use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use crate::app::App;
use crate::error::{AppError, ErrorCode};
use crate::peer::{get_peer_credentials, set_socket_group};
use crate::types::{Request, Response};

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
        let payload = read_frame(stream).map_err(|error| {
            AppError::new(ErrorCode::ValidationError, "failed to read IPC frame")
                .with_detail("source", error.to_string())
        })?;
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

pub fn read_frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    read_frame_from_reader(stream)
}

pub fn write_frame(stream: &mut UnixStream, response: &Response) -> io::Result<()> {
    write_frame_to_writer(stream, response)
}

fn read_frame_from_reader<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut length_bytes = [0_u8; 4];
    reader.read_exact(&mut length_bytes)?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload)?;
    Ok(payload)
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
    fn bind_creates_unix_socket_file() {
        let path = temp_socket_path("bind");
        let server = IpcServer::bind_for_test(path.clone()).expect("bind");
        let metadata = fs::metadata(server.socket_path()).expect("metadata");
        assert!(metadata.file_type().is_socket());
        drop(server);
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
        let mut path = env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        path.push(format!("adminbot-policy-{nanos}.toml"));
        let user = env::var("USER").unwrap_or_else(|_| "unknown".to_string());
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
}
