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
                    let response = match self.handle_stream(app, &mut stream) {
                        Ok(response) => response,
                        Err(error) => {
                            let request_id = "00000000-0000-0000-0000-000000000000".to_string();
                            Response::error(request_id, error.to_body())
                        }
                    };

                    write_frame(&mut stream, &response)?;
                }
                Err(error) => return Err(error),
            }
        }

        Ok(())
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
    use std::io::Cursor;

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
}
