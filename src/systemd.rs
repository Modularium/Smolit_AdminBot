use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::OwnedObjectPath;

use crate::error::{AppError, AppResult, ErrorCode};

const SYSTEMD_SERVICE: &str = "org.freedesktop.systemd1";
const MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
const UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";

#[derive(Debug)]
pub struct SystemdClient {
    connection: Connection,
}

impl SystemdClient {
    pub fn connect() -> AppResult<Self> {
        let connection = Connection::system().map_err(|error| {
            AppError::new(
                ErrorCode::BackendUnavailable,
                "unable to connect to system bus",
            )
            .with_detail("source", error.to_string())
            .retryable(true)
        })?;

        Ok(Self { connection })
    }

    pub fn manager_proxy(&self) -> AppResult<Proxy<'_>> {
        Proxy::new(
            &self.connection,
            SYSTEMD_SERVICE,
            MANAGER_PATH,
            MANAGER_INTERFACE,
        )
        .map_err(|error| {
            AppError::new(
                ErrorCode::BackendUnavailable,
                "unable to create systemd manager proxy",
            )
            .with_detail("source", error.to_string())
            .retryable(true)
        })
    }

    pub fn load_unit_path(&self, unit: &str) -> AppResult<OwnedObjectPath> {
        self.manager_proxy()?
            .call("LoadUnit", &(unit,))
            .map_err(|error| {
                AppError::new(ErrorCode::ExecutionFailed, "unable to load unit")
                    .with_detail("source", error.to_string())
            })
    }

    pub fn unit_proxy<'a>(&'a self, path: &'a str) -> AppResult<Proxy<'a>> {
        Proxy::new(&self.connection, SYSTEMD_SERVICE, path, UNIT_INTERFACE).map_err(|error| {
            AppError::new(ErrorCode::BackendUnavailable, "unable to create unit proxy")
                .with_detail("source", error.to_string())
                .retryable(true)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manager_proxy_uses_documented_v1_systemd_endpoint() {
        let client = SystemdClient::connect().expect("connect system bus");
        let manager = client.manager_proxy().expect("manager proxy");

        assert_eq!(manager.destination().as_str(), SYSTEMD_SERVICE);
        assert_eq!(manager.path().as_str(), MANAGER_PATH);
        assert_eq!(manager.interface().as_str(), MANAGER_INTERFACE);
    }
}
