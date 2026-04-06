mod actions;
mod app;
mod audit;
mod error;
mod ipc;
mod peer;
mod policy;
mod systemd;
mod types;

use std::path::PathBuf;

use crate::app::App;
use crate::ipc::IpcServer;
use crate::policy::PolicyEngine;

const DEFAULT_SOCKET_PATH: &str = "/run/adminbot/adminbot.sock";
const DEFAULT_POLICY_PATH: &str = "/etc/adminbot/policy.toml";

fn main() {
    if let Err(error) = run() {
        eprintln!("adminbotd startup failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let policy_path = PathBuf::from(DEFAULT_POLICY_PATH);
    PolicyEngine::validate_policy_file(&policy_path)?;
    let policy = PolicyEngine::load_from_path(policy_path)?;
    let app = App::new(policy);
    let server = IpcServer::bind(PathBuf::from(DEFAULT_SOCKET_PATH), "adminbotctl")?;
    server.run(&app)?;
    Ok(())
}
