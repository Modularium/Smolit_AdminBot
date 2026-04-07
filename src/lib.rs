pub mod actions;
pub mod app;
pub mod audit;
pub mod cli;
pub mod error;
pub mod ipc;
pub mod peer;
pub mod policy;
pub mod systemd;
pub mod types;

use std::path::PathBuf;

use crate::app::App;
use crate::ipc::IpcServer;
use crate::policy::PolicyEngine;

pub const DEFAULT_SOCKET_PATH: &str = "/run/adminbot/adminbot.sock";
pub const DEFAULT_POLICY_PATH: &str = "/etc/adminbot/policy.toml";
pub const DEFAULT_RUNTIME_DIR: &str = "/run/adminbot";
pub const DEFAULT_POLKIT_PATH: &str = "/etc/polkit-1/rules.d/50-adminbotd-systemd.rules";
pub const DEFAULT_UNIT_PATH: &str = "/etc/systemd/system/adminbotd.service";
pub const DEFAULT_SOCKET_GROUP: &str = "adminbotctl";

pub fn run_daemon() -> Result<(), Box<dyn std::error::Error>> {
    let policy_path = PathBuf::from(DEFAULT_POLICY_PATH);
    PolicyEngine::validate_policy_file(&policy_path)?;
    let policy = PolicyEngine::load_from_path(policy_path)?;
    let inspection = policy.sanity_inspection();
    if !inspection.warnings.is_empty() {
        eprintln!(
            "adminbotd policy sanity warnings detected: {}",
            inspection.warnings.len()
        );
        for warning in &inspection.warnings {
            eprintln!(
                "adminbotd policy warning: {} ({}): {}",
                warning.code, warning.policy_section, warning.message
            );
        }
        for identity in inspection
            .effective_identities
            .iter()
            .filter(|identity| identity.capability_union_leak_detected)
        {
            eprintln!(
                "adminbotd effective identity: {} -> entries [{}], capabilities [{}]",
                identity.unix_user,
                identity.matching_entries.join(", "),
                identity.effective_capabilities.join(", ")
            );
        }
    }
    policy.enforce_sanity_guards()?;
    let app = App::new(policy);
    let server = IpcServer::bind(PathBuf::from(DEFAULT_SOCKET_PATH), DEFAULT_SOCKET_GROUP)?;
    server.run(&app)?;
    Ok(())
}
