use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::{
    DEFAULT_POLICY_PATH, DEFAULT_POLKIT_PATH, DEFAULT_RUNTIME_DIR, DEFAULT_SOCKET_PATH,
    DEFAULT_UNIT_PATH,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateMode {
    Artifact,
    Live,
}

#[derive(Debug, Clone)]
pub struct GateOptions {
    pub mode: GateMode,
    pub policy_path: PathBuf,
    pub polkit_path: PathBuf,
    pub unit_path: PathBuf,
    pub runtime_dir: PathBuf,
    pub socket_path: PathBuf,
    pub expected_polkit_template: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct GateCheck {
    pub status: GateCheckStatus,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateCheckStatus {
    Pass,
    Fail,
}

#[derive(Debug, Clone, Serialize)]
pub struct GateReport {
    pub mode: GateMode,
    pub checks: Vec<GateCheck>,
}

impl GateOptions {
    pub fn defaults(mode: GateMode) -> Self {
        match mode {
            GateMode::Artifact => Self {
                mode,
                policy_path: PathBuf::from("config/policy.example.toml"),
                polkit_path: PathBuf::from("deploy/polkit/50-adminbotd-systemd.rules"),
                unit_path: PathBuf::from("adminbotd.service"),
                runtime_dir: PathBuf::from(DEFAULT_RUNTIME_DIR),
                socket_path: PathBuf::from(DEFAULT_SOCKET_PATH),
                expected_polkit_template: PathBuf::from("deploy/polkit/50-adminbotd-systemd.rules"),
            },
            GateMode::Live => Self {
                mode,
                policy_path: PathBuf::from(DEFAULT_POLICY_PATH),
                polkit_path: PathBuf::from(DEFAULT_POLKIT_PATH),
                unit_path: PathBuf::from(DEFAULT_UNIT_PATH),
                runtime_dir: PathBuf::from(DEFAULT_RUNTIME_DIR),
                socket_path: PathBuf::from(DEFAULT_SOCKET_PATH),
                expected_polkit_template: PathBuf::from("deploy/polkit/50-adminbotd-systemd.rules"),
            },
        }
    }
}

impl GateReport {
    pub fn is_pass(&self) -> bool {
        self.checks
            .iter()
            .all(|check| check.status == GateCheckStatus::Pass)
    }
}

pub fn run_gate(options: &GateOptions) -> GateReport {
    let mut checks = Vec::new();
    match options.mode {
        GateMode::Artifact => {
            check_policy_artifact(&mut checks, &options.policy_path);
            check_polkit_file(&mut checks, &options.polkit_path);
            check_unit_file(&mut checks, &options.unit_path);
        }
        GateMode::Live => {
            check_policy_live(&mut checks, &options.policy_path);
            check_polkit_file(&mut checks, &options.polkit_path);
            check_polkit_matches_template(
                &mut checks,
                &options.polkit_path,
                &options.expected_polkit_template,
            );
            check_unit_file(&mut checks, &options.unit_path);
            check_runtime_directory_live(&mut checks, &options.runtime_dir);
            check_socket_live(&mut checks, &options.socket_path);
        }
    }

    GateReport {
        mode: options.mode,
        checks,
    }
}

fn pass(checks: &mut Vec<GateCheck>, message: impl Into<String>) {
    checks.push(GateCheck {
        status: GateCheckStatus::Pass,
        message: message.into(),
    });
}

fn fail(checks: &mut Vec<GateCheck>, message: impl Into<String>) {
    checks.push(GateCheck {
        status: GateCheckStatus::Fail,
        message: message.into(),
    });
}

fn require_exact_line(checks: &mut Vec<GateCheck>, path: &Path, line: &str) {
    match fs::read_to_string(path) {
        Ok(content) if content.lines().any(|current| current == line) => {
            pass(checks, format!("{}: contains {line}", path.display()));
        }
        Ok(_) => fail(
            checks,
            format!("{}: missing exact line {line}", path.display()),
        ),
        Err(error) => fail(
            checks,
            format!("{}: unable to read file contents: {error}", path.display()),
        ),
    }
}

fn require_substring(checks: &mut Vec<GateCheck>, path: &Path, needle: &str) {
    match fs::read_to_string(path) {
        Ok(content) if content.contains(needle) => {
            pass(checks, format!("{}: contains {needle}", path.display()));
        }
        Ok(_) => fail(checks, format!("{}: missing {needle}", path.display())),
        Err(error) => fail(
            checks,
            format!("{}: unable to read file contents: {error}", path.display()),
        ),
    }
}

fn check_regular_file(checks: &mut Vec<GateCheck>, path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            fail(
                checks,
                format!("{}: symlink is not trusted", path.display()),
            );
            false
        }
        Ok(metadata) if metadata.file_type().is_file() => {
            pass(checks, format!("{}: regular file exists", path.display()));
            true
        }
        Ok(_) => {
            fail(
                checks,
                format!(
                    "{}: expected regular file, found different artifact type",
                    path.display()
                ),
            );
            false
        }
        Err(error) => {
            fail(
                checks,
                format!(
                    "{}: regular file missing or unreadable: {error}",
                    path.display()
                ),
            );
            false
        }
    }
}

fn check_policy_artifact(checks: &mut Vec<GateCheck>, path: &Path) {
    if !check_regular_file(checks, path) {
        return;
    }
    require_exact_line(checks, path, "version = 1");
    require_substring(checks, path, "[constraints]");
    require_substring(checks, path, "max_parallel_mutations = 1");
}

fn check_policy_live(checks: &mut Vec<GateCheck>, path: &Path) {
    if !check_regular_file(checks, path) {
        return;
    }

    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.uid() == 0 {
                pass(checks, format!("{}: owner uid is root", path.display()));
            } else {
                fail(
                    checks,
                    format!(
                        "{}: owner uid must be 0, got {}",
                        path.display(),
                        metadata.uid()
                    ),
                );
            }

            let mode = metadata.mode() & 0o777;
            if mode & 0o022 == 0 {
                pass(
                    checks,
                    format!(
                        "{}: mode {:o} is not group/world-writable",
                        path.display(),
                        mode
                    ),
                );
            } else {
                fail(
                    checks,
                    format!("{}: mode {:o} is too permissive", path.display(), mode),
                );
            }
        }
        Err(error) => fail(
            checks,
            format!("{}: unable to stat policy file: {error}", path.display()),
        ),
    }

    require_exact_line(checks, path, "version = 1");
    require_substring(checks, path, "[constraints]");
    require_substring(checks, path, "max_parallel_mutations = 1");
}

fn check_polkit_file(checks: &mut Vec<GateCheck>, path: &Path) {
    if !check_regular_file(checks, path) {
        return;
    }
    require_substring(
        checks,
        path,
        r#"action.id === "org.freedesktop.systemd1.manage-units""#,
    );
    require_substring(checks, path, r#"subject.user === "adminbot""#);
    require_substring(checks, path, "return polkit.Result.YES;");
}

fn check_polkit_matches_template(checks: &mut Vec<GateCheck>, actual: &Path, expected: &Path) {
    if !check_regular_file(checks, actual) || !check_regular_file(checks, expected) {
        return;
    }

    match (fs::read(actual), fs::read(expected)) {
        (Ok(left), Ok(right)) if left == right => pass(
            checks,
            format!(
                "{}: matches versioned polkit template {}",
                actual.display(),
                expected.display()
            ),
        ),
        (Ok(_), Ok(_)) => fail(
            checks,
            format!(
                "{}: differs from versioned polkit template {}",
                actual.display(),
                expected.display()
            ),
        ),
        (Err(error), _) => fail(
            checks,
            format!(
                "{}: unable to read file contents: {error}",
                actual.display()
            ),
        ),
        (_, Err(error)) => fail(
            checks,
            format!(
                "{}: unable to read file contents: {error}",
                expected.display()
            ),
        ),
    }
}

fn check_unit_file(checks: &mut Vec<GateCheck>, path: &Path) {
    if !check_regular_file(checks, path) {
        return;
    }

    for line in [
        "User=adminbot",
        "Group=adminbot",
        "SupplementaryGroups=adminbotctl",
        "RuntimeDirectory=adminbot",
        "RuntimeDirectoryMode=0750",
        "ExecStart=/usr/local/bin/adminbotd",
        "UMask=0077",
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "PrivateDevices=true",
        "ProtectSystem=strict",
        "ProtectHome=true",
        "ProtectClock=true",
        "ProtectHostname=true",
        "ProtectControlGroups=true",
        "ProtectKernelTunables=true",
        "ProtectKernelModules=true",
        "ProtectKernelLogs=true",
        "MemoryDenyWriteExecute=true",
        "RestrictRealtime=true",
        "RestrictSUIDSGID=true",
        "RestrictNamespaces=true",
        "LockPersonality=true",
        "SystemCallArchitectures=native",
        "CapabilityBoundingSet=",
        "RestrictAddressFamilies=AF_UNIX",
        "RemoveIPC=true",
    ] {
        require_exact_line(checks, path, line);
    }
}

fn check_runtime_directory_live(checks: &mut Vec<GateCheck>, path: &Path) {
    let expected_uid = match uid_from_user_name("adminbot") {
        Some(uid) => uid,
        None => {
            fail(
                checks,
                "adminbot user must exist for live runtime validation",
            );
            return;
        }
    };
    let expected_gid = match gid_from_group_name("adminbot") {
        Some(gid) => gid,
        None => {
            fail(
                checks,
                "adminbot group must exist for live runtime validation",
            );
            return;
        }
    };

    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            fail(
                checks,
                format!("{}: symlink is not trusted", path.display()),
            );
        }
        Ok(metadata) if !metadata.file_type().is_dir() => {
            fail(
                checks,
                format!("{}: runtime directory missing", path.display()),
            );
        }
        Ok(metadata) => {
            pass(
                checks,
                format!("{}: runtime directory exists", path.display()),
            );
            if metadata.uid() == expected_uid {
                pass(
                    checks,
                    format!("{}: owner matches adminbot", path.display()),
                );
            } else {
                fail(
                    checks,
                    format!(
                        "{}: owner uid must be {expected_uid}, got {}",
                        path.display(),
                        metadata.uid()
                    ),
                );
            }
            if metadata.gid() == expected_gid {
                pass(
                    checks,
                    format!("{}: group matches adminbot", path.display()),
                );
            } else {
                fail(
                    checks,
                    format!(
                        "{}: group gid must be {expected_gid}, got {}",
                        path.display(),
                        metadata.gid()
                    ),
                );
            }
            let mode = metadata.mode() & 0o777;
            if mode == 0o750 {
                pass(checks, format!("{}: mode is 0750", path.display()));
            } else {
                fail(
                    checks,
                    format!("{}: mode must be 0750, got {:o}", path.display(), mode),
                );
            }
        }
        Err(error) => fail(
            checks,
            format!("{}: runtime directory missing: {error}", path.display()),
        ),
    }
}

fn check_socket_live(checks: &mut Vec<GateCheck>, path: &Path) {
    let expected_uid = match uid_from_user_name("adminbot") {
        Some(uid) => uid,
        None => {
            fail(
                checks,
                "adminbot user must exist for live socket validation",
            );
            return;
        }
    };
    let expected_gid = match gid_from_group_name("adminbotctl") {
        Some(gid) => gid,
        None => {
            fail(
                checks,
                "adminbotctl group must exist for live socket validation",
            );
            return;
        }
    };

    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            fail(
                checks,
                format!("{}: symlink is not trusted", path.display()),
            );
        }
        Ok(metadata) if !metadata.file_type().is_socket() => {
            fail(checks, format!("{}: unix socket missing", path.display()));
        }
        Ok(metadata) => {
            pass(checks, format!("{}: unix socket exists", path.display()));
            if metadata.uid() == expected_uid {
                pass(
                    checks,
                    format!("{}: owner matches adminbot", path.display()),
                );
            } else {
                fail(
                    checks,
                    format!(
                        "{}: owner uid must be {expected_uid}, got {}",
                        path.display(),
                        metadata.uid()
                    ),
                );
            }
            if metadata.gid() == expected_gid {
                pass(
                    checks,
                    format!("{}: group matches adminbotctl", path.display()),
                );
            } else {
                fail(
                    checks,
                    format!(
                        "{}: group gid must be {expected_gid}, got {}",
                        path.display(),
                        metadata.gid()
                    ),
                );
            }
            let mode = metadata.mode() & 0o777;
            if mode == 0o660 {
                pass(checks, format!("{}: mode is 0660", path.display()));
            } else {
                fail(
                    checks,
                    format!("{}: mode must be 0660, got {:o}", path.display(), mode),
                );
            }
        }
        Err(error) => fail(
            checks,
            format!("{}: unix socket missing: {error}", path.display()),
        ),
    }
}

fn gid_from_group_name(name: &str) -> Option<u32> {
    crate::peer::gid_from_group_name(name).ok().flatten()
}

fn uid_from_user_name(name: &str) -> Option<u32> {
    let c_name = std::ffi::CString::new(name).ok()?;
    let passwd = unsafe { libc::getpwnam(c_name.as_ptr()) };
    if passwd.is_null() {
        return None;
    }

    Some(unsafe { (*passwd).pw_uid })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_gate_fails_for_broken_policy() {
        let temp_dir =
            std::env::temp_dir().join(format!("adminbot-gate-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let broken_policy = temp_dir.join("policy.toml");
        fs::write(&broken_policy, "version = 1\n").expect("write broken policy");

        let mut options = GateOptions::defaults(GateMode::Artifact);
        options.policy_path = broken_policy.clone();
        let report = run_gate(&options);

        assert!(!report.is_pass());
        assert!(report
            .checks
            .iter()
            .any(|check| check.message.contains("max_parallel_mutations = 1")));

        let _ = fs::remove_file(broken_policy);
        let _ = fs::remove_dir(temp_dir);
    }
}
