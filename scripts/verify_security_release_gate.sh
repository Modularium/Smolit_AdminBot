#!/usr/bin/env bash
set -u

MODE="artifact"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

ARTIFACT_POLICY="${REPO_ROOT}/config/policy.example.toml"
ARTIFACT_POLKIT="${REPO_ROOT}/deploy/polkit/50-adminbotd-systemd.rules"
ARTIFACT_UNIT="${REPO_ROOT}/adminbotd.service"

LIVE_POLICY="/etc/adminbot/policy.toml"
LIVE_POLKIT="/etc/polkit-1/rules.d/50-adminbotd-systemd.rules"
LIVE_UNIT="/etc/systemd/system/adminbotd.service"
LIVE_RUNTIME_DIR="/run/adminbot"
LIVE_SOCKET="/run/adminbot/adminbot.sock"

POLICY_PATH=""
POLKIT_PATH=""
UNIT_PATH=""
RUNTIME_DIR=""
SOCKET_PATH=""
EXPECTED_POLKIT_TEMPLATE="${ARTIFACT_POLKIT}"

FAILURES=0

usage() {
    cat <<'EOF'
Usage:
  scripts/verify_security_release_gate.sh [--mode artifact|live]
                                         [--policy PATH]
                                         [--polkit PATH]
                                         [--unit PATH]
                                         [--runtime-dir PATH]
                                         [--socket PATH]
                                         [--expected-polkit-template PATH]

Modes:
  artifact  Validate the repo-versioned security artifacts for CI/review.
  live      Validate an installed deployment, including runtime directory and socket.
EOF
}

pass() {
    printf 'PASS: %s\n' "$1"
}

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    FAILURES=$((FAILURES + 1))
}

require_exact_line() {
    local path="$1"
    local line="$2"
    if grep -Fxq "$line" "$path"; then
        pass "${path}: contains ${line}"
    else
        fail "${path}: missing exact line ${line}"
    fi
}

require_substring() {
    local path="$1"
    local needle="$2"
    if grep -Fq "$needle" "$path"; then
        pass "${path}: contains ${needle}"
    else
        fail "${path}: missing ${needle}"
    fi
}

check_regular_file() {
    local path="$1"
    if [[ -L "$path" ]]; then
        fail "${path}: symlink is not trusted"
        return 1
    elif [[ -e "$path" && ! -r "$path" ]]; then
        fail "${path}: file exists but is unreadable"
        return 1
    elif [[ -f "$path" ]]; then
        pass "${path}: regular file exists"
        return 0
    elif [[ -e "$path" ]]; then
        fail "${path}: expected regular file, found different artifact type"
        return 1
    else
        fail "${path}: regular file missing"
        return 1
    fi
}

check_policy_artifact() {
    local path="$1"
    check_regular_file "$path" || return
    require_exact_line "$path" "version = 1"
    require_substring "$path" "[constraints]"
    require_substring "$path" "max_parallel_mutations = 1"
}

check_policy_live() {
    local path="$1"
    check_regular_file "$path" || return
    local uid mode
    uid="$(stat -c '%u' "$path" 2>/dev/null || true)"
    mode="$(stat -c '%a' "$path" 2>/dev/null || true)"

    if [[ "$uid" == "0" ]]; then
        pass "${path}: owner uid is root"
    else
        fail "${path}: owner uid must be 0, got ${uid:-unknown}"
    fi

    if [[ -n "$mode" ]] && (( ((8#${mode}) & 8#022) == 0 )); then
        pass "${path}: mode ${mode} is not group/world-writable"
    else
        fail "${path}: mode ${mode:-unknown} is too permissive"
    fi

    require_exact_line "$path" "version = 1"
    require_substring "$path" "[constraints]"
    require_substring "$path" "max_parallel_mutations = 1"
}

check_polkit_file() {
    local path="$1"
    check_regular_file "$path" || return
    require_substring "$path" 'action.id === "org.freedesktop.systemd1.manage-units"'
    require_substring "$path" 'subject.user === "adminbot"'
    require_substring "$path" 'return polkit.Result.YES;'
}

check_polkit_matches_template() {
    local actual="$1"
    local expected="$2"
    check_regular_file "$actual" || return
    check_regular_file "$expected" || return
    if cmp -s "$actual" "$expected"; then
        pass "${actual}: matches versioned polkit template"
    else
        fail "${actual}: differs from versioned polkit template ${expected}"
    fi
}

check_unit_file() {
    local path="$1"
    check_regular_file "$path" || return
    require_exact_line "$path" "User=adminbot"
    require_exact_line "$path" "Group=adminbot"
    require_exact_line "$path" "SupplementaryGroups=adminbotctl"
    require_exact_line "$path" "RuntimeDirectory=adminbot"
    require_exact_line "$path" "RuntimeDirectoryMode=0750"
    require_exact_line "$path" "ExecStart=/usr/local/bin/adminbotd"
    require_exact_line "$path" "NoNewPrivileges=true"
    require_exact_line "$path" "PrivateTmp=true"
    require_exact_line "$path" "PrivateDevices=true"
    require_exact_line "$path" "ProtectSystem=strict"
    require_exact_line "$path" "ProtectHome=true"
    require_exact_line "$path" "MemoryDenyWriteExecute=true"
    require_exact_line "$path" "RestrictRealtime=true"
    require_exact_line "$path" "LockPersonality=true"
    require_exact_line "$path" "CapabilityBoundingSet="
    require_exact_line "$path" "RestrictAddressFamilies=AF_UNIX"
}

check_runtime_directory_live() {
    local path="$1"
    if [[ -L "$path" ]]; then
        fail "${path}: symlink is not trusted"
        return
    fi

    if [[ ! -d "$path" ]]; then
        fail "${path}: runtime directory missing"
        return
    fi

    pass "${path}: runtime directory exists"

    local expected_uid expected_gid actual_uid actual_gid mode
    expected_uid="$(id -u adminbot 2>/dev/null || true)"
    expected_gid="$(id -g adminbot 2>/dev/null || true)"
    actual_uid="$(stat -c '%u' "$path" 2>/dev/null || true)"
    actual_gid="$(stat -c '%g' "$path" 2>/dev/null || true)"
    mode="$(stat -c '%a' "$path" 2>/dev/null || true)"

    if [[ -z "$expected_uid" || -z "$expected_gid" ]]; then
        fail "adminbot user/group must exist for live runtime validation"
        return
    fi

    if [[ "$actual_uid" == "$expected_uid" ]]; then
        pass "${path}: owner matches adminbot"
    else
        fail "${path}: owner uid must be ${expected_uid}, got ${actual_uid:-unknown}"
    fi

    if [[ "$actual_gid" == "$expected_gid" ]]; then
        pass "${path}: group matches adminbot"
    else
        fail "${path}: group gid must be ${expected_gid}, got ${actual_gid:-unknown}"
    fi

    if [[ "$mode" == "750" ]]; then
        pass "${path}: mode is 0750"
    else
        fail "${path}: mode must be 0750, got ${mode:-unknown}"
    fi
}

check_socket_live() {
    local path="$1"
    if [[ -L "$path" ]]; then
        fail "${path}: symlink is not trusted"
        return
    fi

    if [[ ! -S "$path" ]]; then
        fail "${path}: unix socket missing"
        return
    fi

    pass "${path}: unix socket exists"

    local expected_uid expected_gid actual_uid actual_gid mode
    expected_uid="$(id -u adminbot 2>/dev/null || true)"
    expected_gid="$(getent group adminbotctl | cut -d: -f3)"
    actual_uid="$(stat -c '%u' "$path" 2>/dev/null || true)"
    actual_gid="$(stat -c '%g' "$path" 2>/dev/null || true)"
    mode="$(stat -c '%a' "$path" 2>/dev/null || true)"

    if [[ -z "$expected_uid" || -z "$expected_gid" ]]; then
        fail "adminbot user and adminbotctl group must exist for live socket validation"
        return
    fi

    if [[ "$actual_uid" == "$expected_uid" ]]; then
        pass "${path}: owner matches adminbot"
    else
        fail "${path}: owner uid must be ${expected_uid}, got ${actual_uid:-unknown}"
    fi

    if [[ "$actual_gid" == "$expected_gid" ]]; then
        pass "${path}: group matches adminbotctl"
    else
        fail "${path}: group gid must be ${expected_gid}, got ${actual_gid:-unknown}"
    fi

    if [[ "$mode" == "660" ]]; then
        pass "${path}: mode is 0660"
    else
        fail "${path}: mode must be 0660, got ${mode:-unknown}"
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)
            MODE="${2:-}"
            shift 2
            ;;
        --policy)
            POLICY_PATH="${2:-}"
            shift 2
            ;;
        --polkit)
            POLKIT_PATH="${2:-}"
            shift 2
            ;;
        --unit)
            UNIT_PATH="${2:-}"
            shift 2
            ;;
        --runtime-dir)
            RUNTIME_DIR="${2:-}"
            shift 2
            ;;
        --socket)
            SOCKET_PATH="${2:-}"
            shift 2
            ;;
        --expected-polkit-template)
            EXPECTED_POLKIT_TEMPLATE="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'Unknown argument: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

case "$MODE" in
    artifact)
        POLICY_PATH="${POLICY_PATH:-$ARTIFACT_POLICY}"
        POLKIT_PATH="${POLKIT_PATH:-$ARTIFACT_POLKIT}"
        UNIT_PATH="${UNIT_PATH:-$ARTIFACT_UNIT}"
        ;;
    live)
        POLICY_PATH="${POLICY_PATH:-$LIVE_POLICY}"
        POLKIT_PATH="${POLKIT_PATH:-$LIVE_POLKIT}"
        UNIT_PATH="${UNIT_PATH:-$LIVE_UNIT}"
        RUNTIME_DIR="${RUNTIME_DIR:-$LIVE_RUNTIME_DIR}"
        SOCKET_PATH="${SOCKET_PATH:-$LIVE_SOCKET}"
        ;;
    *)
        printf 'Unsupported mode: %s\n' "$MODE" >&2
        usage >&2
        exit 2
        ;;
esac

printf 'Security release gate mode: %s\n' "$MODE"

if [[ "$MODE" == "artifact" ]]; then
    check_policy_artifact "$POLICY_PATH"
    check_polkit_file "$POLKIT_PATH"
    check_unit_file "$UNIT_PATH"
else
    check_policy_live "$POLICY_PATH"
    check_polkit_file "$POLKIT_PATH"
    if [[ -f "$POLKIT_PATH" && ! -L "$POLKIT_PATH" && -r "$POLKIT_PATH" ]]; then
        check_polkit_matches_template "$POLKIT_PATH" "$EXPECTED_POLKIT_TEMPLATE"
    fi
    check_unit_file "$UNIT_PATH"
    check_runtime_directory_live "$RUNTIME_DIR"
    check_socket_live "$SOCKET_PATH"
fi

if (( FAILURES > 0 )); then
    printf 'SECURITY RELEASE GATE: FAIL (%d finding(s))\n' "$FAILURES" >&2
    exit 1
fi

printf 'SECURITY RELEASE GATE: PASS\n'
