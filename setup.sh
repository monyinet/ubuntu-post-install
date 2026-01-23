#!/bin/bash
################################################################################
# UBUNTU 24.04.3 LTS - POST-INSTALL CONFIGURATION SCRIPT
# ============================================================================
# This script automates the initial configuration of Ubuntu 24.04.3 LTS
# after a fresh installation, focusing on user configuration, repositories,
# security hardening, and essential tools.
#
# Author: monyinet
# Compatibility: Ubuntu 24.04.3 LTS (Noble Numbat)
# Last Updated: 2026-01-23
#
# USAGE:
#   curl -fsSL https://raw.githubusercontent.com/monyinet/ubuntu-post-install/main/setup.sh | bash
#   OR
#   wget -qO- https://raw.githubusercontent.com/monyinet/ubuntu-post-install/main/setup.sh | bash
#
# IMPORTANT: Run this script as root or with sudo
################################################################################

# Exit on error, undefined variables, and pipe failures
set -euo pipefail
IFS=$'\n\t'

# ============================================================================
# CONFIGURATION AND VARIABLES
# ============================================================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Script metadata
SCRIPT_VERSION="1.0.1"
LOG_FILE="/var/log/ubuntu-setup-$(date +%Y%m%d-%H%M%S).log"

# Dry-run mode (set DRY_RUN=1 to print actions without changing the system)
DRY_RUN="${DRY_RUN:-0}"
AUTO_CONFIRM="${AUTO_CONFIRM:-0}"
CHECK_ONLY="${CHECK_ONLY:-0}"
VALIDATE_ONLY="${VALIDATE_ONLY:-0}"

# User configuration
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
ADMIN_FULLNAME="${ADMIN_FULLNAME:-Administrator}"
ADMIN_SHELL="${ADMIN_SHELL:-/bin/bash}"
ADMIN_PASSWORDLESS_SUDO="${ADMIN_PASSWORDLESS_SUDO:-no}"

# SSH Configuration
SSH_PORT="${SSH_PORT:-22}"
SSH_PERMIT_ROOT_LOGIN="${SSH_PERMIT_ROOT_LOGIN:-no}"
SSH_PASSWORD_AUTH="${SSH_PASSWORD_AUTH:-no}"
DEFAULT_SSH_PUBKEY_PATH="${DEFAULT_SSH_PUBKEY_PATH:-}"
if [[ -z "$DEFAULT_SSH_PUBKEY_PATH" ]]; then
    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER:-}" != "root" ]]; then
        DEFAULT_SSH_PUBKEY_PATH="/home/${SUDO_USER}/.ssh/id_ed25519.pub"
    else
        DEFAULT_SSH_PUBKEY_PATH="$HOME/.ssh/id_ed25519.pub"
    fi
fi
SSH_PUBKEY_PATH="${SSH_PUBKEY_PATH:-$DEFAULT_SSH_PUBKEY_PATH}"
SSH_PUBKEY_CONTENT="${SSH_PUBKEY_CONTENT:-}"
GENERATE_SSH_KEYS="${GENERATE_SSH_KEYS:-no}"

# Timezone
TIMEZONE="${TIMEZONE:-Europe/Madrid}"

# Backup directory
BACKUP_DIR="${BACKUP_DIR:-/opt/backups/system-configs}"
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"

# PHP Version for Ondrej PPA
PHP_VERSION="${PHP_VERSION:-8.3}"

# Optional features
ENABLE_TIMESHIFT="${ENABLE_TIMESHIFT:-no}"
ALLOW_HTTP="${ALLOW_HTTP:-no}"
ALLOW_HTTPS="${ALLOW_HTTPS:-no}"
ALLOW_FTP="${ALLOW_FTP:-no}"
DISABLE_IPV6="${DISABLE_IPV6:-no}"

# Per-run backup location for files modified by this script
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RUN_BACKUP_DIR="${BACKUP_DIR}/run-${RUN_ID}"

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp="$(date +"%Y-%m-%d %H:%M:%S")"
    if [[ "$DRY_RUN" == "1" ]]; then
        printf '%b\n' "[${timestamp}] [${level}] ${message}"
    else
        printf '%b\n' "[${timestamp}] [${level}] ${message}" | tee -a "$LOG_FILE"
    fi
}

log_info()   { log "INFO"    "${GREEN}$*${NC}"; }
log_warn()   { log "WARN"    "${YELLOW}$*${NC}"; }
log_error()  { log "ERROR"   "${RED}$*${NC}"; }
log_success(){ log "SUCCESS" "${CYAN}$*${NC}"; }
log_debug()  { log "DEBUG"   "${BLUE}$*${NC}"; }

# Clean legacy host.conf entries to avoid resolver warnings
clean_host_conf() {
    if [[ -f /etc/host.conf ]]; then
        run_cmd sed -i '/^[[:space:]]*nospoof[[:space:]]\+on/d' /etc/host.conf 2>/dev/null || true
    else
        write_file /etc/host.conf << 'EOF'
multi on
EOF
    fi
    if [[ -f /etc/host.conf ]] && ! grep -q '^[[:space:]]*multi[[:space:]]\+on' /etc/host.conf 2>/dev/null; then
        append_line "multi on" /etc/host.conf
    fi
}

# Run a command, or log it during dry-run
run_cmd() {
    if [[ "$DRY_RUN" == "1" ]]; then
        log_info "DRY_RUN: $*"
        return 0
    fi
    "$@"
}

ensure_run_backup_dir() {
    if [[ "$DRY_RUN" == "1" ]]; then
        return 0
    fi
    run_cmd mkdir -p "$RUN_BACKUP_DIR"
    run_cmd chmod 700 "$RUN_BACKUP_DIR" 2>/dev/null || true
}

backup_file_if_exists() {
    local path="$1"
    if [[ ! -e "$path" ]]; then
        return 0
    fi
    if [[ "$DRY_RUN" == "1" ]]; then
        log_info "DRY_RUN: would backup $path to $RUN_BACKUP_DIR"
        return 0
    fi
    ensure_run_backup_dir
    local rel="${path#/}"
    local dest="${RUN_BACKUP_DIR}/${rel}"
    run_cmd mkdir -p "$(dirname "$dest")"
    run_cmd cp -a -- "$path" "$dest"
    log_info "Backed up $path -> $dest"
}

# Write a file from stdin, or skip during dry-run
write_file() {
    local path="$1"
    if [[ "$DRY_RUN" == "1" ]]; then
        log_info "DRY_RUN: would write $path"
        cat >/dev/null
        return 0
    fi
    cat > "$path"
}

# Append to a file from stdin, or skip during dry-run
append_file() {
    local path="$1"
    if [[ "$DRY_RUN" == "1" ]]; then
        log_info "DRY_RUN: would append to $path"
        cat >/dev/null
        return 0
    fi
    cat >> "$path"
}

# Append a single line to a file, or skip during dry-run
append_line() {
    local line="$1"
    local path="$2"
    if [[ "$DRY_RUN" == "1" ]]; then
        log_info "DRY_RUN: would append to $path: $line"
        return 0
    fi
    echo "$line" >> "$path"
}

# Check if running as root
check_root() {
    if [[ "$DRY_RUN" == "1" ]]; then
        return 0
    fi
    if [[ "$CHECK_ONLY" == "1" || "$VALIDATE_ONLY" == "1" ]]; then
        return 0
    fi
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Confirm before proceeding
confirm_action() {
    local prompt="${1:-Are you sure you want to continue?}"
    if [[ "$AUTO_CONFIRM" == "1" ]]; then
        return 0
    fi
    if [[ ! -t 0 && ! -r /dev/tty ]]; then
        log_info "Non-interactive session detected; proceeding with defaults."
        return 0
    fi
    local response=""
    if [[ -t 0 ]]; then
        read -r -p "$prompt [y/N] " response || response=""
    else
        read -r -p "$prompt [y/N] " response < /dev/tty || response=""
    fi
    if [[ -z "$response" ]]; then
        response=""
    fi
    case "$response" in
        [yY][eE][sS]|[yY])
            return 0
            ;;
        *)
            log_warn "Action cancelled"
            exit 0
            ;;
    esac
}

# Read prompt from stdin or /dev/tty
prompt_read() {
    local prompt="$1"
    local target_var="$2"
    local temp_input=""
    if [[ -t 0 ]]; then
        read -r -p "$prompt" temp_input || temp_input=""
    elif [[ -r /dev/tty ]]; then
        read -r -p "$prompt" temp_input < /dev/tty || temp_input=""
    else
        temp_input=""
    fi
    printf -v "$target_var" '%s' "$temp_input"
}

# Prompt for a value with a default; skip if non-interactive
prompt_default() {
    local var_name="$1"
    local prompt="$2"
    local default_value="$3"
    local input=""

    if [[ "$AUTO_CONFIRM" == "1" || ( ! -t 0 && ! -r /dev/tty ) ]]; then
        return 0
    fi

    prompt_read "${prompt} [${default_value}]: " input
    if [[ -z "$input" ]]; then
        input="$default_value"
    fi
    printf -v "$var_name" '%s' "$input"
}

# Prompt for yes/no with a default; skip if non-interactive
prompt_yes_no() {
    local var_name="$1"
    local prompt="$2"
    local default_value="$3"
    local input=""

    if [[ "$AUTO_CONFIRM" == "1" || ( ! -t 0 && ! -r /dev/tty ) ]]; then
        return 0
    fi

    while true; do
        prompt_read "${prompt} [${default_value}]: " input
        if [[ -z "$input" ]]; then
            input="$default_value"
        fi
        case "$input" in
            y|Y|yes|YES)
                printf -v "$var_name" '%s' "yes"
                return 0
                ;;
            n|N|no|NO)
                printf -v "$var_name" '%s' "no"
                return 0
                ;;
            *)
                log_warn "Invalid input '${input}'. Please enter yes or no."
                ;;
        esac
    done
}

determine_admin_shell() {
    if [[ -x /usr/bin/zsh ]]; then
        ADMIN_SHELL="/usr/bin/zsh"
    elif [[ -x /bin/bash ]]; then
        ADMIN_SHELL="/bin/bash"
    fi
}

list_shell_options() {
    printf '%s' "bash (b) / zsh (z)"
}

prompt_shell() {
    local prompt="$1"
    local default_value="$2"
    local input=""

    if [[ "$AUTO_CONFIRM" == "1" || ( ! -t 0 && ! -r /dev/tty ) ]]; then
        return 0
    fi

    while true; do
        prompt_read "${prompt} [${default_value}]: " input
        if [[ -z "$input" ]]; then
            input="$default_value"
        fi
        case "$input" in
            b|B|bash|/bin/bash)
                ADMIN_SHELL="/bin/bash"
                return 0
                ;;
            z|Z|zsh|/usr/bin/zsh)
                ADMIN_SHELL="/usr/bin/zsh"
                return 0
                ;;
            *)
                log_warn "Invalid shell '${input}'. Use 'b' for bash or 'z' for zsh."
                ;;
        esac
    done
}

is_valid_timezone() {
    local tz="$1"
    if command -v timedatectl &> /dev/null; then
        timedatectl list-timezones 2>/dev/null | grep -qx "$tz"
        return $?
    fi
    [[ -e "/usr/share/zoneinfo/${tz}" ]]
}

prompt_timezone() {
    local prompt="$1"
    local default_value="$2"
    local input=""

    if [[ "$AUTO_CONFIRM" == "1" || ( ! -t 0 && ! -r /dev/tty ) ]]; then
        return 0
    fi

    while true; do
        prompt_read "${prompt} [${default_value}] (e.g. Europe/Madrid, UTC, America/New_York): " input
        if [[ -z "$input" ]]; then
            input="$default_value"
        fi
        if is_valid_timezone "$input"; then
            TIMEZONE="$input"
            return 0
        fi
        log_warn "Invalid timezone '${input}'."
    done
}

prompt_ssh_port() {
    local prompt="$1"
    local default_value="$2"
    local input=""

    if [[ "$AUTO_CONFIRM" == "1" || ( ! -t 0 && ! -r /dev/tty ) ]]; then
        return 0
    fi

    while true; do
        prompt_read "${prompt} [${default_value}] (1-65535, e.g. 22 or 2222): " input
        if [[ -z "$input" ]]; then
            input="$default_value"
        fi
        if [[ "$input" =~ ^[0-9]+$ ]] && (( input >= 1 && input <= 65535 )); then
            SSH_PORT="$input"
            return 0
        fi
        log_warn "Invalid port '${input}'."
    done
}

prompt_ssh_pubkey_path() {
    local prompt="$1"
    local default_value="$2"
    local input=""
    local key_content=""

    if [[ "$AUTO_CONFIRM" == "1" || ( ! -t 0 && ! -r /dev/tty ) ]]; then
        return 0
    fi

    if [[ -n "$default_value" && ! -f "$default_value" ]]; then
        log_warn "Default SSH key path not found (${default_value}); you can paste a key later."
        default_value="skip"
    fi

    while true; do
        prompt_read "${prompt} [${default_value}] (enter a path or 'skip'): " input
        if [[ -z "$input" ]]; then
            input="$default_value"
        fi
        if [[ "$input" == "skip" ]]; then
            SSH_PUBKEY_PATH=""
            return 0
        fi
        if [[ -f "$input" ]]; then
            key_content=$(head -n 1 "$input")
            if [[ "$key_content" =~ ^(ssh-|sk-)[A-Za-z0-9+/=]+(\ .*)?$ ]]; then
                SSH_PUBKEY_PATH="$input"
                return 0
            fi
            log_warn "File '${input}' does not look like a valid SSH public key."
        else
            log_warn "SSH public key not found at '${input}'."
        fi
    done
}

prompt_ssh_pubkey_content() {
    local prompt="$1"

    if [[ "$AUTO_CONFIRM" == "1" || ( ! -t 0 && ! -r /dev/tty ) ]]; then
        return 0
    fi

    while true; do
        prompt_read "${prompt} (single line, or press Enter to skip): " SSH_PUBKEY_CONTENT
        if [[ -z "$SSH_PUBKEY_CONTENT" ]]; then
            return 0
        fi
        if [[ "$SSH_PUBKEY_CONTENT" =~ ^(ssh-|sk-)[A-Za-z0-9+/=]+(\ .*)?$ ]]; then
            return 0
        fi
        log_warn "That does not look like a valid SSH public key."
        SSH_PUBKEY_CONTENT=""
    done
}

prompt_configuration() {
    if [[ "$AUTO_CONFIRM" == "1" || ( ! -t 0 && ! -r /dev/tty ) ]]; then
        log_info "Non-interactive configuration: using defaults"
        return 0
    fi

    log_info "Interactive configuration (press Enter to accept defaults)"
    determine_admin_shell
    local shell_options
    shell_options=$(list_shell_options)
    prompt_default ADMIN_USERNAME "Admin username" "$ADMIN_USERNAME"
    prompt_default ADMIN_FULLNAME "Admin full name" "$ADMIN_FULLNAME"
    prompt_shell "Admin shell (${shell_options})" "$ADMIN_SHELL"
    prompt_yes_no ADMIN_PASSWORDLESS_SUDO "Passwordless sudo for admin (yes/no)" "$ADMIN_PASSWORDLESS_SUDO"
    prompt_timezone "Timezone" "$TIMEZONE"
    prompt_ssh_port "SSH port" "$SSH_PORT"
    prompt_yes_no SSH_PASSWORD_AUTH "Allow SSH password auth (yes/no)" "$SSH_PASSWORD_AUTH"
    if [[ -s "/home/${ADMIN_USERNAME}/.ssh/authorized_keys" ]]; then
        log_info "Existing SSH authorized_keys found for $ADMIN_USERNAME; skipping SSH key prompts"
    else
        prompt_ssh_pubkey_path "SSH public key path" "$SSH_PUBKEY_PATH"
        prompt_ssh_pubkey_content "Paste SSH public key for $ADMIN_USERNAME"
        prompt_yes_no GENERATE_SSH_KEYS "Generate SSH keypair for admin (yes/no)" "$GENERATE_SSH_KEYS"
    fi
    prompt_yes_no ALLOW_HTTP "Open HTTP port 80 (yes/no)" "$ALLOW_HTTP"
    prompt_yes_no ALLOW_HTTPS "Open HTTPS port 443 (yes/no)" "$ALLOW_HTTPS"
    prompt_yes_no ALLOW_FTP "Open FTP port 21 (yes/no)" "$ALLOW_FTP"
    prompt_yes_no DISABLE_IPV6 "Disable IPv6 (yes/no)" "$DISABLE_IPV6"
    prompt_yes_no ENABLE_TIMESHIFT "Enable Timeshift snapshots (yes/no)" "$ENABLE_TIMESHIFT"

    log_info "Selected SSH port: $SSH_PORT"
}

normalize_yes_no() {
    local var_name="$1"
    local value="${!var_name:-}"
    value="${value//[[:space:]]/}"
    case "$value" in
        y|Y|yes|YES)
            printf -v "$var_name" '%s' "yes"
            ;;
        n|N|no|NO)
            printf -v "$var_name" '%s' "no"
            ;;
        *)
            ;;
    esac
}

is_valid_username() {
    local username="$1"
    [[ -n "$username" ]] || return 1
    [[ "$username" != "root" ]] || return 1
    [[ "$username" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]
}

detect_ubuntu_version_id() {
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        if [[ "${ID:-}" == "ubuntu" ]]; then
            printf '%s' "${VERSION_ID:-}"
            return 0
        fi
    fi
    return 1
}

preflight_checks() {
    if ! is_valid_username "$ADMIN_USERNAME"; then
        log_error "Invalid ADMIN_USERNAME '${ADMIN_USERNAME}'. Use lowercase letters/numbers/underscore/dash, start with a letter/underscore, max 32 chars, not 'root'."
        exit 1
    fi
    if ! is_valid_timezone "$TIMEZONE"; then
        log_error "Invalid TIMEZONE '${TIMEZONE}'. Use a value from 'timedatectl list-timezones' (e.g. Europe/Madrid, UTC)."
        exit 1
    fi
    if [[ ! "$BACKUP_RETENTION_DAYS" =~ ^[0-9]+$ ]] || (( BACKUP_RETENTION_DAYS < 1 || BACKUP_RETENTION_DAYS > 3650 )); then
        log_error "Invalid BACKUP_RETENTION_DAYS '${BACKUP_RETENTION_DAYS}'. Must be an integer between 1 and 3650."
        exit 1
    fi

    local ubuntu_version_id=""
    ubuntu_version_id="$(detect_ubuntu_version_id 2>/dev/null || true)"
    if [[ -n "$ubuntu_version_id" && "$ubuntu_version_id" != 24.04* ]]; then
        log_warn "This script targets Ubuntu 24.04.x; detected VERSION_ID='${ubuntu_version_id}'. Proceed with caution."
    fi

    if [[ ! "$SSH_PORT" =~ ^[0-9]+$ ]] || (( SSH_PORT < 1 || SSH_PORT > 65535 )); then
        log_error "Invalid SSH_PORT '${SSH_PORT}'. Must be 1-65535."
        exit 1
    fi
    if [[ "$SSH_PASSWORD_AUTH" == "no" && "$GENERATE_SSH_KEYS" != "yes" ]]; then
        if [[ -z "${SSH_PUBKEY_CONTENT}" ]] && { [[ -z "${SSH_PUBKEY_PATH}" ]] || [[ ! -f "${SSH_PUBKEY_PATH}" ]]; }; then
            if [[ -s "/home/${ADMIN_USERNAME}/.ssh/authorized_keys" ]]; then
                log_info "Existing SSH authorized_keys found for $ADMIN_USERNAME; proceeding with password auth disabled"
                return 0
            fi
            log_error "No SSH key available and password auth is disabled. Set SSH_PUBKEY_PATH, set SSH_PUBKEY_CONTENT, set GENERATE_SSH_KEYS=yes, or set SSH_PASSWORD_AUTH=yes."
            exit 1
        fi
    fi
}

show_help() {
    cat << 'EOF'
Usage:
  ./setup.sh [--yes] [--dry-run] [--check] [--validate] [--help] [--version]

Options:
  -y, --yes        Non-interactive (assume defaults)
  -n, --dry-run    Print actions without changing the system
      --check      Validate inputs and print what would run (no changes)
      --validate   Validate inputs only (no changes)
      --version    Print script version and exit
  -h, --help       Show this help and exit

Common environment variables:
  ADMIN_USERNAME, ADMIN_FULLNAME, ADMIN_PASSWORDLESS_SUDO
  TIMEZONE, SSH_PORT, SSH_PASSWORD_AUTH, SSH_PUBKEY_PATH, SSH_PUBKEY_CONTENT, GENERATE_SSH_KEYS
  ALLOW_HTTP, ALLOW_HTTPS, ALLOW_FTP, DISABLE_IPV6, ENABLE_TIMESHIFT
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run|-n)
                DRY_RUN=1
                ;;
            --yes|-y)
                AUTO_CONFIRM=1
                ;;
            --check)
                CHECK_ONLY=1
                DRY_RUN=1
                AUTO_CONFIRM=1
                ;;
            --validate)
                VALIDATE_ONLY=1
                DRY_RUN=1
                AUTO_CONFIRM=1
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            --version)
                printf '%s\n' "$SCRIPT_VERSION"
                exit 0
                ;;
            *)
                log_warn "Ignoring unknown argument: $1"
                ;;
        esac
        shift
    done
}

print_effective_configuration() {
    log_info "Effective configuration:"
    log_info "  ADMIN_USERNAME=${ADMIN_USERNAME}"
    log_info "  ADMIN_FULLNAME=${ADMIN_FULLNAME}"
    log_info "  ADMIN_SHELL=${ADMIN_SHELL}"
    log_info "  ADMIN_PASSWORDLESS_SUDO=${ADMIN_PASSWORDLESS_SUDO}"
    log_info "  TIMEZONE=${TIMEZONE}"
    log_info "  SSH_PORT=${SSH_PORT}"
    log_info "  SSH_PASSWORD_AUTH=${SSH_PASSWORD_AUTH}"
    log_info "  SSH_PERMIT_ROOT_LOGIN=${SSH_PERMIT_ROOT_LOGIN}"
    log_info "  SSH_PUBKEY_PATH=${SSH_PUBKEY_PATH:-<empty>}"
    log_info "  SSH_PUBKEY_CONTENT=${SSH_PUBKEY_CONTENT:+<set>}"
    log_info "  GENERATE_SSH_KEYS=${GENERATE_SSH_KEYS}"
    log_info "  ALLOW_HTTP=${ALLOW_HTTP}"
    log_info "  ALLOW_HTTPS=${ALLOW_HTTPS}"
    log_info "  ALLOW_FTP=${ALLOW_FTP}"
    log_info "  DISABLE_IPV6=${DISABLE_IPV6}"
    log_info "  ENABLE_TIMESHIFT=${ENABLE_TIMESHIFT}"
    log_info "  BACKUP_DIR=${BACKUP_DIR}"
    log_info "  BACKUP_RETENTION_DAYS=${BACKUP_RETENTION_DAYS}"
}

print_execution_plan() {
    log_info "Planned actions:"
    log_info "  - Configure timezone/locale"
    log_info "  - Configure apt repositories and updates"
    log_info "  - Create/secure admin user and sudo policy"
    log_info "  - Configure SSH server and admin SSH access"
    log_info "  - Configure UFW, Fail2Ban, and AppArmor"
    log_info "  - Apply sysctl hardening and security tweaks"
    log_info "  - Optional: Timeshift snapshots"
    log_info "  - Install monitoring, audit rules, and backups"
}
# Check package manager availability
check_package_manager() {
    if command -v apt-get &> /dev/null; then
        return 0
    else
        log_error "No supported package manager found (apt-get required)"
        exit 1
    fi
}

# ============================================================================
# SYSTEM INITIALIZATION
# ============================================================================

initialize_environment() {
    log_info "Initializing Ubuntu 24.04 Post-Install Configuration Script v${SCRIPT_VERSION}"
    log_info "Log file: $LOG_FILE"
    if [[ "$DRY_RUN" == "1" ]]; then
        log_info "Dry-run mode enabled: no changes will be made"
    fi

    # Create log file
    run_cmd touch "$LOG_FILE" 2>/dev/null || log_warn "Cannot create log file"

    # Remove legacy host.conf options early to prevent resolver warnings
    clean_host_conf

    # Set locale
    if [[ -z "$LANG" ]]; then
        export LANG=C.UTF-8
    fi

    # Disable interactive prompts
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a
    export NEEDRESTART_RESTART_DB=1

    log_success "Environment initialized"
}

# ============================================================================
# REPOSITORY CONFIGURATION
# ============================================================================

configure_repositories() {
    log_info "Configuring package repositories..."

    # Update existing repositories
    log_info "Updating package lists..."
    run_cmd apt-get update -qq

    # Install software-properties-common for add-apt-repository
    log_info "Installing software-properties-common..."
    run_cmd apt-get install -y -qq software-properties-common

    # Enable universe repository (already enabled by default in Ubuntu 24.04)
    log_info "Ensuring universe repository is enabled..."
    run_cmd add-apt-repository -y universe 2>/dev/null || true

    # Enable multiverse repository
    log_info "Enabling multiverse repository..."
    run_cmd add-apt-repository -y multiverse 2>/dev/null || true

    # Update again after adding repositories
    log_info "Updating package lists after repository changes..."
    run_cmd apt-get update -qq

    # Add Ondrej PHP PPA (latest PHP versions)
    log_info "Adding Ondrej PHP PPA (PHP ${PHP_VERSION})..."
    if ! run_cmd add-apt-repository -y ppa:ondrej/php &> /dev/null; then
        log_warn "Failed to add PHP PPA, continuing without it"
    else
        run_cmd apt-get update -qq
        log_success "PHP PPA added successfully"
    fi

    # Add Git Stable PPA for latest Git version
    log_info "Adding Git stable PPA..."
    run_cmd add-apt-repository -y ppa:git-core/ppa &> /dev/null || log_warn "Git PPA not added"

    # Update one more time
    run_cmd apt-get update -qq

    log_success "Repository configuration completed"
}

# ============================================================================
# SYSTEM UPDATE
# ============================================================================

update_system() {
    log_info "Updating system packages..."

    # Upgrade all packages
    log_info "Upgrading installed packages (this may take a while)..."
    run_cmd apt-get upgrade -y -qq

    # Perform distribution upgrade
    log_info "Performing distribution upgrade..."
    run_cmd apt-get dist-upgrade -y -qq

    # Install update management tools
    log_info "Installing unattended-upgrades..."
    run_cmd apt-get install -y -qq unattended-upgrades

    # Configure unattended-upgrades
    log_info "Configuring automatic security updates..."
    backup_file_if_exists /etc/apt/apt.conf.d/20auto-upgrades
    write_file /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

    # Configure unattended-upgrades for security and updates
    backup_file_if_exists /etc/apt/apt.conf.d/50unattended-upgrades
    write_file /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}:${distro_codename}-updates";
};

Unattended-Upgrade::Package-Blacklist {
};

Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";

Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
EOF

    # Clean up
    log_info "Cleaning up..."
    run_cmd apt-get autoremove -y -qq
    run_cmd apt-get autoclean -qq

    log_success "System update completed"
}

# ============================================================================
# USER CONFIGURATION
# ============================================================================

configure_users() {
    log_info "Configuring users and groups..."

    if [[ ! -x "$ADMIN_SHELL" ]]; then
        log_warn "Shell $ADMIN_SHELL not found; falling back to /bin/bash"
        ADMIN_SHELL="/bin/bash"
    fi

    # Create admin user if it doesn't exist
    if id "$ADMIN_USERNAME" &> /dev/null; then
        log_warn "User '$ADMIN_USERNAME' already exists"
    else
        log_info "Creating user '$ADMIN_USERNAME'..."
        if getent group "$ADMIN_USERNAME" &> /dev/null; then
            run_cmd useradd -m -g "$ADMIN_USERNAME" -s "$ADMIN_SHELL" -c "$ADMIN_FULLNAME" "$ADMIN_USERNAME"
        else
            run_cmd useradd -m -s "$ADMIN_SHELL" -c "$ADMIN_FULLNAME" "$ADMIN_USERNAME"
        fi
        log_success "User '$ADMIN_USERNAME' created"
    fi

    # Add to sudo group
    log_info "Adding '$ADMIN_USERNAME' to sudo group..."
    run_cmd usermod -aG sudo "$ADMIN_USERNAME"

    # Configure sudoers
    log_info "Configuring sudo permissions..."
    local sudo_rule="${ADMIN_USERNAME} ALL=(ALL) ALL"
    if [[ "$ADMIN_PASSWORDLESS_SUDO" == "yes" ]]; then
        sudo_rule="${ADMIN_USERNAME} ALL=(ALL) NOPASSWD: ALL"
    fi

    backup_file_if_exists /etc/sudoers.d/99-admin-user
    write_file /etc/sudoers.d/99-admin-user << EOF
# Allow admin user to run all commands
${sudo_rule}

# Defaults for sudo users
Defaults timestamp_timeout=30
Defaults log_input,log_output
Defaults !pwfeedback
EOF
    run_cmd chmod 440 /etc/sudoers.d/99-admin-user

    # Create sudo group and add user
    if ! getent group sudoadmin &> /dev/null; then
        run_cmd groupadd sudoadmin 2>/dev/null || true
    fi
    run_cmd usermod -aG sudoadmin "$ADMIN_USERNAME" 2>/dev/null || true

    # Set password for admin user (optional, SSH key is preferred)
    if [[ -n "${ADMIN_PASSWORD:-}" ]]; then
        log_warn "Setting password for $ADMIN_USERNAME (recommended to use SSH keys instead)"
        echo "${ADMIN_USERNAME}:${ADMIN_PASSWORD}" | run_cmd chpasswd || true
    else
        log_warn "ADMIN_PASSWORD not set; skipping password change"
    fi

    log_success "User configuration completed"
}

# ============================================================================
# SSH CONFIGURATION
# ============================================================================

install_admin_ssh_key() {
    log_info "Ensuring SSH access for $ADMIN_USERNAME..."

    local ssh_dir="/home/${ADMIN_USERNAME}/.ssh"
    local auth_keys="${ssh_dir}/authorized_keys"
    local key_installed=0
    local input_key=""

    run_cmd mkdir -p "$ssh_dir"
    run_cmd chmod 700 "$ssh_dir"
    run_cmd chown "${ADMIN_USERNAME}:${ADMIN_USERNAME}" "$ssh_dir"

    if [[ -s "$auth_keys" && -z "$SSH_PUBKEY_CONTENT" && ! -f "$SSH_PUBKEY_PATH" ]]; then
        log_info "Existing SSH authorized_keys found for $ADMIN_USERNAME; skipping key install"
        key_installed=1
    fi

    if [[ -n "$SSH_PUBKEY_CONTENT" ]]; then
        if [[ "$SSH_PUBKEY_CONTENT" =~ ^(ssh-|sk-)[A-Za-z0-9+/=]+(\ .*)?$ ]]; then
            if [[ ! -f "$auth_keys" ]] || ! grep -qF "$SSH_PUBKEY_CONTENT" "$auth_keys" 2>/dev/null; then
                if [[ "$DRY_RUN" == "1" ]]; then
                    log_info "DRY_RUN: would add SSH key from SSH_PUBKEY_CONTENT to $auth_keys"
                else
                    echo "$SSH_PUBKEY_CONTENT" >> "$auth_keys"
                fi
            else
                log_info "SSH public key already present in $auth_keys"
            fi
            run_cmd chmod 600 "$auth_keys"
            run_cmd chown "${ADMIN_USERNAME}:${ADMIN_USERNAME}" "$auth_keys"
            key_installed=1
            log_success "SSH public key installed for $ADMIN_USERNAME"
        else
            log_warn "SSH_PUBKEY_CONTENT does not look like a valid SSH public key"
        fi
    elif [[ -f "$SSH_PUBKEY_PATH" ]]; then
        local pubkey
        pubkey=$(cat "$SSH_PUBKEY_PATH")
        if [[ -n "$pubkey" ]]; then
            if [[ ! -f "$auth_keys" ]] || ! grep -qF "$pubkey" "$auth_keys" 2>/dev/null; then
                if [[ "$DRY_RUN" == "1" ]]; then
                    log_info "DRY_RUN: would add SSH key from $SSH_PUBKEY_PATH to $auth_keys"
                else
                    echo "$pubkey" >> "$auth_keys"
                fi
            fi
            run_cmd chmod 600 "$auth_keys"
            run_cmd chown "${ADMIN_USERNAME}:${ADMIN_USERNAME}" "$auth_keys"
            key_installed=1
            log_success "SSH public key installed for $ADMIN_USERNAME"
        fi
    elif [[ -n "$SSH_PUBKEY_PATH" ]]; then
        log_warn "SSH public key not found at $SSH_PUBKEY_PATH"
    fi

    if [[ "$SSH_PASSWORD_AUTH" == "no" && "$key_installed" -ne 1 ]]; then
        if [[ "$DRY_RUN" == "1" ]]; then
            log_warn "DRY_RUN: would prompt for an SSH key because password auth is disabled"
            return 0
        fi

        if [[ "$GENERATE_SSH_KEYS" == "yes" ]]; then
            log_info "SSH key generation enabled; proceeding without existing public key"
            return 0
        fi

        if [[ ! -t 0 ]]; then
            log_error "Password auth is disabled but no SSH key is installed, and no TTY is available. Provide SSH_PUBKEY_PATH, set SSH_PUBKEY_CONTENT, enable GENERATE_SSH_KEYS, or set SSH_PASSWORD_AUTH=yes."
            exit 1
        fi

        echo ""
        log_warn "Password auth is disabled and no SSH key is installed."
        log_info "Paste a single-line SSH public key now (or press Enter to abort):"
        read -r input_key
        if [[ -z "$input_key" ]]; then
            log_error "No SSH key provided. Provide SSH_PUBKEY_PATH or set SSH_PASSWORD_AUTH=yes."
            exit 1
        fi
        if [[ ! "$input_key" =~ ^(ssh-|sk-)[A-Za-z0-9+/=]+(\ .*)?$ ]]; then
            log_error "SSH key format looks invalid. Provide a valid public key."
            exit 1
        fi
        if [[ ! -f "$auth_keys" ]] || ! grep -qF "$input_key" "$auth_keys" 2>/dev/null; then
            echo "$input_key" >> "$auth_keys"
        fi
        run_cmd chmod 600 "$auth_keys"
        run_cmd chown "${ADMIN_USERNAME}:${ADMIN_USERNAME}" "$auth_keys"
        key_installed=1
        log_success "SSH public key installed for $ADMIN_USERNAME"
    fi

    # De-duplicate authorized_keys to prevent repeated entries
    if [[ -f "$auth_keys" ]]; then
        if [[ "$DRY_RUN" == "1" ]]; then
            log_info "DRY_RUN: would de-duplicate $auth_keys"
        else
            awk '!seen[$0]++' "$auth_keys" > "${auth_keys}.tmp" && mv "${auth_keys}.tmp" "$auth_keys"
        fi
    fi
}

configure_ssh() {
    log_info "Configuring SSH server..."

    # Backup existing sshd_config
    if [[ -f /etc/ssh/sshd_config ]]; then
        local backup_ts
        backup_ts="$(date +%Y%m%d%H%M%S)"
        run_cmd cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.backup.${backup_ts}"
        log_info "Backed up existing sshd_config"
    fi

    # Generate host keys if they don't exist
    log_info "Generating SSH host keys..."
    run_cmd ssh-keygen -A 2>/dev/null || true

    # Create secure sshd_config
    backup_file_if_exists /etc/ssh/sshd_config
    write_file /etc/ssh/sshd_config << EOF
# SSH Server Configuration - Ubuntu 24.04

# === SSH Protocol and Port ===
Port ${SSH_PORT}
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::

# === Host Keys ===
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# === Authentication ===
PermitRootLogin ${SSH_PERMIT_ROOT_LOGIN}
MaxAuthTries 3
MaxSessions 10
MaxStartups 10:30:60
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# Password Authentication (disable for production)
PasswordAuthentication ${SSH_PASSWORD_AUTH}
KbdInteractiveAuthentication no
UsePAM yes

# === Timeouts ===
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no

# === X11 and Forwarding ===
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no

# === Banner ===
Banner /etc/ssh/banner

# === Subsystem ===
Subsystem sftp /usr/lib/openssh/sftp-server

# === Logging ===
SyslogFacility AUTH
LogLevel INFO

# === Login Grace Time ===
LoginGraceTime 60

# === Disable empty passwords ===
PermitEmptyPasswords no

# === Strict Modes ===
StrictModes yes

# === Ignore Rhosts ===
IgnoreRhosts yes

# === Allow users ===
AllowUsers ${ADMIN_USERNAME}

# === Print Motd ===
PrintMotd no

# === Compression ===
Compression delayed

# === Version Addendum ===
VersionAddendum none
EOF

    # Create SSH banner
    backup_file_if_exists /etc/ssh/banner
    write_file /etc/ssh/banner << 'EOF'
*****************************************
*    AUTHORIZED ACCESS ONLY             *
*****************************************
Disconnect immediately if you are not
authorized to access this system.
All activities are monitored and logged.
*****************************************
EOF

    # Ensure proper permissions
    run_cmd chmod 644 /etc/ssh/sshd_config
    run_cmd chmod 600 /etc/ssh/banner

    # Validate SSH configuration
    run_cmd sshd -t -f /etc/ssh/sshd_config

    # Create .ssh directory for admin user
    run_cmd mkdir -p "/home/${ADMIN_USERNAME}/.ssh"
    run_cmd chmod 700 "/home/${ADMIN_USERNAME}/.ssh"
    run_cmd chown "${ADMIN_USERNAME}:${ADMIN_USERNAME}" "/home/${ADMIN_USERNAME}/.ssh"

    # Restart SSH service
    log_info "Restarting SSH service..."
    if command -v systemctl &> /dev/null; then
        if run_cmd systemctl restart ssh 2>/dev/null; then
            run_cmd systemctl enable ssh 2>/dev/null || log_warn "Failed to enable ssh.service"
        else
            run_cmd systemctl restart sshd 2>/dev/null || log_warn "Failed to restart sshd.service"
            run_cmd systemctl enable sshd 2>/dev/null || log_warn "Failed to enable sshd.service"
        fi
    else
        log_warn "systemctl not available; skipping SSH service restart"
    fi

    log_success "SSH configuration completed"
}

generate_ssh_keys() {
    log_info "Generating SSH key pair for $ADMIN_USERNAME..."

    local ssh_dir="/home/${ADMIN_USERNAME}/.ssh"
    local key_file="${ssh_dir}/id_ed25519"

    # Generate SSH key pair
    run_cmd sudo -u "$ADMIN_USERNAME" ssh-keygen -t ed25519 -f "$key_file" -N "" -C "${ADMIN_USERNAME}@$(hostname)"

    # Set proper permissions
    run_cmd chmod 600 "$key_file"
    run_cmd chmod 644 "${key_file}.pub"
    run_cmd chown "${ADMIN_USERNAME}:${ADMIN_USERNAME}" "$key_file"
    run_cmd chown "${ADMIN_USERNAME}:${ADMIN_USERNAME}" "${key_file}.pub"

    # Add public key to authorized_keys
    if [[ "$DRY_RUN" == "1" ]]; then
        log_info "DRY_RUN: would add ${key_file}.pub to ${ssh_dir}/authorized_keys"
    else
        cat "${key_file}.pub" >> "${ssh_dir}/authorized_keys"
    fi
    run_cmd chmod 644 "${ssh_dir}/authorized_keys"

    log_success "SSH key pair generated at ${key_file}"
    log_warn "PRIVATE KEY LOCATION: ${key_file}"
    log_warn "PUBLIC KEY LOCATION: ${key_file}.pub"
    log_warn "Copy the private key to your local machine to access this server"

    # Display public key
    log_info "Public key content:"
    if [[ "$DRY_RUN" == "1" ]]; then
        log_info "DRY_RUN: would display ${key_file}.pub"
        return 0
    fi
    if [[ -f "${key_file}.pub" ]]; then
        cat "${key_file}.pub"
    else
        log_warn "Public key not found at ${key_file}.pub"
    fi
}

# ============================================================================
# ESSENTIAL TOOLS INSTALLATION
# ============================================================================

install_essential_tools() {
    log_info "Installing essential tools and utilities..."

    local tools=(
        # Core utilities
        git
        curl
        wget
        vim
        nano
        htop
        ncdu
        tree
        zip
        unzip
        tar
        gzip
        bzip2
        xz-utils
        p7zip-full
        rsync
        lsof
        net-tools
        dnsutils
        iputils-ping
        traceroute
        mtr
        openssh-server

        # Development tools
        build-essential
        gcc
        g++
        make
        cmake
        pkg-config
        libssl-dev
        zlib1g-dev
        libbz2-dev
        libreadline-dev
        libsqlite3-dev
        llvm
        libncurses5-dev
        libncursesw5-dev
        tk-dev
        libffi-dev
        libaugeas0
        openssl

        # Process and system monitoring
        neofetch
        bpytop
        btop

        # Terminal tools
        tmux
        zsh
        fzf
        ripgrep
        fd-find
        bat
        eza

        # File management
        stow
        ranger
        mc

        # Network tools
        nmap
        tcpdump
        wireshark-common
        netcat-openbsd

        # Security tools
        fail2ban
        ufw
        apparmor-profiles
        apparmor-utils
        auditd
        chkrootkit
        rkhunter

        # Documentation
        man
        manpages
        info

        # Compression tools
        zstd
        lz4

        # Other useful tools
        jq
        yq
        hugo
    )

    log_info "Installing ${#tools[@]} packages (this may take a while)..."
    run_cmd apt-get install -y -qq "${tools[@]}"

    log_success "Essential tools installed"
}

# ============================================================================
# ZSH AND OH-MY-ZSH CONFIGURATION
# ============================================================================

install_zsh_config() {
    log_info "Configuring Zsh and Oh My Zsh..."

    if [[ "$ADMIN_SHELL" != "/usr/bin/zsh" ]]; then
        log_info "Admin shell is $ADMIN_SHELL; skipping Zsh default shell change"
        return 0
    fi

    # Set Zsh as default shell for admin user
    log_info "Setting Zsh as default shell for $ADMIN_USERNAME..."
    run_cmd chsh -s /usr/bin/zsh "$ADMIN_USERNAME" 2>/dev/null || log_warn "Cannot change shell for $ADMIN_USERNAME"
    run_cmd chsh -s /usr/bin/zsh root 2>/dev/null || true

    # Install Oh My Zsh for admin user
    local omz_dir="/home/${ADMIN_USERNAME}/.oh-my-zsh"
    if [[ ! -d "$omz_dir" ]]; then
        log_info "Installing Oh My Zsh for $ADMIN_USERNAME..."
        if [[ "$DRY_RUN" == "1" ]]; then
            log_info "DRY_RUN: would install Oh My Zsh for $ADMIN_USERNAME"
        else
            run_cmd sudo -u "$ADMIN_USERNAME" sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended 2>/dev/null || {
                log_warn "Failed to install Oh My Zsh, continuing with basic Zsh"
            }
        fi
    else
        log_info "Oh My Zsh already installed"
    fi

    # Install Zsh plugins for admin user
    local plugins_dir="/home/${ADMIN_USERNAME}/.oh-my-zsh/custom/plugins"
    run_cmd sudo -u "$ADMIN_USERNAME" mkdir -p "$plugins_dir"

    # Install zsh-autosuggestions
    if [[ ! -d "${plugins_dir}/zsh-autosuggestions" ]]; then
        run_cmd sudo -u "$ADMIN_USERNAME" git clone https://github.com/zsh-users/zsh-autosuggestions "${plugins_dir}/zsh-autosuggestions" 2>/dev/null || true
    fi

    # Install zsh-syntax-highlighting
    if [[ ! -d "${plugins_dir}/zsh-syntax-highlighting" ]]; then
        run_cmd sudo -u "$ADMIN_USERNAME" git clone https://github.com/zsh-users/zsh-syntax-highlighting.git "${plugins_dir}/zsh-syntax-highlighting" 2>/dev/null || true
    fi

    # Install zsh-completions
    if [[ ! -d "${plugins_dir}/zsh-completions" ]]; then
        run_cmd sudo -u "$ADMIN_USERNAME" git clone https://github.com/zsh-users/zsh-completions "${plugins_dir}/zsh-completions" 2>/dev/null || true
    fi

    # Ensure admin has a .zshrc to avoid zsh-newuser-install prompt
    local admin_zshrc="/home/${ADMIN_USERNAME}/.zshrc"
    if [[ ! -f "$admin_zshrc" ]]; then
        if [[ -d "$omz_dir" ]]; then
            write_file "$admin_zshrc" << 'EOF'
# Managed by ubuntu-post-install
export ZSH="$HOME/.oh-my-zsh"
ZSH_THEME="robbyrussell"
plugins=(git)
source "$ZSH/oh-my-zsh.sh"
[ -f ~/.zsh_aliases ] && source ~/.zsh_aliases
EOF
        else
            write_file "$admin_zshrc" << 'EOF'
# Managed by ubuntu-post-install
[ -f /etc/profile ] && source /etc/profile
[ -f ~/.zsh_aliases ] && source ~/.zsh_aliases
EOF
        fi
        run_cmd chown "${ADMIN_USERNAME}:${ADMIN_USERNAME}" "$admin_zshrc"
        run_cmd chmod 644 "$admin_zshrc"
    fi

    log_success "Zsh configuration completed"
}

# Create custom alias file for Zsh
create_alias_file() {
    local alias_file="/etc/skel/.zsh_aliases"

    write_file "$alias_file" << 'EOF'
# ===================
# ALIASES PERSONALIZADOS
# ===================

# --- Navegación ---
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'
alias d='dirs -v'
alias 1='cd -'
alias 2='cd -2'
alias 3='cd -3'

# --- Lista ---
alias ls='ls --color=auto'
alias ll='ls -lh'
alias la='ls -lha'
alias l='ls -CF'
alias l1='ls -1'

# --- Directorios ---
alias md='mkdir -p'
alias rd='rmdir'
alias dirs='dirs -v'

# --- Archivos ---
alias cp='cp -iv'
alias mv='mv -iv'
alias rm='rm -iv'
alias mkdir='mkdir -pv'

# --- Búsqueda ---
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'
alias rg='ripgrep'

# --- Sistema ---
alias mem='free -h'
alias cpu='lscpu | head -5'
alias df='df -hT'
alias du='du -sh'
alias psa='ps auxf'
alias psg='ps aux | grep -v grep | grep'

# --- Red ---
alias ping='ping -c 5'
alias myip='curl -s https://api.ipify.org'
alias ports='netstat -tulpn | grep LISTEN'

# --- Docker ---
alias dps='docker ps'
alias dpsa='docker ps -a'
alias di='docker images'
alias drm='docker rm'
alias drmi='docker rmi'
alias dcup='docker compose up -d'
alias dcdown='docker compose down'

# --- Git ---
alias g='git'
alias gs='git status'
alias ga='git add'
alias gc='git commit'
alias gp='git push'
alias gl='git log --oneline -10'
alias gd='git diff'
alias gco='git checkout'

# --- Seguridad ---
alias sshkeys='cat ~/.ssh/id_ed25519.pub'

# --- Utilidades ---
alias now='date +"%Y-%m-%d %H:%M:%S"'
alias update='sudo apt-get update && sudo apt-get upgrade -y'
alias install='sudo apt-get install -y'
alias clean='sudo apt-get autoremove -y && sudo apt-get autoclean'
alias hist='history | grep'

# --- Oh My Zsh plugins ---
[ -f ~/.oh-my-zsh/custom/plugins/zsh-autosuggestions/zsh-autosuggestions.zsh ] && source ~/.oh-my-zsh/custom/plugins/zsh-autosuggestions/zsh-autosuggestions.zsh
[ -f ~/.oh-my-zsh/custom/plugins/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh ] && source ~/.oh-my-zsh/custom/plugins/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh
EOF

    run_cmd chmod 644 "$alias_file"
    run_cmd cp "$alias_file" "/home/${ADMIN_USERNAME}/.zsh_aliases" 2>/dev/null || true
    run_cmd chown "${ADMIN_USERNAME}:${ADMIN_USERNAME}" "/home/${ADMIN_USERNAME}/.zsh_aliases" 2>/dev/null || true

    log_success "Custom alias file created at $alias_file"
}

# ============================================================================
# FIREWALL CONFIGURATION (UFW)
# ============================================================================

configure_firewall() {
    log_info "Configuring firewall (UFW)..."

    # Reset UFW to defaults
    run_cmd ufw reset -f 2>/dev/null || true

    # Set default policies
    run_cmd ufw default deny incoming
    run_cmd ufw default allow outgoing

    # Allow SSH
    log_info "Allowing SSH on port $SSH_PORT..."
    if [[ "$SSH_PORT" != "22" ]]; then
        run_cmd ufw delete allow 22/tcp 2>/dev/null || true
    fi
    run_cmd ufw allow "${SSH_PORT}/tcp" comment 'SSH'

    # Allow HTTP/HTTPS for web servers
    if [[ "$ALLOW_HTTP" == "yes" ]]; then
        run_cmd ufw allow 80/tcp comment 'HTTP'
    fi
    if [[ "$ALLOW_HTTPS" == "yes" ]]; then
        run_cmd ufw allow 443/tcp comment 'HTTPS'
    fi

    # Allow FTP (optional)
    if [[ "$ALLOW_FTP" == "yes" ]]; then
        run_cmd ufw allow 21/tcp comment 'FTP' 2>/dev/null || true
    fi

    # Enable IPv6
    run_cmd sed -i 's/IPV6=no/IPV6=yes/' /etc/default/ufw 2>/dev/null || true

    # Enable UFW
    log_info "Enabling firewall..."
    run_cmd ufw --force enable 2>/dev/null || true

    # Reload UFW
    run_cmd ufw reload

    # Show status
    log_info "Firewall status:"
    run_cmd ufw status verbose

    log_success "Firewall configuration completed"
}

# ============================================================================
# FAIL2BAN CONFIGURATION
# ============================================================================

configure_fail2ban() {
    log_info "Configuring Fail2Ban..."

    # Create jail.local configuration
    backup_file_if_exists /etc/fail2ban/jail.local
    write_file /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
ignoreip = 127.0.0.1/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
banaction = ufw
action = %(action_mwl)s

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
EOF

    # Create SSHd filter
    backup_file_if_exists /etc/fail2ban/filter.d/sshd.conf
    write_file /etc/fail2ban/filter.d/sshd.conf << 'EOF'
[INCLUDES]
before = common.conf

[Definition]
failregex = ^%(__prefix_line)sFailed (?:publickey|password) for (?:invalid user )?(?:.* from |)(?:from )?%(__hostname)s port (?:\d+)(?: ssh2)?$
            ^%(__prefix_line)sReceived disconnect: (?:Pre-authentication|failure|disconnect): (?:Authentication|bad|invalid) (?:user )?(?:.* )?(?:port \d+ )?(?:\[preauth\])?\s*$
            ^%(__prefix_line)sConnection closed by (?:invalid user )?(?:.* )?(?:port \d+) \[preauth\]$
ignoreregex =

[Init]
maxlines = 10
EOF

    # Enable and start Fail2Ban
    run_cmd systemctl enable fail2ban
    run_cmd systemctl start fail2ban

    log_success "Fail2Ban configuration completed"
}

# ============================================================================
# APPARMOR CONFIGURATION
# ============================================================================

configure_apparmor() {
    log_info "Configuring AppArmor..."

    # Ensure AppArmor is enabled
    run_cmd systemctl enable apparmor
    run_cmd systemctl start apparmor

    # Install profiles
    run_cmd apt-get install -y -qq apparmor-profiles 2>/dev/null || true
    run_cmd apt-get install -y -qq apparmor-utils 2>/dev/null || true

    log_info "AppArmor status:"
    run_cmd apparmor_status 2>/dev/null || run_cmd aa-status 2>/dev/null || true

    log_success "AppArmor configuration completed"
}

# ============================================================================
# DISABLE UNNECESSARY SERVICES
# ============================================================================

disable_unnecessary_services() {
    log_info "Disabling unnecessary services..."

    if [[ "$DRY_RUN" == "1" ]]; then
        log_info "DRY_RUN: would review running services for potential disablement"
        return 0
    fi

    if ! command -v systemctl &> /dev/null; then
        log_warn "systemctl not available; skipping service review"
        return 0
    fi

    local services_to_disable=(
        avahi-daemon
        cups
        bluetooth
        apache2
        nginx
        postfix
        dovecot
        rpcbind
        xinetd
        telnet
        rsh-client
        talk
        ntalk
        x11-common
    )

    for service in "${services_to_disable[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            log_info "Disabling $service..."
            run_cmd systemctl stop "$service" 2>/dev/null || true
            run_cmd systemctl disable "$service" 2>/dev/null || true
        fi
    done

    # Disable automatically discovered unused services
    systemctl list-units --type=service --state=running 2>/dev/null | awk '{print $1}' | while read -r service; do
        if [[ "$service" != *"ssh"* ]] && [[ "$service" != *"docker"* ]] && [[ "$service" != *"ufw"* ]] && [[ "$service" != *"fail2ban"* ]]; then
            # Check if service is necessary (basic services we want to keep)
            case "$service" in
                systemd-.*|network-.*|dhclient|rsyslog|systemd-timesyncd|cron|auditd)
                    ;;
                *)
                    # Check if service has high load time or is rarely used
                    systemctl is-enabled "$service" 2>/dev/null | grep -q "enabled" && {
                        log_warn "Consider disabling $service if not needed"
                    }
                    ;;
            esac
        fi
    done || true

    log_success "Unnecessary services review completed"
}

# ============================================================================
# SUDO CONFIGURATION
# ============================================================================

configure_sudo() {
    log_info "Configuring sudo with enhanced security..."

    # Create sudo configuration
    backup_file_if_exists /etc/sudoers.d/enhanced-security
    write_file /etc/sudoers.d/enhanced-security << 'EOF'
# Enhanced sudo security configuration

# Require password for all sudo commands (already done by default)
Defaults        env_reset
Defaults        mail_always
Defaults        lecture = always
Defaults        passwd_tries = 3
Defaults        badpass_message = "Wrong password! This incident will be reported."
Defaults        log_host
Defaults        log_year
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Timestamp settings
Defaults        timestamp_timeout=30
Defaults        timestamp_type=tty
# I/O logging for security auditing
Defaults        log_input
Defaults        log_output
Defaults        !mail_no_user

# Wheel group requires password
%wheel ALL=(ALL) ALL
%sudo ALL=(ALL) ALL
EOF

    run_cmd chmod 440 /etc/sudoers.d/enhanced-security

    # Configure sudo logging to syslog
    if ! grep -q "auth,user.info" /etc/rsyslog.d/99-sudo.conf 2>/dev/null; then
        backup_file_if_exists /etc/rsyslog.d/99-sudo.conf
        write_file /etc/rsyslog.d/99-sudo.conf << 'EOF'
auth,user.info     /var/log/sudo.log
EOF
        run_cmd systemctl restart rsyslog 2>/dev/null || true
    fi

    log_success "Sudo configuration completed"
}

# ============================================================================
# KERNEL PARAMETERS (SYSCTL)
# ============================================================================

configure_sysctl() {
    log_info "Configuring kernel parameters for security..."

    local ipv6_disable=0
    if [[ "$DISABLE_IPV6" == "yes" ]]; then
        ipv6_disable=1
    fi

    # Create sysctl configuration
    backup_file_if_exists /etc/sysctl.d/99-security-hardening.conf
    write_file /etc/sysctl.d/99-security-hardening.conf << EOF
# ===============================
# KERNEL SECURITY HARDENING
# ===============================

# Network Security
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Disable IPv6 if not needed (set to 1 to disable)
net.ipv6.conf.all.disable_ipv6 = ${ipv6_disable}
net.ipv6.conf.default.disable_ipv6 = ${ipv6_disable}
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# TCP Hardening
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.core.somaxconn = 1024
net.core.netdev_max_backlog = 1024

# Swappiness
vm.swappiness = 10
vm.vfs_cache_pressure = 50

# Shared Memory
kernel.shmmax = 268435456
kernel.shmall = 268435456

# File Handles
fs.file-max = 2097152
fs.inotify.max_user_watches = 524288
fs.inotify.max_user_instances = 512

# Kernel Hardening
kernel.core_uses_pid = 1
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.kexec_load_disabled = 1
kernel.unprivileged_bpf_disabled = 1

# Disable IPv6 Router Advertisements
net.ipv6.conf.all.accept_ra_rtr_pref = 0
net.ipv6.conf.default.accept_ra_rtr_pref = 0
net.ipv6.conf.all.accept_ra_pinfo = 0
net.ipv6.conf.default.accept_ra_pinfo = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
EOF

    # Apply sysctl settings
    log_info "Applying sysctl settings..."
    run_cmd sysctl --system

    log_success "Kernel parameters configured"
}

# ============================================================================
# SHELL CONFIGURATION (BASH/ZSH)
# ============================================================================

configure_shell() {
    log_info "Configuring shell environment..."

    # Create global bashrc additions
    backup_file_if_exists /etc/profile.d/zzz-secure-path.sh
    write_file /etc/profile.d/zzz-secure-path.sh << 'EOF'
# Add secure path for binaries
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EOF
    run_cmd chmod 644 /etc/profile.d/zzz-secure-path.sh

    # Create global bashrc
    backup_file_if_exists /etc/bash.bashrc
    write_file /etc/bash.bashrc << 'EOF'
# ===================
# GLOBAL BASHRC
# ===================

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

# History settings
export HISTSIZE=10000
export HISTFILESIZE=20000
export HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S: "
export HISTCONTROL=ignoreboth:erasedups

# Don't put duplicate lines or lines starting with space in the history.
HISTCONTROL=ignoreboth

# Check the window size after each command
shopt -s checkwinsize

# Enable color support
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi

# Some more ls aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

# Add "safe" rm alias
alias rm='rm -i'

# Add "safe" cp alias
alias cp='cp -i'

# Add "safe" mv alias
alias mv='mv -i'

# Default editor
export EDITOR=vim
export VISUAL=vim

# Less colors
if [ -f /usr/share/source-highlight/src-hilite-lesspipe.sh ]; then
    export LESS="-R"
    export LESSOPEN="| /usr/share/source-highlight/src-hilite-lesspipe.sh %s"
fi

# Enable vi mode in bash
set -o vi

# Auto-correct commands
shopt -s cdspell
shopt -s checkjobs
shopt -s dirspell

# Make less more friendly for non-text input files
[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/bash lesspipe)"

# Set default umask
umask 022

# Add local bin to PATH
[ -d /usr/local/bin ] && export PATH="/usr/local/bin:$PATH"

# Add ~/.local/bin to PATH
[ -d $HOME/.local/bin ] && export PATH="$HOME/.local/bin:$PATH"

# Add ~/.local/bin to PATH for all users
if [ -d /usr/local/bin ]; then
    case ":$PATH:" in
        *":/usr/local/bin:"*) ;;
        *) export PATH="/usr/local/bin:$PATH" ;;
    esac
fi

# Git prompt
if [ -f /usr/lib/git-core/git-sh-prompt ]; then
    source /usr/lib/git-core/git-sh-prompt
fi
EOF

    run_cmd chmod 644 /etc/bash.bashrc

    # Create global zsh profile
    backup_file_if_exists /etc/zsh/zprofile
    write_file /etc/zsh/zprofile << 'EOF'
# Global Zsh Profile

# Set a safe default PATH
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Set umask
umask 022
EOF

    run_cmd chmod 644 /etc/zsh/zprofile

    # Create /etc/skel files for new users
    run_cmd cp /etc/bash.bashrc /etc/skel/.bashrc 2>/dev/null || true
    run_cmd cp /etc/profile.d/zzz-secure-path.sh /etc/skel/.zshrc 2>/dev/null || true

    log_success "Shell configuration completed"
}

# ============================================================================
# TIMESHIFT CONFIGURATION
# ============================================================================

configure_timeshift() {
    log_info "Configuring Timeshift for system snapshots..."

    # Install Timeshift
    run_cmd apt-get install -y -qq timeshift

    # Configure Timeshift via command line
    # Create auto snapshot schedule
    run_cmd timeshift --create --tags D --comment "Daily snapshot" 2>/dev/null || log_warn "Could not create initial Timeshift snapshot"

    # Configure Timeshift settings
    run_cmd mkdir -p /etc/timeshift

    backup_file_if_exists /etc/timeshift/timeshift.conf
    write_file /etc/timeshift/timeshift.conf << 'EOF'
# Timeshift configuration
# Schedule: Daily (D), Weekly (W), Monthly (M)
BTRFS_SNAPSHOT_CREATE=no
RSYNC_SNAPSHOT_CREATE=yes
STOP_BTRFS_SERVICES=no
DELETE_OLD_SNAPSHOTS=yes
OLD_SNAPSHOTS_TO_KEEP=7
RETAIN_DAILY=7
RETAIN_WEEKLY=4
RETAIN_MONTHLY=3
RETAIN_YEARLY=0
INCLUDE_PATHS="/"
EXCLUDE_PATHS="/var/swap /var/cache /var/log"
EXCLUDE_PATHS_BTRFS=""
ENABLE_LSOF=no
SELECTED_SNAPSHOT_TYPE=RSYNC
CRITICAL_SNAPSHOTS_ONLY=no
FAST_CLEANUP=no
SKIP_POST_SNAPSHOT_SHUTDOWN=no
CHECK_FOR_SPACE=no
CHECK_FOR_SPACE_LOW=1000
CHECK_FOR_SPACE_CRITICAL=500
BACKUP_EXCLUDE=(
    '/var/cache'
    '/var/log'
    '/var/tmp'
)
EOF

    run_cmd chmod 644 /etc/timeshift/timeshift.conf

    # Enable and start Timeshift service
    # Timeshift runs via cron, so we configure it
    log_info "Creating Timeshift cron job..."

    # Create cron job for daily snapshots at 3 AM
    backup_file_if_exists /etc/cron.d/timeshift-daily
    write_file /etc/cron.d/timeshift-daily << 'EOF'
0 3 * * * root timeshift --create --tags D --comment "Automatic daily snapshot" >> /var/log/timeshift.log 2>&1
EOF
    run_cmd chmod 644 /etc/cron.d/timeshift-daily

    log_success "Timeshift configuration completed"
}

# ============================================================================
# BACKUP SCRIPT FOR CRITICAL CONFIGS
# ============================================================================

create_backup_script() {
    log_info "Creating backup script for critical configurations..."

    # Create backup directory
    run_cmd mkdir -p "$BACKUP_DIR"
    run_cmd chmod 755 "$BACKUP_DIR"

    # Create backup script
    backup_file_if_exists /usr/local/bin/backup-critical-configs.sh
    write_file /usr/local/bin/backup-critical-configs.sh << EOF
#!/bin/bash
# ========================================
# BACKUP SCRIPT FOR CRITICAL CONFIGS
# ========================================
# Usage: backup-critical-configs.sh
# ========================================

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR}"
RETENTION_DAYS=${BACKUP_RETENTION_DAYS}
EOF

    append_file /usr/local/bin/backup-critical-configs.sh << 'EOF'

DATE=$(date +%Y%m%d-%H%M%S)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

log_info() { log "${GREEN}[INFO]${NC} $1"; }
log_warn() { log "${YELLOW}[WARN]${NC} $1"; }
log_error() { log "${RED}[ERROR]${NC} $1"; }

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Files to backup
CRITICAL_CONFIGS=(
    "/etc/ssh/sshd_config"
    "/etc/sudoers"
    "/etc/sudoers.d/"
    "/etc/sysctl.conf"
    "/etc/sysctl.d/"
    "/etc/fstab"
    "/etc/passwd"
    "/etc/shadow"
    "/etc/group"
    "/etc/hosts"
    "/etc/resolv.conf"
    "/etc/ufw/"
    "/etc/fail2ban/"
    "/etc/bash.bashrc"
    "/etc/profile.d/"
    "/root/.bashrc"
    "/root/.profile"
    "/etc/hosts.allow"
    "/etc/hosts.deny"
    "/etc/audit/"
    "/etc/rsyslog.conf"
    "/etc/rsyslog.d/"
    "/etc/logrotate.conf"
    "/etc/logrotate.d/"
    "/etc/security/"
    "/etc/apt/sources.list"
    "/etc/apt/sources.list.d/"
    "/etc/apt/apt.conf.d/"
    "/etc/systemd/system/"
    "/etc/cron.d/"
    "/etc/crontab"
)

# Create backup
backup_file="${BACKUP_DIR}/critical-configs-${DATE}.tar.gz"

log_info "Starting backup of critical configurations..."

tar --ignore-failed-read -czf "$backup_file"     "${CRITICAL_CONFIGS[@]}"     2>/dev/null

if [ $? -eq 0 ]; then
    log_info "Backup created: $backup_file"

    # Create symlink to latest backup
    rm -f "${BACKUP_DIR}/latest-critical-configs.tar.gz"
    ln -sf "$backup_file" "${BACKUP_DIR}/latest-critical-configs.tar.gz"

    # Get size
    SIZE=$(du -h "$backup_file" | cut -f1)
    log_info "Backup size: $SIZE"

    # Cleanup old backups
    log_info "Cleaning up backups older than $RETENTION_DAYS days..."
    find "$BACKUP_DIR" -name "critical-configs-*.tar.gz" -type f -mtime +$RETENTION_DAYS -delete

    # Log the backup
    echo "$DATE $backup_file $SIZE" >> "${BACKUP_DIR}/backup.log"

    log_info "Backup completed successfully!"
else
    log_error "Backup failed!"
    exit 1
fi

# Output backup location
echo ""
log_info "Backup location: $backup_file"
log_info "Latest backup symlink: ${BACKUP_DIR}/latest-critical-configs.tar.gz"
EOF

    run_cmd chmod +x /usr/local/bin/backup-critical-configs.sh

    # Create cron job for daily backups at 4 AM
    backup_file_if_exists /etc/cron.d/backup-critical-configs
    write_file /etc/cron.d/backup-critical-configs << 'EOF'
0 4 * * * root /usr/local/bin/backup-critical-configs.sh >> /var/log/backup-configs.log 2>&1
EOF
    run_cmd chmod 644 /etc/cron.d/backup-critical-configs

    log_success "Backup script created at /usr/local/bin/backup-critical-configs.sh"
    log_info "To run manually: /usr/local/bin/backup-critical-configs.sh"
}

# ============================================================================
# ADDITIONAL SECURITY MEASURES
# ============================================================================

additional_security() {
    log_info "Applying additional security measures..."

    # Additional sysctl hardening
    backup_file_if_exists /etc/sysctl.d/99-additional-hardening.conf
    write_file /etc/sysctl.d/99-additional-hardening.conf << 'EOF'
kernel.yama.ptrace_scope = 1
kernel.sysrq = 0
fs.suid_dumpable = 0
EOF

    # Disable core dumps
    backup_file_if_exists /etc/security/limits.d/99-disable-coredumps.conf
    write_file /etc/security/limits.d/99-disable-coredumps.conf << 'EOF'
* hard core 0
EOF

    # Set secure umask for all users
    backup_file_if_exists /etc/profile.d/zzz-umask.sh
    write_file /etc/profile.d/zzz-umask.sh << 'EOF'
umask 022
EOF

    run_cmd sysctl --system 2>/dev/null || true

    log_success "Additional security measures applied"
}

# ============================================================================
# TIMEZONE AND LOCALIZATION
# ============================================================================

configure_timezone() {
    log_info "Configuring timezone and locale..."

    # Set timezone
    run_cmd timedatectl set-timezone "$TIMEZONE"

    # Install language packs if needed
    run_cmd apt-get install -y -qq language-pack-en 2>/dev/null || true

    # Configure locale
    run_cmd localectl set-locale LANG=en_US.UTF-8 2>/dev/null || true

    log_success "Timezone and locale configured"
}

# ============================================================================
# MONITORING AND AUDITING
# ============================================================================

configure_monitoring() {
    log_info "Configuring system monitoring and auditing..."

    # Install auditd if not present
    run_cmd apt-get install -y -qq auditd 2>/dev/null || true

    # Configure audit rules
    backup_file_if_exists /etc/audit/rules.d/audit.rules
    write_file /etc/audit/rules.d/audit.rules << 'EOF'
# Monitor privilege escalation
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo -F key=priv_esc
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/su -F key=priv_esc

# Monitor SSH connections
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /usr/sbin/sshd -p x -k sshd

# Monitor user management
-w /etc/passwd -p wa -k user/group
-w /etc/group -p wa -k user/group
-w /etc/shadow -p wa -k user/group

# Monitor Sudoers changes
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Monitor system changes
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/fstab -p wa -k mount

# Monitor cron jobs
-w /etc/cron.d/ -p wa -k cron
-w /etc/crontab -p wa -k cron

# Monitor authentication
-w /var/log/auth.log -p wa -k auth

# Monitor network changes
-w /etc/hosts -p wa -k network
-w /etc/resolv.conf -p wa -k network

# Monitor package installations
-w /var/lib/dpkg/ -p wa -k packages
-w /usr/bin/apt -p x -k packages
-w /usr/bin/dpkg -p x -k packages
EOF

    # Restart auditd
    if command -v augenrules &> /dev/null; then
        run_cmd augenrules --load 2>/dev/null || true
    fi
    run_cmd systemctl restart auditd 2>/dev/null || true

    # Configure log rotation for audit logs
    backup_file_if_exists /etc/logrotate.d/audit
    write_file /etc/logrotate.d/audit << 'EOF'
/var/log/audit/audit.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    postrotate
        /bin/systemctl reload auditd > /dev/null 2>/dev/null || true
    endscript
}
EOF

    log_success "Monitoring and auditing configured"
}

# ============================================================================
# CLEANUP AND FINALIZATION
# ============================================================================

cleanup() {
    log_info "Performing final cleanup..."

    # Clean apt cache
    run_cmd apt-get clean
    run_cmd apt-get autoremove -y -qq

    # Clear systemd journal logs (keep last 100MB)
    run_cmd journalctl --vacuum-size=100M 2>/dev/null || true

    # Clear bash history for root
    run_cmd history -c 2>/dev/null || true

    # Remove log files older than 30 days
    run_cmd find /var/log -name "*.log" -mtime +30 -delete 2>/dev/null || true
    run_cmd find /var/log -name "*.gz" -mtime +30 -delete 2>/dev/null || true

    log_success "Cleanup completed"
}

finalize() {
    log_info "Finalizing configuration..."

    # Display system information
    echo ""
    echo "=========================================="
    echo "     SYSTEM CONFIGURATION SUMMARY"
    echo "=========================================="
    echo ""
    echo -e "${CYAN}System Information:${NC}"
    echo "  Hostname: $(hostname)"
    echo "  OS: $(lsb_release -ds 2>/dev/null || grep -m1 '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d'=' -f2-)"
    echo "  Kernel: $(uname -r)"
    echo "  Timezone: $(timedatectl | grep Time | awk '{print $3}')"
    echo ""
    echo -e "${CYAN}User Configuration:${NC}"
    echo "  Admin user: $ADMIN_USERNAME"
    echo "  Shell: $ADMIN_SHELL"
    echo "  SSH Port: $SSH_PORT"
    echo ""
    echo -e "${CYAN}Services Status:${NC}"
    echo "  SSH: $(systemctl is-active sshd 2>/dev/null || echo 'not installed')"
    echo "  UFW: $(systemctl is-active ufw 2>/dev/null || echo 'not installed')"
    echo "  Fail2Ban: $(systemctl is-active fail2ban 2>/dev/null || echo 'not installed')"
    echo "  Auditd: $(systemctl is-active auditd 2>/dev/null || echo 'not installed')"
    echo ""
    echo -e "${CYAN}Network Configuration:${NC}"
    echo "  IP Address: $(hostname -I | awk '{print $1}')"
    echo "  Default Gateway: $(ip route | grep default | awk '{print $3}')"
    echo "  DNS: $(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf 2>/dev/null)"
    echo ""
    echo -e "${CYAN}Useful Commands:${NC}"
    echo "  View logs:          tail -f $LOG_FILE"
    echo "  Backup configs:     /usr/local/bin/backup-critical-configs.sh"
    echo "  Check firewall:     ufw status verbose"
    echo "  Check fail2ban:     fail2ban-client status"
    echo "  System info:        neofetch"
    echo ""
    echo -e "${YELLOW}IMPORTANT NEXT STEPS:${NC}"
    echo "  1. Test SSH access as $ADMIN_USERNAME (required before reboot)"
    echo "  2. Reboot the system: sudo reboot"
    echo "  3. Add your SSH public key to /home/$ADMIN_USERNAME/.ssh/authorized_keys (if not already)"
    echo "  4. Test all services are running correctly"
    echo "  5. Review firewall rules: sudo ufw status verbose"
    echo ""
    echo -e "${GREEN}Configuration completed successfully!${NC}"
    echo "=========================================="

    log_success "Script execution completed!"
    log_info "Log file: $LOG_FILE"
    log_info "Please reboot the system to apply all changes"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    parse_args "$@"

    echo ""
    echo -e "${WHITE}╔═════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${WHITE}║                                                             ║${NC}"
    echo -e "${WHITE}║  UBUNTU 24.04.3 | POST-INSTALL CONFIGURATION SCRIPT v${SCRIPT_VERSION}  ║${NC}"
    echo -e "${WHITE}║                                                             ║${NC}"
    echo -e "${WHITE}║  This script will set up your Ubuntu 24.04.3 Server with:   ║${NC}"
    echo -e "${WHITE}║  - User management and SSH configuration                    ║${NC}"
    echo -e "${WHITE}║  - Repository setup (universe, multiverse, PHP PPA)         ║${NC}"
    echo -e "${WHITE}║  - Essential tools and development environment              ║${NC}"
    echo -e "${WHITE}║  - Firewall (UFW), Fail2Ban, and AppArmor                   ║${NC}"
    echo -e "${WHITE}║  - Kernel hardening and security parameters                 ║${NC}"
    echo -e "${WHITE}║  - Timeshift snapshots and backup automation                ║${NC}"
    echo -e "${WHITE}║                                                             ║${NC}"
    echo -e "${WHITE}╚═════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Confirm before proceeding
    if [[ "$DRY_RUN" == "1" ]]; then
        confirm_action "Proceed with DRY-RUN? (No system changes will be made)"
    else
        confirm_action "Do you want to proceed with the configuration? (This will modify system files)"
    fi

    # Check prerequisites
    check_package_manager
    check_root
    prompt_configuration
    normalize_yes_no ADMIN_PASSWORDLESS_SUDO
    normalize_yes_no SSH_PASSWORD_AUTH
    normalize_yes_no GENERATE_SSH_KEYS
    normalize_yes_no ALLOW_HTTP
    normalize_yes_no ALLOW_HTTPS
    normalize_yes_no ALLOW_FTP
    normalize_yes_no DISABLE_IPV6
    normalize_yes_no ENABLE_TIMESHIFT

    # Run all configuration steps
    initialize_environment
    preflight_checks
    if [[ "$VALIDATE_ONLY" == "1" ]]; then
        log_success "Validation successful (no changes made)"
        print_effective_configuration
        exit 0
    fi
    if [[ "$CHECK_ONLY" == "1" ]]; then
        log_success "Check completed (no changes made)"
        print_effective_configuration
        print_execution_plan
        exit 0
    fi
    configure_timezone
    configure_repositories
    update_system
    configure_users
    install_admin_ssh_key
    if [[ "$GENERATE_SSH_KEYS" == "yes" ]]; then
        generate_ssh_keys
    fi
    configure_ssh
    install_essential_tools
    install_zsh_config
    create_alias_file
    configure_firewall
    configure_fail2ban
    configure_apparmor
    disable_unnecessary_services
    configure_sudo
    configure_sysctl
    configure_shell
    if [[ "$ENABLE_TIMESHIFT" == "yes" ]]; then
        configure_timeshift
    else
        log_info "Timeshift is disabled (set ENABLE_TIMESHIFT=yes to enable)"
    fi
    create_backup_script
    additional_security
    configure_monitoring
    cleanup
    finalize
}

# Execute main function
main "$@"
