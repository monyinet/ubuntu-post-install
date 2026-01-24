#!/bin/bash
################################################################################
# DOCKER INSTALLATION AND CONFIGURATION SCRIPT
# ============================================================================
# This script installs and configures Docker on Ubuntu 24.04.3 LTS
# with security hardening and optimization for production use.
#
# Author: monyinet
# Compatibility: Ubuntu 24.04.3 LTS (Noble Numbat)
# Last Updated: 2026-01-23
#
# USAGE:
#   curl -sSL https://raw.githubusercontent.com/monyinet/ubuntu-post-install/main/docker-setup.sh | bash
#   OR
#   wget -O- https://raw.githubusercontent.com/monyinet/ubuntu-post-install/main/docker-setup.sh | bash
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
SCRIPT_VERSION="0.3.0"
LOG_FILE="/var/log/docker-setup-$(date +%Y%m%d-%H%M%S).log"

# Dry-run mode
DRY_RUN="${DRY_RUN:-0}"
AUTO_CONFIRM="${AUTO_CONFIRM:-0}"

# Docker Configuration
DOCKER_COMPOSE_VERSION="${DOCKER_COMPOSE_VERSION:-v2.24.0}"
INSTALL_DOCKER_COMPOSE="${INSTALL_DOCKER_COMPOSE:-yes}"
INSTALL_PORTRAINER="${INSTALL_PORTRAINER:-no}"
INSTALL_DOCKER_BUILDX="${INSTALL_DOCKER_BUILDX:-yes}"
DOCKER_DATA_ROOT="${DOCKER_DATA_ROOT:-}"
CONTAINER_LOG_MAX_SIZE="${CONTAINER_LOG_MAX_SIZE:-100m}"
CONTAINER_LOG_MAX_FILE="${CONTAINER_LOG_MAX_FILE:-3}"
ENABLE_LOG_ROTATION="${ENABLE_LOG_ROTATION:-yes}"
DOCKER_METRICS_ADDR="${DOCKER_METRICS_ADDR:-127.0.0.1:9323}"

# Security Configuration
DOCKER_TLS="${DOCKER_TLS:-no}"
DOCKER_TLS_CERT_PATH="${DOCKER_TLS_CERT_PATH:-/etc/docker/tls}"
RESTRICT_METADATA_SERVICE="${RESTRICT_METADATA_SERVICE:-yes}"
ENABLE_USER_NAMESPACE_REMAPPING="${ENABLE_USER_NAMESPACE_REMAPPING:-no}"

# Network Configuration
DOCKER_MTU="${DOCKER_MTU:-}"
ALLOW_IPV6="${ALLOW_IPV6:-yes}"

# Admin user for Docker access
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"

# Docker Hub Mirror (optional)
DOCKER_HUB_MIRROR="${DOCKER_HUB_MIRROR:-}"

# Backup directory
BACKUP_DIR="${BACKUP_DIR:-/opt/backups/docker}"
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"

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
        echo -e "[${timestamp}] [${level}] ${message}"
    else
        echo -e "[${timestamp}] [${level}] ${message}" | tee -a "$LOG_FILE"
    fi
}

log_info()   { log "INFO"    "${GREEN}$*${NC}"; }
log_warn()   { log "WARN"    "${YELLOW}$*${NC}"; }
log_error()  { log "ERROR"   "${RED}$*${NC}"; }
log_success(){ log "SUCCESS" "${CYAN}$*${NC}"; }
log_debug()  { log "DEBUG"   "${BLUE}$*${NC}"; }

# Run a command, or log it during dry-run
run_cmd() {
    if [[ "$DRY_RUN" == "1" ]]; then
        log_info "DRY_RUN: $*"
        return 0
    fi
    "$@"
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
        echo "Non-interactive session detected; proceeding with defaults."
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

# Prompt for yes/no with a default; skip if non-interactive
prompt_yes_no() {
    local var_name="$1"
    local prompt="$2"
    local default_value="$3"
    local input=""

    if [[ "$AUTO_CONFIRM" == "1" || ( ! -t 0 && ! -r /dev/tty ) ]]; then
        printf -v "$var_name" '%s' "$default_value"
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

# Check package manager availability
check_package_manager() {
    if command -v apt-get &> /dev/null; then
        return 0
    else
        log_error "No supported package manager found (apt-get required)"
        exit 1
    fi
}

# Detect OS version
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_ID="${ID:-}"
        OS_VERSION="${VERSION_ID:-}"
        OS_CODENAME="${VERSION_CODENAME:-}"
    else
        log_error "Cannot detect OS version"
        exit 1
    fi

    # Check if Ubuntu
    if [[ "$OS_ID" != "ubuntu" ]]; then
        log_warn "This script is designed for Ubuntu. Detected: $OS_ID"
        log_warn "Proceeding anyway, but some features may not work correctly"
    fi

    log_info "Detected OS: $OS_ID $OS_VERSION ($OS_CODENAME)"
}

# ============================================================================
# ENVIRONMENT INITIALIZATION
# ============================================================================

initialize_environment() {
    log_info "Initializing Docker Installation and Configuration Script v${SCRIPT_VERSION}"
    log_info "Log file: $LOG_FILE"
    if [[ "$DRY_RUN" == "1" ]]; then
        log_info "Dry-run mode enabled: no changes will be made"
    fi

    # Create log file
    run_cmd touch "$LOG_FILE" 2>/dev/null || log_warn "Cannot create log file"

    # Set locale
    if [[ -z "$LANG" ]]; then
        export LANG=C.UTF-8
    fi

    # Disable interactive prompts
    export DEBIAN_FRONTEND=noninteractive

    log_success "Environment initialized"
}

# ============================================================================
# PRE-INSTALLATION CHECKS
# ============================================================================

preflight_checks() {
    log_info "Running pre-installation checks..."

    # Check for existing Docker installation
    if command -v docker &> /dev/null; then
        DOCKER_INSTALLED_VERSION=$(docker --version 2>/dev/null || echo "unknown")
        log_warn "Docker is already installed: $DOCKER_INSTALLED_VERSION"
        REINSTALL_DOCKER="${REINSTALL_DOCKER:-no}"
        prompt_yes_no REINSTALL_DOCKER "Reinstall Docker? This will remove existing installation" "no"
        if [[ "$REINSTALL_DOCKER" != "yes" ]]; then
            log_info "Keeping existing Docker installation"
        else
            log_info "Proceeding with reinstallation"
        fi
    fi

    # Check kernel version
    KERNEL_VERSION=$(uname -r)
    log_info "Kernel version: $KERNEL_VERSION"

    # Check if running in container
    if [[ -f /.dockerenv ]] || grep -q docker /proc/1/cgroup 2>/dev/null; then
        log_warn "Running inside a Docker container. Some features may not work correctly."
    fi

    # Check available disk space (avoid failing if /var/lib/docker doesn't exist yet)
    local df_target="/var/lib"
    if [[ -d /var/lib/docker ]]; then
        df_target="/var/lib/docker"
    fi
    local available_space=""
    available_space="$(df -BG "$df_target" 2>/dev/null | awk 'NR==2 {gsub(/G/,"",$4); print $4}' || true)"
    if [[ -n "$available_space" && "$available_space" =~ ^[0-9]+$ && "$available_space" -lt 10 ]]; then
        log_warn "Low disk space on ${df_target} (${available_space}GB remaining)"
    fi

    # Validate Docker data root path if specified
    if [[ -n "$DOCKER_DATA_ROOT" ]]; then
        if [[ ! -d "$DOCKER_DATA_ROOT" ]]; then
            log_info "Creating Docker data directory: $DOCKER_DATA_ROOT"
            run_cmd mkdir -p "$DOCKER_DATA_ROOT"
        fi
        local available_data_space=""
        available_data_space="$(df -BG "$(dirname "$DOCKER_DATA_ROOT")" 2>/dev/null | awk 'NR==2 {gsub(/G/,"",$4); print $4}' || true)"
        if [[ -n "$available_data_space" && "$available_data_space" =~ ^[0-9]+$ && "$available_data_space" -lt 20 ]]; then
            log_warn "Low disk space for Docker data directory (${available_data_space}GB remaining)"
        fi
    fi

    log_success "Pre-installation checks completed"
}

# ============================================================================
# REPOSITORY CONFIGURATION
# ============================================================================

configure_repositories() {
    log_info "Configuring Docker repositories..."

    # Remove old Docker packages if reinstalling
    if [[ "${REINSTALL_DOCKER:-}" == "yes" ]]; then
        log_info "Removing old Docker packages..."
        run_cmd apt-get remove -y docker.io docker-compose docker-doc containerd runc 2>/dev/null || true
    fi

    # Install dependencies
    log_info "Installing prerequisites..."
    run_cmd apt-get update -qq
    run_cmd apt-get install -y -qq ca-certificates curl gnupg lsb-release

    # Create keyring directory
    run_cmd mkdir -p /etc/apt/keyrings

    # Add Docker's official GPG key
    log_info "Adding Docker GPG key..."
    run_cmd bash -c 'curl -fsSL "https://download.docker.com/linux/ubuntu/gpg" | gpg --dearmor -o /etc/apt/keyrings/docker.gpg'
    run_cmd chmod 644 /etc/apt/keyrings/docker.gpg

    # Set up the stable repository
    log_info "Adding Docker repository..."
    if [[ -n "$OS_CODENAME" ]]; then
        local apt_arch
        apt_arch="$(dpkg --print-architecture)"
        write_file /etc/apt/sources.list.d/docker.list << EOF
deb [arch=${apt_arch} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${OS_CODENAME} stable
EOF
        run_cmd chmod 644 /etc/apt/sources.list.d/docker.list
    else
        log_error "Cannot determine OS codename"
        exit 1
    fi

    # Update package lists
    log_info "Updating package lists..."
    run_cmd apt-get update -qq

    log_success "Repository configuration completed"
}

# ============================================================================
# DOCKER INSTALLATION
# ============================================================================

install_docker() {
    log_info "Installing Docker Engine..."

    # Install Docker Engine
    log_info "Installing docker-ce packages..."
    local docker_packages=(
        docker-ce
        docker-ce-cli
        containerd.io
        docker-compose-plugin
    )

    if [[ "$INSTALL_DOCKER_BUILDX" == "yes" ]]; then
        docker_packages+=(docker-buildx-plugin)
    fi

    run_cmd apt-get install -y -qq "${docker_packages[@]}"

    if [[ "$DRY_RUN" == "1" ]]; then
        log_success "DRY_RUN: would verify, enable, and start Docker"
        return 0
    fi

    # Verify installation
    log_info "Verifying Docker installation..."
    DOCKER_VERSION=$(docker --version 2>/dev/null || echo "not found")
    COMPOSE_VERSION=$(docker compose version 2>/dev/null || echo "not found")
    log_info "Docker version: $DOCKER_VERSION"
    log_info "Docker Compose: $COMPOSE_VERSION"

    # Enable and start Docker service
    log_info "Enabling Docker service..."
    run_cmd systemctl enable docker
    run_cmd systemctl start docker

    # Wait for Docker to be ready
    log_info "Waiting for Docker daemon to be ready..."
    local max_attempts=30
    local attempt=0
    while ! docker info &>/dev/null; do
        attempt=$((attempt + 1))
        if [[ $attempt -ge $max_attempts ]]; then
            log_error "Docker daemon did not start in time"
            exit 1
        fi
        sleep 1
    done

    log_success "Docker installed and running"
}

# Install Docker Compose standalone (if needed)
install_docker_compose_standalone() {
    if [[ "$INSTALL_DOCKER_COMPOSE" != "yes" ]]; then
        return 0
    fi

    log_info "Installing Docker Compose standalone..."

    # Check if docker compose plugin is already installed
    if docker compose version &>/dev/null; then
        log_info "Docker Compose v2 already installed as plugin"
        return 0
    fi

    # Download Docker Compose standalone
    local compose_arch
    compose_arch="$(uname -m)"
    local compose_url
    compose_url="https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-linux-${compose_arch}"
    local compose_bin="/usr/local/bin/docker-compose"

    log_info "Downloading Docker Compose ${DOCKER_COMPOSE_VERSION}..."
    run_cmd curl -fsSL "$compose_url" -o "$compose_bin"
    run_cmd chmod +x "$compose_bin"

    log_info "Docker Compose installed at $compose_bin"
    log_success "Docker Compose standalone installation completed"
}

# Install Portainer for container management
install_portainer() {
    if [[ "$INSTALL_PORTRAINER" != "yes" ]]; then
        return 0
    fi

    log_info "Installing Portainer..."

    # Create Portainer data volume
    run_cmd docker volume create portainer_data 2>/dev/null || true

    # Run Portainer container
    log_info "Starting Portainer container..."
    run_cmd docker run -d \
        --name portainer \
        --restart always \
        -p 8000:8000 \
        -p 9443:9443 \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v portainer_data:/data \
        portainer/portainer-ce:latest

    log_info "Portainer installed successfully"
    log_info "Access Portainer at: https://$(hostname -I | awk '{print $1}'):9443"
}

# ============================================================================
# USER CONFIGURATION
# ============================================================================

configure_users() {
    log_info "Configuring Docker user permissions..."

    # Create docker group if it doesn't exist
    if ! getent group docker &> /dev/null; then
        run_cmd groupadd docker
    fi

    # Add admin user to docker group
    if id "$ADMIN_USERNAME" &> /dev/null; then
        log_info "Adding $ADMIN_USERNAME to docker group..."
        run_cmd usermod -aG docker "$ADMIN_USERNAME"
        log_success "User $ADMIN_USERNAME added to docker group"
    else
        log_warn "User $ADMIN_USERNAME not found. Skipping group addition."
    fi

    # Add root to docker group
    run_cmd usermod -aG docker root 2>/dev/null || true

    log_success "User configuration completed"
}

# ============================================================================
# DOCKER DAEMON CONFIGURATION
# ============================================================================

generate_docker_daemon_json() {
    local -a lines=()

    lines+=("\"storage-driver\": \"overlay2\"")
    if [[ -n "$DOCKER_DATA_ROOT" ]]; then
        lines+=("\"data-root\": \"${DOCKER_DATA_ROOT}\"")
    fi

    lines+=("\"log-driver\": \"json-file\"")
    lines+=("\"log-opts\": {\"max-size\": \"${CONTAINER_LOG_MAX_SIZE}\", \"max-file\": \"${CONTAINER_LOG_MAX_FILE}\", \"compress\": \"true\"}")

    if [[ -n "$DOCKER_METRICS_ADDR" ]]; then
        lines+=("\"metrics-addr\": \"${DOCKER_METRICS_ADDR}\"")
    fi

    if [[ -n "$DOCKER_MTU" ]]; then
        if [[ "$DOCKER_MTU" =~ ^[0-9]+$ ]]; then
            lines+=("\"mtu\": ${DOCKER_MTU}")
        else
            log_warn "Invalid DOCKER_MTU '${DOCKER_MTU}'; skipping mtu setting"
        fi
    fi

    if [[ "$ALLOW_IPV6" == "yes" ]]; then
        lines+=("\"ipv6\": true")
        lines+=("\"ip6tables\": true")
    fi

    if [[ "$ENABLE_USER_NAMESPACE_REMAPPING" == "yes" ]]; then
        lines+=("\"userns-remap\": \"default\"")
    fi

    if [[ -n "$DOCKER_HUB_MIRROR" ]]; then
        lines+=("\"registry-mirrors\": [\"${DOCKER_HUB_MIRROR}\"]")
    fi

    lines+=("\"features\": {\"buildkit\": true}")

    printf '{\n'
    local i=0
    for i in "${!lines[@]}"; do
        if (( i < ${#lines[@]} - 1 )); then
            printf '  %s,\n' "${lines[i]}"
        else
            printf '  %s\n' "${lines[i]}"
        fi
    done
    printf '}\n'
}

configure_docker_daemon() {
    log_info "Configuring Docker daemon..."

    # Backup existing daemon.json
    if [[ -f /etc/docker/daemon.json ]]; then
        run_cmd cp /etc/docker/daemon.json /etc/docker/daemon.json.backup.$(date +%Y%m%d%H%M%S)
        log_info "Backed up existing daemon.json"
    fi

    # Create daemon.json directory
    run_cmd mkdir -p /etc/docker

    if [[ "$DOCKER_TLS" == "yes" ]]; then
        log_warn "DOCKER_TLS=yes is not implemented by this script (dockerd will remain on the unix socket only; DOCKER_TLS_CERT_PATH=${DOCKER_TLS_CERT_PATH})."
    fi

    # Write daemon.json
    generate_docker_daemon_json | write_file /etc/docker/daemon.json

    log_success "Docker daemon configuration written"

    # Restart Docker to apply changes
    log_info "Restarting Docker daemon..."
    if [[ "$DRY_RUN" == "1" ]]; then
        log_success "DRY_RUN: would restart Docker to apply daemon.json"
        return 0
    fi
    run_cmd systemctl restart docker

    # Wait for Docker to be ready
    local max_attempts=30
    local attempt=0
    while ! docker info &>/dev/null; do
        attempt=$((attempt + 1))
        if [[ $attempt -ge $max_attempts ]]; then
            log_error "Docker daemon did not start after configuration change"
            exit 1
        fi
        sleep 1
    done

    log_success "Docker daemon configuration applied"
}

# ============================================================================
# SECURITY HARDENING
# ============================================================================

configure_security() {
    log_info "Applying security hardening..."

    # Create Docker security directory
    run_cmd mkdir -p /etc/docker/security

    # Create apparmor profile for Docker
    log_info "Configuring AppArmor profiles..."
    write_file /etc/docker/security/docker-apparmor-profile << 'EOF'
#include <tunables/global>

profile docker-default flags=(attach_disconnected, mediate_deleted) {
    # Allow essential operations
    capability net_bind_service,
    capability net_broadcast,
    capability net_admin,
    capability sys_module,
    capability sys_chroot,
    capability dac_override,
    capability fowner,
    capability fsetid,
    capability setpcap,
    
    # Deny all network access by default
    deny network,
    
    # Allow docker network
    network docker-overlay,
    network docker-bridge,
    
    # Allow docker socket
    /var/run/docker.sock rw,
    
    # Allow basic filesystem access
    /dev/pts rw,
    /proc/*/fd/ r,
    /proc/*/oom_score_adj w,
    
    # Allow standard docker paths
    /var/lib/docker/** rw,
    /etc/docker/ r,
}
EOF

    # Configure seccomp profile
    log_info "Configuring seccomp profile..."
    if [[ -f /etc/docker/seccomp-profile.json ]]; then
        run_cmd cp /etc/docker/seccomp-profile.json /etc/docker/seccomp-profile.json.backup 2>/dev/null || true
    fi

    write_file /etc/docker/seccomp-profile.json << 'EOF'
{
    "defaultAction": "SCMP_ACT_ERRNO",
    "syscalls": [
        {
            "names": ["prctl", "chmod", "lseek", "ftruncate"],
            "action": "SCMP_ACT_ALLOW"
        },
        {
            "names": ["unshare", "clone", "setns"],
            "action": "SCMP_ACT_ALLOW"
        }
    ]
}
EOF

    # Create docker.service drop-in override
    log_info "Configuring systemd drop-in for Docker service..."
    run_cmd mkdir -p /etc/systemd/system/docker.service.d

    write_file /etc/systemd/system/docker.service.d/10-security.conf << 'EOF'
[Service]
# Light hardening (avoid breaking dockerd/containerd integration)
NoNewPrivileges=true
PrivateTmp=true
LimitNOFILE=1048576
TasksMax=infinity
EOF

    # Reload systemd and restart Docker
    run_cmd systemctl daemon-reload
    run_cmd systemctl restart docker

    log_success "Security hardening applied"
}

# ============================================================================
# FIREWALL CONFIGURATION
# ============================================================================

configure_firewall() {
    log_info "Configuring firewall for Docker..."

    # Check if UFW is installed and active
    if command -v ufw &> /dev/null && ufw status 2>/dev/null | grep -q "active"; then
        log_info "UFW is active; applying Docker-related rules (if needed)..."
        local ufw_rules_added=0

        # Allow Portainer if installed
        if [[ "$INSTALL_PORTRAINER" == "yes" ]]; then
            run_cmd ufw allow 9443/tcp comment 'Portainer HTTPS' 2>/dev/null || true
            ufw_rules_added=1
        fi

        if [[ "$ufw_rules_added" == "1" ]]; then
            log_info "UFW rule(s) added for Docker-related services"
        else
            log_info "No UFW rules needed (Docker manages iptables rules automatically)"
        fi
    else
        log_info "UFW not active, skipping UFW configuration"
    fi

    # Block cloud metadata service from containers (defense-in-depth)
    if [[ "$RESTRICT_METADATA_SERVICE" == "yes" ]] && command -v iptables &> /dev/null; then
        if iptables -nL DOCKER-USER &>/dev/null; then
            run_cmd iptables -C DOCKER-USER -d 169.254.169.254 -j DROP 2>/dev/null || run_cmd iptables -I DOCKER-USER -d 169.254.169.254 -j DROP
            log_info "Blocked 169.254.169.254 via DOCKER-USER (metadata service)"
        else
            log_warn "DOCKER-USER chain not found; cannot apply metadata-service restriction"
        fi
    fi

    log_success "Firewall configuration completed"
}

# ============================================================================
# DOCKER NETWORK CONFIGURATION
# ============================================================================

configure_networking() {
    log_info "Configuring Docker networking..."

    if [[ "$DRY_RUN" == "1" ]]; then
        log_success "DRY_RUN: would configure Docker networks"
        return 0
    fi

    # Check default bridge network
    if ! docker network inspect bridge &>/dev/null; then
        log_warn "Default bridge network 'bridge' not found (unexpected); continuing"
    fi

    # Create custom bridge network for applications
    log_info "Creating custom bridge network 'app-network'..."
    run_cmd docker network create \
        --driver bridge \
        --subnet 172.20.0.0/16 \
        --gateway 172.20.0.1 \
        --opt com.docker.network.bridge.name=docker_app \
        app-network 2>/dev/null || log_info "app-network already exists or could not be created"

    # Configure Docker to allow container communication
    if [[ -f /etc/docker/daemon.json ]]; then
        log_info "Bridge IP configuration check:"
        docker network inspect bridge --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null || echo "Using default bridge"
    fi

    log_success "Networking configuration completed"
}

# ============================================================================
# MONITORING AND LOGGING
# ============================================================================

configure_monitoring() {
    log_info "Configuring Docker monitoring..."

    # Create Docker logging directory
    run_cmd mkdir -p /var/log/docker
    run_cmd chmod 755 /var/log/docker

    # Configure log rotation for Docker logs
    if [[ "$ENABLE_LOG_ROTATION" == "yes" ]] && command -v logrotate &> /dev/null; then
        write_file /etc/logrotate.d/docker-logs << 'EOF'
/var/log/docker/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    sharedscripts
    postrotate
        docker info > /dev/null 2>&1 || true
    endscript
}

/var/lib/docker/containers/**/*-json.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    sharedscripts
    postrotate
        docker info > /dev/null 2>&1 || true
    endscript
}
EOF
        log_info "Log rotation configured for Docker"
    fi

    # Create monitoring script
    write_file /usr/local/bin/docker-monitor.sh << 'EOF'
#!/bin/bash
# Docker Monitoring Script

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo "========================================"
echo "       DOCKER MONITORING REPORT         "
echo "========================================"
echo ""

echo -e "${CYAN}Docker Version:${NC}"
docker --version
echo ""

echo -e "${CYAN}Docker Compose Version:${NC}"
docker compose version 2>/dev/null || docker-compose --version 2>/dev/null || echo "Not installed"
echo ""

echo -e "${CYAN}Container Summary:${NC}"
docker ps --format "table {{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" | head -20
echo ""

echo -e "${CYAN}Container Statistics:${NC}"
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}" | head -10
echo ""

echo -e "${CYAN}Image Summary:${NC}"
docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedSince}}" | head -15
echo ""

echo -e "${CYAN}Volume Summary:${NC}"
docker volume ls
echo ""

echo -e "${CYAN}Network Summary:${NC}"
docker network ls
echo ""

echo -e "${CYAN}System Info:${NC}"
docker info --format 'Driver: {{.Driver}}' 2>/dev/null
docker info --format 'Data Space: {{.DriverStatus}}' 2>/dev/null | head -1
echo ""

echo -e "${CYAN}Docker Disk Usage:${NC}"
docker system df
echo ""

echo -e "${YELLOW}Container Health Status:${NC}"
docker ps --format '{{.Names}}\t{{.Status}}' | while IFS=$'\t' read -r name status; do
    if echo "$status" | grep -q "Up"; then
        echo -e "  ${name}: ${GREEN}${status}${NC}"
    else
        echo -e "  ${name}: ${RED}${status}${NC}"
    fi
done

echo ""
echo "========================================"
echo "          END OF REPORT                 "
echo "========================================"
EOF

    run_cmd chmod +x /usr/local/bin/docker-monitor.sh

    # Create cron job for monitoring
    write_file /etc/cron.d/docker-health << 'EOF'
0 */6 * * * root /usr/local/bin/docker-monitor.sh >> /var/log/docker/monitoring.log 2>&1
EOF

    log_success "Monitoring configuration completed"
}

# ============================================================================
# BACKUP SCRIPT
# ============================================================================

create_backup_script() {
    log_info "Creating Docker backup script..."

    # Create backup directory
    run_cmd mkdir -p "$BACKUP_DIR"
    run_cmd chmod 755 "$BACKUP_DIR"

    # Create backup script
    write_file /usr/local/bin/docker-backup.sh << EOF
#!/bin/bash
# ========================================
# DOCKER BACKUP SCRIPT
# ========================================
# Usage: docker-backup.sh [--images-only|--volumes-only]
# ========================================

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR}"
RETENTION_DAYS=${BACKUP_RETENTION_DAYS}
DATE=\$(date +%Y%m%d-%H%M%S)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "[\$(date +'%Y-%m-%d %H:%M:%S')] \$1"
}

log_info() { log "${GREEN}[INFO]${NC} \$1"; }
log_warn() { log "${YELLOW}[WARN]${NC} \$1"; }
log_error() { log "${RED}[ERROR]${NC} \$1"; }

# Parse arguments
BACKUP_IMAGES=0
BACKUP_VOLUMES=0
BACKUP_CONFIGS=1

while [[ \$# -gt 0 ]]; do
    case \$1 in
        --images-only)
            BACKUP_IMAGES=1
            BACKUP_VOLUMES=0
            BACKUP_CONFIGS=0
            shift
            ;;
        --volumes-only)
            BACKUP_IMAGES=0
            BACKUP_VOLUMES=1
            BACKUP_CONFIGS=0
            shift
            ;;
        --all)
            BACKUP_IMAGES=1
            BACKUP_VOLUMES=1
            BACKUP_CONFIGS=1
            shift
            ;;
        *)
            log_error "Unknown option: \$1"
            echo "Usage: \$0 [--images-only|--volumes-only|--all]"
            exit 1
            ;;
    esac
done

# Default to all if no option specified
if [[ \$BACKUP_IMAGES -eq 0 && \$BACKUP_VOLUMES -eq 0 && \$BACKUP_CONFIGS -eq 0 ]]; then
    BACKUP_IMAGES=1
    BACKUP_VOLUMES=1
    BACKUP_CONFIGS=1
fi

mkdir -p "\$BACKUP_DIR"

log_info "Starting Docker backup..."

# Backup Docker images
if [[ \$BACKUP_IMAGES -eq 1 ]]; then
    log_info "Backing up Docker images..."
    images_backup_file="\${BACKUP_DIR}/docker-images-\${DATE}.tar.gz"

    mapfile -t images < <(docker images --format '{{.Repository}}:{{.Tag}}' | grep -v '^<none>:' || true)
    if (( \${#images[@]} == 0 )); then
        log_info "No images to backup"
    else
        for image in "\${images[@]}"; do
            log_info "  Saving \${image}..."
        done
        if docker save "\${images[@]}" | gzip > "\$images_backup_file"; then
            SIZE=\$(du -h "\$images_backup_file" | cut -f1)
            log_info "Images backup created: \$images_backup_file (\$SIZE)"
            rm -f "\$BACKUP_DIR/latest-docker-images.tar.gz"
            ln -sf "\$images_backup_file" "\$BACKUP_DIR/latest-docker-images.tar.gz"
        else
            log_error "Failed to backup images"
        fi
    fi
fi

# Backup Docker volumes
if [[ \$BACKUP_VOLUMES -eq 1 ]]; then
    log_info "Backing up Docker volumes..."
    volumes_backup_file="\${BACKUP_DIR}/docker-volumes-\${DATE}.tar.gz"

    mapfile -t volumes < <(docker volume ls -q | grep -v '^portainer_data$' || true)
    if (( \${#volumes[@]} == 0 )); then
        log_info "No volumes to backup (excluding Portainer)"
    else
        temp_dir=\$(mktemp -d)
        for volume in "\${volumes[@]}"; do
            log_info "  Saving volume: \${volume}"
            if ! docker run --rm -v "\${volume}:/data:ro" -v "\${temp_dir}:/backup" alpine sh -c "cd /data && tar czf \"/backup/\${volume}.tar.gz\" ."; then
                log_warn "  Failed to backup volume: \${volume}"
            fi
        done
        tar czf "\$volumes_backup_file" -C "\$temp_dir" .
        rm -rf "\$temp_dir"

        SIZE=\$(du -h "\$volumes_backup_file" | cut -f1)
        log_info "Volumes backup created: \$volumes_backup_file (\$SIZE)"
        rm -f "\$BACKUP_DIR/latest-docker-volumes.tar.gz"
        ln -sf "\$volumes_backup_file" "\$BACKUP_DIR/latest-docker-volumes.tar.gz"
    fi
fi

# Backup Docker configurations
if [[ \$BACKUP_CONFIGS -eq 1 ]]; then
    log_info "Backing up Docker configurations..."
    configs_backup_file="\${BACKUP_DIR}/docker-configs-\${DATE}.tar.gz"
    
    tar czf "\$configs_backup_file" \
        -C /etc docker/ \
        -C /var/lib docker/ \
        -C /lib/systemd/system docker.service \
        2>/dev/null || true
    
    if [ -s "\$configs_backup_file" ]; then
        SIZE=\$(du -h "\$configs_backup_file" | cut -f1)
        log_info "Configs backup created: \$configs_backup_file (\$SIZE)"
        rm -f "\$BACKUP_DIR/latest-docker-configs.tar.gz"
        ln -sf "\$configs_backup_file" "\$BACKUP_DIR/latest-docker-configs.tar.gz"
    else
        rm -f "\$configs_backup_file"
    fi
fi

# Cleanup old backups
log_info "Cleaning up backups older than \$RETENTION_DAYS days..."
find "\$BACKUP_DIR" -name "docker-*.tar.gz" -type f -mtime +\$RETENTION_DAYS -delete

# Create summary
log_info ""
log_info "Docker backup completed!"
log_info "Backup location: \$BACKUP_DIR"
echo ""
echo "Backup files:"
ls -lh "\$BACKUP_DIR"/docker-*.tar.gz 2>/dev/null || echo "No backup files found"
EOF

    run_cmd chmod +x /usr/local/bin/docker-backup.sh

    # Create cron job for daily backups at 5 AM
    write_file /etc/cron.d/docker-backup << 'EOF'
0 5 * * * root /usr/local/bin/docker-backup.sh >> /var/log/docker/backup.log 2>&1
EOF

    log_success "Backup script created at /usr/local/bin/docker-backup.sh"
    log_info "To backup manually: /usr/local/bin/docker-backup.sh"
    log_info "To backup only images: /usr/local/bin/docker-backup.sh --images-only"
    log_info "To backup only volumes: /usr/local/bin/docker-backup.sh --volumes-only"
}

# ============================================================================
# ALIASES AND COMPLETION
# ============================================================================

create_aliases() {
    log_info "Creating Docker aliases..."

    # Create global bash completion for Docker
    if command -v docker &> /dev/null; then
        run_cmd mkdir -p /etc/bash_completion.d
        if [[ -f /usr/share/bash-completion/completions/docker ]]; then
            run_cmd cp /usr/share/bash-completion/completions/docker /etc/bash_completion.d/docker 2>/dev/null || true
        fi
    fi

    # Create Docker aliases file
    write_file /etc/docker/docker-aliases.sh << 'EOF'
# ===================
# DOCKER ALIASES
# ===================

# Essential Docker aliases
alias dps='docker ps'
alias dpsa='docker ps -a'
alias di='docker images'
alias drm='docker rm'
alias drmi='docker rmi'
alias dstop='docker stop'
alias dstart='docker start'
alias drestart='docker restart'
alias dlogs='docker logs'
alias dlogs-f='docker logs -f'
alias dexec='docker exec -it'
alias dbuild='docker build -t'
alias dpull='docker pull'
alias dpush='docker push'
alias dnetwork='docker network'
alias dvolume='docker volume'
alias dinspect='docker inspect'
alias dstats='docker stats'
alias dtop='docker top'

# Docker Compose aliases
alias dcup='docker compose up -d'
alias dcup-build='docker compose up -d --build'
alias dcdown='docker compose down'
alias dcdown-v='docker compose down -v'
alias dcrestart='docker compose restart'
alias dclogs='docker compose logs'
alias dclogs-f='docker compose logs -f'
alias dcexec='docker compose exec'
alias dcps='docker compose ps'
alias dcstop='docker compose stop'
alias dcstart='docker compose start'

# Utility aliases
alias dprune='docker system prune -af --volumes'
alias diprune='docker image prune -af'
alias dclean='docker container prune -f'
alias dvolprune='docker volume prune -f'
alias dnetprune='docker network prune -f'
alias dinspectcfg='docker inspect --format="{{json .Config}}"'
alias dpsformat='docker ps --format "table {{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}\t{{.Names}}"'

# Docker monitoring
alias dmon='docker-monitor.sh'

# Quick container status
alias dstatus='docker ps --filter "status=running" --format "table {{.Names}}\t{{.Image}}\t{{.Status}}"'

# Quick stats
alias dmem='docker stats --no-stream --format "table {{.Name}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.CPUPerc}}"'

# Source completion if available
if [ -f /etc/bash_completion.d/docker ]; then
    source /etc/bash_completion.d/docker
fi

if [ -f /usr/share/bash-completion/completions/docker ]; then
    source /usr/share/bash-completion/completions/docker
fi
EOF

    # Copy aliases to /etc/skel for new users
    run_cmd cp /etc/docker/docker-aliases.sh /etc/skel/.docker-aliases 2>/dev/null || true

    # Add to admin user's profile
    if [[ -f /home/${ADMIN_USERNAME}/.bashrc ]]; then
        if ! grep -q "source /etc/docker/docker-aliases.sh" /home/${ADMIN_USERNAME}/.bashrc 2>/dev/null; then
            append_line "# Docker aliases" /home/${ADMIN_USERNAME}/.bashrc
            append_line "source /etc/docker/docker-aliases.sh" /home/${ADMIN_USERNAME}/.bashrc
        fi
    fi

    # Add to root's profile
    if ! grep -q "source /etc/docker/docker-aliases.sh" /root/.bashrc 2>/dev/null; then
        append_line "# Docker aliases" /root/.bashrc
        append_line "source /etc/docker/docker-aliases.sh" /root/.bashrc
    fi

    log_success "Docker aliases created"
}

# ============================================================================
# FINALIZATION
# ============================================================================

finalize() {
    log_info "Finalizing Docker installation..."

    if [[ "$DRY_RUN" == "1" ]]; then
        log_success "DRY_RUN: Docker setup completed (no changes made)"
        log_info "Log file: $LOG_FILE"
        return 0
    fi

    # Display system information
    echo ""
    echo "=========================================="
    echo "      DOCKER CONFIGURATION SUMMARY"
    echo "=========================================="
    echo ""
    echo -e "${CYAN}Docker Installation:${NC}"
    docker --version
    docker compose version 2>/dev/null || echo "  Docker Compose: Not installed as plugin"
    echo ""
    echo -e "${CYAN}Docker Daemon Configuration:${NC}"
    echo "  Data directory: ${DOCKER_DATA_ROOT:-/var/lib/docker}"
    echo "  Log driver: json-file"
    echo "  Storage driver: overlay2"
    if [[ -n "${DOCKER_METRICS_ADDR:-}" ]]; then
        echo "  Metrics endpoint: ${DOCKER_METRICS_ADDR}"
    else
        echo "  Metrics endpoint: disabled"
    fi
    echo ""
    echo -e "${CYAN}User Configuration:${NC}"
    echo "  Admin user: $ADMIN_USERNAME"
    echo "  Docker group membership: Required for non-root access"
    echo ""
    echo -e "${CYAN}Useful Commands:${NC}"
    echo "  View Docker info:        docker info"
    echo "  List containers:         docker ps"
    echo "  List images:             docker images"
    echo "  Run Docker monitor:      docker-monitor.sh"
    echo "  Create backup:           docker-backup.sh"
    echo "  Logs:                    /var/log/docker/"
    echo "  Config:                  /etc/docker/daemon.json"
    echo ""
    if [[ "$INSTALL_PORTRAINER" == "yes" ]]; then
        echo -e "${CYAN}Portainer:${NC}"
        echo "  Access URL: https://$(hostname -I | awk '{print $1}'):9443"
        echo ""
    fi
    echo -e "${YELLOW}IMPORTANT NEXT STEPS:${NC}"
    echo "  1. Log out and back in to apply docker group membership"
    echo "  2. Test Docker access: docker ps"
    echo "  3. Review daemon configuration: cat /etc/docker/daemon.json"
    echo "  4. Run monitoring: docker-monitor.sh"
    echo "  5. Create first backup: docker-backup.sh"
    echo ""
    echo -e "${GREEN}Docker installation completed successfully!${NC}"
    echo "=========================================="

    log_success "Docker setup completed!"
    log_info "Log file: $LOG_FILE"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    for arg in "$@"; do
        case "$arg" in
            --dry-run|-n)
                DRY_RUN=1
                ;;
            --yes|-y)
                AUTO_CONFIRM=1
                ;;
            *)
                ;;
        esac
    done

    echo ""
    echo -e "${WHITE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${WHITE}║         DOCKER INSTALLATION SCRIPT v${SCRIPT_VERSION}              ║${NC}"
    echo -e "${WHITE}║                                                        ║${NC}"
    echo -e "${WHITE}║  This script will install and configure Docker with:   ║${NC}"
    echo -e "${WHITE}║  - Docker Engine and Docker Compose v2                 ║${NC}"
    echo -e "${WHITE}║  - Security hardening (AppArmor, seccomp, namespaces)  ║${NC}"
    echo -e "${WHITE}║  - Optimized daemon configuration                      ║${NC}"
    echo -e "${WHITE}║  - Firewall rules for Docker ports                     ║${NC}"
    echo -e "${WHITE}║  - Monitoring and backup automation                    ║${NC}"
    echo -e "${WHITE}║  - Custom aliases and completions                      ║${NC}"
    echo -e "${WHITE}║                                                        ║${NC}"
    echo -e "${WHITE}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Confirm before proceeding
    if [[ "$DRY_RUN" == "1" ]]; then
        confirm_action "Proceed with DRY-RUN? (No system changes will be made)"
    else
        confirm_action "Do you want to proceed with Docker installation?"
    fi

    # Run all configuration steps
    initialize_environment
    detect_os
    check_package_manager
    check_root
    preflight_checks
    configure_repositories
    install_docker
    install_docker_compose_standalone
    install_portainer
    configure_users
    configure_docker_daemon
    configure_security
    configure_firewall
    configure_networking
    configure_monitoring
    create_backup_script
    create_aliases
    finalize
}

# Execute main function
main "$@"
