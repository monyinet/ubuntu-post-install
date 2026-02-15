# Ubuntu 24.04.3 LTS Post-Install (Server)

Secure, opinionated post-install automation for Ubuntu 24.04.3 LTS servers.
Focus: SSH hardening, baseline tooling, firewall, monitoring, and sensible defaults.

## Highlights

- Interactive or non-interactive runs
- SSH key enforcement (password auth off by default)
- UFW + Fail2Ban + AppArmor
- Kernel/sysctl hardening and audit rules
- Backup automation and safe cleanup

## Quick Start

> **⚠️ Security Note:** The quick installation methods below use `curl | bash`, which executes code directly from the internet. While convenient, this approach is vulnerable to man-in-the-middle attacks and doesn't allow you to inspect the code before execution. For production environments or security-sensitive deployments, please use the [Secure Installation](#secure-installation-recommended) method instead.

Interactive (prompts):

```bash
curl -fsSL https://raw.githubusercontent.com/monyinet/ubuntu-post-install/main/setup.sh | bash
```

Non-interactive (defaults):

```bash
curl -fsSL https://raw.githubusercontent.com/monyinet/ubuntu-post-install/main/setup.sh | bash -s -- --yes
```

Dry-run (no changes):

```bash
curl -fsSL https://raw.githubusercontent.com/monyinet/ubuntu-post-install/main/setup.sh | bash -s -- --dry-run --yes
```

Check/validate only (no changes):

```bash
curl -fsSL https://raw.githubusercontent.com/monyinet/ubuntu-post-install/main/setup.sh | bash -s -- --check
curl -fsSL https://raw.githubusercontent.com/monyinet/ubuntu-post-install/main/setup.sh | bash -s -- --validate
```

## 🔒 Secure Installation (Recommended)

For enhanced security, download and inspect the script before executing it:

```bash
# Download the script
curl -fsSL https://raw.githubusercontent.com/monyinet/ubuntu-post-install/main/setup.sh -o /tmp/setup.sh

# (Optional) Verify checksum against a known-good hash
# You can obtain checksums from the GitHub releases page:
# https://github.com/monyinet/ubuntu-post-install/releases
# Or generate from a specific commit you trust:
# curl -fsSL "https://raw.githubusercontent.com/monyinet/ubuntu-post-install/<commit-sha>/setup.sh" | sha256sum
# Example: replace <KNOWN_GOOD_SHA256> with the expected value you obtained
echo "<KNOWN_GOOD_SHA256>  /tmp/setup.sh" | sha256sum -c -

# Inspect the script content
less /tmp/setup.sh
# or
cat /tmp/setup.sh

# Execute the script
sudo bash /tmp/setup.sh
```

This approach allows you to:
- Review the code before execution
- Verify the script's integrity (if using checksum verification)
- Ensure no malicious code has been injected
- Keep a local copy for auditing purposes

## Docker (Optional)

Run Docker setup as part of the main script:

```bash
curl -fsSL https://raw.githubusercontent.com/monyinet/ubuntu-post-install/main/setup.sh | bash -s -- --yes --docker
```

Run Docker setup standalone:

```bash
curl -fsSL https://raw.githubusercontent.com/monyinet/ubuntu-post-install/main/docker-setup.sh | bash -s -- --yes
```

Common Docker overrides:

```bash
ADMIN_USERNAME=admin \
DOCKER_DATA_ROOT=/var/lib/docker \
INSTALL_PORTRAINER=no \
RESTRICT_METADATA_SERVICE=yes \
DOCKER_METRICS_ADDR=127.0.0.1:9323 \
curl -fsSL https://raw.githubusercontent.com/monyinet/ubuntu-post-install/main/docker-setup.sh | bash -s -- --yes
```

Cache-buster (if you hit CDN cache):

```bash
ts=$(date +%s)
curl -fsSL "https://raw.githubusercontent.com/monyinet/ubuntu-post-install/main/setup.sh?ts=$ts" -o /tmp/setup.sh
bash /tmp/setup.sh
```

## Prerequisites

- Ubuntu 24.04.x (target: 24.04.3 LTS)
- Run as root (or via `sudo`)
- Internet access + working DNS (APT installs packages)
- You must have SSH access ready (recommended: SSH key auth)

## Supply-Chain Safety (Pin a Commit)

Using `main` is convenient, but it can change over time. To pin to a specific commit:

```bash
COMMIT=cda54890d20e4225b777b502077f63a944c55234
curl -fsSL "https://raw.githubusercontent.com/monyinet/ubuntu-post-install/${COMMIT}/setup.sh" -o /tmp/setup.sh
bash /tmp/setup.sh --yes
```

## Common Overrides

```bash
ADMIN_USERNAME=admin \
ADMIN_FULLNAME="Server Admin" \
ADMIN_PASSWORDLESS_SUDO=no \
TIMEZONE=Europe/Madrid \
SSH_PORT=2222 \
SSH_PASSWORD_AUTH=no \
SSH_PUBKEY_PATH=/root/.ssh/id_ed25519.pub \
ALLOW_HTTPS=yes \
DISABLE_IPV6=no \
ENABLE_TIMESHIFT=no \
curl -fsSL https://raw.githubusercontent.com/monyinet/ubuntu-post-install/main/setup.sh | bash
```

## What This Script Changes

- APT: updates packages; enables `universe`/`multiverse`; optionally adds PPAs; configures unattended upgrades
- Users: creates/updates an admin user; configures sudo policies in `/etc/sudoers.d/`; forces password change on first login
- SSH: rewrites `/etc/ssh/sshd_config`, sets a login banner, restarts SSH, and enforces key-based access by default
- Firewall: resets and enables UFW; opens SSH (and optional HTTP/HTTPS/FTP)
- **Phase 2 Security**: PAM account lockout, password complexity requirements, password aging, file system hardening (/tmp, /var/tmp with noexec)
- Security hardening: writes sysctl hardening files under `/etc/sysctl.d/`; adds audit rules; sets additional system defaults
- Shell defaults: writes global shell config (including `/etc/bash.bashrc` and `/etc/zsh/zprofile`)
- Backups: creates `/usr/local/bin/backup-critical-configs.sh` + a daily cron job
- Cleanup: removes old logs and clears package caches

The script creates per-run backups of files it overwrites under `BACKUP_DIR/run-<timestamp>/`.

## 🔐 Phase 2 Security Features

Building on the Phase 1 critical security fixes (password expiry, checksum verification, secure installation docs), **Phase 2** focuses on **Access Control & Authentication Hardening**:

### PAM Account Lockout
- Automatically locks accounts after **5 failed login attempts**
- **30-minute lockout period** for locked accounts
- Applies to SSH and local console authentication
- Prevents brute-force password attacks

### Password Complexity Requirements
- Minimum **12 characters** password length
- Must include: **1 uppercase, 1 lowercase, 1 digit, 1 special character**
- Prevents password reuse (last **5 passwords**)
- Enforces complexity for all users including root
- Checks against username and GECOS field

### Password Aging Policies
- Maximum password age: **90 days**
- Minimum password age: **1 day** (prevents rapid password changes)
- Warning period: **7 days** before password expiry
- Secure UMASK: **077** (restrictive file permissions by default)

### File System Hardening
- `/tmp` and `/var/tmp` mounted with:
  - `noexec`: Prevents execution of binaries from temp directories
  - `nosuid`: Prevents SUID bit exploitation
  - `nodev`: Prevents device file creation
- Mitigates privilege escalation attacks

### Enhanced Fail2Ban Protection
- **SSH protection** (existing): 3 failed attempts → 1-hour ban
- **Recidive jail** (new): Repeat offenders banned for 24 hours
- **HTTP/HTTPS attack protection** (when web services enabled):
  - Authentication failures
  - Request limit violations
  - Bad bot detection
- All banned IPs logged and can trigger email notifications

### Security Benefits
- **Defense in depth**: Multiple authentication barriers
- **Compliance**: Meets NIST, CIS benchmark requirements
- **Attack surface reduction**: File system restrictions prevent privilege escalation
- **Proactive monitoring**: Enhanced Fail2Ban coverage detects broader attack patterns

### Disabling Phase 2 Features

If you need to disable any Phase 2 features:

```bash
ENABLE_PAM_FAILLOCK=no \
ENABLE_PASSWORD_QUALITY=no \
ENABLE_PASSWORD_AGING=no \
ENABLE_FILESYSTEM_HARDENING=no \
curl -fsSL https://raw.githubusercontent.com/monyinet/ubuntu-post-install/main/setup.sh | bash
```

## Environment Variables

| Variable | Default | Description |
|---|---:|---|
| `DRY_RUN` | `0` | Print actions without changing the system |
| `AUTO_CONFIRM` | `0` | Skip prompts (same as `--yes`) |
| `ADMIN_USERNAME` | `admin` | Admin user to create/configure |
| `ADMIN_FULLNAME` | `Administrator` | GECOS full name for the admin user |
| `ADMIN_SHELL` | `/bin/bash` | Login shell for the admin user |
| `ADMIN_PASSWORDLESS_SUDO` | `no` | If `yes`, admin gets passwordless sudo |
| `ADMIN_PASSWORD` | *(unset)* | Optional admin password (SSH key auth is recommended) |
| `TIMEZONE` | `Europe/Madrid` | Timezone for `timedatectl set-timezone` |
| `SSH_PORT` | `22` | SSH daemon port |
| `SSH_PERMIT_ROOT_LOGIN` | `no` | SSH root login policy |
| `SSH_PASSWORD_AUTH` | `no` | If `yes`, allow SSH password auth |
| `SSH_PUBKEY_PATH` | *(auto-detected)* | Public key path to install into `authorized_keys` |
| `SSH_PUBKEY_CONTENT` | *(unset)* | Public key content to install (single line) |
| `GENERATE_SSH_KEYS` | `no` | If `yes`, generates an SSH keypair for the admin user |
| `ALLOW_HTTP` | `no` | If `yes`, opens port 80/tcp in UFW |
| `ALLOW_HTTPS` | `no` | If `yes`, opens port 443/tcp in UFW |
| `ALLOW_FTP` | `no` | If `yes`, opens port 21/tcp in UFW |
| `DISABLE_IPV6` | `no` | If `yes`, applies sysctl settings to disable IPv6 |
| `ENABLE_TIMESHIFT` | `no` | If `yes`, installs/configures Timeshift + cron |
| `BACKUP_DIR` | `/opt/backups/system-configs` | Backup destination used by the backup script and per-run backups |
| `BACKUP_RETENTION_DAYS` | `30` | Backup retention for the backup script |
| `PHP_VERSION` | `8.3` | PHP version label used when adding the Ondřej PHP PPA |
| `DOCKER_SETUP_SHA256` | *(unset)* | Optional SHA256 checksum (64-character hex string) for verifying downloaded docker-setup.sh integrity. Example: `export DOCKER_SETUP_SHA256="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"` |
| **Phase 2 Security Features** | | |
| `ENABLE_PAM_FAILLOCK` | `yes` | If `yes`, configures PAM account lockout (5 failed attempts → 30-minute lockout) |
| `ENABLE_PASSWORD_QUALITY` | `yes` | If `yes`, enforces password complexity (min 12 chars, uppercase, lowercase, digit, special char) |
| `ENABLE_PASSWORD_AGING` | `yes` | If `yes`, configures password aging (max 90 days, warn 7 days before expiry) |
| `ENABLE_FILESYSTEM_HARDENING` | `yes` | If `yes`, hardens /tmp and /var/tmp with noexec,nosuid,nodev mount options |

## SSH Key Setup

If password auth is disabled, you must provide a key:

- Use `SSH_PUBKEY_PATH` to point to a local public key file
- Or paste the key when prompted

### Windows (PowerShell)

```powershell
ssh-keygen -t ed25519 -C "your_email@example.com"
Get-Content $env:USERPROFILE\.ssh\id_ed25519.pub
```

### Linux

```bash
ssh-keygen -t ed25519 -C "your_email@example.com"
cat ~/.ssh/id_ed25519.pub
```

Copy the public key into `/home/<admin>/.ssh/authorized_keys`.

## Recommended Run Order

1. Run the script
2. Test SSH access as the admin user
3. Reboot the server

## Notes

- HTTP/HTTPS/FTP are closed by default.
- Timeshift is disabled by default for servers.
- Always verify SSH access before rebooting.
