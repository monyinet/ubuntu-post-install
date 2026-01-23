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
- Users: creates/updates an admin user; configures sudo policies in `/etc/sudoers.d/`
- SSH: rewrites `/etc/ssh/sshd_config`, sets a login banner, restarts SSH, and enforces key-based access by default
- Firewall: resets and enables UFW; opens SSH (and optional HTTP/HTTPS/FTP)
- Security hardening: writes sysctl hardening files under `/etc/sysctl.d/`; adds audit rules; sets additional system defaults
- Shell defaults: writes global shell config (including `/etc/bash.bashrc` and `/etc/zsh/zprofile`)
- Backups: creates `/usr/local/bin/backup-critical-configs.sh` + a daily cron job
- Cleanup: removes old logs and clears package caches

The script creates per-run backups of files it overwrites under `BACKUP_DIR/run-<timestamp>/`.

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
