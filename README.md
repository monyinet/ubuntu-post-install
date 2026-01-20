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

Cache-buster (if you hit CDN cache):

```bash
ts=$(date +%s)
curl -fsSL "https://raw.githubusercontent.com/monyinet/ubuntu-post-install/main/setup.sh?ts=$ts" -o /tmp/setup.sh
bash /tmp/setup.sh
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
