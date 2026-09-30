#!/usr/bin/env bash
# Move the real sshd from port 22 to 22022 and start the SSH decoy container
# on port 22. Ubuntu 24.04 uses systemd socket activation for sshd, which is
# disabled here so the Port directive takes effect.
#
# PREREQUISITE (do NOT skip): open 22022/tcp in the Lightsail console
# (Networking → IPv4 firewall → add rule) BEFORE running this script, and
# keep your current SSH session open while it runs.
#
# Rollback: the previous sshd_config is backed up; if sshd fails to restart
# or 22022 is not listening, the old config is restored automatically.
set -u

PORT=22022
DECOY_DIR=/opt/sentry

echo "==> [1/6] Backing up sshd_config"
sudo cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S)"

echo "==> [2/6] Disabling ssh socket activation (Ubuntu 24.04)"
if systemctl list-unit-files | grep -q '^ssh\.socket'; then
    sudo systemctl disable --now ssh.socket || true
fi

echo "==> [3/6] Setting Port ${PORT} in sshd_config"
sudo sed -i -E 's/^#?[[:space:]]*Port[[:space:]].*/Port '"${PORT}"'/' /etc/ssh/sshd_config
if ! grep -qE "^Port ${PORT}$" /etc/ssh/sshd_config; then
    echo "Port ${PORT}" | sudo tee -a /etc/ssh/sshd_config >/dev/null
fi
if ! sudo sshd -t; then
    echo "sshd -t FAILED — aborting (config untouched in memory, nothing restarted)"
    exit 1
fi

echo "==> [4/6] Enabling ssh.service and restarting on port ${PORT}"
sudo systemctl enable ssh.service >/dev/null 2>&1 || true
sudo systemctl restart ssh.service

if ! ss -tln | grep -q ":${PORT} "; then
    echo "Port ${PORT} is NOT listening — ROLLING BACK"
    LATEST_BAK=$(ls -1t /etc/ssh/sshd_config.bak.* | head -1)
    sudo cp "${LATEST_BAK}" /etc/ssh/sshd_config
    sudo systemctl restart ssh.service
    exit 1
fi

echo "==> [5/6] Starting the SSH decoy container on port 22"
cd "${DECOY_DIR}"
sudo docker compose --profile decoy-ssh up -d ssh-decoy

echo "==> [6/6] Done."
echo "    Verify NOW from your machine:  ssh -p ${PORT} ubuntu@<server-ip>"
echo "    Keep this session open until you confirmed the new port works."
echo "    Decoy attempts appear in:      sudo docker logs -f ssh-decoy"
