#!/bin/sh
# Generate host keys on first boot, then run sshd in the foreground so all
# brute-force attempts land in `docker logs ssh-decoy`.
set -e

if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -A
fi

exec /usr/sbin/sshd -D -e
