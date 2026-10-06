#!/bin/sh
cp /etc/letsencrypt/live/test.lucas-romero.com/fullchain.pem /opt/sentry/certs/decoy.crt
cp /etc/letsencrypt/live/test.lucas-romero.com/privkey.pem /opt/sentry/certs/decoy.key
docker start sentry-sentry-1
