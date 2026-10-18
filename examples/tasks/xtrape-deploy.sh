#!/bin/sh
# xtrape-task: xtrape.deploy
# version: 1.0.0
# description: Pull the pinned Xtrape stack images and restart the deployment
# risk: high
# readonly: false
# servers: xtrape-*
# approval: always_human
# param: ref required string Stack version to deploy, e.g. 0.8.6
# param.ref.pattern: ^[0-9]+\.[0-9]+\.[0-9]+$
# maxBytes: 131072
# timeout: 900
set -eu

# This is what the Widget is for: an operation you already worked out once,
# kept as a file, so invoking it later means naming a server and a version
# instead of reassembling the commands.
#
# `# timeout: 900` because a real `docker compose pull` takes minutes, not
# seconds. There is no default deadline — a task that may run for hours simply
# declares none — but this one knows roughly how long it should take, and
# saying so turns a hung pull into a bounded failure.
cd /opt/xtrape
export XTRAPE_VERSION="$XOPS_ref"
docker compose pull
docker compose up -d --remove-orphans
docker compose ps
