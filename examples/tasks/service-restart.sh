#!/bin/sh
# xtrape-task: service.restart
# version: 1.0.0
# description: Restart a single systemd service on the target host, then report its state
# risk: high
# readonly: false
# servers: *
# approval: policy
# param: service required string The systemd unit to restart, e.g. nginx or nginx.service
# param.service.pattern: ^[a-zA-Z0-9@._-]+$
set -eu

# An EXAMPLE task (like system-uptime.sh / nginx-reload.sh): a
# narrowly-bounded, policy-governed service restart, used to demonstrate and
# verify the bounded-profile MECHANISM (linux-ops-widget-nodejs#77). It is
# library content — the task set on any deployment is elastic (#53 online
# grow/edit/remove) — NOT a built-in capability of the Widget. It declares
# HIGH risk; the DECISION is the Platform's — its policy weighs that risk (and
# the invocation's context) and chooses Approval / Confirmation / AUTO / DENY.
# The Widget neither gates nor assumes M4 here: it publishes the Checkpoint's
# risk honestly and executes exactly once (the command carries the invocation's
# idempotency key) only if the Platform delivers an authorized command.
#
# `service` is validated by the param pattern above to a systemd unit token
# (letters, digits, @ . _ -). It CANNOT contain a space, quote, semicolon,
# pipe, `$`, or backtick, so it cannot break out of the argument position
# below — the pattern is the injection boundary, checked before the command
# is ever assembled.
# Parameters arrive as XOPS_-prefixed environment variables (shell.ts),
# shell-quoted by the Widget; the pattern above already bounded the token.
service="$XOPS_service"

# One unit, by exact name. `restart` on an unknown unit fails (set -e aborts),
# and the task reports that failure honestly rather than masking it.
sudo -n systemctl restart -- "$service"

# Prove the outcome: is-active exits non-zero if the unit did not come back,
# so a restart that "succeeded" but left the service dead is still a failure.
systemctl is-active -- "$service"
