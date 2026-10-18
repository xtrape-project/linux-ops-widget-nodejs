#!/bin/sh
# xtrape-task: nginx.reload
# version: 1.0.0
# description: Validate the nginx configuration, then reload it
# risk: medium
# readonly: false
# servers: web-*
# approval: policy
set -eu

# A task is one file, so a sequence stays a sequence. `set -e` aborts before
# the reload if the configuration does not validate, and the whole task
# reports one exit status — an operator reading this file sees the order.
sudo -n nginx -t
sudo -n systemctl reload nginx
systemctl is-active nginx
