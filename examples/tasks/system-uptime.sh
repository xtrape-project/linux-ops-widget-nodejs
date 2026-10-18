#!/bin/sh
# xtrape-task: system.uptime
# version: 1.0.0
# description: Show system uptime and load average
# risk: low
# readonly: true
# servers: *

# The simplest shape a task has: no parameters. The caller says which server,
# and this is what runs there.
uptime
