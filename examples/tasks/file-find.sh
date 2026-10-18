#!/bin/sh
# xtrape-task: file.find
# version: 1.0.0
# description: List files matching a name pattern under an admitted directory
# risk: low
# readonly: true
# servers: *
# approval: policy
# param: root required string Which admitted directory to search under
# param.root.enum: /etc|/var/log|/opt
# param: namePattern required string Glob matched against the file name, e.g. *.conf
# param.namePattern.maxLength: 128
set -eu

# A parameterised task, and the one worth reading twice.
#
# The roots are an ENUM the operator writes, not a path the caller composes.
# That is deliberate: a task that accepts any absolute path is a general
# filesystem reader on every server it is scoped to, and neither `-xdev` nor
# `-maxdepth` changes that — they bound where traversal goes, not what the
# caller may point it at. Widen this list when you mean to.
#
# Values arrive as environment variables, so nothing a caller sends is read as
# part of this script. What a value still influences is what this script does
# WITH it: a value a program would read as one of its own options is not data
# to that program, whatever the quoting (#36). So `namePattern` is checked
# here, in the open, where an operator can see the check.
case "$XOPS_namePattern" in
  -*) echo "namePattern must not start with -" >&2; exit 2 ;;
esac

# TWO different bounds, and the Widget only provides one of them.
#
# Output is bounded by the Widget at the wire, so this does not pipe through
# `head` and lose find's exit status in order to bound itself. But a search
# that matches NOTHING produces no output at all and still walks the tree, and
# the Widget's execution timeout closes the CONNECTION rather than the remote
# command (see the README) — so nothing outside this script bounds the work.
#
# `timeout` does, where the work actually happens. Exit 124 is its own signal
# and is reported as such, rather than as a search that found nothing.
# `status=$?` after `if ! cmd` reads the status of the NEGATION, which is 0
# whenever the branch was taken — so a timeout and a failed search both looked
# like success. `|| status=$?` captures the command's own status, and is what
# keeps `set -e` from exiting first.
#
# No check that `timeout` exists: if a target does not have it, the shell says
# `command not found` and exits 127, the task fails, and that report reaches
# the caller unaltered. That is the right answer and needs no help from here —
# a bespoke message and a bespoke exit code were this script dressing up
# something the shell already said plainly.
status=0
timeout 20s find "$XOPS_root" -xdev -maxdepth 6 -type f -name "$XOPS_namePattern" -print || status=$?

if [ "$status" -eq 124 ]; then
  echo "search did not finish within 20s under $XOPS_root" >&2
  exit 3
fi
exit "$status"
