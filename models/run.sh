#!/usr/bin/env bash
# Runs every command in the models, then the revert checks: each drops a guard the
# design relies on and expects the assertion it enforces to fail.
# Needs alloy6 (nix shell nixpkgs#alloy6).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
failed=0

run() { # MODEL COMMAND...
  local model=$1; shift
  local args=() cmd
  for cmd in "$@"; do args+=(-c "$cmd"); done
  alloy6 exec -f -o "$out/run" "${args[@]}" "$model" 2>&1 | grep -E '^ *[0-9]+\.|Error' || true
}

echo "== gate.als"
report=$(run gate.als '*')
printf '%s\n' "$report"
grep -q 'Error' <<<"$report" && failed=1

# NAME ASSERTION FROM TO: the model with FROM replaced by TO must fail ASSERTION
revert() {
  local name=$1 assertion=$2 from=$3 to=$4
  FROM=$from TO=$to python3 -I -c '
import os, sys
s = open("gate.als").read()
assert os.environ["FROM"] in s, "revert check out of date"
sys.stdout.write(s.replace(os.environ["FROM"], os.environ["TO"]))' >"$out/$name.als"
  local result
  result=$(alloy6 exec -f -o "$out/$name" -c "$assertion" "$out/$name.als" 2>&1 || true)
  if grep -q 'SAT expects=0' <<<"$result"; then
    echo "revert $name: $assertion fails, as it should"
  else
    echo "revert $name: $assertion still holds without its guard"
    failed=1
  fi
}

revert answer-all-domains forwardedWithConsent \
  'r.status = Waiting and r.caller = p.pcaller and r.domain in p.shown' \
  'r.status = Waiting and r.caller = p.pcaller'
revert consent-unshown consentShown \
  "G.consent' = Consent + p.pcaller -> p.shown" \
  "G.consent' = Consent + p.pcaller -> waitingDomains[p.pcaller]"
revert second-prompt onePromptPerCaller \
  $'  no (Open & pcaller.(p.pcaller))\n' ''
revert rule-from-seen forwardedWithConsent \
  "r.caller -> r.domain in Allowed implies r.status' = Forwarded" \
  "r.caller -> r.domain in Allowed + Seen implies r.status' = Forwarded"
revert leave-decided final \
  $'  r.status = Waiting\n  r.status\' = Gone' \
  $'  some r.status\n  r.status\' = Gone'

exit $failed
