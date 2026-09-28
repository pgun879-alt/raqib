#!/usr/bin/env bash
# Reproducible end-to-end demo. Nothing outside this machine is contacted.
#
# Serves the bundled demo site on loopback, then shows the four behaviours that distinguish this
# from `curl` in a loop:
#   1. robots.txt is enforced, not just claimed.
#   2. A page whose only change is a timestamp does NOT report a change.
#   3. A real content change is caught, with a precise diff.
#   4. Outage and recovery each alert exactly once, and repeats stay silent.
set -euo pipefail

cd "$(dirname "$0")/.."

PYTHON="${PYTHON:-.venv/bin/python}"
if [[ ! -x "$PYTHON" ]]; then
  echo "error: $PYTHON not found. Create the environment first:" >&2
  echo "  python3 -m venv .venv && ./.venv/bin/pip install -e '.[dev]'" >&2
  exit 1
fi

PORT="${PORT:-8999}"
export RAQIB_DB_PATH=data/demo.sqlite3
export RAQIB_TARGETS_FILE=targets.example.yaml
export RAQIB_REPORTS_DIR=reports
export RAQIB_ALERT_SINKS=stdout,file
export RAQIB_ALERT_FILE=data/demo-alerts.jsonl
# The demo watches a local test server, so the SSRF guard's private-address refusal is relaxed.
# This is off by default and the CLI warns whenever it is on.
export RAQIB_ALLOW_PRIVATE_TARGETS=true
export RAQIB_MIN_SECONDS_BETWEEN_REQUESTS_PER_HOST=0.2
export RAQIB_LOG_LEVEL=ERROR

rule() { printf '\n\033[1;36m%s\033[0m\n' "── $* ─────────────────────────────────────────"; }

mkdir -p data reports
rm -f data/demo.sqlite3 data/demo.sqlite3-wal data/demo.sqlite3-shm data/demo-alerts.jsonl

# Work on a copy so the demo can edit pages without dirtying the repository.
WORK="$(mktemp -d)"
cp -r demo_site/. "$WORK/"
cleanup() {
  [[ -n "${SERVER_PID:-}" ]] && kill "$SERVER_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

export DEMO_WORK="$WORK"

# Refuse to run if something else already holds the port.
#
# Without this the demo silently monitors whatever that other process is serving. That happened
# during development: a leftover server kept answering, the demo's own edits had no visible
# effect, and the output looked like broken change detection rather than a port clash.
port_is_free() {
  "$PYTHON" -c "
import socket, sys
with socket.socket() as probe:
    probe.settimeout(1)
    sys.exit(1 if probe.connect_ex(('127.0.0.1', $PORT)) == 0 else 0)
"
}

if ! port_is_free; then
  echo "error: port $PORT is already in use, so the demo would monitor the wrong server." >&2
  echo "       Stop that process, or re-run with:  PORT=9001 ./scripts/demo.sh" >&2
  exit 1
fi

"$PYTHON" -m raqib.cli serve-demo --port "$PORT" --directory "$WORK" >/dev/null 2>&1 &
SERVER_PID=$!
sleep 2

if ! "$PYTHON" -c "
import sys, urllib.request
try:
    urllib.request.urlopen('http://127.0.0.1:$PORT/index.html', timeout=5)
except Exception as exc:
    sys.exit(f'demo server did not start: {exc}')
"; then
  exit 1
fi

check() { "$PYTHON" -m raqib.cli check 2>&1 | grep -vE '^warning:|allow_private_targets|^$' || true; }

rule "0. What we are watching"
"$PYTHON" -m raqib.cli list 2>&1 | grep -vE '^warning:|allow_private_targets' || true

rule "1. Targets pass the SSRF guard before anything is fetched"
"$PYTHON" -m raqib.cli validate 2>&1 | grep -vE '^warning:|allow_private_targets' || true

rule "2. First run: baselines captured, and robots.txt refuses /private/"
echo "Note the demo-disallowed target: robots.txt forbids it, so raqib refuses to fetch it."
check

rule "3. The page's timestamp changes — this must NOT be reported as a change"
"$PYTHON" - <<'PY'
import os, pathlib, re
work = pathlib.Path(os.environ["DEMO_WORK"])
page = work / "index.html"
page.write_text(
    re.sub(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", "2026-09-28T23:59:59Z", page.read_text()),
    encoding="utf-8",
)
print("updated the generated-at timestamp only")
PY
check
echo
echo ">>> changed=0 above is the point: without ignore_patterns this page would report a"
echo "    change on every single poll, and the tool would be unusable."

rule "4. A real price change — this MUST be caught, with a diff"
"$PYTHON" - <<'PY'
import os, pathlib
work = pathlib.Path(os.environ["DEMO_WORK"])
page = work / "index.html"
page.write_text(page.read_text().replace("89,900 DZD", "79,900 DZD"), encoding="utf-8")
api = work / "api.json"
api.write_text(api.read_text().replace('"price": 89900', '"price": 79900'), encoding="utf-8")
print("dropped the air-conditioner price in both the page and the JSON API")
PY
check

rule "5. The same change again — must stay silent (alerts=0)"
check

rule "6. The site goes down"
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""
sleep 1
check
echo
echo ">>> Reported as unreachable, not as a robots problem."

rule "7. Still down — no repeat alerts"
check

rule "8. The site comes back"
"$PYTHON" -m raqib.cli serve-demo --port "$PORT" --directory "$WORK" >/dev/null 2>&1 &
SERVER_PID=$!
sleep 2
check

rule "9. Every alert raised during this run"
"$PYTHON" - <<'PY'
import json, pathlib
path = pathlib.Path("data/demo-alerts.jsonl")
for line in path.read_text(encoding="utf-8").splitlines():
    alert = json.loads(line)
    print(f"  {alert['severity']:8} {alert['kind']:15} {alert['target']:24} {alert['title'][:54]}")
PY

rule "10. Reports"
"$PYTHON" -m raqib.cli report --output-stem demo 2>&1 | grep -vE '^warning:|allow_private_targets' || true

rule "Done"
cat <<EOF
Everything above ran against a local server on 127.0.0.1 — no external site was contacted.

  reports/demo.html   open in a browser (self-contained, no internet needed)
  reports/demo.md     paste into an email or a ticket
  data/demo-alerts.jsonl   one JSON object per alert

To watch real sites, edit targets.yaml, leave RAQIB_ALLOW_PRIVATE_TARGETS unset, and run:
    ./.venv/bin/python -m raqib.cli watch
EOF
