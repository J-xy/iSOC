#!/usr/bin/env bash
# Run the soc-triage skill headless on one or more test alerts and check the output.
# Usage: tests/run.sh [aws|oauth|cspm ...]   (default: all alerts in tests/*_alert.json)
set -uo pipefail
cd "$(dirname "$0")/.."
mkdir -p tests/output

names=("$@")
if [ ${#names[@]} -eq 0 ]; then
  for f in tests/*_alert.json; do n=$(basename "$f" _alert.json); names+=("$n"); done
fi

run_one() {
  local n=$1 stamp out
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  out="tests/output/${n}_${stamp}"
  claude -p "$(cat "tests/${n}_alert.json")" --output-format stream-json --verbose \
    --allowedTools "Skill Read Glob Grep" > "${out}.jsonl" 2> "${out}.err"
  python3 - "${out}.jsonl" "${out}.md" <<'PY'
import json, sys
res = None
for line in open(sys.argv[1]):
    try:
        m = json.loads(line)
    except json.JSONDecodeError:
        continue
    if m.get("type") == "result":
        res = m
open(sys.argv[2], "w").write((res or {}).get("result", ""))
if res:
    print(f"  turns={res.get('num_turns')} cost=${res.get('total_cost_usd', 0):.2f}")
PY
  echo "== ${n} (${out}.md)"
  python3 tests/check_handoff.py "${out}.md" "tests/${n}_alert.json" "${out}.jsonl" --expect "$n"
}

status=0
for n in "${names[@]}"; do run_one "$n" & done
for job in $(jobs -p); do wait "$job" || status=1; done
exit $status
