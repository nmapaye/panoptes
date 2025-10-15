#!/usr/bin/env bash
set -euo pipefail
# Demo: collect -> normalize -> build engine -> analyze -> show-path -> remediate
make engine
make cli
./bin/panoptes collect aws --org o-2a1b2c3d4e --out state.json
./bin/panoptes normalize state.json
./bin/panoptes analyze graph.json --out findings.json
finding_count=$(python3 - <<'PY'
import json
with open("findings.json", "r", encoding="utf-8") as fh:
    data = json.load(fh)
print(len(data.get("findings", [])))
PY
)
if [ "$finding_count" -gt 0 ]; then
  finding_id=$(python3 - <<'PY'
import json
with open("findings.json", "r", encoding="utf-8") as fh:
    data = json.load(fh)
print(data.get("findings", [{}])[0].get("id", ""))
PY
)
  ./bin/panoptes show-path "$finding_id" findings.json
  ./bin/panoptes remediate findings.json --emit terraform_out
else
  echo "No actionable findings detected; remediation skipped."
fi
echo "OK"
