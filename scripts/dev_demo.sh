#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
cd "${repo_root}"

# Demo: collect -> normalize -> build engine -> analyze -> show-path -> remediate
make engine
make cli
mkdir -p out
./bin/panoptes collect aws --fixture fixtures/aws/demo_state.json --org o-2a1b2c3d4e --out out/state.json
./bin/panoptes normalize out/state.json --out out/graph.json
./bin/panoptes analyze out/graph.json --rules rules/aws --out out/findings.json
finding_count=$(python3 - <<'PY'
import json
with open("out/findings.json", "r", encoding="utf-8") as fh:
    data = json.load(fh)
print(len(data.get("findings", [])))
PY
)
if [ "$finding_count" -gt 0 ]; then
  finding_id=$(python3 - <<'PY'
import json
with open("out/findings.json", "r", encoding="utf-8") as fh:
    data = json.load(fh)
print(data.get("findings", [{}])[0].get("id", ""))
PY
)
  ./bin/panoptes show-path "$finding_id" out/findings.json
  ./bin/panoptes remediate out/findings.json --emit out/terraform
else
  echo "No actionable findings detected; remediation skipped."
fi
echo "OK"
