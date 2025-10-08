#!/usr/bin/env bash
set -euo pipefail
# Demo: collect -> normalize -> build engine -> analyze -> show-path -> remediate
make engine
make cli
./bin/panoptes collect aws --org 123456789012 --out state.json
./bin/panoptes normalize state.json
./bin/panoptes analyze graph.json --out findings.json
./bin/panoptes show-path F-0001 findings.json
./bin/panoptes remediate findings.json --emit terraform_out
echo "OK"
