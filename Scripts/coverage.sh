#!/usr/bin/env bash
set -euo pipefail

swift test --enable-swift-testing --enable-code-coverage

CODECOV_JSON_PATH="$(swift test --enable-swift-testing --enable-code-coverage --show-codecov-path)"

python3 - "$CODECOV_JSON_PATH" <<'PY'
import json
import sys

path = sys.argv[1]

with open(path, "r", encoding="utf-8") as handle:
    payload = json.load(handle)

files = payload["data"][0]["files"]
target_files = [item for item in files if "/Sources/UFOLib/" in item["filename"]]

if not target_files:
    print("No UFOLib source files found in coverage report.")
    sys.exit(1)

line_count = 0
line_covered = 0
branch_count = 0
branch_covered = 0

for item in target_files:
    summary = item["summary"]
    line_count += summary["lines"]["count"]
    line_covered += summary["lines"]["covered"]
    branch_count += summary["branches"]["count"]
    branch_covered += summary["branches"]["covered"]

line_percent = 100.0 if line_count == 0 else (line_covered / line_count) * 100.0
branch_percent = 100.0 if branch_count == 0 else (branch_covered / branch_count) * 100.0

print(f"UFOLib line coverage: {line_covered}/{line_count} ({line_percent:.2f}%)")
print(f"UFOLib branch coverage: {branch_covered}/{branch_count} ({branch_percent:.2f}%)")

if line_covered != line_count or branch_covered != branch_count:
    sys.exit(1)
PY
