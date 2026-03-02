#!/usr/bin/env bash
set -euo pipefail

SWIFT_TEST_HELP="$(swift test --help)"
SWIFT_TEST_ARGS=(--enable-code-coverage)
SWIFTC_HELP="$(swiftc -help)"

if [[ "$SWIFTC_HELP" == *"-suppress-remarks"* ]]; then
    SWIFT_TEST_ARGS=(-Xswiftc -suppress-remarks "${SWIFT_TEST_ARGS[@]}")
fi

if [[ "$SWIFT_TEST_HELP" == *"--enable-swift-testing"* ]]; then
    SWIFT_TEST_ARGS=(--enable-swift-testing "${SWIFT_TEST_ARGS[@]}")
elif [[ "$SWIFT_TEST_HELP" == *"--enable-experimental-swift-testing"* ]]; then
    SWIFT_TEST_ARGS=(--enable-experimental-swift-testing "${SWIFT_TEST_ARGS[@]}")
fi

export LLVM_PROFILE_FILE="${LLVM_PROFILE_FILE:-${TMPDIR:-/tmp}/ufo-%p-%m.profraw}"

swift test "${SWIFT_TEST_ARGS[@]}" 2> >(python3 Scripts/filter-swift-noise.py >&2)

CODECOV_JSON_PATH="$(swift test --show-codecov-path 2> >(python3 Scripts/filter-swift-noise.py >&2))"

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
