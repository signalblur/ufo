#!/usr/bin/env bash
set -euo pipefail

BASE_ARGS=("$@")

SWIFTC_HELP="$(swiftc -help)"
if [[ "$SWIFTC_HELP" == *"-suppress-remarks"* ]]; then
    BASE_ARGS=(-Xswiftc -suppress-remarks "${BASE_ARGS[@]}")
fi

TMP_LOG_PATH="$(mktemp "${TMPDIR:-/tmp}/ufo-swift-test.XXXXXX.log")"
cleanup() {
    rm -f "$TMP_LOG_PATH"
}
trap cleanup EXIT

classify_log() {
    local log_path="$1"

    python3 - "$log_path" <<'PY'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")

if "Unknown option" in text:
    print("unknown_option")
    raise SystemExit(0)

match = re.search(r"Test run with\s+(\d+)\s+tests", text)
if match is not None:
    if int(match.group(1)) > 0:
        print("swift_testing_nonzero")
    else:
        print("zero_tests")
    raise SystemExit(0)

if "No matching test cases were run" in text:
    print("zero_tests")
    raise SystemExit(0)

if "Executed 0 tests," in text:
    print("zero_tests")
    raise SystemExit(0)

match = re.search(r"Executed\s+(\d+)\s+tests,", text)
if match is not None:
    if int(match.group(1)) > 0:
        print("xctest_nonzero")
    else:
        print("zero_tests")
    raise SystemExit(0)

print("unknown")
PY
}

run_with_flag() {
    local test_flag="$1"
    local args=("${BASE_ARGS[@]}")

    if [[ -n "$test_flag" ]]; then
        args=("$test_flag" "${args[@]}")
    fi

    : > "$TMP_LOG_PATH"

    local status=0
    swift test "${args[@]}" >"$TMP_LOG_PATH" 2>&1 || status=$?

    local classification
    classification="$(classify_log "$TMP_LOG_PATH")"

    if [[ "$classification" == "unknown_option" ]]; then
        return 125
    fi

    python3 Scripts/filter-swift-noise.py < "$TMP_LOG_PATH"

    if [[ "$classification" == "zero_tests" ]]; then
        return 124
    fi

    if [[ $status -ne 0 ]]; then
        return "$status"
    fi

    if [[ "$classification" == "swift_testing_nonzero" || "$classification" == "xctest_nonzero" ]]; then
        return 0
    fi

    return 124
}

CANDIDATE_FLAGS=("--enable-swift-testing" "--enable-experimental-swift-testing" "--experimental-swift-testing" "")

for candidate_flag in "${CANDIDATE_FLAGS[@]}"; do
    status=0
    run_with_flag "$candidate_flag" || status=$?

    if [[ $status -eq 0 ]]; then
        exit 0
    fi

    if [[ $status -eq 125 ]]; then
        continue
    fi

    if [[ $status -eq 124 ]]; then
        if [[ -n "$candidate_flag" ]]; then
            echo "swift test with '$candidate_flag' executed zero tests; trying fallback." >&2
            continue
        fi

        echo "swift test executed zero tests with available flags." >&2
        exit 1
    fi

    exit "$status"
done

echo "No compatible swift-testing flag produced a runnable test suite." >&2
exit 1
