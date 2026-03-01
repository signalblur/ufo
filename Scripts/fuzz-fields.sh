#!/usr/bin/env bash
set -euo pipefail

ITERATIONS="${1:-1000}"

if ! command -v radamsa >/dev/null 2>&1; then
    printf "radamsa is required. Install with: brew install radamsa\n" >&2
    exit 1
fi

swift build -c release --product ufo-fuzz >/dev/null
BIN_PATH="$(swift build -c release --show-bin-path)/ufo-fuzz"

python3 - "$BIN_PATH" "$ITERATIONS" <<'PY'
import subprocess
import sys

harness = sys.argv[1]
iterations = int(sys.argv[2])

seeds = [
    b"team|~/.ufo/keychains|github|ci|git|team|token|secret set",
    b"alpha-01|/tmp/ufo|apple|ops|app|alpha-01|value|keychain create",
    b"beta.keychain|~/safe/path|service.internal|build-bot|bot|beta.keychain|x|secret get",
    b"prod_2|/Users/tester/.ufo/keychains|registry|automation|reg|prod_2|super-secret|secret remove",
]

for index in range(iterations):
    seed = seeds[index % len(seeds)]
    mutation = subprocess.run(
        ["radamsa"],
        input=seed,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout

    result = subprocess.run(
        [harness],
        input=mutation,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=2,
    )

    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        print(
            f"Fuzz harness failed at case {index + 1} with exit {result.returncode}: {stderr}",
            file=sys.stderr,
        )
        sys.exit(1)

print(
    f"Radamsa fuzzed {iterations} payloads across keychain/service/account/path/query/value fields with no crashes."
)
PY
