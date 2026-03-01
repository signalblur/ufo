#!/usr/bin/env bash
set -euo pipefail

swift build -c release --product ufo >/dev/null
BIN_PATH="$(swift build -c release --show-bin-path)/ufo"

python3 - "$BIN_PATH" <<'PY'
import subprocess
import sys

binary = sys.argv[1]
allowed_prefixes = ("/usr/lib/", "/System/Library/")

result = subprocess.run(
    ["otool", "-L", binary],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    check=True,
)

print(result.stdout.strip())

lines = [line.strip() for line in result.stdout.splitlines()[1:] if line.strip()]
dependencies = [line.split(" (compatibility version", 1)[0].strip() for line in lines]

unexpected = [
    dep for dep in dependencies if not dep.startswith(allowed_prefixes)
]

if unexpected:
    print("\nRuntime dependency check failed. Non-system libraries detected:", file=sys.stderr)
    for dep in unexpected:
        print(f"- {dep}", file=sys.stderr)
    sys.exit(1)

print("Runtime dependency check passed: binary links only Apple system libraries.")
PY
