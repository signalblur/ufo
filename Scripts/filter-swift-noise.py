#!/usr/bin/env python3
import re
import sys

PATTERNS = (
    re.compile(r'^LLVM Profile Error: Failed to write file "default\.profraw": Operation not permitted\s*$'),
    re.compile(
        r"^.*: remark: add '@preconcurrency' to suppress 'Sendable'-related warnings from module '(ObjectiveC|XCTest)'\s*$"
    ),
    re.compile(r'^\s*\^\s*$'),
    re.compile(r'^\s*@preconcurrency\s*$'),
)

for raw_line in sys.stdin:
    line = raw_line.rstrip("\n")
    if any(pattern.match(line) for pattern in PATTERNS):
        continue
    sys.stdout.write(raw_line)
