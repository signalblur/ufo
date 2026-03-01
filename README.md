# ufo

Minimal macOS CLI for managed local Keychain secrets.

`ufo` manages only UFO-registered keychains and blocks protected system/user keychains.

## Platform

- macOS only (current environment target)

## Build and test

```bash
swift build
swift test
bash Scripts/coverage.sh
bash Scripts/check-runtime-deps.sh
```

`Scripts/coverage.sh` enforces 100% UFOLib line coverage (and branch gate when branch data is present).

`Scripts/check-runtime-deps.sh` verifies the release binary links only Apple system libraries.

## Release binary posture

- `ufo` is built as a single binary artifact.
- Fully static Swift linking is not supported on Apple platforms (`-static-stdlib` is unavailable).
- Runtime dependency gate ensures no non-system shared libraries are linked.

## Fuzzing

Use Radamsa (FOSS mutation fuzzer) to fuzz key command fields through a dedicated harness:

```bash
brew install radamsa
bash Scripts/fuzz-fields.sh 2000
```

The harness exercises parser, input validation, and keychain protection policy across keychain name/path, service/account, query, confirm, and secret value fields without mutating real keychains.

## Commands

```text
ufo keychain create <name> [--path <dir>]
ufo keychain harden <name>
ufo keychain list
ufo keychain delete <name> --yes --confirm <name>
ufo secret set --keychain <name> --service <svc> --account <acct> --stdin
ufo secret get --keychain <name> --service <svc> --account <acct> --reveal
ufo secret remove --keychain <name> --service <svc> --account <acct> --yes
ufo secret search --keychain <name> --query <q>
ufo doctor
ufo help [command]
```

## Safety model

- Mutating operations are restricted to UFO-managed keychains in the registry.
- Protected keychains and protected keychain locations are denied.
- Deletion is high-friction and requires both `--yes` and exact `--confirm <name>`.
- Secret insertion is stdin-only to avoid argv secret exposure, stdin bytes are stored verbatim, and stdin is limited to 16384 bytes.
- Secret retrieval requires explicit `--reveal`.
- Secret retrieval removes exactly one transport newline from `security` output and preserves payload newlines.
- Search returns metadata only (service/account), never secret values.
- `security` subprocess calls enforce timeouts and force cleanup if a subprocess hangs.

## Logging

- Metadata-only audit logs (secret values are redacted/suppressed).
- Preferred log path: `/var/log/ufo/ufo.log`.
- Fallback path: `~/Library/Logs/ufo/ufo.log`.
- Rotation interval: 30 days.
