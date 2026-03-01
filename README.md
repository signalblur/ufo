# ufo

[![CI and Release](https://github.com/signalblur/ufo/actions/workflows/ci-release.yml/badge.svg)](https://github.com/signalblur/ufo/actions/workflows/ci-release.yml)
[![UFOLib Coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/signalblur/ufo/badges/.github/badges/coverage.json)](https://github.com/signalblur/ufo/actions/workflows/ci-release.yml)

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

## CI and releases

Coverage/test status note:

- The CI badge is pass/fail for the full pipeline (build, tests, coverage gate, runtime dependency gate).
- The coverage badge is updated on each successful push to `main` from data in `Scripts/coverage.sh`.

- GitHub Actions workflow: `.github/workflows/ci-release.yml`
- On every push to `main`, CI runs (`swift build`, `swift test --parallel`, coverage gate, runtime dependency gate).
- If CI passes on `main`, a GitHub Release is created automatically.
- Release asset format: `ufo-main-<sha12>-macos-arm64.tar.gz` (arm64 only), plus a `.sha256` checksum file.

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
ufo keychain inventory [--user <name>]
ufo keychain delete <name> --yes --confirm <name>
ufo secret set --keychain <name> --service <svc> --account <acct> --stdin
ufo secret run --keychain <name> --service <svc> --account <acct> --env <VAR> [--timeout <sec>] -- <cmd> [args...]
ufo --env <VAR> [--keychain <name>] [--service <svc>] [--account <acct>] [--timeout <sec>] [--] <cmd> [args...]
ufo secret get --keychain <name> --service <svc> --account <acct> --reveal
ufo secret remove --keychain <name> --service <svc> --account <acct> --yes
ufo secret search --keychain <name> --query <q>
ufo doctor
ufo help [command]
```

Global option:

- `--trace` prints local troubleshooting details to stdout (secrets stay redacted).

## Safety model

- Mutating operations are restricted to UFO-managed keychains in the registry.
- Protected keychains and protected keychain locations are denied.
- Deletion is high-friction and requires both `--yes` and exact `--confirm <name>`.
- Secret insertion is stdin-only to avoid argv secret exposure, stdin bytes are stored verbatim, and stdin is limited to 16384 bytes.
- Secret script execution injects resolved secrets through process environment variables, not argv.
- Shortcut run defaults to the only managed keychain and can infer secret metadata from `--env` when unambiguous.
- Secret retrieval requires explicit `--reveal`.
- Secret retrieval removes exactly one transport newline from `security` output and preserves payload newlines.
- Search returns metadata only (service/account), never secret values.
- `security` subprocess calls enforce timeouts and force cleanup if a subprocess hangs.

## Keychain inventory

Use `keychain inventory` to inspect the active macOS keychain search list and attach UFO metadata:

```bash
ufo keychain inventory
```

Defaults explained in output:

- Without `--user`, UFO queries the current macOS user.
- Managed status and secret-count metadata come from `~/.ufo/registry.json`.
- `status=pending` means managed but not hardened yet.

Optional user targeting:

```bash
ufo keychain inventory --user alice
```

This uses `sudo -n` non-interactively to query another user's keychain list.

## Run scripts with injected secrets

`secret run` resolves a managed secret and injects it into a child process environment variable without placing the secret on argv.
Child stdout/stderr and exit code are passed through.

For safety, process-control variables like `PATH`, `DYLD_*`, and `LD_*` are blocked for `--env`.

If you already have one managed keychain and an unambiguous metadata match, use shortcut mode:

```bash
ufo --env OPENAI_API_KEY python script.py
```

Optional selectors can disambiguate shortcut mode:

```bash
ufo --env OPENAI_API_KEY --service openai --account ci python script.py
```

```bash
ufo secret run \
  --keychain team-api \
  --service openai \
  --account ci \
  --env OPENAI_API_KEY \
  -- python script.py
```

## Logging

- Metadata-only audit logs (secret values are redacted/suppressed).
- Preferred log path: `/var/log/ufo/ufo.log`.
- Fallback path: `~/Library/Logs/ufo/ufo.log`.
- Rotation interval: 30 days.
