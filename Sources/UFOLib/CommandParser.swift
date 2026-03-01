import Foundation

public struct CommandParser {
    public init() {}

    public func parse(_ arguments: [String]) throws -> Command {
        guard !arguments.isEmpty else {
            return .help(topic: nil)
        }

        if arguments[0].hasPrefix("--") {
            return try parseRootSecretRunShortcut(arguments)
        }

        switch arguments[0] {
        case "help":
            return parseHelp(Array(arguments.dropFirst()))
        case "doctor":
            return try parseDoctor(Array(arguments.dropFirst()))
        case "keychain":
            return try parseKeychain(Array(arguments.dropFirst()))
        case "secret":
            return try parseSecret(Array(arguments.dropFirst()))
        default:
            throw UFOError.usage("Unknown command '\(arguments[0])'. Use 'ufo help'.")
        }
    }

    private func parseRootSecretRunShortcut(_ arguments: [String]) throws -> Command {
        let valueOptions: Set<String> = ["--env", "--keychain", "--service", "--account", "--timeout"]
        var optionTokens: [String] = []
        var index = 0

        while index < arguments.count {
            let token = arguments[index]
            if token == "--" {
                index += 1
                break
            }

            guard token.hasPrefix("--") else {
                break
            }

            guard valueOptions.contains(token) else {
                throw UFOError.usage("Unknown option '\(token)'.")
            }

            guard index + 1 < arguments.count else {
                throw UFOError.usage("Option '\(token)' requires a value.")
            }

            let value = arguments[index + 1]
            guard !value.hasPrefix("--") else {
                throw UFOError.usage("Option '\(token)' requires a value.")
            }

            optionTokens.append(token)
            optionTokens.append(value)
            index += 2
        }

        let commandTokens = Array(arguments.dropFirst(index))
        guard let executable = commandTokens.first, !executable.isEmpty else {
            throw UFOError.usage(
                "Shortcut run requires a command. Example: 'ufo --env OPENAI_API_KEY python script.py'."
            )
        }

        let options = try parseOptions(optionTokens, valueOptions: valueOptions, flagOptions: [])

        let timeout: TimeInterval?
        if let timeoutValue = options.values["--timeout"] {
            guard let parsed = TimeInterval(timeoutValue), parsed.isFinite, parsed > 0 else {
                throw UFOError.usage("Option '--timeout' requires a positive number of seconds.")
            }
            timeout = parsed
        } else {
            timeout = nil
        }

        return .secretRunShortcut(
            keychain: options.values["--keychain"],
            service: options.values["--service"],
            account: options.values["--account"],
            environmentVariable: try requiredOption("--env", from: options.values),
            executable: executable,
            arguments: Array(commandTokens.dropFirst()),
            timeout: timeout
        )
    }

    private func parseHelp(_ arguments: [String]) -> Command {
        if arguments.isEmpty {
            return .help(topic: nil)
        }
        return .help(topic: arguments.joined(separator: " "))
    }

    private func parseDoctor(_ arguments: [String]) throws -> Command {
        guard arguments.isEmpty else {
            throw UFOError.usage("'doctor' does not accept arguments.")
        }
        return .doctor
    }

    private func parseKeychain(_ arguments: [String]) throws -> Command {
        guard let subcommand = arguments.first else {
            throw UFOError.usage("Missing keychain subcommand. Use 'ufo help keychain'.")
        }

        let tail = Array(arguments.dropFirst())
        switch subcommand {
        case "create":
            return try parseKeychainCreate(tail)
        case "harden":
            return try parseKeychainHarden(tail)
        case "list":
            return try parseKeychainList(tail)
        case "delete":
            return try parseKeychainDelete(tail)
        default:
            throw UFOError.usage("Unknown keychain subcommand '\(subcommand)'.")
        }
    }

    private func parseKeychainCreate(_ arguments: [String]) throws -> Command {
        guard let name = arguments.first else {
            throw UFOError.usage("'keychain create' requires <name>.")
        }

        let options = try parseOptions(Array(arguments.dropFirst()), valueOptions: ["--path"], flagOptions: [])
        return .keychainCreate(name: name, path: options.values["--path"])
    }

    private func parseKeychainHarden(_ arguments: [String]) throws -> Command {
        guard arguments.count == 1 else {
            throw UFOError.usage("'keychain harden' requires exactly one <name>.")
        }
        return .keychainHarden(name: arguments[0])
    }

    private func parseKeychainList(_ arguments: [String]) throws -> Command {
        guard arguments.isEmpty else {
            throw UFOError.usage("'keychain list' does not accept arguments.")
        }
        return .keychainList
    }

    private func parseKeychainDelete(_ arguments: [String]) throws -> Command {
        guard let name = arguments.first else {
            throw UFOError.usage("'keychain delete' requires <name>.")
        }

        let options = try parseOptions(
            Array(arguments.dropFirst()),
            valueOptions: ["--confirm"],
            flagOptions: ["--yes"]
        )

        return .keychainDelete(
            name: name,
            yes: options.flags.contains("--yes"),
            confirm: options.values["--confirm"]
        )
    }

    private func parseSecret(_ arguments: [String]) throws -> Command {
        guard let subcommand = arguments.first else {
            throw UFOError.usage("Missing secret subcommand. Use 'ufo help secret'.")
        }

        let tail = Array(arguments.dropFirst())
        switch subcommand {
        case "set":
            return try parseSecretSet(tail)
        case "run":
            return try parseSecretRun(tail)
        case "get":
            return try parseSecretGet(tail)
        case "remove":
            return try parseSecretRemove(tail)
        case "search":
            return try parseSecretSearch(tail)
        default:
            throw UFOError.usage("Unknown secret subcommand '\(subcommand)'.")
        }
    }

    private func parseSecretSet(_ arguments: [String]) throws -> Command {
        let options = try parseOptions(
            arguments,
            valueOptions: ["--keychain", "--service", "--account", "--value"],
            flagOptions: ["--stdin"]
        )

        let keychain = try requiredOption("--keychain", from: options.values)
        let service = try requiredOption("--service", from: options.values)
        let account = try requiredOption("--account", from: options.values)

        if options.values["--value"] != nil {
            throw UFOError.usage("'secret set --value' is disabled to avoid argv secret exposure. Use --stdin.")
        }

        guard options.flags.contains("--stdin") else {
            throw UFOError.usage("'secret set' requires --stdin.")
        }

        return .secretSet(keychain: keychain, service: service, account: account, input: .stdin)
    }

    private func parseSecretRun(_ arguments: [String]) throws -> Command {
        guard let separatorIndex = arguments.firstIndex(of: "--") else {
            throw UFOError.usage("'secret run' requires '-- <command> [args...]'.")
        }

        let optionTokens = Array(arguments[..<separatorIndex])
        let commandTokens = Array(arguments.dropFirst(separatorIndex + 1))
        guard let executable = commandTokens.first, !executable.isEmpty else {
            throw UFOError.usage("'secret run' requires a command after '--'.")
        }

        let options = try parseOptions(
            optionTokens,
            valueOptions: ["--keychain", "--service", "--account", "--env", "--timeout"],
            flagOptions: []
        )

        let timeout: TimeInterval?
        if let timeoutValue = options.values["--timeout"] {
            guard let parsed = TimeInterval(timeoutValue), parsed.isFinite, parsed > 0 else {
                throw UFOError.usage("Option '--timeout' requires a positive number of seconds.")
            }
            timeout = parsed
        } else {
            timeout = nil
        }

        return .secretRun(
            keychain: try requiredOption("--keychain", from: options.values),
            service: try requiredOption("--service", from: options.values),
            account: try requiredOption("--account", from: options.values),
            environmentVariable: try requiredOption("--env", from: options.values),
            executable: executable,
            arguments: Array(commandTokens.dropFirst()),
            timeout: timeout
        )
    }

    private func parseSecretGet(_ arguments: [String]) throws -> Command {
        let options = try parseOptions(
            arguments,
            valueOptions: ["--keychain", "--service", "--account"],
            flagOptions: ["--reveal"]
        )

        return .secretGet(
            keychain: try requiredOption("--keychain", from: options.values),
            service: try requiredOption("--service", from: options.values),
            account: try requiredOption("--account", from: options.values),
            reveal: options.flags.contains("--reveal")
        )
    }

    private func parseSecretRemove(_ arguments: [String]) throws -> Command {
        let options = try parseOptions(
            arguments,
            valueOptions: ["--keychain", "--service", "--account"],
            flagOptions: ["--yes"]
        )

        return .secretRemove(
            keychain: try requiredOption("--keychain", from: options.values),
            service: try requiredOption("--service", from: options.values),
            account: try requiredOption("--account", from: options.values),
            yes: options.flags.contains("--yes")
        )
    }

    private func parseSecretSearch(_ arguments: [String]) throws -> Command {
        let options = try parseOptions(
            arguments,
            valueOptions: ["--keychain", "--query"],
            flagOptions: []
        )

        return .secretSearch(
            keychain: try requiredOption("--keychain", from: options.values),
            query: try requiredOption("--query", from: options.values)
        )
    }

    private func requiredOption(_ name: String, from options: [String: String]) throws -> String {
        guard let value = options[name], !value.isEmpty else {
            throw UFOError.usage("Missing required option '\(name)'.")
        }
        return value
    }

    private func parseOptions(
        _ arguments: [String],
        valueOptions: Set<String>,
        flagOptions: Set<String>
    ) throws -> ParsedOptions {
        var parsedValues: [String: String] = [:]
        var parsedFlags: Set<String> = []
        var index = 0

        while index < arguments.count {
            let token = arguments[index]
            guard token.hasPrefix("--") else {
                throw UFOError.usage("Unexpected positional argument '\(token)'.")
            }

            if flagOptions.contains(token) {
                let inserted = parsedFlags.insert(token).inserted
                if !inserted {
                    throw UFOError.usage("Option '\(token)' was provided multiple times.")
                }
                index += 1
                continue
            }

            guard valueOptions.contains(token) else {
                throw UFOError.usage("Unknown option '\(token)'.")
            }
            guard index + 1 < arguments.count else {
                throw UFOError.usage("Option '\(token)' requires a value.")
            }

            let value = arguments[index + 1]
            guard !value.hasPrefix("--") else {
                throw UFOError.usage("Option '\(token)' requires a value.")
            }

            if parsedValues[token] != nil {
                throw UFOError.usage("Option '\(token)' was provided multiple times.")
            }

            parsedValues[token] = value
            index += 2
        }

        return ParsedOptions(values: parsedValues, flags: parsedFlags)
    }
}

private struct ParsedOptions {
    let values: [String: String]
    let flags: Set<String>
}
