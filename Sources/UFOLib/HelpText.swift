import Foundation

public enum HelpText {
    public static func render(topic: String?) -> String {
        let normalized = topic?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased() ?? ""

        switch normalized {
        case "", "ufo":
            return rootHelp
        case "keychain":
            return keychainHelp
        case "keychain create":
            return keychainCreateHelp
        case "keychain harden":
            return keychainHardenHelp
        case "keychain list":
            return keychainListHelp
        case "keychain delete":
            return keychainDeleteHelp
        case "secret":
            return secretHelp
        case "secret set":
            return secretSetHelp
        case "secret get":
            return secretGetHelp
        case "secret remove":
            return secretRemoveHelp
        case "secret search":
            return secretSearchHelp
        case "doctor":
            return doctorHelp
        case "help":
            return helpCommandHelp
        default:
            return "Unknown help topic '\(normalized)'.\n\n\(rootHelp)"
        }
    }

    private static let rootHelp = """
    UFO - managed local keychain CLI for macOS

    Usage:
      ufo <command> [options]

    Commands:
      keychain create <name> [--path <dir>]
      keychain harden <name>
      keychain list
      keychain delete <name> --yes --confirm <name>
      secret set --keychain <name> --service <svc> --account <acct> --stdin
      secret get --keychain <name> --service <svc> --account <acct> --reveal
      secret remove --keychain <name> --service <svc> --account <acct> --yes
      secret search --keychain <name> --query <q>
      doctor
      help [command]

    Tips:
      - Mutating commands are limited to UFO-managed keychains.
      - Protected keychains (login, iCloud, System, Local Items) are blocked.
      - Secrets are never written to logs.
      - security subprocesses use bounded timeouts with forced cleanup on hangs.

    Examples:
      ufo keychain create team-api
      ufo secret set --keychain team-api --service github --account ci --stdin
      ufo secret get --keychain team-api --service github --account ci --reveal
      ufo help secret set
    """

    private static let keychainHelp = """
    Usage:
      ufo keychain <subcommand>

    Subcommands:
      create <name> [--path <dir>]   Create a managed keychain.
      harden <name>                  Apply secure keychain settings.
      list                           List managed keychains.
      delete <name> --yes --confirm <name>
                                     Delete a managed keychain.
    """

    private static let keychainCreateHelp = """
    Usage:
      ufo keychain create <name> [--path <dir>]

    Create a UFO-managed keychain at <dir>/<name>.keychain-db.
    """

    private static let keychainHardenHelp = """
    Usage:
      ufo keychain harden <name>

    Reapply secure lock settings on an existing managed keychain.
    """

    private static let keychainListHelp = """
    Usage:
      ufo keychain list

    List UFO-managed keychains and hardening status.
    """

    private static let keychainDeleteHelp = """
    Usage:
      ufo keychain delete <name> --yes --confirm <name>

    High-friction safety delete. Name confirmation must match exactly.
    """

    private static let secretHelp = """
    Usage:
      ufo secret <subcommand>

    Subcommands:
      set     Store or update a secret.
      get     Reveal a secret (requires --reveal).
      remove  Delete a secret (requires --yes).
      search  Search stored metadata only.
    """

    private static let secretSetHelp = """
    Usage:
      ufo secret set --keychain <name> --service <svc> --account <acct> --stdin

    Store or update a generic password item in a managed keychain.
    Standard input is stored verbatim; use printf to avoid an accidental trailing newline.
    Standard input is limited to 16384 bytes.
    """

    private static let secretGetHelp = """
    Usage:
      ufo secret get --keychain <name> --service <svc> --account <acct> --reveal

    Reads and prints plaintext secret value only when --reveal is present.
    Exactly one transport newline is removed from security output; payload newlines are preserved.
    """

    private static let secretRemoveHelp = """
    Usage:
      ufo secret remove --keychain <name> --service <svc> --account <acct> --yes

    Delete a generic password item from a managed keychain.
    """

    private static let secretSearchHelp = """
    Usage:
      ufo secret search --keychain <name> --query <q>

    Metadata-only search over service/account entries tracked by UFO.
    """

    private static let doctorHelp = """
    Usage:
      ufo doctor

    Run local environment diagnostics for security binary, registry, and logging.
    """

    private static let helpCommandHelp = """
    Usage:
      ufo help [command]

    Show general help or help for a specific command topic.
    """
}
