import Testing
@testable import UFOLib

@Suite("Input Validation")
struct InputValidationTests {
    @Test("Validates keychain names")
    func validateKeychainName() {
        do {
            try InputValidation.validateKeychainName("team-prod_1")
        } catch {
            Issue.record("Unexpected error: \(error)")
        }

        expectValidationError("Keychain name cannot be empty.") {
            try InputValidation.validateKeychainName("")
        }

        let tooLong = String(repeating: "a", count: 129)
        expectValidationError("Keychain name must be 128 characters or fewer.") {
            try InputValidation.validateKeychainName(tooLong)
        }

        expectValidationError("Keychain name cannot contain leading or trailing whitespace.") {
            try InputValidation.validateKeychainName(" bad")
        }

        expectValidationError(
            "Keychain name must start with an alphanumeric character and contain only letters, numbers, '.', '_', or '-'."
        ) {
            try InputValidation.validateKeychainName("bad name")
        }
    }

    @Test("Rejects empty service/account/query/secret")
    func validateEmptyCoreInputs() {
        expectValidationError("Service cannot be empty.") { try InputValidation.validateService("  ") }
        expectValidationError("Account cannot be empty.") { try InputValidation.validateAccount("\n") }
        expectValidationError("Query cannot be empty.") { try InputValidation.validateQuery("\t") }
        expectValidationError("Secret value cannot be empty.") { try InputValidation.validateSecret("") }
    }

    @Test("Rejects control characters and oversize field values")
    func validateFieldContentRules() {
        expectValidationError("Service cannot contain control characters.") {
            try InputValidation.validateService("svc\nname")
        }

        expectValidationError("Account cannot contain control characters.") {
            try InputValidation.validateAccount("acct\u{0007}")
        }

        expectValidationError("Query cannot contain control characters.") {
            try InputValidation.validateQuery("gh\u{0000}")
        }

        let longService = String(repeating: "s", count: 257)
        expectValidationError("Service must be 256 characters or fewer.") {
            try InputValidation.validateService(longService)
        }

        let longSecret = String(repeating: "x", count: 4_097)
        expectValidationError("Secret value must be 4096 characters or fewer.") {
            try InputValidation.validateSecret(longSecret)
        }

        expectValidationError("Secret value cannot contain NUL bytes.") {
            try InputValidation.validateSecret("abc\u{0000}def")
        }
    }

    @Test("Generates keychain filename suffix")
    func keychainFilenameSuffix() {
        #expect(KeychainPath.filename(for: "alpha") == "alpha.keychain-db")
        #expect(KeychainPath.filename(for: "alpha.keychain") == "alpha.keychain")
        #expect(KeychainPath.filename(for: "alpha.keychain-db") == "alpha.keychain-db")
    }
}

private func expectValidationError(_ message: String, _ operation: () throws -> Void) {
    do {
        try operation()
        Issue.record("Expected validation error")
    } catch {
        #expect(error as? UFOError == .validation(message))
    }
}
