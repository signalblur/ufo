import Foundation
import Testing
@testable import UFOLib

@Suite("Audit Logger")
struct AuditLoggerTests {
    @Test("Uses primary directory when writable")
    func usesPrimaryDirectory() {
        let fs = FakeFileSystem()
        let clock = FakeClock(currentDate: Date(timeIntervalSince1970: 1_700_000_000))
        let logger = AuditLogger(fileSystem: fs, clock: clock)

        logger.log(event: "keychain.create", outcome: "success", metadata: ["keychain": "alpha"])

        let logPath = "/var/log/ufo/ufo.log"
        let line = fs.string(at: logPath)
        #expect(line.contains("\"event\":\"keychain.create\""))
        #expect(line.contains("\"keychain\":\"alpha\""))
        #expect(logger.health().activeLogPath == logPath)
        #expect(logger.health().usingFallbackDirectory == false)
    }

    @Test("Falls back when primary directory cannot be created")
    func fallsBackToUserLogDirectory() {
        let fs = FakeFileSystem()
        fs.createDirectoryFailures.insert("/var/log/ufo")
        let logger = AuditLogger(fileSystem: fs, clock: FakeClock(currentDate: Date(timeIntervalSince1970: 1_700_000_000)))

        logger.log(event: "doctor", outcome: "success")

        let fallbackPath = "/Users/tester/Library/Logs/ufo/ufo.log"
        #expect(fs.string(at: fallbackPath).isEmpty == false)
        #expect(logger.health().usingFallbackDirectory)
        #expect(logger.health().activeLogPath == fallbackPath)
        #expect(logger.health().writable)
    }

    @Test("Rotates old log after configured interval")
    func rotatesOldLogs() {
        let fs = FakeFileSystem()
        let oldPath = "/var/log/ufo/ufo.log"
        fs.writeString("old\n", to: oldPath)
        fs.modificationDates[oldPath] = Date(timeIntervalSince1970: 1_600_000_000)
        let clock = FakeClock(currentDate: Date(timeIntervalSince1970: 1_700_000_000))

        let logger = AuditLogger(fileSystem: fs, clock: clock)
        logger.log(event: "secret.search", outcome: "success")

        #expect(fs.string(at: "/var/log/ufo/ufo-20231114221320.log") == "old\n")
        #expect(fs.string(at: oldPath).contains("\"event\":\"secret.search\""))
    }

    @Test("Redacts sensitive metadata values")
    func redactsSensitiveMetadata() {
        let fs = FakeFileSystem()
        let logger = AuditLogger(fileSystem: fs, clock: FakeClock(currentDate: Date(timeIntervalSince1970: 1_700_000_000)))

        logger.log(
            event: "secret.set",
            outcome: "success",
            metadata: [
                "secretValue": "top-secret",
                "account": "ci\nagent"
            ]
        )

        let line = fs.string(at: "/var/log/ufo/ufo.log")
        #expect(line.contains("\"secretValue\":\"<redacted>\""))
        #expect(line.contains("\"account\":\"ci agent\""))
        #expect(line.contains("top-secret") == false)
    }

    @Test("Reports unwritable when both directories fail")
    func reportsUnwritable() {
        let fs = FakeFileSystem()
        fs.createDirectoryFailures.insert("/var/log/ufo")
        fs.createDirectoryFailures.insert("/Users/tester/Library/Logs/ufo")
        let logger = AuditLogger(fileSystem: fs, clock: FakeClock(currentDate: Date(timeIntervalSince1970: 1_700_000_000)))

        logger.log(event: "help", outcome: "success")

        let health = logger.health()
        #expect(health.writable == false)
        #expect(health.lastError == "Audit log directory is not writable.")
    }

    @Test("Captures append and rotation failures")
    func capturesWriteAndRotationFailures() {
        let fs = FakeFileSystem()
        let path = "/var/log/ufo/ufo.log"
        fs.writeString("old\n", to: path)
        fs.modificationDates[path] = Date(timeIntervalSince1970: 1_600_000_000)
        fs.moveFailures.insert(path)

        let logger = AuditLogger(fileSystem: fs, clock: FakeClock(currentDate: Date(timeIntervalSince1970: 1_700_000_000)))
        logger.log(event: "x", outcome: "success")
        #expect(logger.lastError == UFOError.io("move failed").message)

        fs.moveFailures.remove(path)
        fs.appendFailures.insert(path)
        logger.log(event: "x", outcome: "success")
        #expect(logger.lastError == UFOError.io("append failed").message)

        fs.appendFailures.remove(path)
        fs.writeString("old\n", to: path)
        fs.modificationDates[path] = Date(timeIntervalSince1970: 1_600_000_000)
        fs.modificationFailures.insert(path)
        logger.log(event: "x", outcome: "success")
        #expect(logger.lastError == UFOError.io("modification failed").message)
    }

    @Test("Uses localized description for non-UFO errors")
    func capturesGenericErrors() {
        let fs = FakeFileSystem()
        let path = "/var/log/ufo/ufo.log"
        fs.appendGenericFailures.insert(path)

        let logger = AuditLogger(fileSystem: fs, clock: FakeClock(currentDate: Date(timeIntervalSince1970: 1_700_000_000)))
        logger.log(event: "x", outcome: "success")

        #expect(logger.lastError == "generic append failure")
    }
}
