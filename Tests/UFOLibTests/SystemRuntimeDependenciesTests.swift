import Foundation
import Testing
@testable import UFOLib
@testable import ufo

@Suite("System runtime dependencies")
struct SystemRuntimeDependenciesTests {
    @Test("StandardInputReader reads input at exact byte limit")
    func standardInputReaderReadsAtExactLimit() throws {
        let pipe = Pipe()
        pipe.fileHandleForWriting.write(Data("abcd".utf8))
        pipe.fileHandleForWriting.closeFile()

        let reader = StandardInputReader(standardInput: pipe.fileHandleForReading, chunkSize: 2)
        let value = try reader.readStandardInput(maxBytes: 4)

        #expect(value == "abcd")
    }

    @Test("StandardInputReader rejects oversized stdin payload")
    func standardInputReaderRejectsOversizedInput() {
        let pipe = Pipe()
        pipe.fileHandleForWriting.write(Data("abcde".utf8))
        pipe.fileHandleForWriting.closeFile()

        let reader = StandardInputReader(standardInput: pipe.fileHandleForReading, chunkSize: 3)
        do {
            _ = try reader.readStandardInput(maxBytes: 4)
            Issue.record("Expected oversized input failure")
        } catch {
            #expect(error as? UFOError == .validation("Secret stdin input exceeds 4 bytes."))
        }
    }

    @Test("StandardInputReader rejects invalid UTF-8")
    func standardInputReaderRejectsInvalidUTF8() {
        let pipe = Pipe()
        pipe.fileHandleForWriting.write(Data([0xFF, 0xFE]))
        pipe.fileHandleForWriting.closeFile()

        let reader = StandardInputReader(standardInput: pipe.fileHandleForReading)
        do {
            _ = try reader.readStandardInput(maxBytes: 8)
            Issue.record("Expected UTF-8 decode failure")
        } catch {
            #expect(error as? UFOError == .io("Standard input is not valid UTF-8."))
        }
    }

    @Test("StandardInputReader rejects nonpositive byte limit")
    func standardInputReaderRejectsNonpositiveLimit() {
        let pipe = Pipe()
        pipe.fileHandleForWriting.closeFile()

        let reader = StandardInputReader(standardInput: pipe.fileHandleForReading)
        do {
            _ = try reader.readStandardInput(maxBytes: 0)
            Issue.record("Expected nonpositive limit failure")
        } catch {
            #expect(error as? UFOError == .io("Standard input byte limit must be greater than zero."))
        }
    }

    @Test("SystemProcessRunner writes stdin payload to child process")
    func systemProcessRunnerWritesPayload() throws {
        let runner = SystemProcessRunner()

        let result = try runner.run(
            executable: "/bin/cat",
            arguments: [],
            standardInput: Data("runtime-payload".utf8),
            timeout: 2,
            environment: nil
        )

        #expect(result.exitCode == 0)
        #expect(String(decoding: result.standardOutput, as: UTF8.self) == "runtime-payload")
        #expect(result.standardError.isEmpty)
    }

    @Test("SystemProcessRunner redirects missing stdin to /dev/null")
    func systemProcessRunnerRedirectsNilInputToDevNull() throws {
        let runner = SystemProcessRunner()

        let result = try runner.run(
            executable: "/bin/sh",
            arguments: ["-c", "if read -r _; then printf has-data; else printf eof; fi"],
            standardInput: nil,
            timeout: 2,
            environment: nil
        )

        #expect(result.exitCode == 0)
        #expect(String(decoding: result.standardOutput, as: UTF8.self) == "eof")
    }

    @Test("SystemProcessRunner enforces one timeout budget across write and wait")
    func systemProcessRunnerUsesSingleDeadline() {
        let runner = SystemProcessRunner()
        let payload = Data(repeating: 0x61, count: 8 * 1024 * 1024)
        let timeout: TimeInterval = 0.75
        let start = DispatchTime.now().uptimeNanoseconds

        do {
            _ = try runner.run(
                executable: "/bin/sh",
                arguments: ["-c", "sleep 5"],
                standardInput: payload,
                timeout: timeout,
                environment: nil
            )
            Issue.record("Expected timeout failure")
        } catch {
            guard case .subprocess(let message) = error as? UFOError else {
                Issue.record("Unexpected error: \(error)")
                return
            }

            #expect(
                message.contains("Subprocess stdin write timed out") || message.contains("Subprocess timed out")
            )
        }

        let elapsedNanos = DispatchTime.now().uptimeNanoseconds - start
        let elapsed = TimeInterval(elapsedNanos) / 1_000_000_000
        #expect(elapsed < timeout + 1.5)
    }

    @Test("SystemProcessRunner handles early child stdin close safely")
    func systemProcessRunnerHandlesEarlyChildStdinClose() {
        let runner = SystemProcessRunner()
        let payload = Data(repeating: 0x62, count: 8 * 1024 * 1024)

        do {
            _ = try runner.run(
                executable: "/usr/bin/true",
                arguments: [],
                standardInput: payload,
                timeout: 2,
                environment: nil
            )
            Issue.record("Expected stdin write failure")
        } catch {
            guard case .subprocess(let message) = error as? UFOError else {
                Issue.record("Unexpected error: \(error)")
                return
            }

            #expect(
                message.contains("Failed writing subprocess stdin") ||
                    message.contains("Subprocess stdin write timed out")
            )
        }
    }
}
