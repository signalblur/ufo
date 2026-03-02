import Foundation
import Darwin
import os
import UFOLib

struct SystemClock: Clock {
    func now() -> Date {
        Date()
    }
}

struct StandardInputReader: InputReading {
    private let standardInput: FileHandle
    private let chunkSize: Int

    init(standardInput: FileHandle = .standardInput, chunkSize: Int = 4096) {
        self.standardInput = standardInput
        self.chunkSize = max(1, chunkSize)
    }

    func readStandardInput(maxBytes: Int) throws -> String {
        guard maxBytes > 0 else {
            throw UFOError.io("Standard input byte limit must be greater than zero.")
        }

        var data = Data()
        while true {
            let nextReadLength = min(chunkSize, maxBytes - data.count + 1)
            let chunk = standardInput.readData(ofLength: nextReadLength)
            if chunk.isEmpty {
                break
            }

            data.append(chunk)
            if data.count > maxBytes {
                throw UFOError.validation("Secret stdin input exceeds \(maxBytes) bytes.")
            }
        }

        guard let value = String(data: data, encoding: .utf8) else {
            throw UFOError.io("Standard input is not valid UTF-8.")
        }
        return value
    }
}

final class SystemProcessRunner: ProcessRunning {
    func run(
        executable: String,
        arguments: [String],
        standardInput: Data?,
        timeout: TimeInterval,
        environment: [String: String]?
    ) throws -> ProcessResult {
        guard timeout > 0 else {
            throw UFOError.subprocess("Subprocess timeout must be greater than zero seconds.")
        }

        let deadline = DispatchTime.now() + timeout

        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        if let environment {
            process.environment = environment
        }

        let completion = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in
            completion.signal()
        }
        defer {
            process.terminationHandler = nil
        }

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = errorPipe

        let inputPipe: Pipe?
        let nullInputHandle: FileHandle?
        if standardInput != nil {
            let pipe = Pipe()
            process.standardInput = pipe
            inputPipe = pipe
            nullInputHandle = nil
        } else {
            guard let handle = FileHandle(forReadingAtPath: "/dev/null") else {
                throw UFOError.subprocess("Failed to open /dev/null for subprocess stdin redirection.")
            }
            process.standardInput = handle
            inputPipe = nil
            nullInputHandle = handle
        }
        defer {
            nullInputHandle?.closeFile()
        }

        do {
            try process.run()
        } catch {
            throw UFOError.subprocess("Failed to launch subprocess at \(executable): \(error.localizedDescription)")
        }

        outputPipe.fileHandleForWriting.closeFile()
        errorPipe.fileHandleForWriting.closeFile()

        let pipeCapture = PipeCaptureState()
        let readerGroup = DispatchGroup()
        let readerQueue = DispatchQueue(label: "ufo.system-process-runner.pipe-reader", attributes: .concurrent)

        readerGroup.enter()
        readerQueue.async {
            let data = (try? outputPipe.fileHandleForReading.readToEnd()) ?? Data()
            pipeCapture.setOutput(data)
            readerGroup.leave()
        }

        readerGroup.enter()
        readerQueue.async {
            let data = (try? errorPipe.fileHandleForReading.readToEnd()) ?? Data()
            pipeCapture.setError(data)
            readerGroup.leave()
        }

        if let payload = standardInput, let inputPipe {
            do {
                try writeStandardInput(
                    payload,
                    to: inputPipe.fileHandleForWriting,
                    executable: executable,
                    deadline: deadline,
                    timeout: timeout
                )
            } catch let error as UFOError {
                terminateAndReap(process, completion: completion)
                awaitPipeReaders(readerGroup, outputPipe: outputPipe, errorPipe: errorPipe)
                throw error
            }
        }

        let waitResult = completion.wait(timeout: deadline)
        guard waitResult == .success else {
            terminateAndReap(process, completion: completion)
            awaitPipeReaders(readerGroup, outputPipe: outputPipe, errorPipe: errorPipe)
            throw UFOError.subprocess(
                "Subprocess timed out after \(formatTimeout(timeout)) seconds at \(executable)."
            )
        }

        awaitPipeReaders(readerGroup, outputPipe: outputPipe, errorPipe: errorPipe)

        let captured = pipeCapture.get()

        return ProcessResult(
            exitCode: process.terminationStatus,
            standardOutput: captured.output,
            standardError: captured.error
        )
    }

    private func formatTimeout(_ timeout: TimeInterval) -> String {
        if timeout.rounded() == timeout {
            return String(Int(timeout))
        }
        return String(format: "%.3f", timeout)
    }

    private func terminateAndReap(_ process: Process, completion: DispatchSemaphore) {
        if process.isRunning {
            process.terminate()
        }

        let graceWait = completion.wait(timeout: .now() + 1)
        guard graceWait == .timedOut, process.isRunning else {
            return
        }

        _ = Darwin.kill(process.processIdentifier, SIGKILL)
        _ = completion.wait(timeout: .now() + 1)
    }

    private func awaitPipeReaders(_ group: DispatchGroup, outputPipe: Pipe, errorPipe: Pipe) {
        let waitResult = group.wait(timeout: .now() + 1)
        guard waitResult == .timedOut else {
            return
        }

        outputPipe.fileHandleForReading.closeFile()
        errorPipe.fileHandleForReading.closeFile()
        _ = group.wait(timeout: .now() + 1)
    }

    private func writeStandardInput(
        _ payload: Data,
        to handle: FileHandle,
        executable: String,
        deadline: DispatchTime,
        timeout: TimeInterval
    ) throws {
        let completion = DispatchSemaphore(value: 0)
        let writeState = StdinWriteState()

        DispatchQueue.global(qos: .userInitiated).async {
            let descriptor = handle.fileDescriptor
            if fcntl(descriptor, F_SETNOSIGPIPE, 1) == -1 {
                let errorCode = errno
                let message = String(cString: strerror(errorCode))
                writeState.setError(
                    UFOError.subprocess("Failed to configure subprocess stdin writer: \(message)")
                )
                completion.signal()
                return
            }

            do {
                try handle.write(contentsOf: payload)
                try handle.close()
            } catch {
                writeState.setError(error)
            }
            completion.signal()
        }

        let waitResult = completion.wait(timeout: deadline)
        guard waitResult == .success else {
            throw UFOError.subprocess(
                "Subprocess stdin write timed out after \(formatTimeout(timeout)) seconds at \(executable)."
            )
        }

        if let error = writeState.get() {
            throw UFOError.subprocess("Failed writing subprocess stdin at \(executable): \(error.localizedDescription)")
        }
    }
}

// MARK: - Sendable state containers for cross-queue data transfer

/// Thread-safe container for pipe capture results.
/// `OSAllocatedUnfairLock` is Sendable and compiler-verified safe on macOS 14+.
private struct PipeCaptureState: Sendable {
    private let state = OSAllocatedUnfairLock(initialState: (output: Data(), error: Data()))

    func setOutput(_ data: Data) { state.withLock { $0.output = data } }
    func setError(_ data: Data) { state.withLock { $0.error = data } }
    func get() -> (output: Data, error: Data) { state.withLock { $0 } }
}

/// Thread-safe container for stdin write error propagation.
private struct StdinWriteState: Sendable {
    private let state = OSAllocatedUnfairLock<Error?>(initialState: nil)

    func setError(_ value: Error) { state.withLock { $0 = value } }
    func get() -> Error? { state.withLock { $0 } }
}

final class SystemFileSystem: FileSysteming {
    private let fileManager: FileManager

    var homeDirectoryPath: String {
        NSHomeDirectory()
    }

    init(fileManager: FileManager = .default) {
        self.fileManager = fileManager
    }

    func expandTilde(in path: String) -> String {
        (path as NSString).expandingTildeInPath
    }

    func canonicalPath(_ path: String) -> String {
        let expandedPath = expandTilde(in: path)
        let url = URL(fileURLWithPath: expandedPath)
        if fileManager.fileExists(atPath: url.path) {
            return url.resolvingSymlinksInPath().standardizedFileURL.path
        }
        return url.standardizedFileURL.path
    }

    func createDirectory(at path: String) throws {
        try fileManager.createDirectory(
            at: URL(fileURLWithPath: canonicalPath(path)),
            withIntermediateDirectories: true
        )
    }

    func fileExists(at path: String) -> Bool {
        fileManager.fileExists(atPath: canonicalPath(path))
    }

    func isWritableDirectory(_ path: String) -> Bool {
        let canonical = canonicalPath(path)
        var isDirectory: ObjCBool = false
        if fileManager.fileExists(atPath: canonical, isDirectory: &isDirectory) {
            return isDirectory.boolValue && fileManager.isWritableFile(atPath: canonical)
        }

        let parentPath = (canonical as NSString).deletingLastPathComponent
        return fileManager.fileExists(atPath: parentPath) && fileManager.isWritableFile(atPath: parentPath)
    }

    func readFile(at path: String) throws -> Data {
        let canonical = canonicalPath(path)
        do {
            return try Data(contentsOf: URL(fileURLWithPath: canonical))
        } catch {
            throw UFOError.io("Failed reading file at \(canonical): \(error.localizedDescription)")
        }
    }

    func writeFile(_ data: Data, to path: String) throws {
        let canonical = canonicalPath(path)
        let parentPath = (canonical as NSString).deletingLastPathComponent
        try createDirectory(at: parentPath)
        do {
            try data.write(to: URL(fileURLWithPath: canonical), options: .atomic)
        } catch {
            throw UFOError.io("Failed writing file at \(canonical): \(error.localizedDescription)")
        }
    }

    func appendFile(_ data: Data, to path: String) throws {
        let canonical = canonicalPath(path)
        let parentPath = (canonical as NSString).deletingLastPathComponent
        try createDirectory(at: parentPath)

        if !fileManager.fileExists(atPath: canonical) {
            do {
                try data.write(to: URL(fileURLWithPath: canonical))
            } catch {
                throw UFOError.io("Failed creating file at \(canonical): \(error.localizedDescription)")
            }
            return
        }

        do {
            let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: canonical))
            try handle.seekToEnd()
            handle.write(data)
            try handle.close()
        } catch {
            throw UFOError.io("Failed appending file at \(canonical): \(error.localizedDescription)")
        }
    }

    func modificationDate(at path: String) throws -> Date {
        let canonical = canonicalPath(path)
        do {
            let attributes = try fileManager.attributesOfItem(atPath: canonical)
            guard let date = attributes[.modificationDate] as? Date else {
                throw UFOError.io("Modification date missing at \(canonical).")
            }
            return date
        } catch let error as UFOError {
            throw error
        } catch {
            throw UFOError.io("Failed reading file attributes at \(canonical): \(error.localizedDescription)")
        }
    }

    func moveItem(at source: String, to destination: String) throws {
        let canonicalSource = canonicalPath(source)
        let canonicalDestination = canonicalPath(destination)

        let parentPath = (canonicalDestination as NSString).deletingLastPathComponent
        try createDirectory(at: parentPath)

        do {
            if fileManager.fileExists(atPath: canonicalDestination) {
                try fileManager.removeItem(atPath: canonicalDestination)
            }
            try fileManager.moveItem(atPath: canonicalSource, toPath: canonicalDestination)
        } catch {
            throw UFOError.io(
                "Failed moving file from \(canonicalSource) to \(canonicalDestination): \(error.localizedDescription)"
            )
        }
    }

    func removeItem(at path: String) throws {
        let canonical = canonicalPath(path)
        guard fileManager.fileExists(atPath: canonical) else {
            return
        }

        do {
            try fileManager.removeItem(atPath: canonical)
        } catch {
            throw UFOError.io("Failed removing file at \(canonical): \(error.localizedDescription)")
        }
    }
}

func buildApplication() -> UFOApplication {
    let fileSystem = SystemFileSystem()
    let clock = SystemClock()
    let processRunner = SystemProcessRunner()

    return UFOApplication(
        parser: CommandParser(),
        fileSystem: fileSystem,
        inputReader: StandardInputReader(),
        policy: KeychainProtectionPolicy(fileSystem: fileSystem),
        registryStore: ManagedRegistryStore(fileSystem: fileSystem, clock: clock),
        securityCLI: SecurityCLI(processRunner: processRunner),
        processRunner: processRunner,
        auditLogger: AuditLogger(fileSystem: fileSystem, clock: clock)
    )
}
