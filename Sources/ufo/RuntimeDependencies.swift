import Foundation
import Darwin
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

        let inputPipe: Pipe?
        if standardInput != nil {
            let pipe = Pipe()
            process.standardInput = pipe
            inputPipe = pipe
        } else {
            // Use a Foundation Pipe with its write end closed immediately
            // so the child reads EOF on first read (equivalent to /dev/null).
            let nullPipe = Pipe()
            nullPipe.fileHandleForWriting.closeFile()
            process.standardInput = nullPipe
            inputPipe = nil
        }

        // Build POSIX pipe pairs for stdout/stderr so we fully control
        // every fd and nothing in Foundation can invalidate them.
        var stdoutFDs: [Int32] = [0, 0]
        var stderrFDs: [Int32] = [0, 0]
        guard pipe(&stdoutFDs) == 0, pipe(&stderrFDs) == 0 else {
            throw UFOError.subprocess("Failed to create output pipes for subprocess.")
        }

        // Give Process a duplicate of each write end.  Foundation's
        // Process.run() may close the fd it receives during posix_spawn
        // setup.  A dup keeps our originals valid for deterministic close.
        let stdoutWriteDup = dup(stdoutFDs[1])
        let stderrWriteDup = dup(stderrFDs[1])
        guard stdoutWriteDup >= 0, stderrWriteDup >= 0 else {
            Darwin.close(stdoutFDs[0]); Darwin.close(stdoutFDs[1])
            Darwin.close(stderrFDs[0]); Darwin.close(stderrFDs[1])
            if stdoutWriteDup >= 0 { Darwin.close(stdoutWriteDup) }
            if stderrWriteDup >= 0 { Darwin.close(stderrWriteDup) }
            throw UFOError.subprocess("Failed to duplicate output pipe descriptors for subprocess.")
        }
        process.standardOutput = FileHandle(fileDescriptor: stdoutWriteDup, closeOnDealloc: false)
        process.standardError = FileHandle(fileDescriptor: stderrWriteDup, closeOnDealloc: false)

        do {
            try process.run()
        } catch {
            Darwin.close(stdoutFDs[0]); Darwin.close(stdoutFDs[1])
            Darwin.close(stderrFDs[0]); Darwin.close(stderrFDs[1])
            Darwin.close(stdoutWriteDup); Darwin.close(stderrWriteDup)
            throw UFOError.subprocess("Failed to launch subprocess at \(executable): \(error.localizedDescription)")
        }

        // Close ALL write-end copies in the parent.  The child inherited
        // its own copies via posix_spawn.  With no writers remaining in
        // the parent, read(2) will see EOF once the child exits.
        Darwin.close(stdoutFDs[1])
        Darwin.close(stderrFDs[1])
        Darwin.close(stdoutWriteDup)
        Darwin.close(stderrWriteDup)

        let outputReadFD = stdoutFDs[0]
        let errorReadFD = stderrFDs[0]

        // Write stdin payload if provided.
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
                Darwin.close(outputReadFD)
                Darwin.close(errorReadFD)
                throw error
            }
        }

        // Wait for the child to exit within the remaining budget.
        let waitResult = completion.wait(timeout: deadline)
        guard waitResult == .success else {
            terminateAndReap(process, completion: completion)
            Darwin.close(outputReadFD)
            Darwin.close(errorReadFD)
            throw UFOError.subprocess(
                "Subprocess timed out after \(formatTimeout(timeout)) seconds at \(executable)."
            )
        }

        // Child has exited — all output is now buffered in pipe kernel
        // buffers.  Read synchronously on the calling thread.  This
        // avoids GCD dispatch entirely, eliminating thread-pool starvation
        // that caused empty reads on resource-constrained CI runners.
        let stdoutData = Self.readAll(from: outputReadFD)
        Darwin.close(outputReadFD)
        let stderrData = Self.readAll(from: errorReadFD)
        Darwin.close(errorReadFD)

        return ProcessResult(
            exitCode: process.terminationStatus,
            standardOutput: stdoutData,
            standardError: stderrData
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

    /// Read all available bytes from a file descriptor using POSIX read(2).
    /// Returns accumulated data after EOF (read returns 0) or an error.
    /// This avoids Foundation's FileHandle.readToEnd() which can throw ObjC
    /// NSFileHandleOperationException on some CI environments.
    private static func readAll(from fd: Int32) -> Data {
        var result = Data()
        let bufferSize = 65_536
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer { buffer.deallocate() }

        while true {
            let bytesRead = Darwin.read(fd, buffer, bufferSize)
            if bytesRead > 0 {
                result.append(buffer, count: bytesRead)
            } else {
                // 0 = EOF, -1 = error (treat both as end of stream)
                break
            }
        }
        return result
    }

    private func writeStandardInput(
        _ payload: Data,
        to handle: FileHandle,
        executable: String,
        deadline: DispatchTime,
        timeout: TimeInterval
    ) throws {
        let descriptor = handle.fileDescriptor

        // Suppress SIGPIPE so broken-pipe writes return EPIPE instead of
        // killing the process.
        if fcntl(descriptor, F_SETNOSIGPIPE, 1) == -1 {
            let errorCode = errno
            let message = String(cString: strerror(errorCode))
            throw UFOError.subprocess("Failed to configure subprocess stdin writer: \(message)")
        }

        // Set the file descriptor to non-blocking so write(2) returns
        // immediately when the pipe buffer is full, allowing us to check
        // the deadline between attempts.
        let originalFlags = fcntl(descriptor, F_GETFL)
        if originalFlags == -1 || fcntl(descriptor, F_SETFL, originalFlags | O_NONBLOCK) == -1 {
            let errorCode = errno
            let message = String(cString: strerror(errorCode))
            throw UFOError.subprocess("Failed to configure subprocess stdin writer: \(message)")
        }

        var offset = 0
        let chunkSize = 65_536
        let pollInterval: useconds_t = 5_000 // 5 ms

        while offset < payload.count {
            guard DispatchTime.now() < deadline else {
                throw UFOError.subprocess(
                    "Subprocess stdin write timed out after \(formatTimeout(timeout)) seconds at \(executable)."
                )
            }

            let end = min(offset + chunkSize, payload.count)
            let written = payload[offset..<end].withUnsafeBytes { buffer -> Int in
                Darwin.write(descriptor, buffer.baseAddress!, buffer.count)
            }

            if written > 0 {
                offset += written
            } else if written == 0 {
                break
            } else {
                let errorCode = errno
                if errorCode == EAGAIN || errorCode == EWOULDBLOCK {
                    // Pipe buffer full — poll briefly then retry.
                    usleep(pollInterval)
                    continue
                }
                if errorCode == EPIPE {
                    throw UFOError.subprocess(
                        "Failed writing subprocess stdin at \(executable): Broken pipe"
                    )
                }
                let message = String(cString: strerror(errorCode))
                throw UFOError.subprocess(
                    "Failed writing subprocess stdin at \(executable): \(message)"
                )
            }
        }

        do {
            try handle.close()
        } catch {
            throw UFOError.subprocess(
                "Failed writing subprocess stdin at \(executable): \(error.localizedDescription)"
            )
        }
    }
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
