import Foundation
import UFOLib

struct SystemClock: Clock {
    func now() -> Date {
        Date()
    }
}

struct StandardInputReader: InputReading {
    func readStandardInput() throws -> String {
        let data = FileHandle.standardInput.readDataToEndOfFile()
        guard let value = String(data: data, encoding: .utf8) else {
            throw UFOError.io("Standard input is not valid UTF-8.")
        }
        return value
    }
}

final class SystemProcessRunner: ProcessRunning {
    func run(executable: String, arguments: [String], standardInput: Data?) throws -> ProcessResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = errorPipe

        let inputPipe: Pipe?
        if standardInput != nil {
            let pipe = Pipe()
            process.standardInput = pipe
            inputPipe = pipe
        } else {
            inputPipe = nil
        }

        do {
            try process.run()
        } catch {
            throw UFOError.subprocess("Failed to launch subprocess at \(executable): \(error.localizedDescription)")
        }

        if let payload = standardInput, let inputPipe {
            inputPipe.fileHandleForWriting.write(payload)
            try? inputPipe.fileHandleForWriting.close()
        }

        process.waitUntilExit()

        return ProcessResult(
            exitCode: process.terminationStatus,
            standardOutput: outputPipe.fileHandleForReading.readDataToEndOfFile(),
            standardError: errorPipe.fileHandleForReading.readDataToEndOfFile()
        )
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

    return UFOApplication(
        parser: CommandParser(),
        fileSystem: fileSystem,
        inputReader: StandardInputReader(),
        policy: KeychainProtectionPolicy(fileSystem: fileSystem),
        registryStore: ManagedRegistryStore(fileSystem: fileSystem, clock: clock),
        securityCLI: SecurityCLI(processRunner: SystemProcessRunner()),
        auditLogger: AuditLogger(fileSystem: fileSystem, clock: clock)
    )
}
