import Foundation
@testable import UFOLib

final class FakeProcessRunner: ProcessRunning {
    struct Invocation: Equatable {
        let executable: String
        let arguments: [String]
        let standardInput: Data?
    }

    var invocations: [Invocation] = []
    var queuedResults: [Result<ProcessResult, Error>] = []

    func enqueueSuccess(
        exitCode: Int32 = 0,
        standardOutput: Data = Data(),
        standardError: Data = Data()
    ) {
        queuedResults.append(.success(ProcessResult(
            exitCode: exitCode,
            standardOutput: standardOutput,
            standardError: standardError
        )))
    }

    func enqueueFailure(_ error: Error) {
        queuedResults.append(.failure(error))
    }

    func run(executable: String, arguments: [String], standardInput: Data?) throws -> ProcessResult {
        invocations.append(
            Invocation(executable: executable, arguments: arguments, standardInput: standardInput)
        )

        guard !queuedResults.isEmpty else {
            return ProcessResult(exitCode: 0, standardOutput: Data(), standardError: Data())
        }

        let next = queuedResults.removeFirst()
        switch next {
        case .success(let result):
            return result
        case .failure(let error):
            throw error
        }
    }
}

final class FakeClock: Clock {
    var currentDate: Date

    init(currentDate: Date) {
        self.currentDate = currentDate
    }

    func now() -> Date {
        currentDate
    }
}

final class FakeInputReader: InputReading {
    var value: String
    var error: Error?

    init(value: String = "", error: Error? = nil) {
        self.value = value
        self.error = error
    }

    func readStandardInput() throws -> String {
        if let error {
            throw error
        }
        return value
    }
}

final class FakeFileSystem: FileSysteming {
    var homeDirectoryPath: String

    var files: [String: Data]
    var directories: Set<String>
    var writableDirectories: Set<String>
    var modificationDates: [String: Date]

    var createDirectoryFailures: Set<String>
    var readFailures: Set<String>
    var readGenericFailures: Set<String>
    var writeFailures: Set<String>
    var appendFailures: Set<String>
    var appendGenericFailures: Set<String>
    var modificationFailures: Set<String>
    var moveFailures: Set<String>
    var removeFailures: Set<String>

    init(homeDirectoryPath: String = "/Users/tester") {
        self.homeDirectoryPath = homeDirectoryPath
        self.files = [:]
        self.directories = ["/", "/Users", homeDirectoryPath]
        self.writableDirectories = ["/", "/Users", homeDirectoryPath]
        self.modificationDates = [:]
        self.createDirectoryFailures = []
        self.readFailures = []
        self.readGenericFailures = []
        self.writeFailures = []
        self.appendFailures = []
        self.appendGenericFailures = []
        self.modificationFailures = []
        self.moveFailures = []
        self.removeFailures = []
    }

    func expandTilde(in path: String) -> String {
        guard path.hasPrefix("~") else {
            return path
        }
        return path.replacingOccurrences(of: "~", with: homeDirectoryPath, options: [], range: path.startIndex..<path.index(after: path.startIndex))
    }

    func canonicalPath(_ path: String) -> String {
        let expanded = expandTilde(in: path)
        let standardized = (expanded as NSString).standardizingPath
        return standardized.isEmpty ? "/" : standardized
    }

    func createDirectory(at path: String) throws {
        let canonical = canonicalPath(path)
        if createDirectoryFailures.contains(canonical) {
            throw UFOError.io("create failed")
        }

        addDirectoryRecursively(canonical)
    }

    func fileExists(at path: String) -> Bool {
        let canonical = canonicalPath(path)
        return files[canonical] != nil || directories.contains(canonical)
    }

    func isWritableDirectory(_ path: String) -> Bool {
        let canonical = canonicalPath(path)
        return directories.contains(canonical) && writableDirectories.contains(canonical)
    }

    func readFile(at path: String) throws -> Data {
        let canonical = canonicalPath(path)
        if readFailures.contains(canonical) {
            throw UFOError.io("read failed")
        }
        if readGenericFailures.contains(canonical) {
            throw GenericReadError()
        }
        guard let data = files[canonical] else {
            throw UFOError.io("missing file")
        }
        return data
    }

    func writeFile(_ data: Data, to path: String) throws {
        let canonical = canonicalPath(path)
        if writeFailures.contains(canonical) {
            throw UFOError.io("write failed")
        }
        let parent = (canonical as NSString).deletingLastPathComponent
        addDirectoryRecursively(parent)
        files[canonical] = data
        modificationDates[canonical] = Date()
    }

    func appendFile(_ data: Data, to path: String) throws {
        let canonical = canonicalPath(path)
        if appendFailures.contains(canonical) {
            throw UFOError.io("append failed")
        }
        if appendGenericFailures.contains(canonical) {
            throw GenericAppendError()
        }
        let parent = (canonical as NSString).deletingLastPathComponent
        addDirectoryRecursively(parent)
        if var existing = files[canonical] {
            existing.append(data)
            files[canonical] = existing
        } else {
            files[canonical] = data
        }
        modificationDates[canonical] = Date()
    }

    func modificationDate(at path: String) throws -> Date {
        let canonical = canonicalPath(path)
        if modificationFailures.contains(canonical) {
            throw UFOError.io("modification failed")
        }
        guard let date = modificationDates[canonical] else {
            throw UFOError.io("missing modification date")
        }
        return date
    }

    func moveItem(at source: String, to destination: String) throws {
        let from = canonicalPath(source)
        let to = canonicalPath(destination)
        if moveFailures.contains(from) || moveFailures.contains(to) {
            throw UFOError.io("move failed")
        }
        let data = files[from]
        files[to] = data
        files[from] = nil
        modificationDates[to] = modificationDates[from]
        modificationDates[from] = nil
        let parent = (to as NSString).deletingLastPathComponent
        addDirectoryRecursively(parent)
    }

    func removeItem(at path: String) throws {
        let canonical = canonicalPath(path)
        if removeFailures.contains(canonical) {
            throw UFOError.io("remove failed")
        }
        files[canonical] = nil
        directories.remove(canonical)
        modificationDates[canonical] = nil
    }

    func writeString(_ value: String, to path: String) {
        let canonical = canonicalPath(path)
        files[canonical] = Data(value.utf8)
        modificationDates[canonical] = Date()
        let parent = (canonical as NSString).deletingLastPathComponent
        addDirectoryRecursively(parent)
    }

    func string(at path: String) -> String {
        let canonical = canonicalPath(path)
        guard let data = files[canonical] else {
            return ""
        }
        return String(decoding: data, as: UTF8.self)
    }

    private func addDirectoryRecursively(_ path: String) {
        let canonical = canonicalPath(path)
        guard !canonical.isEmpty else {
            return
        }
        if directories.contains(canonical) {
            return
        }

        let parent = (canonical as NSString).deletingLastPathComponent
        if parent != canonical {
            addDirectoryRecursively(parent)
        }
        directories.insert(canonical)
        writableDirectories.insert(canonical)
    }
}

struct GenericAppendError: LocalizedError {
    var errorDescription: String? {
        "generic append failure"
    }
}

struct GenericReadError: LocalizedError {
    var errorDescription: String? {
        "generic read failure"
    }
}
