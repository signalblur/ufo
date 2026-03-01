import Foundation

public protocol ProcessRunning {
    func run(
        executable: String,
        arguments: [String],
        standardInput: Data?,
        timeout: TimeInterval
    ) throws -> ProcessResult
}

public protocol FileSysteming {
    var homeDirectoryPath: String { get }
    func expandTilde(in path: String) -> String
    func canonicalPath(_ path: String) -> String
    func createDirectory(at path: String) throws
    func fileExists(at path: String) -> Bool
    func isWritableDirectory(_ path: String) -> Bool
    func readFile(at path: String) throws -> Data
    func writeFile(_ data: Data, to path: String) throws
    func appendFile(_ data: Data, to path: String) throws
    func modificationDate(at path: String) throws -> Date
    func moveItem(at source: String, to destination: String) throws
    func removeItem(at path: String) throws
}

public protocol Clock {
    func now() -> Date
}

public protocol InputReading {
    func readStandardInput() throws -> String
}
