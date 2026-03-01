import Foundation

public final class AuditLogger {
    private let fileSystem: FileSysteming
    private let clock: Clock
    private let primaryDirectory: String
    private let fallbackDirectory: String
    private let rotationIntervalDays: Int

    public private(set) var lastError: String?

    public init(
        fileSystem: FileSysteming,
        clock: Clock,
        primaryDirectory: String = "/var/log/ufo",
        fallbackDirectory: String? = nil,
        rotationIntervalDays: Int = 30
    ) {
        self.fileSystem = fileSystem
        self.clock = clock
        self.primaryDirectory = fileSystem.canonicalPath(primaryDirectory)
        let fallback = fallbackDirectory ?? "\(fileSystem.homeDirectoryPath)/Library/Logs/ufo"
        self.fallbackDirectory = fileSystem.canonicalPath(fallback)
        self.rotationIntervalDays = rotationIntervalDays
    }

    public func health() -> AuditHealth {
        let resolution = resolveDirectory()
        let logPath = fileSystem.canonicalPath("\(resolution.directory)/ufo.log")
        return AuditHealth(
            activeLogPath: logPath,
            usingFallbackDirectory: resolution.usingFallback,
            writable: resolution.writable,
            lastError: lastError
        )
    }

    public func log(event: String, outcome: String, metadata: [String: String] = [:]) {
        let resolution = resolveDirectory()
        guard resolution.writable else {
            lastError = "Audit log directory is not writable."
            return
        }

        let logPath = fileSystem.canonicalPath("\(resolution.directory)/ufo.log")

        do {
            try rotateIfNeeded(logPath: logPath)

            let payload: [String: Any] = [
                "timestamp": iso8601(clock.now()),
                "event": event,
                "outcome": outcome,
                "metadata": sanitize(metadata: metadata)
            ]

            let data = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
            var line = data
            line.append(Data("\n".utf8))
            try fileSystem.appendFile(line, to: logPath)
        } catch {
            if let ufoError = error as? UFOError {
                lastError = ufoError.message
            } else {
                lastError = error.localizedDescription
            }
        }
    }

    private func resolveDirectory() -> (directory: String, usingFallback: Bool, writable: Bool) {
        if canUse(directory: primaryDirectory) {
            return (primaryDirectory, false, true)
        }

        if canUse(directory: fallbackDirectory) {
            return (fallbackDirectory, true, true)
        }

        return (fallbackDirectory, true, false)
    }

    private func canUse(directory: String) -> Bool {
        do {
            try fileSystem.createDirectory(at: directory)
            return fileSystem.isWritableDirectory(directory)
        } catch {
            return false
        }
    }

    private func rotateIfNeeded(logPath: String) throws {
        guard fileSystem.fileExists(at: logPath) else {
            return
        }

        let modifiedAt = try fileSystem.modificationDate(at: logPath)
        let maxAge = Double(rotationIntervalDays) * 24 * 60 * 60
        guard clock.now().timeIntervalSince(modifiedAt) >= maxAge else {
            return
        }

        let directory = (logPath as NSString).deletingLastPathComponent
        let stamp = timestampForFilename(clock.now())
        let rotatedPath = fileSystem.canonicalPath("\(directory)/ufo-\(stamp).log")
        try fileSystem.moveItem(at: logPath, to: rotatedPath)
    }

    private func sanitize(metadata: [String: String]) -> [String: String] {
        var result: [String: String] = [:]
        let sensitiveTokens = ["secret", "value", "password", "token"]

        for (key, value) in metadata {
            let lowerKey = key.lowercased()
            if sensitiveTokens.contains(where: { lowerKey.contains($0) }) {
                result[key] = "<redacted>"
            } else {
                result[key] = value.replacingOccurrences(of: "\n", with: " ")
            }
        }

        return result
    }

    private func iso8601(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        return formatter.string(from: date)
    }

    private func timestampForFilename(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyyMMddHHmmss"
        return formatter.string(from: date)
    }
}
