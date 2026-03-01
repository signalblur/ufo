import Foundation
import UFOLib

let result = buildApplication().run(arguments: Array(CommandLine.arguments.dropFirst()))

func emit(_ text: String, to handle: FileHandle) {
    guard !text.isEmpty else {
        return
    }

    let suffix = text.hasSuffix("\n") ? "" : "\n"
    if let data = "\(text)\(suffix)".data(using: .utf8) {
        handle.write(data)
    }
}

emit(result.standardOutput, to: FileHandle.standardOutput)
emit(result.standardError, to: FileHandle.standardError)
exit(result.exitCode)
