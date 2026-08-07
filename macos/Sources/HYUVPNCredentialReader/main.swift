import Darwin
import Foundation
import HYUVPNMenuAppSupport

let status = CredentialReaderCommand.run(
    arguments: Array(CommandLine.arguments.dropFirst()),
    store: KeychainCredentialStore()
) { value in
    FileHandle.standardOutput.write(Data(value.utf8))
}
exit(status)
