import Darwin
import Foundation
import HYUVPNMenuAppSupport

let status = CredentialReaderCommand.run(
    arguments: Array(CommandLine.arguments.dropFirst()),
    store: EncryptedCredentialStore()
) { value in
    FileHandle.standardOutput.write(Data(value.utf8))
}
exit(status)
