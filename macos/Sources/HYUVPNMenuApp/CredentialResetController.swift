import AppKit
import HYUVPNMenuCore

@MainActor
package final class CredentialResetController: NSObject, NSWindowDelegate {
    package typealias Completion = (CredentialResetController, ValidatedCredentials?) -> Void

    private let completion: Completion
    fileprivate var window: NSWindow?
    fileprivate let idField = NSTextField(string: "")
    fileprivate let firstSecretField = NSSecureTextField(string: "")
    fileprivate let firstSecretConfirmationField = NSSecureTextField(string: "")
    fileprivate let secondSecretField = NSSecureTextField(string: "")
    fileprivate let secondSecretConfirmationField = NSSecureTextField(string: "")
    fileprivate let validationMessage = NSTextField(labelWithString: " ")

    package init(prefillUsername: String?, completion: @escaping Completion) {
        self.completion = completion
        super.init()
        idField.stringValue = prefillUsername ?? ""
    }

    package func present() {
        let resetWindow = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 430, height: 270), styleMask: [.titled, .closable], backing: .buffered, defer: false)
        resetWindow.title = "Reset Login Information"
        resetWindow.delegate = self
        resetWindow.contentView = makeContentView()
        window = resetWindow
        resetWindow.center()
        resetWindow.makeKeyAndOrderFront(nil)
    }

    package func dismissWithoutSaving() {
        finish(with: nil)
    }

    package func windowWillClose(_ notification: Notification) {
        finish(with: nil)
    }

    private func makeContentView() -> NSView {
        let content = NSView(frame: NSRect(x: 0, y: 0, width: 430, height: 270))
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 10
        stack.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(stack)

        stack.addArrangedSubview(row(label: "HYU ID", field: idField))
        stack.addArrangedSubview(row(label: "Password", field: firstSecretField))
        stack.addArrangedSubview(row(label: "Confirm Password", field: firstSecretConfirmationField))
        stack.addArrangedSubview(row(label: "TOTP Setup Secret", field: secondSecretField))
        stack.addArrangedSubview(row(label: "Confirm TOTP Secret", field: secondSecretConfirmationField))

        validationMessage.textColor = .systemRed
        validationMessage.lineBreakMode = .byWordWrapping
        validationMessage.maximumNumberOfLines = 2
        validationMessage.translatesAutoresizingMaskIntoConstraints = false
        stack.addArrangedSubview(validationMessage)

        let buttons = NSStackView()
        buttons.orientation = .horizontal
        buttons.alignment = .centerY
        buttons.spacing = 12
        let cancel = NSButton(title: "Cancel", target: self, action: #selector(cancelPressed))
        let save = NSButton(title: "Save", target: self, action: #selector(savePressed))
        save.keyEquivalent = "\r"
        buttons.addArrangedSubview(cancel)
        buttons.addArrangedSubview(save)
        stack.addArrangedSubview(buttons)

        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            stack.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),
            stack.topAnchor.constraint(equalTo: content.topAnchor, constant: 20),
            stack.bottomAnchor.constraint(lessThanOrEqualTo: content.bottomAnchor, constant: -20),
            validationMessage.widthAnchor.constraint(equalToConstant: 390)
        ])
        return content
    }

    private func row(label: String, field: NSTextField) -> NSView {
        let row = NSStackView()
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 12
        let labelView = NSTextField(labelWithString: label)
        labelView.widthAnchor.constraint(equalToConstant: 145).isActive = true
        field.widthAnchor.constraint(equalToConstant: 230).isActive = true
        row.addArrangedSubview(labelView)
        row.addArrangedSubview(field)
        return row
    }

    @objc fileprivate func cancelPressed() {
        finish(with: nil)
    }

    @objc fileprivate func savePressed() {
        do {
            let input = CredentialResetInput(
                username: idField.stringValue,
                password: firstSecretField.stringValue,
                passwordConfirmation: firstSecretConfirmationField.stringValue,
                totpSeed: secondSecretField.stringValue,
                totpSeedConfirmation: secondSecretConfirmationField.stringValue
            )
            let validated = try CredentialValidator.validate(input)
            finish(with: validated)
        } catch let error as CredentialValidationError {
            validationMessage.stringValue = validationCopy(for: error)
        } catch {
            validationMessage.stringValue = "Unable to validate login information."
        }
    }

    private func validationCopy(for error: CredentialValidationError) -> String {
        switch error {
        case .usernameRequired: return "Enter your HYU ID."
        case .usernameTooLong, .usernameContainsControlCharacter: return "Use a valid HYU ID."
        case .passwordRequired: return "Enter a password."
        case .passwordTooLong, .passwordContainsDisallowedCharacter: return "Use a valid password."
        case .passwordMismatch: return "Passwords do not match."
        case .totpSeedRequired: return "Enter the TOTP setup secret in both fields, or leave both blank to retain it."
        case .totpSeedMismatch: return "TOTP setup secrets do not match."
        case .totpSeedInvalidAlphabetOrPadding, .totpSeedTooShort, .totpSeedTooLong, .totpSeedLooksLikeOneTimeCode:
            return "Use a valid TOTP setup secret, not a one-time code."
        }
    }

    fileprivate func finish(with value: ValidatedCredentials?) {
        guard let resetWindow = window else { return }
        window = nil
        idField.stringValue = ""
        firstSecretField.stringValue = ""
        firstSecretConfirmationField.stringValue = ""
        secondSecretField.stringValue = ""
        secondSecretConfirmationField.stringValue = ""
        validationMessage.stringValue = " "
        if let sheetParent = resetWindow.sheetParent {
            sheetParent.endSheet(resetWindow)
        } else {
            resetWindow.close()
        }
        completion(self, value)
    }

    package var harnessWindow: NSWindow? { window }
    package var harnessValidationMessage: String { validationMessage.stringValue }
    package var harnessInputFields: [NSTextField] { [idField, firstSecretField, firstSecretConfirmationField, secondSecretField, secondSecretConfirmationField] }
    package var harnessFieldValues: [String] { harnessInputFields.map(\.stringValue) + [validationMessage.stringValue] }

    package func harnessSetValues(first: String, firstConfirmation: String, second: String, secondConfirmation: String) {
        firstSecretField.stringValue = first
        firstSecretConfirmationField.stringValue = firstConfirmation
        secondSecretField.stringValue = second
        secondSecretConfirmationField.stringValue = secondConfirmation
    }

    package func harnessSubmit() { savePressed() }
    package func harnessCancel() { cancelPressed() }
}
