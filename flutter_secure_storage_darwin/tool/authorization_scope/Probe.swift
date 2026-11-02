import AppKit
import Foundation
import LocalAuthentication
import Security

private final class ObservedAuthentication: VerifiedAuthentication {
    var evaluations = 0
    let record: (String) -> Void
    init(record: @escaping (String) -> Void) { self.record = record }
    func authorize(_ context: LAContext, accessControl: SecAccessControl, reason: String) -> OSStatus {
        evaluations += 1; record("authorization.begin")
        let status = SystemVerifiedAuthentication().authorize(context, accessControl: accessControl, reason: reason)
        record("authorization.end status=\(status)")
        return status
    }
}

@main
private final class Probe: NSObject, NSApplicationDelegate, NSWindowDelegate {
    private var window: NSWindow!
    private let output = NSTextView()
    private let contexts = VerifiedWriteContexts()
    private let worker = DispatchQueue(label: "auth-scope-probe")
    private var busy = false
    private var ready = false
    private var needsCleanup = false
    private var buttons = [NSButton]()
    // Only these two synthetic accounts in this random service may be touched.
    private let service = "cloud.igenogram.authscope.probe." + UUID().uuidString
    private var observers = [(NotificationCenter, NSObjectProtocol)]()
    private var lines = [String]()
    private var generation = 0

    static func main() {
        let app = NSApplication.shared
        let delegate = Probe(); app.delegate = delegate
        app.setActivationPolicy(.regular); app.run()
    }
    func applicationDidFinishLaunching(_ notification: Notification) {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 800, height: 650),
            styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.delegate = self
        window.title = "iGen — laboratorio autorizzazioni sintetiche"
        let stack = NSStackView(); stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 8
        stack.translatesAutoresizingMaskIntoConstraints = false
        window.contentView!.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: window.contentView!.leadingAnchor, constant: 16),
            stack.trailingAnchor.constraint(equalTo: window.contentView!.trailingAnchor, constant: -16),
            stack.topAnchor.constraint(equalTo: window.contentView!.topAnchor, constant: 16),
            stack.bottomAnchor.constraint(equalTo: window.contentView!.bottomAnchor, constant: -16)])
        let description = NSTextField(wrappingLabelWithString: "Solo due elementi Keychain sintetici. Nessun account, documento o server iGen.\nAvvio senza autenticazione. Inizia da Prepara; conta i pannelli del sistema.\nLa prova mista attende 3 secondi tra lettura e scrittura. Puoi revocarla o nascondere l’app.\nPer Timeout lascia il pannello aperto senza approvare. Pulisci prima di chiudere.")
        stack.addArrangedSubview(description)
        for (title, action) in [("1. Prepara elemento sintetico", #selector(setup)),
                                ("2. Prova lettura → aggiornamento → creazione → rilettura", #selector(mixed)),
                                ("3. Timeout del prompt dopo 4 secondi", #selector(timeout)),
                                ("Revoca operazione attiva", #selector(revoke)),
                                ("Pulisci soltanto i due elementi sintetici", #selector(cleanup)),
                                ("Salva resoconto…", #selector(exportReport))] {
            let button = NSButton(title: title, target: self, action: action)
            button.heightAnchor.constraint(greaterThanOrEqualToConstant: 44).isActive = true
            stack.addArrangedSubview(button); buttons.append(button)
        }
        let scroll = NSScrollView(); scroll.hasVerticalScroller = true
        output.isEditable = false; output.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        scroll.documentView = output; stack.addArrangedSubview(scroll)
        scroll.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 160).isActive = true
        observe(.default, NSApplication.didHideNotification, "hidden", suspend: true)
        observe(.default, NSApplication.didUnhideNotification, "hidden", suspend: false)
        observe(NSWorkspace.shared.notificationCenter, NSWorkspace.willSleepNotification, "sleep", suspend: true)
        observe(NSWorkspace.shared.notificationCenter, NSWorkspace.didWakeNotification, "sleep", suspend: false)
        observe(NSWorkspace.shared.notificationCenter, NSWorkspace.sessionDidResignActiveNotification, "session", suspend: true)
        observe(NSWorkspace.shared.notificationCenter, NSWorkspace.sessionDidBecomeActiveNotification, "session", suspend: false)
        window.center(); window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true); record("probe.ready; physical prompt count must be observed")
        updateButtons()
    }
    private func observe(_ center: NotificationCenter, _ name: Notification.Name, _ reason: String, suspend: Bool) {
        let token = center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
            guard let self = self else { return }
            if suspend { self.generation += 1; self.contexts.cancel(suspending: reason) }
            else { self.contexts.resume(reason) }
            self.record("lifecycle.\(reason).\(suspend ? "revoke" : "resume")")
        }
        observers.append((center, token))
    }
    private func record(_ value: String) {
        if !Thread.isMainThread { DispatchQueue.main.async { self.record(value) }; return }
        lines.append("\(ISO8601DateFormatter().string(from: Date())) \(value)")
        output.string = lines.joined(separator: "\n")
        output.scrollToEndOfDocument(nil)
    }
    private func updateButtons() {
        for (index, button) in buttons.enumerated() {
            button.isEnabled = index == 3 ? busy : !busy && (index != 1 && index != 2 || ready)
        }
    }
    @objc private func setup() { run("setup", timeout: 120) { scope in
        scope.writeVerified("journal", value: "synthetic journal")
    } }
    @objc private func mixed() { run("mixed", timeout: 120) { scope in
        let first = scope.read("journal")
        guard first.0 == errSecSuccess, first.1 != nil else { return first.0 == errSecSuccess ? errSecDecode : first.0 }
        self.record("checkpoint.read; delay.begin")
        Thread.sleep(forTimeInterval: 3)
        self.record("delay.end")
        var status = scope.writeVerified("journal", value: "synthetic updated journal")
        guard status == errSecSuccess else { return status }
        self.record("checkpoint.updated")
        status = scope.writeVerified("copy", value: "synthetic copy")
        guard status == errSecSuccess else { return status }
        self.record("checkpoint.copyWritten")
        let result = scope.read("copy")
        return result.0 == errSecSuccess && result.1 != "synthetic copy" ? errSecDecode : result.0
    } }
    @objc private func timeout() { run("timeout", timeout: 4) { scope in scope.read("journal").0 } }
    @objc private func revoke() {
        generation += 1; contexts.cancel(); record("explicit.revoke")
    }
    private func run(_ phase: String, timeout: TimeInterval, body: @escaping (AuthorizationScope) -> OSStatus) {
        guard !busy else { return }; busy = true; updateButtons()
        let token = generation
        if phase == "setup" || phase == "mixed" { needsCleanup = true }
        record("\(phase).begin")
        worker.async {
            let auth = ObservedAuthentication(record: self.record)
            let params = KeychainQueryParameters(service: self.service, isSynchronizable: false,
                accessibilityLevel: "unlocked_this_device", usesDataProtectionKeychain: false,
                accessControlFlags: "userPresence", useSecureEnclave: false)
            guard let scope = AuthorizationScope(contexts: self.contexts, params: params,
                plan: ["journal": [.read, .writeVerified], "copy": [.read, .writeVerified]],
                reason: "Prova sintetica iGen: \(phase)", timeout: timeout, authentication: auth) else {
                DispatchQueue.main.async { self.record("\(phase).scopeUnavailable"); self.busy = false; self.updateButtons() }; return
            }
            let status = body(scope)
            let valid = scope.isValid
            scope.close()
            DispatchQueue.main.async {
                let current = token == self.generation
                self.record("\(phase).end status=\(status) evaluations=\(auth.evaluations) validBeforeClose=\(valid) current=\(current)")
                if phase == "setup", status == errSecSuccess, current, valid { self.ready = true }
                self.busy = false; self.updateButtons()
            }
        }
    }
    @objc private func cleanup() {
        guard !busy else { return }
        contexts.cancel(); ready = false
        var cleaned = true
        for key in ["journal", "copy"] {
            let query: [CFString: Any] = [kSecClass: kSecClassGenericPassword,
                kSecAttrService: service, kSecAttrAccount: key,
                kSecAttrSynchronizable: false, kSecUseDataProtectionKeychain: false]
            let status = SecItemDelete(query as CFDictionary)
            record("cleanup.item status=\(status)")
            if status != errSecSuccess && status != errSecItemNotFound { cleaned = false }
        }
        needsCleanup = !cleaned
        updateButtons()
    }
    @objc private func exportReport() {
        let panel = NSSavePanel(); panel.nameFieldStringValue = "auth-scope-report.txt"
        panel.beginSheetModal(for: window) { response in
            guard response == .OK, let url = panel.url else { return }
            do { try self.lines.joined(separator: "\n").write(to: url, atomically: true, encoding: .utf8) }
            catch { self.record("report.writeFailed") }
        }
    }
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        applicationShouldTerminate(NSApp) == .terminateNow
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        contexts.cancel()
        if needsCleanup || busy {
            let alert = NSAlert(); alert.messageText = "Pulisci gli elementi sintetici prima di uscire"
            alert.informativeText = "Torna alla finestra, attendi la fine dell’operazione e usa Pulisci."
            alert.addButton(withTitle: "Torna alla prova")
            alert.runModal(); return .terminateCancel
        }
        return .terminateNow
    }
}
