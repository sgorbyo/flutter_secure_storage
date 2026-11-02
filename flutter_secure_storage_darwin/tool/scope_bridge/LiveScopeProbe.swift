// Signed, isolated hardware gate for the production plugin channel.
// Only two synthetic items in a fresh namespace; no iGen storage or server.
import AppKit
import FlutterMacOS
import Foundation
import Security

@main
final class LiveScopeProbe: NSObject, NSApplicationDelegate, NSWindowDelegate {
    private let plugin = FlutterSecureStorageDarwinPlugin()
    private let service = "cloud.igenogram.authscope.channel." + UUID().uuidString
    private let output = NSTextView()
    private var window: NSWindow!
    private var buttons: [NSButton] = []
    private var busy = false
    private var sequence: Int64 = 0
    private var handle: String?
    private var lines: [String] = []
    private var preflight = false
    private let log = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("igen-production-scope-gate.log")
    static func main() {
        let app = NSApplication.shared
        let delegate = LiveScopeProbe(); app.delegate = delegate
        app.setActivationPolicy(.regular); app.run()
    }
    func applicationDidFinishLaunching(_ notification: Notification) {
        let menu = NSMenu(), item = NSMenuItem(), submenu = NSMenu()
        menu.addItem(item); item.submenu = submenu
        submenu.addItem(withTitle: "Nascondi", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        submenu.addItem(withTitle: "Esci", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        NSApp.mainMenu = menu
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 830, height: 580),
                          styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        window.title = "iGen — verifica API Darwin v4"; window.delegate = self
        let stack = NSStackView(); stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false; window.contentView!.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: window.contentView!.leadingAnchor, constant: 20),
            stack.trailingAnchor.constraint(equalTo: window.contentView!.trailingAnchor, constant: -20),
            stack.topAnchor.constraint(equalTo: window.contentView!.topAnchor, constant: 20),
            stack.bottomAnchor.constraint(equalTo: window.contentView!.bottomAnchor, constant: -20)])
        stack.addArrangedSubview(NSTextField(wrappingLabelWithString:
            "Verifica il plugin definitivo attraverso il canale Flutter. Solo due elementi sintetici, rimossi dopo ogni prova. Nessun account o documento iGen.\nOgni pulsante avvia una prova indipendente. Autenticati e conta i prompt. La seconda prova nasconde e ripristina da sola la finestra."))
        for (title, action) in [("1. Verifica sequenza con una autorizzazione", #selector(mixed)),
                                ("2. Verifica revoca al nascondimento", #selector(hidden))] {
            let button = NSButton(title: title, target: self, action: action)
            button.heightAnchor.constraint(greaterThanOrEqualToConstant: 44).isActive = true
            stack.addArrangedSubview(button); buttons.append(button)
        }
        let scroll = NSScrollView(); scroll.hasVerticalScroller = true
        output.isEditable = false; output.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        scroll.documentView = output; stack.addArrangedSubview(scroll)
        scroll.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 300).isActive = true
        preflight = true
        record("ready; protected Keychain creation is checked inside the authenticated trial")
        buttons.forEach { $0.isEnabled = preflight }
        window.center(); window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }
    private func record(_ line: String) {
        lines.append("\(ISO8601DateFormatter().string(from: Date())) \(line)")
        output.string = lines.joined(separator: "\n"); output.scrollToEndOfDocument(nil)
        do { try output.string.write(to: log, atomically: true, encoding: .utf8) }
        catch { output.string += "\nreport.writeFailed" }
    }
    private func call(_ method: String, _ args: [String: Any], then: @escaping (Any?) -> Void) {
        let codec = FlutterStandardMethodCodec.sharedInstance()
        let encoded = codec.encode(FlutterMethodCall(methodName: method, arguments: args))
        plugin.handle(codec.decodeMethodCall(encoded)) { value in then(value) }
    }
    private var options: [String: String] {
        ["accountName": service, "synchronizable": "false", "accessibility": "unlocked_this_device",
         "usesDataProtectionKeychain": "false", "accessControlFlags": "userPresence"]
    }
    private func operation(_ method: String, _ args: [String: Any] = [:], then: @escaping (Any?) -> Void) {
        guard let handle = handle else { finish("FAIL missing handle"); return }
        sequence += 1
        call(method, args.merging(["handle": handle, "ownerEpoch": Int64(0), "sequence": sequence]) { _, new in new }, then: then)
    }
    private func cleanup() -> Bool {
        var okay = true
        for key in ["journal", "copy"] {
            let status = SecItemDelete([kSecClass: kSecClassGenericPassword,
                kSecAttrService: service, kSecAttrAccount: key, kSecAttrSynchronizable: false] as CFDictionary)
            if status != errSecSuccess && status != errSecItemNotFound { okay = false }
        }
        return okay
    }
    @objc private func mixed() { start(hide: false) }
    @objc private func hidden() { start(hide: true) }
    private func start(hide: Bool) {
        guard !busy, preflight else { return }
        busy = true; buttons.forEach { $0.isEnabled = false }
        record(hide ? "hidden.begin" : "mixed.begin")
        guard cleanup() else { finish("FAIL synthetic cleanup"); return }
        let slots: [[String: Any]] = [
            ["key": "journal", "access": ["read", "writeVerified", "createVerified"], "maxReads": 1, "maxWrites": 2],
            ["key": "copy", "access": ["read", "createVerified"], "maxReads": 1, "maxWrites": 1]]
        call("scopeOpen", ["slots": slots, "options": options, "localizedReason": "Verifica sintetica API iGen",
            "lifetimeMilliseconds": 120000, "ownerEpoch": Int64(0), "actionNonce": UUID().uuidString]) { value in
            guard let handle = value as? String else { self.finish("FAIL scopeOpen"); return }
            self.handle = handle; self.sequence = 0
            self.operation("scopeCreateVerified", ["key": "journal", "value": "synthetic journal"]) { value in
                guard value == nil else { self.finish("FAIL protected journal creation"); return }
                self.record("checkpoint.seedCreatedAndVerified")
            self.operation("scopeReadBatch", ["keys": ["journal"]]) { value in
                guard (value as? [String: Any])?["journal"] as? String == "synthetic journal" else {
                    self.finish("FAIL initial protected read"); return
                }
                self.record("checkpoint.read")
                if hide { NSApp.hide(nil) }
                DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                    self.operation("scopeWriteVerified", ["key": "journal", "value": "synthetic updated journal"]) { value in
                        if hide {
                            NSApp.unhide(nil); self.window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
                            self.finish((value as? FlutterError)?.code == "revoked" ? "PASS hidden: write denied" : "FAIL hidden: expected revoked")
                            return
                        }
                        guard value == nil else { self.finish("FAIL verified update"); return }
                        self.record("checkpoint.updated")
                        self.operation("scopeCreateVerified", ["key": "copy", "value": "synthetic copy"]) { value in
                            guard value == nil else { self.finish("FAIL verified create"); return }
                            self.record("checkpoint.created")
                            self.operation("scopeReadBatch", ["keys": ["copy"]]) { value in
                                self.finish((value as? [String: Any])?["copy"] as? String == "synthetic copy" ?
                                    "PASS mixed: protected read/update/create/readback" : "FAIL copy readback")
                            }
                        }
                    }
                }
            }
            }
        }
    }
    private func finish(_ message: String) {
        record(message)
        let done = {
            let cleaned = self.cleanup()
            self.record(cleaned ? "cleanup.passed" : "cleanup.failed")
            self.busy = false; self.buttons.forEach { $0.isEnabled = self.preflight && cleaned }
        }
        if let handle = handle {
            self.handle = nil
            call("scopeClose", ["handle": handle, "ownerEpoch": Int64(0)]) { _ in done() }
        } else { done() }
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func windowShouldClose(_ sender: NSWindow) -> Bool { !busy && cleanup() }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        busy || !cleanup() ? .terminateCancel : .terminateNow
    }
}
