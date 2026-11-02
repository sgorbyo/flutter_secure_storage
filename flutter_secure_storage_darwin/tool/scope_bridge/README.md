# Production scope channel gates

These tools compile the **production** `FlutterSecureStorageDarwinPlugin` and
use Flutter's standard method codec. They do not start a Dart engine or iGen.
The ordinary Swift unit suite tests the scope and engine registry separately;
Dart tests cover serialization, queue cancellation and normalized errors.

`ScopeBridgeChecks.swift` exercises the actual native method handler without
Keychain operations: open/busy/check, an unknown handle, out-of-plan rejection,
close, owner-epoch revocation and hide notification. Compile it with every Swift
file in `darwin/.../Sources/flutter_secure_storage_darwin`, the installed
FlutterMacOS framework, and an rpath to that framework. Run it with stdout and
stderr preserved in a temporary log. Its notification test is synthetic, not
proof of an OS lifecycle transition.

`build_live_probe.py --identity CERT_SHA1 --profile PROFILE_PATH
--flutter-frameworks FRAMEWORK_PARENT` builds a separately signed, native macOS
14+ diagnostic app, verifies its signature. Protected Keychain creation is verified inside
each authenticated trial, not by a preliminary noninteractive add (which may
return interactionNotAllowed depending on device state). It neither launches the UI nor installs certificates/profiles. It
uses the existing lab bundle/group `cloud.igenogram.authscope.lab`, a random
service per process and only synthetic journal/copy items. The installed Flutter
framework is a build/runtime dependency; this is not a redistributable app.

The window is titled **iGen — verifica API Darwin v4**. Each button prepares its
own synthetic items and cleans both afterward:

1. Authenticate once: add-only journal creation and readback, protected read, three-second pause, verified update,
   add-only creation and protected readback must succeed. Count OS prompts.
2. Authenticate once: add-only journal creation and readback, protected read, real app hide, three-second pause, then
   a write must return `revoked`. The app restores its window without prompting.

The report is `igen-production-scope-gate.log` in the system temporary directory.
It contains phases and normalized outcomes, not keys, values or account data.
Do not infer iGen end-to-end, iOS hardware or Dart lifecycle correctness from
these two native tests. No server or existing iGen data is accessed.
