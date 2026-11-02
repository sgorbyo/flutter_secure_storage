# Native authorization scope experiment

Development tooling only. No Flutter plugin API or runtime behavior is changed.
The test target compiles AuthorizationScope against the real internal storage
implementation. The standalone macOS probe compiles the same sources directly.

Run `swift test --disable-sandbox` from this package with full output retained.
LocalAuthentication needs access to its system service even for LAContext flags;
a restricted host sandbox can cause false failures. Never interpret a mock
success as a measured OS prompt count.

Run `python3 tool/authorization_scope/build_probe.py --identity CERT_SHA1 --profile PROFILE_PATH`
to build an Apple Development signed standalone arm64 macOS 14+ diagnostic app
in a fresh temporary directory. Supply an existing profile permitting
`cloud.igenogram.authscope.lab`; the script never registers identifiers or
changes Apple account settings. It embeds that profile and grants only its own
Keychain group, with no App Group or production/acceptance bundle identity.
An ad-hoc signature is insufficient: the initial physical attempt authenticated
successfully but storage then failed with errSecMissingEntitlement (-34018). It does not load Flutter,
read accounts, call a backend or open any existing archive. Only two fixed
synthetic item names in a new random Keychain service per process are accessed
by interactive trials. An additional transient canary in its own random
service is created/deleted by the noninteractive native preflight.
The probe is unsandboxed diagnostic tooling, not a distribution artifact; its
results do not replace verification inside the signed Flutter application.

Before reporting a build ready, the script runs its signed executable with
`--preflight`: create a userPresence canary, verify that a fresh context with
interaction disabled cannot read it, then delete precisely that canary. The
same gate runs at GUI startup; preparation stays disabled if it fails. No
biometric evaluation is performed by this gate. Its queries include the same
SecAccessControl as the storage component so they target the same native path.

## Physical gate

1. Launch: no prompt expected. Press Prepare and approve the OS prompt. This
   creates and reads back only the synthetic journal with userPresence.
2. Press the mixed-operation button: approve once, then observe read, a
   three-second delay, update/readback, creation/readback and a final read.
   Expected success and one explicit authorization evaluation. Record actual
   panel count independently. On repeat, copy already exists, so use Cleanup
   and Prepare again when testing *creation* rather than update.
3. Use the mixed action with cancellation, hide or sleep during the delay;
   verify that the operation does not report a current successful result.
4. Timeout: leave the prompt unapproved. At four seconds the independent timer
   invalidates its context. Expect cancellation, no automatic retry. A prompt
   manually approved first is not a timeout test.
5. Retry explicitly with the mixed button. It must use a fresh authorization.
6. Save the phase/status-only report if needed, then Cleanup before quitting.
   Cleanup deletes exactly the two synthetic items in this process's service.
   Quit is blocked while work or cleanup is pending. A forced kill may leave
   harmless synthetic items; the probe does not enumerate Keychain to recover
   them and must not be used to clean any other namespace.

The production boundary is not validated yet: Flutter event delivery, owner
changes, post-logout cleanup, actual workflows, iOS hardware, Android and Windows
remain outside this experiment. The scope's options are immutable, access is
allowlisted, calls are serialized, one context is active per manager, and its
independent monotonic deadline includes idle/network time. Revocation cannot
roll back writes or retrieve values already delivered. No polling or implicit
reauthentication is performed. Constants (32 slots, 64 calls, <=120 seconds) are
experimental bounds, not a validated workload policy.
