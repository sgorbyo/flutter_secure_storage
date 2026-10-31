# Apple verified-write prototype

Owner-authorized fork of juliansteenbakker/flutter_secure_storage, BSD-3-Clause.
Base: tag v10.3.1, commit 3fc4c53ecffd7bc1f977bc5d76f0f3fb33eb3228 (Darwin 0.3.2).
Only the Darwin package changes. Preserve the original LICENSE and attribution.
Upstream develop is already newer; do not silently combine its major-version
changes with this prototype. Rebase/cherry-pick deliberately after regression
and native compatibility tests. Consumers must pin a published commit SHA.

## Contract

`DarwinVerifiedStorage.writeAndVerify(key:, value:, options:)` uses the existing
channel and storage options, a fresh LAContext, an in-place update (or add only
on item-not-found), and a real byte-for-byte readback. It does not delete on
failure, cache values, change protection attributes, or use a time-based reuse
window. The context is invalidated on exit and is never shared across calls.
Existing APIs are unchanged. Secure Enclave is rejected, not silently emulated.

`cancelPendingWrites()` cancels active and already queued calls on this engine.
Call it on app lock/logout. Protected-data unavailability, iOS background, macOS
sleep and session switch also cancel and suspend the new operations. Mere focus
loss does not cancel, because native authentication itself can change focus.
A late result after cancellation is not reported as success. A failure may
follow a committed Keychain write; retry with the same intended value. There is
no transactional rollback claim and no cross-item transaction.

First consumer: iGen's deletion journal, currently write + read verification.
Do not append an independent protected read after this verified operation and
expect the same prompt count. Its readback is already native and real.
The application still needs an explicit, tested domain integration; this fork
alone does not change iGen's behavior. Missing native API must fail closed.

## Verification

- `flutter pub get`; `dart analyze lib test`; `flutter test` in this package.
- `swift test` here compiles the native core with injected Keychain operations.
- Compile the entire plugin against Flutter and the iOS/macOS SDKs.
- Native canary: old API creates a synthetic item; new API updates/verifies it;
  old API reads it again. Verify prompt count, denial/retry, next-action fresh
  authentication, lock/background and crash/restart. Never use existing user
  items for this test. Repeat on physical Mac and iPhone; simulator tests do not
  certify biometric behavior.

No Cloud schema, Local ObjectBox schema, encrypted payload format, or Keychain
identifier migration. Old and new methods must interoperate on the same canary.
An app downgrade retains the existing storage representation; cancellation can
leave a successfully written value, as with ordinary write + verification.

Current status: prototype; Dart/native unit checks are recorded by the consumer
acceptance report. Physical-device prompt and lifecycle acceptance are required
before production integration. No blanket promise of one prompt on every OS.

Apple contract references:
- https://developer.apple.com/documentation/security/ksecuseauthenticationcontext
- https://developer.apple.com/documentation/localauthentication/lacontext/invalidate()

## First physical macOS observation (2026-10-31)

Code commit 3f065aed4a9275a2bafe7f57e7fdf6e118b114a4, isolated signed consumer.
An existing synthetic item created by the old implementation remained readable
through the ordinary API. Two separate verified updates each required one Touch
ID, compared with three for ordinary write plus readback in the baseline probe.
A third verified update was cancelled by the user: errSecUserCanceled (-128),
followed by a successful ordinary read of the original value. Every ordinary
read also required one prompt. Counts were supplied by the device owner; phase
completion and native cancellation status were checked against the probe log.

Scope: the same value was rewritten. Different-value update, new-item creation,
programmatic cancellation/retry, native lifecycle/crash tests and physical iOS
acceptance remain pending. These observations do not certify production readiness.
Local verification: 13 Swift tests, 4 Dart tests, clean Dart analyzer, whole-plugin
iOS and macOS typechecks, and signed macOS consumer build succeeded. Remote CI
run 41234415479 was cancelled; do not interpret it as passing.

## Extended physical macOS acceptance (2026-10-31)

Same native code commit, new synthetic fixture. New-item creation and a real
payload change (different contents, length and Unicode) succeeded with one Touch
ID each. Ordinary-API readbacks matched. Following a system sleep/wake cycle,
the pre-interruption payload was preserved, retry with a new payload succeeded,
and ordinary read after quitting/relaunching the app matched the retry payload.
Each of these reads and the retry required one Touch ID. Existing user archive
inventories/hashes were unchanged.

**Open defect: pending native prompt is not dismissed automatically on sleep.**
The power log confirms actual sleep at 22:21:58 +0100 and wake at 22:22:44 +0100.
The prompt remained pending until the owner pressed Cancel. The call then
returned `Verified write cancelled`, establishing logical invalidation but not
prompt dismissal. The exact native cancellation failure is not yet isolated.
Do not claim the sleep cancellation requirement passes merely because the probe
advanced after manual cancellation. No production integration until corrected
and re-tested. Physical iOS and abrupt-process-interruption acceptance remain
outstanding; this run tested orderly application restart, not an OS reboot.

## Sleep prompt correction under native validation

The verified operation now explicitly evaluates its requested SecAccessControl
with `LAContext.evaluateAccessControl(.useItem)` on the same scoped context.
Subsequent Keychain operations have `interactionNotAllowed = true`: the actual
stored ACL still applies, and insufficient authorization fails closed without
opening a separate Keychain-owned prompt. There is no weaker fallback. A new
required `localizedReason` argument supplies the application's prompt purpose.
Noninteractive/skip UI options are rejected before prompting or mutation.

This addresses ownership of the pending evaluation; logical invalidation alone
had not dismissed the previous Keychain-owned prompt. Existing ordinary APIs,
ACLs, item identifiers and payload formats are unchanged. Native automatic
cancellation and sleep/wake must pass before claiming the defect corrected.
Apple reference: https://developer.apple.com/documentation/localauthentication/lacontext/evaluateaccesscontrol(_:operation:localizedreason:reply:)

The new API rejects any explicit legacy authenticationUIBehavior option; leave
it absent. Prompt control uses LAContext exclusively, avoiding deprecated UI
constants and ambiguous legacy allow/skip behavior. Ordinary APIs are unchanged.

## Corrected prompt: physical macOS acceptance (2026-10-31)

Code commit 6d4de3886c53da84870663b6e7d52e5720b366df, isolated signed consumer,
new synthetic fixture. Owner-confirmed automatic prompt dismissal in both:

- Programmatic cancel four seconds after starting authentication, without
  authenticating or pressing Cancel; native operation returns revoked.
- Standby requested with authentication pending, without manual interaction;
  prompt dismissed automatically. OS power log confirms sleep at 22:35:13 +0100
  and wake at 22:36:24 +0100. Cancellation was delivered at the sleep request,
  before actual system sleep, as intended.

The previous value was preserved. Retry with a different Unicode payload and
ordinary-API readback passed. Orderly app restart (boot 1 -> 2) preserved that
payload. Creation, retry, and each ordinary read required one fresh Touch ID.
All existing archive inventories and file hashes remained unchanged.

The earlier sleep-prompt defect is resolved for these observed Mac scenarios.
17 native unit tests and 4 Dart channel tests pass; Dart analysis is clean.
The exact revision also typechecks against iOS, but physical iOS, abrupt-process
interruption and application workflow integration remain outstanding. This is
not a global Apple acceptance or a production deployment assertion.

## iOS scene lifecycle correction (2026-10-31)

Physical iPad testing passed five journal writes (one authentication each),
explicit lock/logout revocation and unchanged-value readbacks, but background
acceptance failed in a UIScene-based consumer. The plugin registered only legacy
UIApplicationDelegate background/foreground callbacks; Flutter's scene lifecycle
does not forward those UI callbacks. The correction observes UIApplication's
aggregate background/foreground notifications, compatible with both scene and
legacy lifecycles and without raising the minimum Flutter API requirement.
It does not cancel on inactive/focus loss, which native authentication itself
can cause. Notification subscriptions are removed with the plugin; foreground
does not override a separate protected-data suspension. Physical retest pending.

References: https://docs.flutter.dev/release/breaking-changes/uiscenedelegate
and https://developer.apple.com/documentation/uikit/uiapplicationdelegate/applicationdidenterbackground(_:)

## Physical iPad acceptance and status qualification (2026-10-31)

Isolated iPad Pro 11-inch (2nd generation), iOS 26.6. On 6d4de, five real
consumer journal writes each required one authentication; explicit app-lock
and logout revocations dismissed the prompt, rejected stale actions and
preserved the old record. Ordinary readbacks required one authentication.

On code commit 1da2d3ce762cf51f8e70789b4d2dd81c6edd5658, background instrumentation
recorded errSecUserCanceled (-128) BEFORE the application's paused event. iOS
can cancel LocalAuthentication before UIKit background notification delivery;
the existing response adapter exposes -128 as `Unexpected security result code`.
Do not require the generation-specific text `Verified write cancelled` as the
only valid cancellation outcome. Do not accept arbitrary errors as cancellation.
The corrected development probe required both the exact cancellation status
and an actual paused event, then verified byte-equivalent old data after return.
This physical run does not demonstrate an active prompt surviving until the
fork's background notification callback: the OS cancelled it earlier.

A changed-payload retry and ordinary read after terminating/relaunching only the
probe (boot 3 -> 4) succeeded, each with one fresh authentication. 20 Swift tests,
4 Dart tests, whole-plugin iOS typecheck and clean analyzer pass; 36 consumer
regression tests and its analyzer pass. The earlier rejected background trials
remain recorded as failed instrumentation attempts, not retroactive successes.

No production user item or archive was accessed, no Cloud operation performed,
and no store release made. This does not certify physical device lock, reboot,
or the complete server-backed C04 workflow. Mac physical evidence still refers
to 6d4de; the new observer wiring is compiled only for iOS.
