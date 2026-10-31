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
