import 'package:flutter/services.dart';

/// Apple-only, bounded write with a native Keychain readback.
///
/// Pass the same IOSOptions/MacOsOptions.toMap() as ordinary storage calls.
/// A failure/cancellation may follow a successful write: retry idempotently.
/// Secure Enclave is intentionally unsupported. Existing methods are unchanged.
abstract final class DarwinVerifiedStorage {
  static const _channel =
      MethodChannel('plugins.it_nomads.com/flutter_secure_storage');

  /// Writes and verifies one item using a fresh, operation-scoped LAContext.
  /// No fallback to ordinary write/read is performed when unsupported.
  static Future<void> writeAndVerify({
    required String key,
    required String value,
    required String localizedReason,
    required Map<String, String> options,
  }) async {
    if (key.isEmpty ||
        localizedReason.trim().isEmpty ||
        options['useSecureEnclave'] == 'true') {
      throw ArgumentError('Requires a nonempty key and non-Enclave storage');
    }
    await _channel.invokeMethod<void>('writeAndVerify', {
      'key': key,
      'value': value,
      'localizedReason': localizedReason,
      'options': Map<String, String>.of(options),
    });
  }

  /// Cancels active and already queued verified writes for this Flutter engine.
  /// Invoke when the application locks/logs out. Ordinary calls are unaffected.
  static Future<void> cancelPendingWrites() =>
      _channel.invokeMethod<void>('cancelVerifiedWrites');
}
