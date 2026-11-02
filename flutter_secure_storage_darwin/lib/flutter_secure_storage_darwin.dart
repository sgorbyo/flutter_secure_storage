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

  /// Reads only the requested items in one finite, revocable native operation.
  /// Missing items are null. Failure never returns a partial result.
  static Future<Map<String, String?>> readBatch({
    required List<String> keys,
    required String localizedReason,
    required Map<String, String> options,
  }) async {
    if (keys.isEmpty ||
        keys.length > 32 ||
        keys.any((key) => key.isEmpty) ||
        keys.toSet().length != keys.length ||
        localizedReason.trim().isEmpty ||
        options['useSecureEnclave'] == 'true') {
      throw ArgumentError('Requires 1–32 unique keys and non-Enclave storage');
    }
    final result =
        await _channel.invokeMapMethod<String, String?>('readBatch', {
      'keys': List<String>.of(keys),
      'localizedReason': localizedReason,
      'options': Map<String, String>.of(options),
    });
    if (result == null ||
        result.length != keys.length ||
        !keys.every(result.containsKey)) {
      throw StateError('Incomplete protected read');
    }
    return result;
  }

  /// Revokes active/queued bounded reads and verified writes for this engine.
  /// Ordinary legacy storage calls are not part of this scope.
  static Future<void> cancelPendingOperations() =>
      _channel.invokeMethod<void>('cancelVerifiedWrites');

  /// Cancels active and already queued verified writes for this Flutter engine.
  /// Invoke when the application locks/logs out. Ordinary calls are unaffected.
  static Future<void> cancelPendingWrites() =>
      _channel.invokeMethod<void>('cancelVerifiedWrites');
}
