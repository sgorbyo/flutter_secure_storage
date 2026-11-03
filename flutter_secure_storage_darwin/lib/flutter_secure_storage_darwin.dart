import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// Apple-only, bounded write with a native Keychain readback.
///
/// Pass the same IOSOptions/MacOsOptions.toMap() as ordinary storage calls.
/// A failure/cancellation may follow a successful write: retry idempotently.
/// Secure Enclave is intentionally unsupported. Existing methods are unchanged.
abstract final class DarwinVerifiedStorage {
  static const _channel =
      MethodChannel('plugins.it_nomads.com/flutter_secure_storage');

  static void _requireDarwin() {
    if (kIsWeb ||
        (defaultTargetPlatform != TargetPlatform.macOS &&
            defaultTargetPlatform != TargetPlatform.iOS)) {
      throw const DarwinScopeException('unsupported');
    }
  }

  /// Events identify one evaluation; they never authorize another action.
  static final Stream<DarwinScopeEvaluation> evaluations = const EventChannel(
    'plugins.it_nomads.com/flutter_secure_storage/scope_events',
  ).receiveBroadcastStream().map(DarwinScopeEvaluation._decode);

  /// Registers an immutable finite plan. Authentication is lazy, on first need.
  /// A new action needs a fresh UUID nonce and the current engine owner epoch.
  static Future<DarwinOperationScope> openScope({
    required List<DarwinSlotRule> slots,
    required Map<String, String> options,
    required String localizedReason,
    required Duration lifetime,
    required int ownerEpoch,
    required String actionNonce,
  }) async {
    _requireDarwin();
    final plan = List<DarwinSlotRule>.unmodifiable(slots);
    if (plan.isEmpty ||
        plan.length > 23 ||
        plan.map((s) => s.key).toSet().length != plan.length ||
        plan.fold<int>(0, (n, s) => n + s.maxReads + s.maxWrites) > 28 ||
        localizedReason.trim().isEmpty ||
        ownerEpoch < 0 ||
        lifetime.inMilliseconds <= 0 ||
        lifetime > const Duration(seconds: 120) ||
        !RegExp(r'^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')
            .hasMatch(actionNonce) ||
        options['accountName']?.isNotEmpty != true ||
        options['useSecureEnclave'] == 'true') {
      throw const DarwinScopeException('invalidPlan');
    }
    try {
      final handle = await _channel.invokeMethod<String>('scopeOpen', {
        'slots': plan.map((s) => s._encode()).toList(growable: false),
        'options': Map<String, String>.of(options),
        'localizedReason': localizedReason,
        'lifetimeMilliseconds': lifetime.inMilliseconds,
        'ownerEpoch': ownerEpoch,
        'actionNonce': actionNonce,
      });
      if (handle == null || handle.isEmpty) {
        throw const DarwinScopeException('unknownScope');
      }
      return DarwinOperationScope._(handle, ownerEpoch);
    } on PlatformException catch (error) {
      throw DarwinScopeException._fromPlatform(error);
    }
  }

  /// Invalidates the old owner before any later scope can open. Never queued
  /// behind a pending authentication. Epoch must increase strictly per engine.
  static Future<void> revokeScopes({required int nextOwnerEpoch}) async {
    _requireDarwin();
    if (nextOwnerEpoch < 0) throw const DarwinScopeException('invalidPlan');
    try {
      await _channel.invokeMethod<void>('scopeRevoke', {
        'nextOwnerEpoch': nextOwnerEpoch,
      });
    } on PlatformException catch (error) {
      throw DarwinScopeException._fromPlatform(error);
    }
  }

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

enum DarwinSlotAccess { read, writeVerified, createVerified }

/// Immutable permissions and quotas for one exact storage key.
final class DarwinSlotRule {
  DarwinSlotRule({
    required this.key,
    required Set<DarwinSlotAccess> access,
    required this.maxReads,
    required this.maxWrites,
  }) : access = Set<DarwinSlotAccess>.unmodifiable(access) {
    if (key.isEmpty ||
        maxReads < 0 ||
        maxWrites < 0 ||
        maxReads > 28 ||
        maxWrites > 28 ||
        access.contains(DarwinSlotAccess.read) != (maxReads > 0) ||
        (access.contains(DarwinSlotAccess.writeVerified) ||
                access.contains(DarwinSlotAccess.createVerified)) !=
            (maxWrites > 0) ||
        access.isEmpty) {
      throw const DarwinScopeException('invalidPlan');
    }
  }
  final String key;
  final Set<DarwinSlotAccess> access;
  final int maxReads;
  final int maxWrites;
  Map<String, Object> _encode() => {
        'key': key,
        'access': access.map((p) => p.name).toList(growable: false),
        'maxReads': maxReads,
        'maxWrites': maxWrites,
      };
  @override
  String toString() => 'DarwinSlotRule(<redacted>)';
}

/// Normalized failure. Never includes native values, slot names or raw errors.
final class DarwinScopeException implements Exception {
  const DarwinScopeException(this.code, {this.mutationMayHaveOccurred = false});
  factory DarwinScopeException._fromPlatform(PlatformException error,
          {bool mutation = false}) =>
      DarwinScopeException(
        _codes.contains(error.code) ? error.code : 'storageFailure',
        mutationMayHaveOccurred: error.details is Map &&
                (error.details as Map)['mutationMayHaveOccurred'] is bool
            ? (error.details as Map)['mutationMayHaveOccurred'] as bool
            : mutation,
      );
  static const _codes = {
    'unsupported',
    'invalidPlan',
    'busy',
    'unknownScope',
    'revoked',
    'expired',
    'denied',
    'userCancelled',
    'interrupted',
    'interactionRequired',
    'duplicateItem',
    'verificationFailed',
    'storageFailure',
  };
  final String code;
  final bool mutationMayHaveOccurred;
  @override
  String toString() => 'DarwinScopeException($code)';
}

final class DarwinScopeEvaluation {
  const DarwinScopeEvaluation._(
      this.actionNonce, this.ownerEpoch, this.sequence, this.active);
  factory DarwinScopeEvaluation._decode(dynamic event) {
    final row = Map<String, dynamic>.from(event as Map);
    return DarwinScopeEvaluation._(
        row['actionNonce'] as String,
        row['ownerEpoch'] as int,
        row['sequence'] as int,
        row['active'] as bool);
  }
  final String actionNonce;
  final int ownerEpoch;
  final int sequence;
  final bool active;
  @override
  String toString() => 'DarwinScopeEvaluation(active: $active)';
}

/// Nontransferable native scope. Its handle deliberately has no public getter.
/// Calls serialize; close bypasses the queue and rejects queued continuations.
final class DarwinOperationScope {
  DarwinOperationScope._(this._handle, this._ownerEpoch);
  final String _handle;
  final int _ownerEpoch;
  Future<void> _tail = Future<void>.value();
  Future<void>? _closing;
  int _sequence = 0;
  bool _closed = false;

  Future<T?> _invoke<T>(String method, Map<String, Object> payload,
      {bool mutation = false}) {
    final result = _tail.then((_) async {
      if (_closed) throw const DarwinScopeException('revoked');
      try {
        final value =
            await DarwinVerifiedStorage._channel.invokeMethod<T>(method, {
          ...payload,
          'handle': _handle,
          'ownerEpoch': _ownerEpoch,
          'sequence': ++_sequence,
        });
        if (_closed) {
          throw DarwinScopeException('revoked',
              mutationMayHaveOccurred: mutation);
        }
        return value;
      } on PlatformException catch (error) {
        unawaited(close().catchError((Object _) {}));
        throw DarwinScopeException._fromPlatform(error, mutation: mutation);
      } catch (_) {
        unawaited(close().catchError((Object _) {}));
        rethrow;
      }
    });
    _tail = result.then<void>((_) {}, onError: (Object _, StackTrace __) {});
    return result;
  }

  Future<Map<String, String?>> readBatch(List<String> keys) async {
    final requested = List<String>.of(keys);
    final raw = await _invoke<Map<dynamic, dynamic>>(
        'scopeReadBatch', {'keys': requested});
    if (raw == null ||
        raw.length != requested.length ||
        !requested.every(raw.containsKey) ||
        raw.values.any((v) => v != null && v is! String)) {
      await close();
      throw const DarwinScopeException('verificationFailed');
    }
    return Map<String, String?>.from(raw);
  }

  Future<void> writeVerified(
      {required String key, required String value}) async {
    await _invoke<void>('scopeWriteVerified', {'key': key, 'value': value},
        mutation: true);
  }

  Future<void> createVerified(
      {required String key, required String value}) async {
    await _invoke<void>('scopeCreateVerified', {'key': key, 'value': value},
        mutation: true);
  }

  Future<void> checkActive() async {
    await _invoke<void>('scopeCheck', {});
  }

  Future<void> close() {
    _closed = true;
    return _closing ??= DarwinVerifiedStorage._channel.invokeMethod<void>(
      'scopeClose',
      {'handle': _handle, 'ownerEpoch': _ownerEpoch},
    );
  }

  @override
  String toString() => 'DarwinOperationScope(<redacted>)';
}
