import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_secure_storage_darwin/flutter_secure_storage_darwin.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('plugins.it_nomads.com/flutter_secure_storage');
  const nonce = '00000000-0000-4000-8000-000000000001';
  final calls = <MethodCall>[];
  Future<Object?> Function(MethodCall)? responder;
  Future<DarwinOperationScope> open() => DarwinVerifiedStorage.openScope(
        slots: [
          DarwinSlotRule(
              key: 'synthetic',
              access: DarwinSlotAccess.values.toSet(),
              maxReads: 1,
              maxWrites: 2)
        ],
        options: {'accountName': 'synthetic'},
        localizedReason: 'Test',
        lifetime: const Duration(seconds: 1),
        ownerEpoch: 0,
        actionNonce: nonce,
      );
  Matcher failure(String code, {bool? uncertain}) =>
      isA<DarwinScopeException>().having((e) => e.code, 'code', code).having(
          (e) => e.mutationMayHaveOccurred, 'uncertain', uncertain ?? false);
  setUp(() {
    debugDefaultTargetPlatformOverride = TargetPlatform.macOS;
    calls.clear();
    responder = null;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      if (responder != null) return responder!(call);
      return switch (call.method) {
        'scopeOpen' => 'opaque-handle',
        'scopeReadBatch' => {'synthetic': null},
        _ => null,
      };
    });
  });
  tearDown(() {
    debugDefaultTargetPlatformOverride = null;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });
  test('read create update check serialize with no options after open',
      () async {
    final scope = await open();
    expect(await scope.readBatch(['synthetic']), {'synthetic': null});
    await scope.createVerified(key: 'synthetic', value: 'synthetic');
    await scope.writeVerified(key: 'synthetic', value: 'synthetic');
    await scope.checkActive();
    await scope.close();
    await scope.close();
    expect(calls.map((c) => c.method), [
      'scopeOpen',
      'scopeReadBatch',
      'scopeCreateVerified',
      'scopeWriteVerified',
      'scopeCheck',
      'scopeClose'
    ]);
    expect(calls.skip(1).take(4).map((c) => c.arguments['sequence']),
        [1, 2, 3, 4]);
    expect(
        calls
            .skip(1)
            .every((c) => !(c.arguments as Map).containsKey('options')),
        isTrue);
    expect(scope.toString(), isNot(contains('opaque-handle')));
  });
  test('close bypasses pending write and rejects queued operation', () async {
    final scope = await open();
    final pending = Completer<Object?>();
    final started = Completer<void>();
    responder = (call) async {
      if (call.method == 'scopeWriteVerified') {
        started.complete();
        return pending.future;
      }
      return null;
    };
    final write = scope.writeVerified(key: 'synthetic', value: 'synthetic');
    final writeCheck =
        expectLater(write, throwsA(failure('revoked', uncertain: true)));
    final queued = scope.checkActive();
    final queuedCheck = expectLater(queued, throwsA(failure('revoked')));
    await started.future;
    await scope.close();
    expect(calls.last.method, 'scopeClose');
    pending.complete(null);
    await Future.wait([writeCheck, queuedCheck]);
    expect(calls.where((c) => c.method == 'scopeCheck'), isEmpty);
  });
  for (final code in ['denied', 'userCancelled', 'interrupted']) {
    test('native $code retires scope and preserves its cause', () async {
      final scope = await open();
      responder = (call) async {
        if (call.method == 'scopeReadBatch')
          throw PlatformException(code: code);
        return null;
      };
      await expectLater(scope.readBatch(['synthetic']), throwsA(failure(code)));
      await expectLater(scope.checkActive(), throwsA(failure('revoked')));
      await scope.close();
      expect(calls.map((c) => c.method),
          ['scopeOpen', 'scopeReadBatch', 'scopeClose']);
    });
  }
  test('partial batch retires scope', () async {
    final scope = await open();
    responder = (call) async =>
        call.method == 'scopeReadBatch' ? <String, Object?>{} : null;
    await expectLater(
        scope.readBatch(['synthetic']), throwsA(failure('verificationFailed')));
    expect(calls.last.method, 'scopeClose');
  });
  test('uncertain mutation preserves native flag without raw error', () async {
    final scope = await open();
    responder = (call) async {
      if (call.method == 'scopeWriteVerified') {
        throw PlatformException(
            code: 'expired',
            message: 'must not escape',
            details: {'mutationMayHaveOccurred': true});
      }
      return null;
    };
    await expectLater(scope.writeVerified(key: 'synthetic', value: 'synthetic'),
        throwsA(failure('expired', uncertain: true)));
    await scope.close();
  });
  test('transport failure cannot claim mutation did not happen', () async {
    final scope = await open();
    responder = (call) async {
      if (call.method == 'scopeWriteVerified') {
        throw PlatformException(code: 'channel-error');
      }
      return null;
    };
    await expectLater(scope.writeVerified(key: 'synthetic', value: 'synthetic'),
        throwsA(failure('storageFailure', uncertain: true)));
    await scope.close();
  });
  test('unsupported platform fails before opening native scope', () async {
    debugDefaultTargetPlatformOverride = TargetPlatform.windows;
    await expectLater(open(), throwsA(failure('unsupported')));
    await expectLater(DarwinVerifiedStorage.revokeScopes(nextOwnerEpoch: 1),
        throwsA(failure('unsupported')));
    expect(calls, isEmpty);
  });
  test('permissions cannot be modified after construction', () {
    final permissions = {DarwinSlotAccess.read};
    final rule = DarwinSlotRule(
        key: 'synthetic', access: permissions, maxReads: 1, maxWrites: 0);
    permissions.add(DarwinSlotAccess.writeVerified);
    expect(rule.access, {DarwinSlotAccess.read});
    expect(() => rule.access.clear(), throwsUnsupportedError);
  });
  test('invalid and oversized quotas fail before native access', () {
    expect(
        () => DarwinSlotRule(
            key: 'synthetic',
            access: {DarwinSlotAccess.read},
            maxReads: 29,
            maxWrites: 0),
        throwsA(failure('invalidPlan')));
    expect(
        () => DarwinSlotRule(
            key: 'synthetic',
            access: {DarwinSlotAccess.read},
            maxReads: 0,
            maxWrites: 1),
        throwsA(failure('invalidPlan')));
    expect(calls, isEmpty);
  });
  test('owner revocation bypasses operation queue', () async {
    await DarwinVerifiedStorage.revokeScopes(nextOwnerEpoch: 1);
    expect(calls.single.method, 'scopeRevoke');
    expect(calls.single.arguments, {'nextOwnerEpoch': 1});
  });
}
