import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_secure_storage_darwin/flutter_secure_storage_darwin.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('plugins.it_nomads.com/flutter_secure_storage');
  final calls = <MethodCall>[];
  setUp(() {
    calls.clear();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      return call.method == 'readBatch'
          ? {'journal': 'synthetic', 'receipt': null}
          : null;
    });
  });
  tearDown(() => TestDefaultBinaryMessengerBinding
      .instance.defaultBinaryMessenger
      .setMockMethodCallHandler(channel, null));
  test('bounded batch forwards exact keys and preserves absent items',
      () async {
    final values = await DarwinVerifiedStorage.readBatch(
        keys: ['journal', 'receipt'],
        localizedReason: 'Test',
        options: {'accessControlFlags': 'userPresence'});
    expect(values, {'journal': 'synthetic', 'receipt': null});
    expect(calls.single.method, 'readBatch');
    expect(calls.single.arguments['keys'], ['journal', 'receipt']);
    await DarwinVerifiedStorage.cancelPendingOperations();
    expect(calls.last.method, 'cancelVerifiedWrites');
  });
  test('duplicates and enclave fail before platform call', () async {
    await expectLater(
        DarwinVerifiedStorage.readBatch(
            keys: ['a', 'a'], localizedReason: 'Test', options: {}),
        throwsArgumentError);
    await expectLater(
        DarwinVerifiedStorage.readBatch(
            keys: ['a'],
            localizedReason: 'Test',
            options: {'useSecureEnclave': 'true'}),
        throwsArgumentError);
    expect(calls, isEmpty);
  });
  test('incomplete native response fails closed', () async {
    await expectLater(
        DarwinVerifiedStorage.readBatch(
            keys: ['different'], localizedReason: 'Test', options: {}),
        throwsStateError);
  });
}
