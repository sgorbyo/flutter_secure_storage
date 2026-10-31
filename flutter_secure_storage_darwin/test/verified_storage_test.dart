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
      return null;
    });
  });
  tearDown(() => TestDefaultBinaryMessengerBinding
      .instance.defaultBinaryMessenger
      .setMockMethodCallHandler(channel, null));
  test('one native operation forwards exact storage options', () async {
    const options = {
      'accountName': 'synthetic',
      'accessControlFlags': 'userPresence'
    };
    await DarwinVerifiedStorage.writeAndVerify(
        key: 'canary',
        value: 'synthetic',
        localizedReason: 'Test protected write',
        options: options);
    expect(calls.single.method, 'writeAndVerify');
    expect(calls.single.arguments, {
      'key': 'canary',
      'value': 'synthetic',
      'localizedReason': 'Test protected write',
      'options': options
    });
  });
  test('cancellation is an independent channel call', () async {
    await DarwinVerifiedStorage.cancelPendingWrites();
    expect(calls.single.method, 'cancelVerifiedWrites');
  });
  test('rejects unsupported mode without native calls', () async {
    await expectLater(
        DarwinVerifiedStorage.writeAndVerify(
            key: 'canary',
            value: 'synthetic',
            localizedReason: 'Test protected write',
            options: {'useSecureEnclave': 'true'}),
        throwsArgumentError);
    expect(calls, isEmpty);
  });
  test('native denial propagates with no weaker fallback', () async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      throw PlatformException(code: 'cancelled');
    });
    await expectLater(
        DarwinVerifiedStorage.writeAndVerify(
            key: 'canary',
            value: 'synthetic',
            localizedReason: 'Test protected write',
            options: {}),
        throwsA(isA<PlatformException>()));
    expect(calls, hasLength(1));
  });
}
