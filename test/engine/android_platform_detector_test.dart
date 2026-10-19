import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:kryvon/kryvon.dart';

const channel = MethodChannel('dev.kryvon/security.v1');

DetectorRequest request({
  String signal = AndroidPlatformDetector.debuggerAttachedSignal,
  String platform = 'android',
}) =>
    DetectorRequest(
      requestId: 'request-123',
      signalId: signal,
      context: AssessmentContext.transaction,
      platform: platform,
    );

Map<String, Object?> response({
  String status = 'detected',
  Object? confidence = 'high',
  Object? requestId = 'request-123',
  Object? signalId = AndroidPlatformDetector.debuggerAttachedSignal,
  Object? observedAt = '2026-10-19T12:00:00.000Z',
}) =>
    <String, Object?>{
      'protocolVersion': 1,
      'requestId': requestId,
      'signalId': signalId,
      'status': status,
      'confidence': confidence,
      'source': 'android.platform.debugger_api',
      'platform': 'android',
      'observedAt': observedAt,
      'metadata': <String, Object?>{'observationCode': 'debugger_attached_api'},
    };

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  group('AndroidPlatformDetector channel adapter', () {
    test('valid positive response is correlated and parsed', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async => response());
      final detector = AndroidPlatformDetector(channel: channel);

      final result = await detector.evaluate(request());

      expect(result.status, EvidenceStatus.detected);
      expect(result.confidence, Confidence.high);
      expect(result.signal, AndroidPlatformDetector.debuggerAttachedSignal);
      expect(result.source, 'android.platform.debugger_api');
      expect(result.observedAt.isUtc, isTrue);
    });

    test('valid negative response remains a negative observation', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(
        channel,
        (call) async => response(status: 'not_detected'),
      );
      final detector = AndroidPlatformDetector(channel: channel);

      final result = await detector.evaluate(request());

      expect(result.status, EvidenceStatus.notDetected);
      expect(result.confidence, Confidence.high);
    });

    test('native failed and unsupported statuses remain distinct', () async {
      final detector = AndroidPlatformDetector(channel: channel);
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(
        channel,
        (call) async => response(status: 'failed', confidence: null),
      );
      final failed = await detector.evaluate(request());
      expect(failed.status, EvidenceStatus.failed);

      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(
        channel,
        (call) async => response(status: 'unsupported', confidence: null),
      );
      final unsupported = await detector.evaluate(request());
      expect(unsupported.status, EvidenceStatus.unsupported);
    });

    test('mismatched identifiers, invalid status and malformed timestamp fail closed', () async {
      final detector = AndroidPlatformDetector(channel: channel);

      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(
        channel,
        (call) async => response(requestId: 'another-request'),
      );
      expect((await detector.evaluate(request())).status, EvidenceStatus.failed);

      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(
        channel,
        (call) async => response(status: 'safe'),
      );
      expect((await detector.evaluate(request())).status, EvidenceStatus.failed);

      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(
        channel,
        (call) async => response(observedAt: 'not-a-timestamp'),
      );
      expect((await detector.evaluate(request())).status, EvidenceStatus.failed);

      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(
        channel,
        (call) async => response(confidence: null),
      );
      expect((await detector.evaluate(request())).status, EvidenceStatus.failed);
    });

    test('channel timeout becomes failed evidence', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(
        channel,
        (call) => Completer<Object?>().future,
      );
      final detector = AndroidPlatformDetector(
        channel: channel,
        timeout: const Duration(milliseconds: 10),
      );

      final result = await detector.evaluate(request());

      expect(result.status, EvidenceStatus.failed);
      expect(result.metadata['diagnosticCode'], 'channel_timeout');
    });

    test('missing native implementation becomes failed evidence', () async {
      final detector = AndroidPlatformDetector(channel: channel);

      final result = await detector.evaluate(request());

      expect(result.status, EvidenceStatus.failed);
      expect(result.metadata['diagnosticCode'], 'channel_unavailable');
    });

    test('unknown signal is unsupported and is not sent to native channel', () async {
      var invoked = false;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
        invoked = true;
        return response();
      });
      final detector = AndroidPlatformDetector(channel: channel);

      final result = await detector.evaluate(
        request(signal: 'android.not.registered'),
      );

      expect(invoked, isFalse);
      expect(result.status, EvidenceStatus.unsupported);
      expect(result.metadata['diagnosticCode'], 'unsupported_signal');
    });

    test('non-Android platform reports unsupported', () async {
      final detector = AndroidPlatformDetector(channel: channel);

      final result = await detector.evaluate(request(platform: 'ios'));

      expect(result.status, EvidenceStatus.unsupported);
    });
  });
}
