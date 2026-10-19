import 'dart:async';

import '../domain/evidence.dart';
import '../domain/kryvon_enums.dart';
import '../domain/signal_run.dart';
import 'detector.dart';

class DetectorOrchestrator {
  DetectorOrchestrator({
    required this.registry,
    this.timeout = const Duration(seconds: 3),
  }) {
    if (timeout <= Duration.zero) {
      throw ArgumentError.value(
        timeout,
        'timeout',
        'Timeout must be positive.',
      );
    }
  }

  final DetectorRegistry registry;
  final Duration timeout;
  static int _nextRequestId = 0;

  Future<SignalRun> run({
    required AssessmentContext context,
    required String platform,
    Map<String, Object?> configuration = const <String, Object?>{},
  }) async {
    // Snapshot the run-level configuration before starting concurrent work.
    final configSnapshot = _freezeRunConfiguration(configuration);
    final normalizedPlatform = platform.trim().isEmpty ? 'unknown' : platform.trim();
    final expected = registry.expectedSignals;
    final outcomes = await Future.wait<Evidence>(
      registry.registrations.expand(
        (registration) => registration.signalIds.map(
          (signalId) => _runOne(
            detector: registration.detector,
            signalId: signalId,
            context: context,
            platform: normalizedPlatform,
            configuration: configSnapshot,
          ),
        ),
      ),
    );
    return SignalRun(expectedSignals: expected, outcomes: outcomes);
  }

  Future<Evidence> _runOne({
    required SignalDetector detector,
    required String signalId,
    required AssessmentContext context,
    required String platform,
    required Map<String, Object?> configuration,
  }) async {
    final requestId = 'kryvon-${++_nextRequestId}';
    try {
      final evidence = await detector
          .evaluate(
            DetectorRequest(
              requestId: requestId,
              signalId: signalId,
              context: context,
              platform: platform,
              configuration: configuration,
            ),
          )
          .timeout(timeout);
      if (evidence.signal != signalId ||
          evidence.source.trim().isEmpty ||
          evidence.platform.trim().isEmpty ||
          ((evidence.status == EvidenceStatus.detected ||
                  evidence.status == EvidenceStatus.notDetected) &&
              evidence.confidence == null)) {
        return _failed(signalId, platform, 'invalid_detector_result');
      }
      return evidence;
    } on TimeoutException {
      return _failed(signalId, platform, 'detector_timeout');
    } catch (_) {
      return _failed(signalId, platform, 'detector_error');
    }
  }

  Evidence _failed(String signalId, String platform, String code) => Evidence(
        signal: signalId,
        status: EvidenceStatus.failed,
        confidence: null,
        source: 'kryvon.orchestrator',
        platform: platform,
        observedAt: DateTime.now().toUtc(),
        metadata: <String, Object?>{'errorCode': code},
      );
}

Map<String, Object?> _freezeRunConfiguration(Map<String, Object?> values) =>
    Map<String, Object?>.unmodifiable(
      values.map((key, value) => MapEntry(key, _freezeRunValue(value))),
    );

Object? _freezeRunValue(Object? value) {
  if (value is Map) {
    return Map<Object?, Object?>.unmodifiable(
      value.map((key, nested) => MapEntry(key, _freezeRunValue(nested))),
    );
  }
  if (value is List) {
    return List<Object?>.unmodifiable(value.map(_freezeRunValue));
  }
  if (value is Set) {
    return Set<Object?>.unmodifiable(value.map(_freezeRunValue));
  }
  return value;
}
