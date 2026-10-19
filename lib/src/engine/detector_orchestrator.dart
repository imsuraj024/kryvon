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
      throw ArgumentError.value(timeout, 'timeout', 'Timeout must be positive.');
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
    final expected = registry.expectedSignals;
    final outcomes = await Future.wait<Evidence>(
      registry.detectors.expand(
        (detector) => detector.signalIds.map(
          (signalId) => _runOne(
            detector: detector,
            signalId: signalId.trim(),
            context: context,
            platform: platform,
            configuration: configuration,
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
    final now = DateTime.now().toUtc();
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
        return _failed(signalId, platform, now, 'invalid_detector_result');
      }
      return evidence;
    } on TimeoutException {
      return _failed(signalId, platform, now, 'detector_timeout');
    } catch (_) {
      return _failed(signalId, platform, now, 'detector_error');
    }
  }

  Evidence _failed(String signalId, String platform, DateTime observedAt, String code) => Evidence(
        signal: signalId,
        status: EvidenceStatus.failed,
        confidence: null,
        source: 'kryvon.orchestrator',
        platform: platform.trim().isEmpty ? 'unknown' : platform,
        observedAt: observedAt,
        metadata: <String, Object?>{'errorCode': code},
      );
}
