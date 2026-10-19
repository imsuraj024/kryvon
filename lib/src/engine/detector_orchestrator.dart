import 'dart:async';

import '../domain/evidence.dart';
import '../domain/kryvon_enums.dart';
import '../domain/signal_run.dart';
import 'detector.dart';

class DetectorOrchestrator {
  DetectorOrchestrator({
    required this.registry,
    this.timeout = const Duration(seconds: 3),
    this.maxConcurrentSignals = 4,
  }) {
    if (timeout <= Duration.zero) {
      throw ArgumentError.value(
        timeout,
        'timeout',
        'Timeout must be positive.',
      );
    }
    if (maxConcurrentSignals < 1) {
      throw ArgumentError.value(
        maxConcurrentSignals,
        'maxConcurrentSignals',
        'Concurrency limit must be positive.',
      );
    }
  }

  final DetectorRegistry registry;
  final Duration timeout;

  /// Maximum in-flight signal evaluations for a single run.
  final int maxConcurrentSignals;

  static int _nextRequestId = 0;

  Future<SignalRun> run({
    required AssessmentContext context,
    required String platform,
    Map<String, Object?> configuration = const <String, Object?>{},
  }) async {
    // Snapshot run configuration before starting concurrent work.
    final configSnapshot = _freezeRunConfiguration(configuration);
    final normalizedPlatform =
        platform.trim().isEmpty ? 'unknown' : platform.trim();
    final expected = registry.expectedSignals;
    final tasks = <_DetectorTask>[
      for (final registration in registry.registrations)
        for (final signalId in registration.signalIds)
          _DetectorTask(registration.detector, signalId),
    ];
    final outcomes = List<Evidence?>.filled(tasks.length, null);
    var nextIndex = 0;

    Future<void> worker() async {
      while (true) {
        // Dart isolate execution is single-threaded between awaits, so each
        // task index is claimed by exactly one worker.
        final index = nextIndex++;
        if (index >= tasks.length) return;
        final task = tasks[index];
        outcomes[index] = await _runOne(
          detector: task.detector,
          signalId: task.signalId,
          context: context,
          platform: normalizedPlatform,
          configuration: configSnapshot,
        );
      }
    }

    final workerCount = tasks.length < maxConcurrentSignals
        ? tasks.length
        : maxConcurrentSignals;
    await Future.wait<void>(
      List<Future<void>>.generate(workerCount, (_) => worker()),
    );

    // Every task writes its slot, including operational failures.
    return SignalRun(
      expectedSignals: expected,
      outcomes: outcomes.cast<Evidence>(),
    );
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

class _DetectorTask {
  const _DetectorTask(this.detector, this.signalId);

  final SignalDetector detector;
  final String signalId;
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
