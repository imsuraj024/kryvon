import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:kryvon/kryvon.dart';

class FakeDetector implements SignalDetector {
  FakeDetector(this.id, this.signalIds, this.handler);
  @override
  final String id;
  @override
  final List<String> signalIds;
  final Future<Evidence> Function(DetectorRequest request) handler;
  @override
  Future<Evidence> evaluate(DetectorRequest request) => handler(request);
}

Evidence result(String signal, EvidenceStatus status, {Confidence? confidence}) => Evidence(
      signal: signal,
      status: status,
      confidence: confidence,
      source: 'test.detector',
      platform: 'test',
      observedAt: DateTime.utc(2026),
    );

void main() {
  group('DetectorRegistry', () {
    test('rejects blank and duplicate detector IDs', () {
      expect(() => DetectorRegistry([FakeDetector(' ', ['a'], (_) async => result('a', EvidenceStatus.notDetected, confidence: Confidence.high))]), throwsArgumentError);
      expect(() => DetectorRegistry([
        FakeDetector('same', ['a'], (_) async => result('a', EvidenceStatus.notDetected, confidence: Confidence.high)),
        FakeDetector(' same ', ['b'], (_) async => result('b', EvidenceStatus.notDetected, confidence: Confidence.high)),
      ]), throwsArgumentError);
    });

    test('rejects blank, duplicate, and ambiguously owned signals', () {
      expect(() => DetectorRegistry([FakeDetector('a', [' '], (_) async => result(' ', EvidenceStatus.notDetected, confidence: Confidence.high))]), throwsArgumentError);
      expect(() => DetectorRegistry([FakeDetector('a', ['x', ' x '], (_) async => result('x', EvidenceStatus.notDetected, confidence: Confidence.high))]), throwsArgumentError);
      expect(() => DetectorRegistry([
        FakeDetector('a', ['x'], (_) async => result('x', EvidenceStatus.notDetected, confidence: Confidence.high)),
        FakeDetector('b', [' x '], (_) async => result('x', EvidenceStatus.notDetected, confidence: Confidence.high)),
      ]), throwsArgumentError);
    });
  });

  group('DetectorOrchestrator', () {
    test('snapshots detector signal ownership at registry creation', () async {
      final signals = <String>['a'];
      final registry = DetectorRegistry([
        FakeDetector('mutable-definition', signals, (request) async {
          return result(request.signalId, EvidenceStatus.notDetected,
              confidence: Confidence.high);
        }),
      ]);
      signals
        ..clear()
        ..add('changed-after-registration');

      expect(registry.expectedSignals, ['a']);
      expect(registry.ownerOf('a'), isNotNull);
      expect(registry.ownerOf('changed-after-registration'), isNull);
      final run = await DetectorOrchestrator(registry: registry).run(
        context: AssessmentContext.appStartup,
        platform: 'test',
      );
      expect(run.outcomes.single.signal, 'a');
      expect(run.isComplete, isTrue);
    });

    test('configuration is a deep immutable snapshot', () async {
      final nestedList = <Object?>['before'];
      final nestedMap = <String, Object?>{'items': nestedList};
      final configuration = <String, Object?>{'nested': nestedMap};
      final registry = DetectorRegistry([
        FakeDetector('config', ['a'], (request) async {
          expect(
            () => (request.configuration['nested'] as Map)['new'] = true,
            throwsUnsupportedError,
          );
          expect(
            () => ((request.configuration['nested'] as Map)['items'] as List)
                .add('mutate'),
            throwsUnsupportedError,
          );
          return result('a', EvidenceStatus.notDetected,
              confidence: Confidence.high);
        }),
      ]);
      final pending = DetectorOrchestrator(registry: registry).run(
        context: AssessmentContext.appStartup,
        platform: 'test',
        configuration: configuration,
      );
      nestedList[0] = 'after';
      nestedMap['extra'] = true;
      await pending;
      // The detector sees the snapshot captured before asynchronous work starts.
      expect(nestedList, ['after']);
    });

    test('preserves registry order despite completion order', () async {
      final registry = DetectorRegistry([
        FakeDetector('slow-first', ['a'], (_) async {
          await Future<void>.delayed(const Duration(milliseconds: 20));
          return result('a', EvidenceStatus.notDetected, confidence: Confidence.high);
        }),
        FakeDetector('fast-second', ['b'], (_) async => result('b', EvidenceStatus.detected, confidence: Confidence.high)),
      ]);
      final run = await DetectorOrchestrator(registry: registry).run(context: AssessmentContext.appStartup, platform: 'test');
      expect(run.expectedSignals, ['a', 'b']);
      expect(run.outcomes.map((e) => e.signal), ['a', 'b']);
      expect(run.isComplete, isTrue);
    });

    test('converts detector exceptions to failed evidence without suppressing peers', () async {
      final registry = DetectorRegistry([
        FakeDetector('throws', ['a'], (_) async => throw StateError('sensitive exception detail')),
        FakeDetector('works', ['b'], (_) async => result('b', EvidenceStatus.notDetected, confidence: Confidence.high)),
      ]);
      final run = await DetectorOrchestrator(registry: registry).run(context: AssessmentContext.appStartup, platform: 'test');
      expect(run.outcomes[0].status, EvidenceStatus.failed);
      expect(run.outcomes[0].metadata['errorCode'], 'detector_error');
      expect(run.outcomes[0].metadata.toString(), isNot(contains('sensitive exception detail')));
      expect(run.outcomes[1].status, EvidenceStatus.notDetected);
    });

    test('maps timeout to failed and ignores late completion', () async {
      final completer = Completer<Evidence>();
      final registry = DetectorRegistry([FakeDetector('late', ['a'], (_) => completer.future)]);
      final run = await DetectorOrchestrator(registry: registry, timeout: const Duration(milliseconds: 10))
          .run(context: AssessmentContext.appStartup, platform: 'test');
      expect(run.outcomes.single.status, EvidenceStatus.failed);
      expect(run.outcomes.single.metadata['errorCode'], 'detector_timeout');
      completer.complete(result('a', EvidenceStatus.notDetected, confidence: Confidence.high));
      await Future<void>.delayed(const Duration(milliseconds: 1));
      expect(run.outcomes.single.status, EvidenceStatus.failed);
      expect(run.isComplete, isFalse);
    });

    test('converts mismatched signal and invalid status-confidence to failed', () async {
      final registry = DetectorRegistry([
        FakeDetector('mismatch', ['a'], (_) async => result('other', EvidenceStatus.notDetected, confidence: Confidence.high)),
        FakeDetector('no-confidence', ['b'], (_) async => result('b', EvidenceStatus.detected)),
      ]);
      final run = await DetectorOrchestrator(registry: registry).run(context: AssessmentContext.appStartup, platform: 'test');
      expect(run.outcomes.map((e) => e.status), [EvidenceStatus.failed, EvidenceStatus.failed]);
      expect(run.isComplete, isFalse);
    });

    test('rejects a non-positive timeout', () {
      expect(() => DetectorOrchestrator(registry: DetectorRegistry([]), timeout: Duration.zero), throwsArgumentError);
    });

    test('isolates concurrent run request IDs', () async {
      final ids = <String>{};
      final registry = DetectorRegistry([
        FakeDetector('ids', ['a'], (request) async {
          ids.add(request.requestId);
          return result('a', EvidenceStatus.notDetected, confidence: Confidence.high);
        }),
      ]);
      final orchestrator = DetectorOrchestrator(registry: registry);
      await Future.wait([
        orchestrator.run(context: AssessmentContext.appStartup, platform: 'test'),
        orchestrator.run(context: AssessmentContext.transaction, platform: 'test'),
      ]);
      expect(ids.length, 2);
    });
  });
}
