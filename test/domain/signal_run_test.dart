import 'package:flutter_test/flutter_test.dart';
import 'package:kryvon/kryvon.dart';

Evidence outcome(String signal, EvidenceStatus status, {Confidence? confidence}) => Evidence(
  signal: signal,
  status: status,
  confidence: confidence ?? (status == EvidenceStatus.failed || status == EvidenceStatus.unknown || status == EvidenceStatus.unsupported ? null : Confidence.high),
  source: 'test',
  platform: 'test',
  observedAt: DateTime.utc(2026),
);

void main() {
  group('SignalRun', () {
    test('is complete only when every expected signal has one supported outcome', () {
      expect(SignalRun(expectedSignals: ['root', 'debug'], outcomes: [outcome('root', EvidenceStatus.notDetected), outcome('debug', EvidenceStatus.notDetected)]).isComplete, isTrue);
      expect(SignalRun(expectedSignals: ['root', 'debug'], outcomes: [outcome('root', EvidenceStatus.notDetected)]).isComplete, isFalse);
      expect(SignalRun(expectedSignals: ['root'], outcomes: [outcome('root', EvidenceStatus.failed)]).isComplete, isFalse);
      expect(SignalRun(expectedSignals: ['root'], outcomes: [outcome('root', EvidenceStatus.unsupported)]).isComplete, isFalse);
      expect(SignalRun(expectedSignals: ['root'], outcomes: [outcome('root', EvidenceStatus.unknown)]).isComplete, isFalse);
      final noConfidence = Evidence(signal: 'root', status: EvidenceStatus.notDetected, confidence: null, source: 'test', platform: 'test', observedAt: DateTime.utc(2026));
      expect(SignalRun(expectedSignals: ['root'], outcomes: [noConfidence]).isComplete, isFalse);
    });

    test('rejects duplicate, unexpected, and empty expected signal identifiers', () {
      expect(SignalRun(expectedSignals: ['root', 'root'], outcomes: [outcome('root', EvidenceStatus.notDetected)]).isComplete, isFalse);
      expect(SignalRun(expectedSignals: ['root'], outcomes: [outcome('root', EvidenceStatus.notDetected), outcome('root', EvidenceStatus.notDetected)]).isComplete, isFalse);
      expect(SignalRun(expectedSignals: ['root'], outcomes: [outcome('other', EvidenceStatus.notDetected)]).isComplete, isFalse);
      expect(SignalRun(expectedSignals: [], outcomes: []).isComplete, isFalse);
      expect(SignalRun(expectedSignals: ['   '], outcomes: [outcome('   ', EvidenceStatus.notDetected)]).isComplete, isFalse);
      expect(SignalRun(expectedSignals: [' root '], outcomes: [outcome(' root ', EvidenceStatus.notDetected)]).isComplete, isFalse);
    });
  });

  group('RiskEvaluator signal coverage semantics', () {
    const evaluator = RiskEvaluator();

    test('complete high-confidence all-negative coverage is low risk', () {
      final run = SignalRun(expectedSignals: ['root', 'debug'], outcomes: [outcome('root', EvidenceStatus.notDetected), outcome('debug', EvidenceStatus.notDetected)]);
      final risk = evaluator.evaluate(const [], signalRun: run);
      expect(risk.level, RiskLevel.lowRisk);
      expect(risk.uncertainties, isEmpty);
    });

    test('low-confidence negative outcomes do not establish low risk', () {
      final run = SignalRun(expectedSignals: ['root'], outcomes: [outcome('root', EvidenceStatus.notDetected, confidence: Confidence.low)]);
      final risk = evaluator.evaluate(const [], signalRun: run);
      expect(risk.level, RiskLevel.unknown);
      expect(risk.uncertainties, contains('Signal "root" has insufficient confidence to establish a negative result.'));
    });

    test('failed or missing coverage is unknown rather than safe', () {
      final failed = SignalRun(expectedSignals: ['root'], outcomes: [outcome('root', EvidenceStatus.failed)]);
      final missing = SignalRun(expectedSignals: ['root', 'debug'], outcomes: [outcome('root', EvidenceStatus.notDetected)]);
      expect(evaluator.evaluate(const [], signalRun: failed).level, RiskLevel.unknown);
      expect(evaluator.evaluate(const [], signalRun: missing).level, RiskLevel.unknown);
      expect(evaluator.evaluate(const [], signalRun: failed).uncertainties, isNotEmpty);
      expect(evaluator.evaluate(const [], signalRun: missing).uncertainties, isNotEmpty);
    });

    test('detected evidence without an assessment remains unknown', () {
      final run = SignalRun(expectedSignals: ['root'], outcomes: [outcome('root', EvidenceStatus.detected)]);
      final risk = evaluator.evaluate(const [], signalRun: run);
      expect(risk.level, RiskLevel.unknown);
      expect(risk.uncertainties, contains('Detected signal evidence has not been interpreted by an assessment.'));
    });

    test('failed coverage does not erase an independently assessed high risk', () {
      final run = SignalRun(expectedSignals: ['root', 'debug'], outcomes: [outcome('root', EvidenceStatus.detected), outcome('debug', EvidenceStatus.failed)]);
      final assessment = Assessment(id: 'root-assessment', threat: 'ROOT', severity: Severity.high, confidence: Confidence.high, supportingEvidence: [outcome('root', EvidenceStatus.detected)], reason: 'test');
      final risk = evaluator.evaluate([assessment], signalRun: run);
      expect(risk.level, RiskLevel.highRisk);
      expect(risk.uncertainties, isNotEmpty);
    });
  });
}
