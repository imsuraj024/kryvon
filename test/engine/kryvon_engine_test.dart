import 'package:flutter_test/flutter_test.dart';
import 'package:kryvon/kryvon.dart';

Assessment assessment({
  String id = 'root-signal',
  Severity severity = Severity.high,
  Confidence confidence = Confidence.high,
}) => Assessment(
  id: id,
  threat: 'ROOT_INDICATOR',
  severity: severity,
  confidence: confidence,
  supportingEvidence: const [],
  reason: 'A test assessment.',
);
Evidence outcome(String signal, EvidenceStatus status) => Evidence(
  signal: signal,
  status: status,
  confidence:
      status == EvidenceStatus.failed ||
          status == EvidenceStatus.unknown ||
          status == EvidenceStatus.unsupported
      ? null
      : Confidence.high,
  source: 'test',
  platform: 'test',
  observedAt: DateTime.utc(2026),
);

void main() {
  const engine = KryvonEngine();

  group('KryvonEngine', () {
    test(
      'returns an explainable unknown result when neither assessments nor coverage are supplied',
      () {
        final result = engine.evaluate(
          context: AssessmentContext.appStartup,
          assessments: const [],
        );
        expect(result.risk.level, RiskLevel.unknown);
        expect(result.decision, KryvonDecision.monitor);
        expect(result.policyId, 'default');
        expect(result.policyVersion, 1);
        expect(result.reason, contains('not a detected threat'));
      },
    );

    test('complete all-negative coverage can establish low risk', () {
      final run = SignalRun(
        expectedSignals: ['root', 'debug'],
        outcomes: [
          outcome('root', EvidenceStatus.notDetected),
          outcome('debug', EvidenceStatus.notDetected),
        ],
      );
      final result = engine.evaluate(
        context: AssessmentContext.appStartup,
        assessments: const [],
        signalRun: run,
      );
      expect(result.risk.level, RiskLevel.lowRisk);
      expect(result.decision, KryvonDecision.allow);
      expect(result.risk.uncertainties, isEmpty);
    });

    test('does not treat failed coverage as safe', () {
      final run = SignalRun(
        expectedSignals: ['root'],
        outcomes: [outcome('root', EvidenceStatus.failed)],
      );
      final result = engine.evaluate(
        context: AssessmentContext.appStartup,
        assessments: const [],
        signalRun: run,
      );
      expect(result.risk.level, RiskLevel.unknown);
      expect(result.decision, KryvonDecision.monitor);
      expect(result.risk.uncertainties, isNotEmpty);
    });

    test('connects assessment, risk, policy and result in one call', () {
      final result = engine.evaluate(
        context: AssessmentContext.accountAccess,
        assessments: [assessment()],
      );
      expect(result.risk.level, RiskLevel.highRisk);
      expect(result.decision, KryvonDecision.restrict);
      expect(result.risk.contributors.single.assessmentId, 'root-signal');
      expect(result.reason, contains('restrict'));
      expect(result.reason, contains('accountAccess'));
    });

    test('preserves severe risk even when confidence is low', () {
      final result = engine.evaluate(
        context: AssessmentContext.transaction,
        assessments: [assessment(confidence: Confidence.low)],
      );
      expect(result.risk.level, RiskLevel.highRisk);
      expect(result.decision, KryvonDecision.restrict);
      expect(result.risk.uncertainties, isNotEmpty);
      expect(result.reason, contains('uncertainty'));
    });

    test('uses the supplied policy and records its identity', () {
      const policy = KryvonPolicy(
        id: 'strict-app',
        version: 3,
        unknownDecision: KryvonDecision.block,
      );
      final result = engine.evaluate(
        context: AssessmentContext.authentication,
        assessments: const [],
        policy: policy,
      );
      expect(result.decision, KryvonDecision.block);
      expect(result.policyId, 'strict-app');
      expect(result.policyVersion, 3);
    });

    test(
      'restricts elevated risk for transactions but monitors startup by default',
      () {
        final assessments = [assessment(severity: Severity.medium)];
        expect(
          engine
              .evaluate(
                context: AssessmentContext.appStartup,
                assessments: assessments,
              )
              .decision,
          KryvonDecision.monitor,
        );
        expect(
          engine
              .evaluate(
                context: AssessmentContext.transaction,
                assessments: assessments,
              )
              .decision,
          KryvonDecision.restrict,
        );
      },
    );
  });

  group('domain collection immutability', () {
    test('assessment snapshots its supporting evidence list', () {
      final evidence = outcome('test', EvidenceStatus.detected);
      final source = <Evidence>[evidence];
      final item = Assessment(
        id: 'a',
        threat: 't',
        severity: Severity.low,
        confidence: Confidence.high,
        supportingEvidence: source,
        reason: 'test',
      );
      source.clear();
      expect(item.supportingEvidence, hasLength(1));
      expect(() => item.supportingEvidence.clear(), throwsUnsupportedError);
    });

    test('evidence snapshots metadata', () {
      final nestedItems = <Object?>['before'];
      final nested = <String, Object?>{'items': nestedItems};
      final metadata = <String, Object?>{'key': 'before', 'nested': nested};
      final evidence = Evidence(
        signal: 'test',
        status: EvidenceStatus.detected,
        confidence: Confidence.high,
        source: 'unit-test',
        platform: 'test',
        observedAt: DateTime.utc(2026),
        metadata: metadata,
      );
      metadata['key'] = 'after';
      nested['new'] = true;
      nestedItems.add('after');
      expect(evidence.metadata['key'], 'before');
      expect(() => evidence.metadata['new'] = true, throwsUnsupportedError);
      final frozenNested = evidence.metadata['nested'] as Map;
      final frozenItems = frozenNested['items'] as List;
      expect(frozenNested.containsKey('new'), isFalse);
      expect(frozenItems, ['before']);
      expect(() => frozenNested['new'] = true, throwsUnsupportedError);
      expect(() => frozenItems.add('mutation'), throwsUnsupportedError);
    });
  });
}
