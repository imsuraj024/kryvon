import 'package:flutter_test/flutter_test.dart';
import 'package:kryvon/kryvon.dart';

Assessment assessment({String id = 'root-signal', Severity severity = Severity.high, Confidence confidence = Confidence.high}) {
  return Assessment(id: id, threat: 'ROOT_INDICATOR', severity: severity, confidence: confidence, supportingEvidence: const [], reason: 'A test assessment.');
}

void main() {
  const engine = KryvonEngine();

  group('KryvonEngine', () {
    test('returns an explainable unknown result when no assessments are supplied', () {
      final result = engine.evaluate(context: AssessmentContext.appStartup, assessments: const []);
      expect(result.risk.level, RiskLevel.unknown);
      expect(result.decision, KryvonDecision.monitor);
      expect(result.policyId, 'default');
      expect(result.policyVersion, 1);
      expect(result.reason, contains('not a detected threat'));
    });

    test('connects assessment, risk, policy and result in one call', () {
      final result = engine.evaluate(context: AssessmentContext.accountAccess, assessments: [assessment()]);
      expect(result.risk.level, RiskLevel.highRisk);
      expect(result.decision, KryvonDecision.restrict);
      expect(result.risk.contributors.single.assessmentId, 'root-signal');
      expect(result.reason, contains('RESTRICT'));
      expect(result.reason, contains('accountAccess'));
    });

    test('preserves severe risk even when confidence is low', () {
      final result = engine.evaluate(context: AssessmentContext.transaction, assessments: [assessment(confidence: Confidence.low)]);
      expect(result.risk.level, RiskLevel.highRisk);
      expect(result.decision, KryvonDecision.restrict);
      expect(result.risk.uncertainties, isNotEmpty);
      expect(result.reason, contains('uncertainty'));
    });

    test('uses the supplied policy and records its identity', () {
      const policy = KryvonPolicy(id: 'strict-app', version: 3, unknownDecision: KryvonDecision.block);
      final result = engine.evaluate(context: AssessmentContext.authentication, assessments: const [], policy: policy);
      expect(result.decision, KryvonDecision.block);
      expect(result.policyId, 'strict-app');
      expect(result.policyVersion, 3);
    });

    test('restricts elevated risk for transactions but monitors startup by default', () {
      final assessments = [assessment(severity: Severity.medium)];
      expect(engine.evaluate(context: AssessmentContext.appStartup, assessments: assessments).decision, KryvonDecision.monitor);
      expect(engine.evaluate(context: AssessmentContext.transaction, assessments: assessments).decision, KryvonDecision.restrict);
    });
  });

  group('domain collection immutability', () {
    test('assessment snapshots its supporting evidence list', () {
      final evidence = Evidence(signal: 'test', status: EvidenceStatus.detected, confidence: Confidence.high, source: 'unit-test', platform: 'test', observedAt: DateTime.utc(2026), metadata: {'key': 'value'});
      final source = <Evidence>[evidence];
      final item = Assessment(id: 'a', threat: 't', severity: Severity.low, confidence: Confidence.high, supportingEvidence: source, reason: 'test');
      source.clear();
      expect(item.supportingEvidence, hasLength(1));
      expect(() => item.supportingEvidence.clear(), throwsUnsupportedError);
    });

    test('evidence snapshots metadata', () {
      final metadata = <String, Object?>{'key': 'before'};
      final evidence = Evidence(signal: 'test', status: EvidenceStatus.detected, confidence: Confidence.high, source: 'unit-test', platform: 'test', observedAt: DateTime.utc(2026), metadata: metadata);
      metadata['key'] = 'after';
      expect(evidence.metadata['key'], 'before');
      expect(() => evidence.metadata['new'] = true, throwsUnsupportedError);
    });
  });
}
