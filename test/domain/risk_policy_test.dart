import 'package:flutter_test/flutter_test.dart';

import '../../lib/src/domain/assessment.dart';
import '../../lib/src/domain/kryvon_enums.dart';
import '../../lib/src/domain/policy.dart';
import '../../lib/src/domain/risk.dart';

Assessment assessment({
  String id = 'a1',
  Severity severity = Severity.medium,
  Confidence confidence = Confidence.high,
}) {
  return Assessment(
    id: id,
    threat: 'TEST_THREAT',
    severity: severity,
    confidence: confidence,
    supportingEvidence: const [],
    reason: 'test reason',
  );
}

void main() {
  group('RiskEvaluator', () {
    const evaluator = RiskEvaluator();

    test('returns unknown when there are no assessments', () {
      final result = evaluator.evaluate(const []);
      expect(result.level, RiskLevel.unknown);
      expect(result.contributors, isEmpty);
    });

    test('maps low severity to low risk', () {
      final result = evaluator.evaluate([
        assessment(severity: Severity.low),
      ]);
      expect(result.level, RiskLevel.lowRisk);
    });

    test('maps medium severity to elevated risk', () {
      final result = evaluator.evaluate([
        assessment(severity: Severity.medium),
      ]);
      expect(result.level, RiskLevel.elevated);
    });

    test('maps high severity with high confidence to high risk', () {
      final result = evaluator.evaluate([
        assessment(severity: Severity.high),
      ]);
      expect(result.level, RiskLevel.highRisk);
    });

    test('maps high severity with low confidence to elevated risk and uncertainty', () {
      final result = evaluator.evaluate([
        assessment(severity: Severity.high, confidence: Confidence.low),
      ]);
      expect(result.level, RiskLevel.elevated);
      expect(result.uncertainties, isNotEmpty);
    });

    test('maps critical severity to critical risk', () {
      final result = evaluator.evaluate([
        assessment(severity: Severity.critical),
      ]);
      expect(result.level, RiskLevel.critical);
    });

    test('preserves every assessment as a contributor', () {
      final result = evaluator.evaluate([
        assessment(id: 'a1', severity: Severity.low),
        assessment(id: 'a2', severity: Severity.high),
      ]);
      expect(result.contributors.map((e) => e.assessmentId), ['a1', 'a2']);
    });
  });

  group('KryvonPolicy', () {
    const policy = KryvonPolicy();

    test('allows low risk', () {
      final result = policy.decide(
        context: AssessmentContext.appStartup,
        risk: const RiskAssessment(level: RiskLevel.lowRisk),
      );
      expect(result, KryvonDecision.allow);
    });

    test('monitors elevated startup risk', () {
      final result = policy.decide(
        context: AssessmentContext.appStartup,
        risk: const RiskAssessment(level: RiskLevel.elevated),
      );
      expect(result, KryvonDecision.monitor);
    });

    test('restricts elevated transaction risk', () {
      final result = policy.decide(
        context: AssessmentContext.transaction,
        risk: const RiskAssessment(level: RiskLevel.elevated),
      );
      expect(result, KryvonDecision.restrict);
    });

    test('restricts high risk by default', () {
      final result = policy.decide(
        context: AssessmentContext.accountAccess,
        risk: const RiskAssessment(level: RiskLevel.highRisk),
      );
      expect(result, KryvonDecision.restrict);
    });

    test('blocks critical risk by default', () {
      final result = policy.decide(
        context: AssessmentContext.transaction,
        risk: const RiskAssessment(level: RiskLevel.critical),
      );
      expect(result, KryvonDecision.block);
    });

    test('uses the configured unknown decision', () {
      const strict = KryvonPolicy(unknownDecision: KryvonDecision.block);
      final result = strict.decide(
        context: AssessmentContext.transaction,
        risk: const RiskAssessment(level: RiskLevel.unknown),
      );
      expect(result, KryvonDecision.block);
    });
  });
}
