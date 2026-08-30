import 'package:flutter_test/flutter_test.dart';
import 'package:kryvon/src/domain/assessment.dart';
import 'package:kryvon/src/domain/kryvon_enums.dart';
import 'package:kryvon/src/domain/policy.dart';
import 'package:kryvon/src/domain/risk.dart';

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

    test('returns unknown for no assessments', () {
      final result = evaluator.evaluate(const []);
      expect(result.level, RiskLevel.unknown);
      expect(result.contributors, isEmpty);
    });

    test('maps severity to risk', () {
      expect(
        evaluator.evaluate([assessment(severity: Severity.low)]).level,
        RiskLevel.lowRisk,
      );
      expect(
        evaluator.evaluate([assessment(severity: Severity.medium)]).level,
        RiskLevel.elevated,
      );
      expect(
        evaluator.evaluate([assessment(severity: Severity.high)]).level,
        RiskLevel.highRisk,
      );
      expect(
        evaluator.evaluate([assessment(severity: Severity.critical)]).level,
        RiskLevel.critical,
      );
    });

    test('preserves low-confidence uncertainty', () {
      final result = evaluator.evaluate([
        assessment(severity: Severity.high, confidence: Confidence.low),
      ]);
      expect(result.level, RiskLevel.elevated);
      expect(result.uncertainties, isNotEmpty);
    });

    test('preserves assessment contributors', () {
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
      expect(
        policy.decide(
          context: AssessmentContext.appStartup,
          risk: const RiskAssessment(level: RiskLevel.lowRisk, contributors: []),
        ),
        KryvonDecision.allow,
      );
    });

    test('monitors elevated startup risk', () {
      expect(
        policy.decide(
          context: AssessmentContext.appStartup,
          risk: const RiskAssessment(level: RiskLevel.elevated, contributors: []),
        ),
        KryvonDecision.monitor,
      );
    });

    test('restricts elevated transaction risk', () {
      expect(
        policy.decide(
          context: AssessmentContext.transaction,
          risk: const RiskAssessment(level: RiskLevel.elevated, contributors: []),
        ),
        KryvonDecision.restrict,
      );
    });

    test('restricts high risk and blocks critical risk by default', () {
      expect(
        policy.decide(
          context: AssessmentContext.accountAccess,
          risk: const RiskAssessment(level: RiskLevel.highRisk, contributors: []),
        ),
        KryvonDecision.restrict,
      );
      expect(
        policy.decide(
          context: AssessmentContext.transaction,
          risk: const RiskAssessment(level: RiskLevel.critical, contributors: []),
        ),
        KryvonDecision.block,
      );
    });

    test('supports a custom unknown-risk decision', () {
      const strict = KryvonPolicy(unknownDecision: KryvonDecision.block);
      expect(
        strict.decide(
          context: AssessmentContext.transaction,
          risk: const RiskAssessment(level: RiskLevel.unknown, contributors: []),
        ),
        KryvonDecision.block,
      );
    });
  });
}
