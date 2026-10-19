import 'package:flutter_test/flutter_test.dart';
import 'package:kryvon/kryvon.dart';

Assessment assessment({String id = 'a1', Severity severity = Severity.medium, Confidence confidence = Confidence.high}) {
  return Assessment(id: id, threat: 'TEST_THREAT', severity: severity, confidence: confidence, supportingEvidence: const [], reason: 'test reason');
}

void main() {
  group('RiskEvaluator', () {
    const evaluator = RiskEvaluator();

    test('returns unknown with uncertainty when no assessments exist', () {
      final result = evaluator.evaluate(const []);
      expect(result.level, RiskLevel.unknown);
      expect(result.contributors, isEmpty);
      expect(result.uncertainties, isNotEmpty);
    });

    test('maps the highest severity to risk', () {
      expect(evaluator.evaluate([assessment(severity: Severity.info)]).level, RiskLevel.lowRisk);
      expect(evaluator.evaluate([assessment(severity: Severity.low)]).level, RiskLevel.lowRisk);
      expect(evaluator.evaluate([assessment(severity: Severity.medium)]).level, RiskLevel.elevated);
      expect(evaluator.evaluate([assessment(severity: Severity.high)]).level, RiskLevel.highRisk);
      expect(evaluator.evaluate([assessment(severity: Severity.critical)]).level, RiskLevel.critical);
    });

    test('does not downgrade high severity because confidence is low', () {
      final result = evaluator.evaluate([assessment(severity: Severity.high, confidence: Confidence.low)]);
      expect(result.level, RiskLevel.highRisk);
      expect(result.uncertainties, hasLength(1));
    });

    test('records medium and low confidence as uncertainty', () {
      final result = evaluator.evaluate([
        assessment(id: 'low', confidence: Confidence.low),
        assessment(id: 'medium', confidence: Confidence.medium),
      ]);
      expect(result.uncertainties, hasLength(2));
    });

    test('preserves contributors in input order', () {
      final result = evaluator.evaluate([assessment(id: 'a1', severity: Severity.low), assessment(id: 'a2', severity: Severity.high)]);
      expect(result.contributors.map((e) => e.assessmentId), ['a1', 'a2']);
    });

    test('result collections cannot be mutated by consumers', () {
      final result = evaluator.evaluate([assessment(confidence: Confidence.low)]);
      expect(() => result.contributors.add(const RiskContributor(assessmentId: 'x', severity: Severity.low, confidence: Confidence.high, reason: 'x')), throwsUnsupportedError);
      expect(() => result.uncertainties.add('mutated'), throwsUnsupportedError);
    });
  });

  group('KryvonPolicy', () {
    const policy = KryvonPolicy();
    RiskAssessment risk(RiskLevel level) => RiskAssessment(level: level, contributors: const []);

    test('maps every default risk level explicitly', () {
      expect(policy.decide(context: AssessmentContext.appStartup, risk: risk(RiskLevel.lowRisk)), KryvonDecision.allow);
      expect(policy.decide(context: AssessmentContext.appStartup, risk: risk(RiskLevel.elevated)), KryvonDecision.monitor);
      expect(policy.decide(context: AssessmentContext.transaction, risk: risk(RiskLevel.elevated)), KryvonDecision.restrict);
      expect(policy.decide(context: AssessmentContext.accountAccess, risk: risk(RiskLevel.highRisk)), KryvonDecision.restrict);
      expect(policy.decide(context: AssessmentContext.transaction, risk: risk(RiskLevel.critical)), KryvonDecision.block);
      expect(policy.decide(context: AssessmentContext.transaction, risk: risk(RiskLevel.unknown)), KryvonDecision.monitor);
    });

    test('supports explicit overrides for unknown and elevated risk', () {
      const strict = KryvonPolicy(unknownDecision: KryvonDecision.block, elevatedRiskDecision: KryvonDecision.restrict, elevatedTransactionDecision: KryvonDecision.block);
      expect(strict.decide(context: AssessmentContext.appStartup, risk: risk(RiskLevel.unknown)), KryvonDecision.block);
      expect(strict.decide(context: AssessmentContext.sessionStart, risk: risk(RiskLevel.elevated)), KryvonDecision.restrict);
      expect(strict.decide(context: AssessmentContext.transaction, risk: risk(RiskLevel.elevated)), KryvonDecision.block);
    });
  });
}
