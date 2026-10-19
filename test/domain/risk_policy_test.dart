import 'package:flutter_test/flutter_test.dart';
import 'package:kryvon/kryvon.dart';

Assessment assessment({String id = 'a1', Severity severity = Severity.medium, Confidence confidence = Confidence.high}) => Assessment(id: id, threat: 'TEST_THREAT', severity: severity, confidence: confidence, supportingEvidence: const [], reason: 'test reason');

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
      final result = evaluator.evaluate([assessment(id: 'low', confidence: Confidence.low), assessment(id: 'medium', confidence: Confidence.medium)]);
      expect(result.uncertainties, hasLength(2));
    });

    test('rejects blank or duplicate assessment IDs', () {
      expect(
        () => evaluator.evaluate([assessment(id: '  ')]),
        throwsArgumentError,
      );
      expect(
        () => evaluator.evaluate([
          assessment(id: 'same'),
          assessment(id: ' same '),
        ]),
        throwsArgumentError,
      );
    });

    test('rejects blank threat, reason, and correlation identifiers', () {
      Assessment build({
        String id = 'id',
        String threat = 'threat',
        String reason = 'reason',
        String? correlationKey,
      }) => Assessment(
        id: id,
        threat: threat,
        severity: Severity.low,
        confidence: Confidence.high,
        supportingEvidence: const [],
        reason: reason,
        correlationKey: correlationKey,
      );

      expect(() => evaluator.evaluate([build(threat: ' ')]), throwsArgumentError);
      expect(() => evaluator.evaluate([build(reason: ' ')]), throwsArgumentError);
      expect(() => evaluator.evaluate([build(correlationKey: ' ')]), throwsArgumentError);
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

    test('keeps correlated contributors traceable without counting them as independent', () {
      final result = evaluator.evaluate([
        Assessment(id: 'a1', threat: 'ROOT_ARTIFACT', severity: Severity.high, confidence: Confidence.high, supportingEvidence: const [], reason: 'root file', correlationKey: 'device-compromise'),
        Assessment(id: 'a2', threat: 'ROOT_ARTIFACT', severity: Severity.high, confidence: Confidence.high, supportingEvidence: const [], reason: 'root property', correlationKey: 'device-compromise'),
        assessment(id: 'a3', severity: Severity.medium),
      ]);
      expect(result.level, RiskLevel.highRisk);
      expect(result.contributors, hasLength(3));
      expect(result.independentContributorCount, 2);
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

    test('rejects blank policy IDs and non-positive versions at engine boundary', () {
      const engine = KryvonEngine();
      expect(
        () => engine.evaluate(
          context: AssessmentContext.appStartup,
          assessments: const [],
          policy: KryvonPolicy(id: '  '),
        ),
        throwsArgumentError,
      );
      expect(
        () => engine.evaluate(
          context: AssessmentContext.appStartup,
          assessments: const [],
          policy: KryvonPolicy(version: 0),
        ),
        throwsArgumentError,
      );
    });

    test('supports explicit overrides for unknown and elevated risk', () {
      const strict = KryvonPolicy(unknownDecision: KryvonDecision.block, elevatedRiskDecision: KryvonDecision.restrict, elevatedTransactionDecision: KryvonDecision.block);
      expect(strict.decide(context: AssessmentContext.appStartup, risk: risk(RiskLevel.unknown)), KryvonDecision.block);
      expect(strict.decide(context: AssessmentContext.sessionStart, risk: risk(RiskLevel.elevated)), KryvonDecision.restrict);
      expect(strict.decide(context: AssessmentContext.transaction, risk: risk(RiskLevel.elevated)), KryvonDecision.block);
    });
  });
}
