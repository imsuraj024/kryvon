import 'package:flutter_test/flutter_test.dart';
import 'package:kryvon/kryvon.dart';

Evidence evidence(
  String signal,
  EvidenceStatus status, {
  Confidence? confidence = Confidence.high,
}) =>
    Evidence(
      signal: signal,
      status: status,
      confidence: confidence,
      source: 'test.detector',
      platform: 'test',
      observedAt: DateTime.utc(2026),
    );

AssessmentRule rule({
  String id = 'rule-a',
  String threat = 'THREAT_A',
  Severity severity = Severity.high,
  String reason = 'Explicit test rule matched.',
  String? correlationKey,
  String? conflictGroup,
  List<EvidenceRequirement>? requirements,
}) =>
    AssessmentRule(
      id: id,
      threat: threat,
      severity: severity,
      reason: reason,
      correlationKey: correlationKey,
      conflictGroup: conflictGroup,
      requirements: requirements ??
          [
            EvidenceRequirement(
              signalId: 'a',
              expectedStatus: EvidenceStatus.detected,
              minimumConfidence: Confidence.medium,
            ),
          ],
    );

SignalRun run(
  List<String> expected,
  List<Evidence> outcomes,
) =>
    SignalRun(expectedSignals: expected, outcomes: outcomes);

void main() {
  group('AssessmentGenerator', () {
    test('generates an assessment from explicit matching evidence', () {
      final result = AssessmentGenerator(rules: [rule()]).generate(
        run(['a'], [evidence('a', EvidenceStatus.detected)]),
      );

      expect(result.assessments, hasLength(1));
      expect(result.assessments.single.id, 'rule-a');
      expect(result.assessments.single.threat, 'THREAT_A');
      expect(result.assessments.single.severity, Severity.high);
      expect(result.assessments.single.confidence, Confidence.high);
      expect(result.assessments.single.supportingEvidence.map((e) => e.signal), ['a']);
      expect(result.diagnostics, isEmpty);
    });

    test('opposite status is a normal non-match', () {
      final result = AssessmentGenerator(rules: [rule()]).generate(
        run(['a'], [evidence('a', EvidenceStatus.notDetected)]),
      );

      expect(result.assessments, isEmpty);
      expect(
        result.diagnostics.any((d) => d.ruleId == 'rule-a' && d.code == AssessmentGenerationIssueCode.inconclusiveEvidence),
        isFalse,
      );
    });

    test('requires configured minimum confidence', () {
      final result = AssessmentGenerator(
        rules: [
          rule(
            requirements: [
              EvidenceRequirement(
                signalId: 'a',
                expectedStatus: EvidenceStatus.detected,
                minimumConfidence: Confidence.high,
              ),
            ],
          ),
        ],
      ).generate(run(['a'], [
        evidence('a', EvidenceStatus.detected, confidence: Confidence.medium),
      ]));

      expect(result.assessments, isEmpty);
      expect(
        result.diagnostics.any((d) => d.ruleId == 'rule-a' && d.code == AssessmentGenerationIssueCode.insufficientConfidence),
        isTrue,
      );
    });

    test('derives assessment confidence from weakest supporting evidence', () {
      final result = AssessmentGenerator(
        rules: [
          rule(
            requirements: [
              EvidenceRequirement(
                signalId: 'a',
                expectedStatus: EvidenceStatus.detected,
                minimumConfidence: Confidence.low,
              ),
              EvidenceRequirement(
                signalId: 'b',
                expectedStatus: EvidenceStatus.detected,
                minimumConfidence: Confidence.low,
              ),
            ],
          ),
        ],
      ).generate(run(['a', 'b'], [
        evidence('a', EvidenceStatus.detected, confidence: Confidence.high),
        evidence('b', EvidenceStatus.detected, confidence: Confidence.medium),
      ]));

      expect(result.assessments.single.confidence, Confidence.medium);
      expect(result.assessments.single.supportingEvidence.map((e) => e.signal), ['a', 'b']);
    });

    test('rejects a NOT_DETECTED requirement below high confidence', () {
      expect(
        () => EvidenceRequirement(
          signalId: 'a',
          expectedStatus: EvidenceStatus.notDetected,
          minimumConfidence: Confidence.medium,
        ),
        throwsArgumentError,
      );
    });

    test('missing evidence cannot match a rule', () {
      final result = AssessmentGenerator(rules: [rule()]).generate(run(['a', 'b'], []));

      expect(result.assessments, isEmpty);
      expect(
        result.diagnostics.any((d) => d.ruleId == 'rule-a' && d.code == AssessmentGenerationIssueCode.missingEvidence),
        isTrue,
      );
    });

    test('duplicate evidence is never resolved by selecting the first item', () {
      final result = AssessmentGenerator(rules: [rule()]).generate(
        run(['a'], [
          evidence('a', EvidenceStatus.detected),
          evidence('a', EvidenceStatus.detected),
        ]),
      );

      expect(result.assessments, isEmpty);
      expect(
        result.diagnostics.any((d) => d.code == AssessmentGenerationIssueCode.duplicateEvidence),
        isTrue,
      );
    });

    test('failed, unknown, unsupported and null-confidence evidence do not match', () {
      for (final status in [
        EvidenceStatus.failed,
        EvidenceStatus.unknown,
        EvidenceStatus.unsupported,
      ]) {
        final result = AssessmentGenerator(rules: [rule()]).generate(
          run(['a'], [evidence('a', status, confidence: null)]),
        );
        expect(result.assessments, isEmpty, reason: status.name);
        expect(
          result.diagnostics.any((d) => d.code == AssessmentGenerationIssueCode.inconclusiveEvidence),
          isTrue,
          reason: status.name,
        );
      }

      final missingConfidence = AssessmentGenerator(rules: [rule()]).generate(
        run(['a'], [evidence('a', EvidenceStatus.detected, confidence: null)]),
      );
      expect(missingConfidence.assessments, isEmpty);
      expect(
        missingConfidence.diagnostics.any((d) => d.code == AssessmentGenerationIssueCode.missingConfidence),
        isTrue,
      );
    });

    test('generates a fully supported rule despite unrelated incomplete coverage', () {
      final result = AssessmentGenerator(rules: [rule()]).generate(
        run(['a', 'b'], [evidence('a', EvidenceStatus.detected)]),
      );

      expect(result.assessments, hasLength(1));
      expect(
        result.diagnostics.any((d) => d.signalId == 'b' && d.code == AssessmentGenerationIssueCode.missingEvidence),
        isTrue,
      );
    });

    test('suppresses every matching rule in an explicit conflict group', () {
      final result = AssessmentGenerator(rules: [
        rule(id: 'first', conflictGroup: 'exclusive'),
        rule(id: 'second', threat: 'THREAT_B', conflictGroup: 'exclusive'),
        rule(id: 'independent', conflictGroup: 'other'),
      ]).generate(run(['a'], [evidence('a', EvidenceStatus.detected)]));

      expect(result.assessments.map((a) => a.id), ['independent']);
      expect(result.conflicts, hasLength(1));
      expect(result.conflicts.single.group, 'exclusive');
      expect(result.conflicts.single.ruleIds, ['first', 'second']);
    });

    test('does not infer correlation from shared threat IDs', () {
      final result = AssessmentGenerator(rules: [
        rule(id: 'one', threat: 'SAME'),
        rule(id: 'two', threat: 'SAME'),
      ]).generate(run(['a'], [evidence('a', EvidenceStatus.detected)]));

      expect(result.assessments, hasLength(2));
      expect(result.assessments.every((a) => a.correlationKey == null), isTrue);
    });

    test('copies only explicitly configured correlation keys', () {
      final result = AssessmentGenerator(
        rules: [rule(correlationKey: ' explicit-root ')],
      ).generate(run(['a'], [evidence('a', EvidenceStatus.detected)]));

      expect(result.assessments.single.correlationKey, 'explicit-root');
    });

    test('rejects duplicate rule IDs and malformed run coverage', () {
      expect(
        () => AssessmentGenerator(rules: [rule(id: 'same'), rule(id: ' same ')]),
        throwsArgumentError,
      );

      final result = AssessmentGenerator(rules: [rule()]).generate(
        run(['a', ' a '], [evidence('a', EvidenceStatus.detected)]),
      );
      expect(result.assessments, isEmpty);
      expect(
        result.diagnostics.any((d) => d.code == AssessmentGenerationIssueCode.invalidSignalCoverage),
        isTrue,
      );
    });

    test('returns immutable result collections', () {
      final result = AssessmentGenerator(rules: [rule()]).generate(
        run(['a'], [evidence('a', EvidenceStatus.detected)]),
      );

      expect(
        () => result.assessments.add(rule().toAssessmentForTest()),
        throwsUnsupportedError,
      );
      expect(
        () => result.diagnostics.add(
          const AssessmentGenerationDiagnostic(
            code: AssessmentGenerationIssueCode.missingEvidence,
          ),
        ),
        throwsUnsupportedError,
      );
    });
  });
}

extension _AssessmentTestHelper on AssessmentRule {
  Assessment toAssessmentForTest() => Assessment(
        id: id,
        threat: threat,
        severity: severity,
        confidence: Confidence.high,
        supportingEvidence: const [],
        reason: reason,
      );
}
