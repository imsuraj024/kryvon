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
      source: 'fixture.android',
      platform: 'android',
      observedAt: DateTime.utc(2026, 10, 19),
      metadata: const {},
    );

void main() {
  group('first Android threat rules', () {
    final generator = AssessmentGenerator(rules: firstAndroidThreatRules);

    test('positive fixtures emit only the corresponding assessment', () {
      final root = generator.generate(SignalRun(
        expectedSignals: ['android.root.su_binary_present'],
        outcomes: [
          evidence(
            'android.root.su_binary_present',
            EvidenceStatus.detected,
            confidence: Confidence.medium,
          ),
        ],
      ));
      expect(root.assessments.map((a) => a.id),
          ['android.root.su-binary-indicator.v1']);

      final debugger = generator.generate(SignalRun(
        expectedSignals: ['android.debugger.attached'],
        outcomes: [
          evidence('android.debugger.attached', EvidenceStatus.detected),
        ],
      ));
      expect(debugger.assessments.map((a) => a.id),
          ['android.debugger-attached.v1']);
    });

    test('negative fixtures do not emit threat assessments', () {
      final result = generator.generate(SignalRun(
        expectedSignals: [
          'android.root.su_binary_present',
          'android.debugger.attached',
        ],
        outcomes: [
          evidence('android.root.su_binary_present', EvidenceStatus.notDetected),
          evidence('android.debugger.attached', EvidenceStatus.notDetected),
        ],
      ));
      expect(result.assessments, isEmpty);
      expect(result.conflicts, isEmpty);
    });

    test('conflicting outcomes are not resolved by selecting a winner', () {
      final result = generator.generate(SignalRun(
        expectedSignals: ['android.debugger.attached'],
        outcomes: [
          evidence('android.debugger.attached', EvidenceStatus.detected),
          evidence('android.debugger.attached', EvidenceStatus.notDetected),
        ],
      ));
      expect(result.assessments, isEmpty);
      expect(
        result.diagnostics.any(
          (d) => d.code == AssessmentGenerationIssueCode.duplicateEvidence,
        ),
        isTrue,
      );
    });

    test('failure fixture never becomes a threat or a negative result', () {
      final result = generator.generate(SignalRun(
        expectedSignals: ['android.debugger.attached'],
        outcomes: [
          evidence(
            'android.debugger.attached',
            EvidenceStatus.failed,
            confidence: null,
          ),
        ],
      ));
      expect(result.assessments, isEmpty);
      expect(
        result.diagnostics.any(
          (d) => d.code == AssessmentGenerationIssueCode.inconclusiveEvidence,
        ),
        isTrue,
      );
    });

    test('debugger rule rejects medium-confidence positive evidence', () {
      final result = generator.generate(SignalRun(
        expectedSignals: ['android.debugger.attached'],
        outcomes: [
          evidence(
            'android.debugger.attached',
            EvidenceStatus.detected,
            confidence: Confidence.medium,
          ),
        ],
      ));
      expect(result.assessments, isEmpty);
      expect(
        result.diagnostics.any(
          (d) => d.code == AssessmentGenerationIssueCode.insufficientConfidence,
        ),
        isTrue,
      );
    });

    test('unsupported and unknown stay inconclusive', () {
      for (final status in [
        EvidenceStatus.unsupported,
        EvidenceStatus.unknown,
      ]) {
        final result = generator.generate(SignalRun(
          expectedSignals: ['android.debugger.attached'],
          outcomes: [
            evidence('android.debugger.attached', status, confidence: null),
          ],
        ));
        expect(result.assessments, isEmpty, reason: status.name);
        expect(
          result.diagnostics.any(
            (d) => d.code == AssessmentGenerationIssueCode.inconclusiveEvidence,
          ),
          isTrue,
          reason: status.name,
        );
      }
    });
  });
}
