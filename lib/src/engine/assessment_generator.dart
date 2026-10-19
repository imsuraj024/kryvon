import '../domain/assessment.dart';
import '../domain/evidence.dart';
import '../domain/kryvon_enums.dart';
import '../domain/signal_run.dart';

/// The status and confidence required for one rule input.
class EvidenceRequirement {
  EvidenceRequirement({
    required String signalId,
    required this.expectedStatus,
    this.minimumConfidence = Confidence.high,
  }) : signalId = signalId.trim() {
    if (this.signalId.isEmpty) {
      throw ArgumentError.value(signalId, 'signalId', 'Signal ID must not be blank.');
    }
    if (expectedStatus != EvidenceStatus.detected &&
        expectedStatus != EvidenceStatus.notDetected) {
      throw ArgumentError.value(
        expectedStatus,
        'expectedStatus',
        'Only detected or notDetected can satisfy a rule.',
      );
    }
    if (expectedStatus == EvidenceStatus.notDetected &&
        minimumConfidence != Confidence.high) {
      throw ArgumentError.value(
        minimumConfidence,
        'minimumConfidence',
        'A notDetected requirement must require high confidence.',
      );
    }
  }

  final String signalId;
  final EvidenceStatus expectedStatus;
  final Confidence minimumConfidence;
}

/// An explicit, deterministic interpretation of a set of signal outcomes.
class AssessmentRule {
  AssessmentRule({
    required String id,
    required String threat,
    required this.severity,
    required String reason,
    required List<EvidenceRequirement> requirements,
    String? correlationKey,
    String? conflictGroup,
  })  : id = id.trim(),
        threat = threat.trim(),
        reason = reason.trim(),
        correlationKey = _normalizeOptional(correlationKey, 'correlationKey'),
        conflictGroup = _normalizeOptional(conflictGroup, 'conflictGroup'),
        requirements = List<EvidenceRequirement>.unmodifiable(requirements) {
    if (this.id.isEmpty) {
      throw ArgumentError.value(id, 'id', 'Rule ID must not be blank.');
    }
    if (this.threat.isEmpty) {
      throw ArgumentError.value(threat, 'threat', 'Threat ID must not be blank.');
    }
    if (this.reason.isEmpty) {
      throw ArgumentError.value(reason, 'reason', 'Reason must not be blank.');
    }
    if (this.requirements.isEmpty) {
      throw ArgumentError.value(
        requirements,
        'requirements',
        'A rule must have at least one evidence requirement.',
      );
    }
    final signalIds = this.requirements.map((r) => r.signalId).toSet();
    if (signalIds.length != this.requirements.length) {
      throw ArgumentError.value(
        requirements,
        'requirements',
        'A rule may require each signal only once.',
      );
    }
  }

  final String id;
  final String threat;
  final Severity severity;
  final String reason;
  final List<EvidenceRequirement> requirements;
  final String? correlationKey;
  final String? conflictGroup;
}

/// Machine-readable reason a rule or run could not be interpreted safely.
enum AssessmentGenerationIssueCode {
  invalidSignalCoverage,
  unexpectedEvidence,
  signalNotExpected,
  missingEvidence,
  duplicateEvidence,
  inconclusiveEvidence,
  missingConfidence,
  insufficientConfidence,
}

class AssessmentGenerationDiagnostic {
  const AssessmentGenerationDiagnostic({
    required this.code,
    this.ruleId,
    this.signalId,
  });

  /// Null for run-level diagnostics that do not belong to one rule.
  final String? ruleId;
  final String? signalId;
  final AssessmentGenerationIssueCode code;
}

class AssessmentRuleConflict {
  AssessmentRuleConflict({
    required this.group,
    required List<String> ruleIds,
  }) : ruleIds = List<String>.unmodifiable(ruleIds);

  final String group;
  final List<String> ruleIds;
}

class AssessmentGenerationResult {
  AssessmentGenerationResult({
    required List<Assessment> assessments,
    required List<AssessmentGenerationDiagnostic> diagnostics,
    required List<AssessmentRuleConflict> conflicts,
  })  : assessments = List<Assessment>.unmodifiable(assessments),
        diagnostics =
            List<AssessmentGenerationDiagnostic>.unmodifiable(diagnostics),
        conflicts = List<AssessmentRuleConflict>.unmodifiable(conflicts);

  final List<Assessment> assessments;
  final List<AssessmentGenerationDiagnostic> diagnostics;
  final List<AssessmentRuleConflict> conflicts;
}

/// Applies explicit rules without inferring threat, confidence, or correlation.
class AssessmentGenerator {
  AssessmentGenerator({required List<AssessmentRule> rules})
      : rules = List<AssessmentRule>.unmodifiable(rules) {
    final ids = <String>{};
    for (final rule in this.rules) {
      if (!ids.add(rule.id)) {
        throw ArgumentError.value(
          rule.id,
          'rules',
          'Rule IDs must be unique.',
        );
      }
    }
  }

  final List<AssessmentRule> rules;

  AssessmentGenerationResult generate(SignalRun run) {
    final diagnostics = <AssessmentGenerationDiagnostic>[];
    if (!run.hasUniqueExpectedSignals) {
      return AssessmentGenerationResult(
        assessments: const [],
        diagnostics: const [
          AssessmentGenerationDiagnostic(
            code: AssessmentGenerationIssueCode.invalidSignalCoverage,
          ),
        ],
        conflicts: const [],
      );
    }

    final expected = run.expectedSignals.toSet();
    final outcomesBySignal = <String, List<Evidence>>{};
    for (final outcome in run.outcomes) {
      if (!expected.contains(outcome.signal)) {
        diagnostics.add(
          AssessmentGenerationDiagnostic(
            code: AssessmentGenerationIssueCode.unexpectedEvidence,
            signalId: outcome.signal,
          ),
        );
        continue;
      }
      outcomesBySignal.putIfAbsent(outcome.signal, () => <Evidence>[]).add(outcome);
    }

    // Preserve run-level coverage issues, including signals no rule references.
    for (final signalId in run.expectedSignals) {
      final outcomes = outcomesBySignal[signalId] ?? const <Evidence>[];
      if (outcomes.isEmpty) {
        diagnostics.add(
          AssessmentGenerationDiagnostic(
            code: AssessmentGenerationIssueCode.missingEvidence,
            signalId: signalId,
          ),
        );
      } else if (outcomes.length > 1) {
        diagnostics.add(
          AssessmentGenerationDiagnostic(
            code: AssessmentGenerationIssueCode.duplicateEvidence,
            signalId: signalId,
          ),
        );
      } else {
        final outcome = outcomes.single;
        if (outcome.status == EvidenceStatus.failed ||
            outcome.status == EvidenceStatus.unknown ||
            outcome.status == EvidenceStatus.unsupported) {
          diagnostics.add(
            AssessmentGenerationDiagnostic(
              code: AssessmentGenerationIssueCode.inconclusiveEvidence,
              signalId: signalId,
            ),
          );
        } else if (outcome.confidence == null) {
          diagnostics.add(
            AssessmentGenerationDiagnostic(
              code: AssessmentGenerationIssueCode.missingConfidence,
              signalId: signalId,
            ),
          );
        } else if (outcome.status == EvidenceStatus.notDetected &&
            outcome.confidence != Confidence.high) {
          diagnostics.add(
            AssessmentGenerationDiagnostic(
              code: AssessmentGenerationIssueCode.insufficientConfidence,
              signalId: signalId,
            ),
          );
        }
      }
    }

    final candidates = <_AssessmentCandidate>[];
    for (final rule in rules) {
      var matched = true;
      final supportingEvidence = <Evidence>[];

      for (final requirement in rule.requirements) {
        if (!expected.contains(requirement.signalId)) {
          diagnostics.add(
            AssessmentGenerationDiagnostic(
              ruleId: rule.id,
              signalId: requirement.signalId,
              code: AssessmentGenerationIssueCode.signalNotExpected,
            ),
          );
          matched = false;
          continue;
        }

        final outcomes = outcomesBySignal[requirement.signalId] ?? const <Evidence>[];
        if (outcomes.isEmpty) {
          diagnostics.add(
            AssessmentGenerationDiagnostic(
              ruleId: rule.id,
              signalId: requirement.signalId,
              code: AssessmentGenerationIssueCode.missingEvidence,
            ),
          );
          matched = false;
          continue;
        }
        if (outcomes.length != 1) {
          diagnostics.add(
            AssessmentGenerationDiagnostic(
              ruleId: rule.id,
              signalId: requirement.signalId,
              code: AssessmentGenerationIssueCode.duplicateEvidence,
            ),
          );
          matched = false;
          continue;
        }

        final outcome = outcomes.single;
        if (outcome.status != EvidenceStatus.detected &&
            outcome.status != EvidenceStatus.notDetected) {
          diagnostics.add(
            AssessmentGenerationDiagnostic(
              ruleId: rule.id,
              signalId: requirement.signalId,
              code: AssessmentGenerationIssueCode.inconclusiveEvidence,
            ),
          );
          matched = false;
          continue;
        }
        if (outcome.status != requirement.expectedStatus) {
          // A valid opposite status disproves this rule's condition.
          matched = false;
          continue;
        }
        final confidence = outcome.confidence;
        if (confidence == null) {
          diagnostics.add(
            AssessmentGenerationDiagnostic(
              ruleId: rule.id,
              signalId: requirement.signalId,
              code: AssessmentGenerationIssueCode.missingConfidence,
            ),
          );
          matched = false;
          continue;
        }
        if (_confidenceRank(confidence) <
            _confidenceRank(requirement.minimumConfidence)) {
          diagnostics.add(
            AssessmentGenerationDiagnostic(
              ruleId: rule.id,
              signalId: requirement.signalId,
              code: AssessmentGenerationIssueCode.insufficientConfidence,
            ),
          );
          matched = false;
          continue;
        }
        supportingEvidence.add(outcome);
      }

      if (matched) {
        final confidence = supportingEvidence
            .map((evidence) => evidence.confidence!)
            .reduce(
              (left, right) => _confidenceRank(left) <= _confidenceRank(right)
                  ? left
                  : right,
            );
        candidates.add(
          _AssessmentCandidate(
            rule: rule,
            assessment: Assessment(
              id: rule.id,
              threat: rule.threat,
              severity: rule.severity,
              confidence: confidence,
              supportingEvidence: supportingEvidence,
              reason: rule.reason,
              correlationKey: rule.correlationKey,
            ),
          ),
        );
      }
    }

    final groupedCandidates = <String, List<_AssessmentCandidate>>{};
    for (final candidate in candidates) {
      final group = candidate.rule.conflictGroup;
      if (group != null) {
        groupedCandidates.putIfAbsent(group, () => <_AssessmentCandidate>[]).add(candidate);
      }
    }

    final suppressedRuleIds = <String>{};
    final conflicts = <AssessmentRuleConflict>[];
    for (final entry in groupedCandidates.entries) {
      if (entry.value.length > 1) {
        final ruleIds = entry.value.map((candidate) => candidate.rule.id).toList();
        suppressedRuleIds.addAll(ruleIds);
        conflicts.add(AssessmentRuleConflict(group: entry.key, ruleIds: ruleIds));
      }
    }

    return AssessmentGenerationResult(
      assessments: candidates
          .where((candidate) => !suppressedRuleIds.contains(candidate.rule.id))
          .map((candidate) => candidate.assessment)
          .toList(),
      diagnostics: diagnostics,
      conflicts: conflicts,
    );
  }
}

int _confidenceRank(Confidence confidence) {
  switch (confidence) {
    case Confidence.low:
      return 0;
    case Confidence.medium:
      return 1;
    case Confidence.high:
      return 2;
  }
}

String? _normalizeOptional(String? value, String name) {
  if (value == null) return null;
  final normalized = value.trim();
  if (normalized.isEmpty) {
    throw ArgumentError.value(value, name, '$name must not be blank when provided.');
  }
  return normalized;
}

class _AssessmentCandidate {
  const _AssessmentCandidate({required this.rule, required this.assessment});

  final AssessmentRule rule;
  final Assessment assessment;
}
