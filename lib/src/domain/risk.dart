import 'assessment.dart';
import 'kryvon_enums.dart';
import 'signal_run.dart';

class RiskContributor {
  const RiskContributor({required this.assessmentId, required this.severity, required this.confidence, required this.reason, this.correlationKey});
  final String assessmentId;
  final Severity severity;
  final Confidence confidence;
  final String reason;
  final String? correlationKey;
}

/// Aggregate risk with traceable contributors and explicit uncertainty.
/// Confidence is retained as uncertainty; it never silently downgrades severity.
class RiskAssessment {
  RiskAssessment({required this.level, required List<RiskContributor> contributors, List<String> uncertainties = const <String>[]})
      : contributors = List<RiskContributor>.unmodifiable(contributors),
        uncertainties = List<String>.unmodifiable(uncertainties);

  final RiskLevel level;
  final List<RiskContributor> contributors;
  final List<String> uncertainties;

  /// Number of independently identified assessment groups. Correlated
  /// assessments remain visible in [contributors] but count as one group.
  int get independentContributorCount {
    final correlationKeys = <String>{};
    var uncorrelatedCount = 0;
    for (final contributor in contributors) {
      final key = contributor.correlationKey;
      if (key == null || key.trim().isEmpty) {
        uncorrelatedCount++;
      } else {
        correlationKeys.add(key);
      }
    }
    return uncorrelatedCount + correlationKeys.length;
  }
}

class RiskEvaluator {
  const RiskEvaluator();

  RiskAssessment evaluate(List<Assessment> assessments, {SignalRun? signalRun}) {
    final contributors = assessments.map((a) => RiskContributor(
      assessmentId: a.id,
      severity: a.severity,
      confidence: a.confidence,
      reason: a.reason,
      correlationKey: a.correlationKey,
    )).toList(growable: false);
    final uncertainties = <String>[];
    if (signalRun != null) uncertainties.addAll(signalRun.uncertainties);
    for (final assessment in assessments) {
      if (assessment.confidence == Confidence.low) {
        uncertainties.add('Assessment "${assessment.id}" has low confidence.');
      } else if (assessment.confidence == Confidence.medium) {
        uncertainties.add('Assessment "${assessment.id}" has medium confidence.');
      }
    }

    if (assessments.isEmpty) {
      if (signalRun?.allNotDetected == true) {
        return RiskAssessment(level: RiskLevel.lowRisk, contributors: contributors, uncertainties: uncertainties);
      }
      if (signalRun == null) {
        uncertainties.add('No assessments or signal coverage were supplied; risk cannot be established.');
      } else if (signalRun.isComplete && signalRun.outcomes.any((e) => e.status == EvidenceStatus.detected)) {
        uncertainties.add('Detected signal evidence has not been interpreted by an assessment.');
      } else if (signalRun.isComplete) {
        uncertainties.add('Negative outcomes do not have sufficient confidence to establish low risk.');
      }
      return RiskAssessment(level: RiskLevel.unknown, contributors: contributors, uncertainties: uncertainties);
    }

    var highestRank = -1;
    var highestSeverity = Severity.info;
    for (final assessment in assessments) {
      final rank = _severityRank(assessment.severity);
      if (rank > highestRank) {
        highestRank = rank;
        highestSeverity = assessment.severity;
      }
    }
    final level = switch (highestSeverity) {
      Severity.info || Severity.low => RiskLevel.lowRisk,
      Severity.medium => RiskLevel.elevated,
      Severity.high => RiskLevel.highRisk,
      Severity.critical => RiskLevel.critical,
    };
    return RiskAssessment(level: level, contributors: contributors, uncertainties: uncertainties);
  }

  int _severityRank(Severity severity) => switch (severity) {
        Severity.info => 0,
        Severity.low => 1,
        Severity.medium => 2,
        Severity.high => 3,
        Severity.critical => 4,
      };
}
