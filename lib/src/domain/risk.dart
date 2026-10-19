import 'assessment.dart';
import 'kryvon_enums.dart';

class RiskContributor {
  const RiskContributor({required this.assessmentId, required this.severity, required this.confidence, required this.reason});
  final String assessmentId;
  final Severity severity;
  final Confidence confidence;
  final String reason;
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
}

class RiskEvaluator {
  const RiskEvaluator();

  RiskAssessment evaluate(List<Assessment> assessments) {
    if (assessments.isEmpty) {
      return RiskAssessment(level: RiskLevel.unknown, contributors: const <RiskContributor>[], uncertainties: const <String>['No assessments are available; risk cannot be established.']);
    }
    final contributors = assessments.map((a) => RiskContributor(assessmentId: a.id, severity: a.severity, confidence: a.confidence, reason: a.reason)).toList(growable: false);
    var highestRank = -1;
    var highestSeverity = Severity.info;
    final uncertainties = <String>[];
    for (final assessment in assessments) {
      final rank = _severityRank(assessment.severity);
      if (rank > highestRank) {
        highestRank = rank;
        highestSeverity = assessment.severity;
      }
      if (assessment.confidence == Confidence.low) {
        uncertainties.add('Assessment "${assessment.id}" has low confidence.');
      } else if (assessment.confidence == Confidence.medium) {
        uncertainties.add('Assessment "${assessment.id}" has medium confidence.');
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
