import 'assessment.dart';
import 'kryvon_enums.dart';

/// Explains why a risk level was produced.
class RiskContributor {
  const RiskContributor({
    required this.assessmentId,
    required this.severity,
    required this.confidence,
    required this.reason,
  });

  final String assessmentId;
  final Severity severity;
  final Confidence confidence;
  final String reason;
}

/// Aggregated security risk for an assessment run.
class RiskAssessment {
  const RiskAssessment({
    required this.level,
    required this.contributors,
    this.score,
    this.uncertainties = const <String>[],
  });

  final RiskLevel level;
  final int? score;
  final List<RiskContributor> contributors;
  final List<String> uncertainties;
}

/// Conservative, deterministic risk evaluator for the initial engine.
class RiskEvaluator {
  const RiskEvaluator();

  RiskAssessment evaluate(List<Assessment> assessments) {
    if (assessments.isEmpty) {
      return const RiskAssessment(level: RiskLevel.unknown);
    }

    final contributors = assessments
        .map(
          (assessment) => RiskContributor(
            assessmentId: assessment.id,
            severity: assessment.severity,
            confidence: assessment.confidence,
            reason: assessment.reason,
          ),
        )
        .toList(growable: false);

    var highestSeverity = Severity.info;
    var hasUncertainty = false;

    for (final assessment in assessments) {
      if (assessment.severity.index > highestSeverity.index) {
        highestSeverity = assessment.severity;
      }
      if (assessment.confidence == Confidence.low) {
        hasUncertainty = true;
      }
    }

    final level = switch (highestSeverity) {
      Severity.info => RiskLevel.lowRisk,
      Severity.low => RiskLevel.lowRisk,
      Severity.medium => hasUncertainty ? RiskLevel.elevated : RiskLevel.elevated,
      Severity.high => hasUncertainty ? RiskLevel.elevated : RiskLevel.highRisk,
      Severity.critical => RiskLevel.critical,
    };

    return RiskAssessment(
      level: level,
      contributors: contributors,
      uncertainties: hasUncertainty
          ? const <String>['One or more assessments have low confidence.']
          : const <String>[],
    );
  }
}
