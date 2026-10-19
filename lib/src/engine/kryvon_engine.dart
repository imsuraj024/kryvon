import '../domain/assessment.dart';
import '../domain/decision.dart';
import '../domain/kryvon_enums.dart';
import '../domain/policy.dart';
import '../domain/risk.dart';

/// Runs the deterministic assessment -> risk -> policy -> decision pipeline.
///
/// This core engine consumes assessments supplied by callers. It deliberately
/// does not discover signals, invoke platform detectors, or enforce decisions.
class KryvonEngine {
  const KryvonEngine({this.riskEvaluator = const RiskEvaluator()});

  final RiskEvaluator riskEvaluator;

  KryvonDecisionResult evaluate({
    required AssessmentContext context,
    required List<Assessment> assessments,
    KryvonPolicy policy = const KryvonPolicy(),
  }) {
    final risk = riskEvaluator.evaluate(assessments);
    final decision = policy.decide(context: context, risk: risk);
    final reason = _explain(
      decision: decision,
      context: context,
      risk: risk,
      policy: policy,
    );

    return KryvonDecisionResult(
      decision: decision,
      context: context,
      risk: risk,
      reason: reason,
      policyId: policy.id,
      policyVersion: policy.version,
    );
  }

  String _explain({
    required KryvonDecision decision,
    required AssessmentContext context,
    required RiskAssessment risk,
    required KryvonPolicy policy,
  }) {
    final base = 'Policy "${policy.id}" v${policy.version} selected '
        '${decision.name} for ${risk.level.name} risk in ${context.name} context.';
    if (risk.level == RiskLevel.unknown) {
      return '$base No assessments were available; this is uncertainty, not a detected threat.';
    }
    if (risk.uncertainties.isNotEmpty) {
      return '$base ${risk.uncertainties.length} confidence uncertainty '
          'item(s) require review.';
    }
    return base;
  }
}
