import 'kryvon_enums.dart';
import 'risk.dart';

class KryvonDecisionResult {
  const KryvonDecisionResult({
    required this.decision,
    required this.context,
    required this.risk,
    required this.reason,
    required this.policyId,
    required this.policyVersion,
  });

  final KryvonDecision decision;
  final AssessmentContext context;
  final RiskAssessment risk;
  final String reason;
  final String policyId;
  final int policyVersion;
}
