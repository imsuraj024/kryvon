import 'kryvon_enums.dart';
import 'risk.dart';

class KryvonPolicy {
  const KryvonPolicy({
    this.id = 'default',
    this.version = 1,
    this.highRiskDecision = KryvonDecision.restrict,
    this.criticalRiskDecision = KryvonDecision.block,
    this.unknownDecision = KryvonDecision.monitor,
  });

  final String id;
  final int version;
  final KryvonDecision highRiskDecision;
  final KryvonDecision criticalRiskDecision;
  final KryvonDecision unknownDecision;

  KryvonDecision decide({
    required AssessmentContext context,
    required RiskAssessment risk,
  }) {
    switch (risk.level) {
      case RiskLevel.unknown:
        return unknownDecision;
      case RiskLevel.critical:
        return criticalRiskDecision;
      case RiskLevel.highRisk:
        return highRiskDecision;
      case RiskLevel.elevated:
        return context == AssessmentContext.transaction
            ? KryvonDecision.restrict
            : KryvonDecision.monitor;
      case RiskLevel.lowRisk:
        return KryvonDecision.allow;
    }
  }
}
