import 'kryvon_enums.dart';
import 'risk.dart';

/// Maps an evaluated risk level to a host-application decision.
/// Defaults are conservative for critical risk and configurable for unknowns.
class KryvonPolicy {
  const KryvonPolicy({
    this.id = 'default',
    this.version = 1,
    this.highRiskDecision = KryvonDecision.restrict,
    this.criticalRiskDecision = KryvonDecision.block,
    this.elevatedRiskDecision = KryvonDecision.monitor,
    this.elevatedTransactionDecision = KryvonDecision.restrict,
    this.unknownDecision = KryvonDecision.monitor,
  });

  final String id;
  final int version;
  final KryvonDecision highRiskDecision;
  final KryvonDecision criticalRiskDecision;
  final KryvonDecision elevatedRiskDecision;
  final KryvonDecision elevatedTransactionDecision;
  final KryvonDecision unknownDecision;

  /// Throws when the policy identity is invalid. Called by the engine before
  /// evaluating so const policy instances can still be used.
  void validate() {
    if (id.trim().isEmpty) {
      throw ArgumentError.value(id, 'id', 'Policy ID must not be empty.');
    }
    if (version < 1) {
      throw ArgumentError.value(version, 'version', 'Policy version must be positive.');
    }
  }

  KryvonDecision decide({required AssessmentContext context, required RiskAssessment risk}) {
    switch (risk.level) {
      case RiskLevel.unknown:
        return unknownDecision;
      case RiskLevel.critical:
        return criticalRiskDecision;
      case RiskLevel.highRisk:
        return highRiskDecision;
      case RiskLevel.elevated:
        return context == AssessmentContext.transaction
            ? elevatedTransactionDecision
            : elevatedRiskDecision;
      case RiskLevel.lowRisk:
        return KryvonDecision.allow;
    }
  }
}
