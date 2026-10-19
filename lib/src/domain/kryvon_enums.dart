enum EvidenceStatus { detected, notDetected, unknown, failed, unsupported }

enum Confidence { low, medium, high }

enum Severity { info, low, medium, high, critical }

enum RiskLevel { unknown, lowRisk, elevated, highRisk, critical }

enum AssessmentContext {
  appStartup,
  sessionStart,
  authentication,
  accountAccess,
  sensitiveOperation,
  transaction,
}

enum KryvonDecision { allow, monitor, restrict, block }
