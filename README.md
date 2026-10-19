# Kryvon

Kryvon is a runtime security assessment and policy engine for Flutter applications.

The `kryvon-rebuild` branch is being rebuilt from first principles. The deterministic core engine is implemented; platform detectors and runtime integrations remain intentionally out of scope until the core contracts are validated.

## Core model

```text
Evidence → Assessment → Risk → Policy → Decision → Host application
```

Kryvon deliberately separates observations from application decisions. Evidence sources do not decide whether the host application should allow, monitor, restrict, or block an operation.

## Core engine

The current `KryvonEngine` accepts assessments from a caller, evaluates aggregate risk, applies a policy for the requested context, and returns an explainable `KryvonDecisionResult` with policy identity/version.

```dart
import 'package:kryvon/kryvon.dart';

const engine = KryvonEngine();
final result = engine.evaluate(
  context: AssessmentContext.transaction,
  assessments: assessments,
);

if (result.decision == KryvonDecision.block) {
  // The host application decides how to respond.
}
```

Core semantics:

- No assessments means `unknown` risk, not a detected threat.
- Risk follows the highest assessed severity; confidence is surfaced as uncertainty and does not silently downgrade severity.
- Policy maps risk and context to a decision; unknown-risk behavior is configurable.
- Returned contributor, uncertainty, evidence metadata, and supporting-evidence collections are read-only snapshots.
- The engine does not execute detectors or enforce decisions.

## Current state

Implemented:

- Evidence and assessment domain models.
- Explicit severity-to-risk mapping and uncertainty reporting.
- Configurable policy decisions.
- Deterministic assessment-to-decision engine.
- Domain and engine unit tests.

Not yet implemented:

- Runtime detectors.
- Native platform bridge.
- Android security checks.
- Production enforcement.
- Correlation/deduplication of related signals.

## Documentation

- `KRYVON.md` — product and engineering specification.
- `docs/WHY_KRYVON.md` — problem and purpose.
- `docs/DOMAIN_MODEL.md` — domain semantics.
- `docs/THREAT_MODEL.md` — threat scenarios and security boundaries.
- `docs/IMPLEMENTATION_CONTRACT.md` — implementation rules.

## Development principle

Every security feature must answer:

1. What was observed?
2. What evidence represents it?
3. What does the evidence mean?
4. How does it affect risk?
5. Which policy controls the consequence?
6. What decision is returned?

Kryvon provides explainable risk signals, not proof that a client process is trustworthy. High-value operations must still rely on server-side authorization and appropriate platform protections.
