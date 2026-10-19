# Kryvon

Kryvon is a runtime security assessment and policy engine for Flutter applications.

The `kryvon-rebuild` branch is being rebuilt from first principles. The deterministic core is implemented without platform detectors or native integrations.

## Core model

```text
Expected signals + outcomes → Assessment → Risk → Policy → Decision → Host application
```

Kryvon separates observations from interpretation and application decisions. The core engine accepts caller-supplied assessments and an optional `SignalRun` describing expected signal coverage. It does not execute detectors or enforce the returned decision.

## Example

```dart
import 'package:kryvon/kryvon.dart';

const engine = KryvonEngine();
final result = engine.evaluate(
  context: AssessmentContext.transaction,
  assessments: assessments,
  signalRun: signalRun,
);

if (result.decision == KryvonDecision.block) {
  // The host application owns the response.
}
```

## Core semantics

- No assessments and no coverage means `unknown` risk, not a detected threat.
- Risk follows the highest assessed severity; confidence is surfaced as uncertainty and does not silently downgrade severity.
- Missing, failed, unknown, unsupported, duplicate, or unexpected signal outcomes are explicit coverage gaps.
- A low-risk result from negative signal outcomes requires every expected signal to have exactly one outcome and every negative outcome to have high confidence.
- Detected signal evidence without an interpreting assessment remains `unknown`; the engine does not invent a threat conclusion.
- Policy maps risk and context to a configurable decision.
- Evidence metadata, supporting evidence, signal outcomes, contributors, and uncertainty collections are read-only snapshots.

## Current state

Implemented:

- Evidence and assessment domain models.
- Explicit severity-to-risk mapping and confidence uncertainty.
- Signal coverage contract and failure semantics.
- Configurable policy decisions.
- Deterministic assessment-to-decision engine.
- Domain and engine unit tests.
- GitHub Actions workflow for `flutter analyze` and `flutter test`.

Not yet implemented:

- Assessment generation and signal correlation/deduplication.
- Runtime detectors or detector orchestration.
- Native platform bridge or Android security checks.
- Production enforcement.

## Documentation

- `KRYVON.md` — product and engineering specification.
- `docs/WHY_KRYVON.md` — problem and purpose.
- `docs/DOMAIN_MODEL.md` — domain semantics.
- `docs/THREAT_MODEL.md` — threat scenarios and security boundaries.
- `docs/IMPLEMENTATION_CONTRACT.md` — implementation rules.

## Development principle

Every security feature must answer what was observed, what evidence represents it, how it is interpreted, how it affects risk, which policy controls the consequence, and what happens when the check cannot run.

Kryvon provides explainable risk signals, not proof that a client process is trustworthy. High-value operations must still rely on server-side authorization and appropriate platform protections.
