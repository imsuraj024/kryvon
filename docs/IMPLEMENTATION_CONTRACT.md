# Kryvon Implementation Contract

This document freezes the semantic contract for the first implementation of Kryvon. It is intentionally stricter than an implementation sketch: code, tests, and platform adapters must preserve these rules.

## 1. Architecture

```text
Host Application
      ↓
Public API
      ↓
Assessment Engine
      ├── Detector Registry
      ├── Evidence Collection
      ├── Assessment
      ├── Risk Evaluation
      └── Policy Evaluation
             ↓
          Decision
             ↓
      Host Application
```

Platform implementations sit underneath detectors:

```text
Detector Contract
      ↓
Platform Adapter
      ↓
Android APIs / native signals
```

The core domain must not depend directly on Android APIs.

---

# 2. Core Contracts

## 2.1 Signal

A stable identifier for an observable condition.

Required properties:

```text
id
family
platform capability
```

Signal identifiers must be stable once published. Renaming a signal is a compatibility change.

---

## 2.2 Evidence

Represents exactly what a detector observed.

Required semantic fields:

```text
signal
status
confidence
source
platform
observedAt
metadata (optional and sanitized)
```

### Status

```text
DETECTED
NOT_DETECTED
UNKNOWN
FAILED
UNSUPPORTED
```

### Rules

- `DETECTED` means the detector has positive evidence for the signal.
- `NOT_DETECTED` means the detector completed and did not observe the signal.
- `UNKNOWN` means the detector could not establish either state without being classified as a technical failure.
- `FAILED` means the detector attempted evaluation but could not complete it.
- `UNSUPPORTED` means the capability is not available for the current platform/runtime.

No status may be silently converted into another status.

---

## 2.3 Confidence

Initial enum:

```text
LOW
MEDIUM
HIGH
```

Confidence describes certainty in the observation, not security impact.

Every `DETECTED` evidence item must have an explicit confidence.

`FAILED` and `UNSUPPORTED` may use a null/non-applicable confidence representation rather than inventing certainty.

---

## 2.4 Severity

Initial enum:

```text
INFO
LOW
MEDIUM
HIGH
CRITICAL
```

Severity is associated with an assessment/threat, not automatically with a raw signal.

---

## 2.5 Assessment

An assessment interprets evidence.

Required properties:

```text
id
threat
severity
confidence
supportingEvidence
reason
```

An assessment may use multiple evidence items.

Assessment confidence must be derived from evidence according to a defined, testable rule. It must not be an arbitrary constant hidden in detector code.

---

## 2.6 Risk

Risk summarizes the assessed security posture.

Initial public representation:

```text
level
score (optional)
contributors
uncertainties
```

Risk levels:

```text
UNKNOWN
LOW_RISK
ELEVATED
HIGH_RISK
CRITICAL
```

A score is allowed as a supporting representation, but the decision engine must never require consumers to understand an arbitrary score to use Kryvon.

Every elevated risk must have explainable contributors.

---

## 2.7 Context

Context identifies what the application is protecting.

Initial values:

```text
APP_STARTUP
SESSION_START
AUTHENTICATION
ACCOUNT_ACCESS
SENSITIVE_OPERATION
TRANSACTION
```

Custom context values may be supported later without changing the core semantics.

Context is an input to policy, not detector logic.

---

## 2.8 Policy

Policy evaluates risk, assessments, evidence availability, and context.

A policy must be:

- Explicit.
- Deterministic for the same input.
- Versionable.
- Testable.
- Inspectable.

A policy must define how it treats:

- High-risk assessments.
- Low-confidence evidence.
- Detector failures.
- Unsupported capabilities.
- Unknown posture.
- Conflicting evidence.

---

## 2.9 Decision

Initial decision values:

```text
ALLOW
MONITOR
RESTRICT
BLOCK
```

Required properties:

```text
action
context
posture
reason
policy identifier/version
contributors
```

The decision must be explainable without reading internal detector code.

---

# 3. Detector Contract

A detector is responsible only for producing evidence.

Conceptual contract:

```text
Detector
  ├── id
  ├── supported capabilities
  └── evaluate(context) → Evidence[]
```

Requirements:

1. A detector must be independently testable.
2. A detector must not invoke policy.
3. A detector must not invoke application UI.
4. A detector must not terminate the process.
5. A detector must report technical failure as `FAILED`.
6. A detector must report unsupported capability as `UNSUPPORTED`.
7. A detector must not fabricate evidence to compensate for a failed check.
8. A detector should avoid collecting unnecessary sensitive data.

---

# 4. Detector Lifecycle

The engine owns detector orchestration.

```text
REGISTERED
    ↓
AVAILABLE / UNSUPPORTED
    ↓
EVALUATING
    ↓
COMPLETED / FAILED
```

The lifecycle must be deterministic and observable at the result level.

Repeated assessments must not accidentally accumulate stale evidence unless explicitly requested by a future session/history feature.

---

# 5. Assessment Engine

The engine performs:

```text
1. Resolve requested context.
2. Resolve applicable detectors.
3. Evaluate detectors.
4. Preserve all evidence.
5. Group/correlate evidence.
6. Generate assessments.
7. Calculate risk.
8. Evaluate policy.
9. Produce decision.
```

The engine must not discard evidence merely because it does not contribute to the final decision.

---

# 6. Failure Semantics

Failure handling is a first-class contract.

### Detector failure

```text
Detector exception
      ↓
Evidence: FAILED
      ↓
Assessment may become UNKNOWN
      ↓
Policy decides consequence
```

### Native communication failure

```text
Communication failure
      ↓
Engine/system failure evidence
      ↓
Policy decides consequence
```

### Invalid configuration

Invalid required configuration must be surfaced as a configuration error before a misleading security decision is produced.

### Unsupported platform

Unsupported capability produces `UNSUPPORTED` evidence and does not imply compromise.

---

# 7. Risk Contract

The initial risk implementation should prioritize explainability over mathematical sophistication.

Risk evaluation must:

- Consider assessment severity.
- Consider assessment confidence.
- Avoid double-counting correlated evidence.
- Preserve uncertainty.
- Produce deterministic results.
- Expose contributors.

The first algorithm may be deliberately simple, but its inputs and output semantics must be explicit and covered by tests.

Future algorithms must be replaceable without changing detector contracts.

---

# 8. Policy Contract

Policy is the only layer allowed to convert security posture into application action.

Example:

```text
HIGH_RISK + TRANSACTION → BLOCK
HIGH_RISK + APP_STARTUP → RESTRICT
LOW_RISK + APP_STARTUP → ALLOW
UNKNOWN + TRANSACTION → RESTRICT
```

These are examples, not hard-coded defaults.

The default policy must be documented and safe for the intended use case.

---

# 9. Public API Contract

The public API should expose high-level security operations rather than detector implementation details.

Conceptual usage:

```dart
final result = await Kryvon.assess(
  context: KryvonContext.transaction,
);

switch (result.decision) {
  case KryvonDecision.allow:
    // continue
  case KryvonDecision.monitor:
    // continue with monitoring
  case KryvonDecision.restrict:
    // apply application-specific restrictions
  case KryvonDecision.block:
    // reject operation
}
```

The exact API names remain subject to implementation review, but the semantics are fixed.

The host application should not need to call individual detectors for normal usage.

---

# 10. Sensitive Operation Model

The engine must support fresh assessment for sensitive operations.

```text
Application startup assessment
          ↓
Normal use
          ↓
Sensitive operation requested
          ↓
Fresh assessment
          ↓
Decision
```

A previous clean result must not be treated as proof that a later runtime is clean.

---

# 11. Native Boundary

Native adapters must expose normalized evidence to the Dart engine.

The boundary should have:

- Explicit method identifiers.
- Versionable protocol semantics.
- Input validation.
- Output validation.
- Error mapping.
- Timeout handling where required.
- No hidden policy.

A nonce can help prevent stale request/response confusion, but must not be described as cryptographic authentication unless a real authentication mechanism exists.

---

# 12. Integrity Contract

Integrity verification must explicitly represent:

```text
VERIFIED
MISMATCH
NOT_CONFIGURED
FAILED
UNSUPPORTED
```

`NOT_CONFIGURED` is not equivalent to `VERIFIED`.

If integrity is mandatory under the active policy, `NOT_CONFIGURED` must produce an appropriate configuration/security outcome rather than silently passing.

---

# 13. Logging Contract

Core security results and diagnostic logs are separate concepts.

Production logging must:

- Avoid secrets.
- Avoid unnecessary device identifiers.
- Avoid raw sensitive metadata.
- Allow application-controlled verbosity.

The decision result must not depend on logging being enabled.

---

# 14. Privacy Contract

Kryvon should collect only information required to make or explain a security decision.

No device fingerprint should be created unless a future, explicit feature defines why it is necessary and how it is governed.

---

# 15. Testing Contract

Every domain type must have unit tests.

Minimum test categories:

### Evidence

- Every status.
- Confidence validation.
- Serialization if exposed.

### Assessment

- Single evidence.
- Multiple evidence.
- Correlated evidence.
- Conflicting evidence.
- Missing evidence.

### Risk

- Each risk level.
- Confidence effects.
- Severity effects.
- Correlation.
- Uncertainty.
- Determinism.

### Policy

- Every decision.
- Every context.
- Failure handling.
- Unsupported handling.
- Configuration handling.

### Engine

- Empty detector set.
- One detector.
- Multiple detectors.
- Detector failure.
- Native failure.
- Repeated assessment.
- Fresh assessment.

### Platform

Every native detector needs deterministic test fixtures for positive, negative, unsupported, and failure conditions where feasible.

---

# 16. Versioning Rules

The following are compatibility-sensitive:

- Public enum values.
- Public signal identifiers.
- Decision semantics.
- Evidence status semantics.
- Serialized result fields if serialization becomes public.

Internal detector implementation may change without a public API break provided the documented semantic contract remains intact.

Risk algorithm changes must be documented because they can change application decisions.

---

# 17. Non-Goals for v1

The first rebuild will not attempt to solve everything.

Explicit non-goals:

- Absolute anti-tamper guarantees.
- Perfect root detection.
- Perfect hook detection.
- Complete malware detection.
- Client-side authorization.
- Device fingerprinting.
- Large telemetry/analytics platform.
- Automatic backend fraud decisions.
- Platform attestation replacement.

---

# 18. Implementation Order

The implementation must follow this order:

```text
1. Domain primitives
2. Evidence model
3. Assessment model
4. Risk engine
5. Policy engine
6. Decision/result model
7. Engine orchestration
8. Test suite
9. Native boundary
10. Android detectors
11. Public Flutter API
12. Example integration
13. Hardening and performance validation
```

No detector should be implemented before the core domain and its tests establish the contract it must satisfy.

---

# 19. Definition of Contract Complete

The implementation contract is considered satisfied when:

- Every detector produces structured evidence.
- Failures remain failures.
- Unsupported capabilities remain unsupported.
- Assessments explain their conclusions.
- Risk exposes contributors and uncertainty.
- Policy determines decisions.
- Decisions include context and reasons.
- Sensitive operations can request fresh assessment.
- Native failures are represented explicitly.
- Integrity configuration cannot silently pass when required.
- Core behavior is independently testable.
- The public API does not expose unnecessary implementation details.

This contract is the baseline for the Kryvon rebuild.
