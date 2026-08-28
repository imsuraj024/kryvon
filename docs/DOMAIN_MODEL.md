# Kryvon Domain Model

This document defines the core concepts that make Kryvon meaningful. It is intentionally implementation-independent. Code should follow these definitions, not redefine them.

## 1. Core Principle

Kryvon separates **what was observed** from **what it means** and from **what the application should do**.

```text
Signal → Evidence → Assessment → Risk → Policy → Decision → Response
```

No detector may directly make a product-level security decision.

---

## 2. Signal

A **Signal** is a specific observable security condition that a platform detector can evaluate.

Examples:

- `su_binary_present`
- `debugger_attached`
- `hook_framework_artifact`
- `emulator_indicator`
- `unexpected_signing_certificate`

A signal is not a threat by itself.

### Responsibilities

A signal defines:

- Stable identity.
- Signal family.
- Platform applicability.
- Detector implementation contract.
- Expected evidence shape.

### Non-responsibilities

A signal must not:

- Decide risk.
- Decide whether the application is blocked.
- Terminate the process.
- Assume that its observation proves compromise.

---

## 3. Evidence

**Evidence** is the factual result of evaluating a signal.

It answers:

> What did Kryvon actually observe?

Conceptually:

```text
Evidence
├── signal
├── status
├── observed
├── confidence
├── source
├── platform
├── timestamp/session context
└── safe metadata
```

### Evidence status

At minimum:

```text
DETECTED
NOT_DETECTED
UNKNOWN
FAILED
UNSUPPORTED
```

This distinction is mandatory.

`FAILED` must never silently become `DETECTED`.

`UNSUPPORTED` must never silently become `COMPROMISED`.

### Security rule

Evidence must represent truth as closely as the detector can establish it. Interpretation belongs to the assessment layer.

---

## 4. Confidence

**Confidence** expresses how strongly the available evidence supports the observation or assessment.

Suggested initial levels:

```text
LOW
MEDIUM
HIGH
```

Confidence is not severity.

Example:

```text
Debugger detected
Confidence: HIGH
Severity: MEDIUM
```

A highly confident observation can still have moderate security impact.

---

## 5. Assessment

An **Assessment** interprets one or more pieces of evidence.

It answers:

> What does the available evidence most likely mean?

Example:

```text
Evidence:
  su executable detected
  privileged filesystem indicator detected

Assessment:
  ROOTED_ENVIRONMENT

Confidence:
  HIGH
```

Assessment is where correlation becomes meaningful.

Multiple observations representing the same underlying condition should not automatically inflate risk as independent threats.

---

## 6. Threat

A **Threat** represents a security condition relevant to the application.

Initial families may include:

- Device compromise.
- Runtime instrumentation.
- Debugging.
- Emulated environment.
- Application integrity failure.

Threats are conclusions from evidence and assessment, not raw detector names.

Example:

```text
Signal:
  su_binary_present

Evidence:
  detected / high confidence

Assessment:
  ROOTED_ENVIRONMENT

Threat:
  DEVICE_COMPROMISE
```

This separation allows the detection implementation to evolve without changing the conceptual security model.

---

## 7. Severity

**Severity** describes the potential security impact of a threat.

Suggested levels:

```text
INFO
LOW
MEDIUM
HIGH
CRITICAL
```

Severity must not be confused with confidence.

Example:

```text
Emulator detected
Severity: LOW
Confidence: HIGH
```

versus:

```text
Runtime instrumentation suspected
Severity: HIGH
Confidence: MEDIUM
```

---

## 8. Risk

**Risk** represents the security significance of the current assessed state.

Risk is not simply the sum of detector scores.

The risk model should consider, where supported:

- Threat severity.
- Evidence confidence.
- Signal independence.
- Correlation.
- Application context.
- Policy.
- Detector availability.
- Assessment uncertainty.

A numerical score may be exposed, but the score must remain explainable.

Example:

```text
Risk level: HIGH

Contributors:
  DEVICE_COMPROMISE     high confidence
  RUNTIME_INSTRUMENTATION medium confidence

Correlation:
  independent signal families
```

The engine must be able to explain why a risk level was produced.

---

## 9. Security Posture

**Security posture** is the human/application-readable representation of the current security state.

Suggested levels:

```text
UNKNOWN
LOW_RISK
ELEVATED
HIGH_RISK
CRITICAL
```

Posture is derived from risk and policy context. It is not a detector result.

---

## 10. Context

**Context** describes what the application is asking Kryvon to protect.

Examples:

```text
APP_STARTUP
SESSION_START
AUTHENTICATION
ACCOUNT_ACCESS
SENSITIVE_OPERATION
TRANSACTION
```

Context matters because the same environment can require different responses for different operations.

Example:

```text
Emulator detected

Browsing:
  ALLOW

High-value transaction:
  RESTRICT
```

Context should be extensible without requiring new detectors.

---

## 11. Policy

**Policy** translates assessed risk and application context into an expected response.

Policy controls:

- Which threats matter.
- Required confidence.
- Risk thresholds.
- Treatment of detector failures.
- Treatment of unsupported checks.
- Context-specific decisions.
- Recommended responses.

Policy must be explicit and inspectable.

A detector must never contain hidden application policy.

---

## 12. Decision

A **Decision** is the final recommendation made by Kryvon for the host application.

Initial decision set:

```text
ALLOW
MONITOR
RESTRICT
BLOCK
```

Every decision should include:

- Decision value.
- Security posture.
- Relevant context.
- Primary reason.
- Supporting assessments/evidence.
- Policy identity/version where appropriate.

Example:

```text
Decision: RESTRICT
Context: TRANSACTION
Posture: HIGH_RISK
Reason: Runtime instrumentation suspected with high-impact context
```

---

## 13. Response

A **Response** is how the host application acts on a decision.

Examples:

```text
ALLOW
Require re-authentication
Disable a sensitive feature
Require step-up verification
Reject transaction
Terminate session
```

Kryvon should recommend or expose decisions. The host application owns business behavior.

This keeps the security engine independent from application navigation, UI, transaction systems, and product-specific workflows.

---

## 14. Detector

A **Detector** is an implementation that evaluates one or more signals on a platform.

A detector must have a clear contract:

```text
Input
  ↓
Platform observation
  ↓
Evidence
```

It must report failures honestly.

A detector must not:

- Modify policy.
- Change another detector's result.
- Perform hidden enforcement.
- Convert exceptions into threats without evidence.

---

## 15. Detector Capability

Kryvon must distinguish:

```text
SUPPORTED
UNSUPPORTED
FAILED
```

This is important for cross-platform behavior.

For example, if a platform cannot expose a particular signal, the framework should know that the signal was unavailable rather than treating the absence of a result as evidence of compromise.

---

## 16. Assessment Result

The engine should ultimately produce a structured result similar to:

```text
KryvonResult
├── context
├── posture
├── decision
├── risk
│   ├── level
│   ├── score (optional)
│   └── contributors
├── assessments
├── evidence
├── detector status
└── diagnostic information
```

The exact Dart types are deliberately deferred until the semantics are validated.

---

## 17. Error Model

Errors are part of the domain model, not implementation noise.

Kryvon must distinguish:

```text
CONFIGURATION_ERROR
DETECTOR_FAILURE
NATIVE_COMMUNICATION_FAILURE
PLATFORM_UNSUPPORTED
ENGINE_FAILURE
TIMEOUT
```

An error can affect risk according to policy, but the original failure must remain observable.

Example:

```text
Detector failure
      ↓
Evidence status: FAILED
      ↓
Policy: fail-closed for transaction
      ↓
Decision: BLOCK
```

This is valid.

What is invalid is:

```text
Detector exception
      ↓
Pretend root/hook/debugger was detected
```

---

## 18. Domain Relationships

```text
Detector
   │
   └── evaluates ──→ Signal
                       │
                       └── produces ──→ Evidence
                                          │
                                          └── interpreted by ──→ Assessment
                                                                    │
                                                                    └── identifies ──→ Threat
                                                                                         │
                                                                                         └── contributes to ──→ Risk
                                                                                                                  │
Context ─────────────────────────────────────────────────────────────┤
Policy ──────────────────────────────────────────────────────────────┤
                                                                                         ↓
                                                                                      Decision
                                                                                         │
                                                                                         ↓
                                                                                      Response
```

---

## 19. Invariants

These rules must remain true throughout the implementation:

1. **Evidence records observations, not business decisions.**
2. **Detector failure is not threat detection.**
3. **Unsupported is not compromised.**
4. **Confidence and severity are independent concepts.**
5. **Risk must be explainable.**
6. **Policy determines application response.**
7. **Context may change the appropriate decision without changing the underlying evidence.**
8. **Enforcement is outside core detection logic.**
9. **The host application must be able to inspect the reason for a decision.**
10. **No component may claim stronger security guarantees than its implementation can support.**

---

## 20. Example End-to-End Assessment

```text
Context:
  TRANSACTION

Evidence:
  root indicator              DETECTED / HIGH
  debugger                    NOT_DETECTED / HIGH
  hook artifact               DETECTED / MEDIUM
  emulator                    NOT_DETECTED / HIGH
  signing identity            VERIFIED / HIGH

Assessment:
  Device compromise           HIGH
  Runtime instrumentation     MEDIUM

Risk:
  HIGH

Policy:
  Transactions require a trusted runtime

Decision:
  RESTRICT

Host response:
  Require additional verification or reject operation
```

Notice that no individual detector made the final decision.

---

# 21. Design Test

A proposed Kryvon feature should be rejected or redesigned if it cannot clearly answer:

- What signal does it produce?
- What evidence does it create?
- How confident is that evidence?
- What assessment can it support?
- What threat does it represent?
- How does it affect risk?
- Under what context does it matter?
- Which policy controls its consequence?
- What decision can result?
- What happens if the detector fails?
- What happens if the platform does not support it?
- How can the result be tested?

If these questions cannot be answered, the feature is not sufficiently defined for the Kryvon core.

---

# 22. Final Model

The mental model for Kryvon is:

```text
OBSERVE
  ↓
PRESERVE FACTS
  ↓
INTERPRET
  ↓
CORRELATE
  ↓
ASSESS RISK
  ↓
APPLY POLICY
  ↓
MAKE AN EXPLAINABLE DECISION
  ↓
LET THE APPLICATION RESPOND
```

This is the domain foundation on which the rebuilt Kryvon should be implemented.
