# KRYVON

## Runtime Security & Risk Decision Engine for Flutter Applications

> **Kryvon is a runtime security framework for collecting security evidence, assessing application/device risk, making explicit security decisions, and exposing those decisions to the host application.**

This document is the source of truth for what Kryvon is, why it exists, how it should work, what it must not claim, and how the project will be built.

---

## 1. What Is Kryvon?

Kryvon is a security layer designed primarily for Flutter applications, with native Android capabilities where platform-level signals are required.

Its purpose is not simply to detect root, emulators, debuggers, or hooking frameworks. Its purpose is to answer a more useful question:

> **What security evidence is present right now, how trustworthy is that evidence, what does it mean for the application, and what should the application do about it?**

Kryvon therefore separates four concerns:

1. **Evidence** — what was observed.
2. **Assessment** — what the observations mean.
3. **Risk and decision** — how serious the situation is and what policy recommends.
4. **Response** — how the host application applies the decision.

The framework must remain useful even as individual detectors evolve.

---

## 2. Why Kryvon Exists

Mobile applications operate in environments the application developer does not control. A production application may run on:

- A normal consumer device.
- A rooted or modified device.
- An emulator.
- A developer/debug build environment.
- A device with runtime instrumentation.
- A repackaged or resigning-modified application.
- An environment where individual security checks fail or become unavailable.

Applications handling authentication, payments, financial data, credentials, personal information, proprietary logic, or high-value transactions may need additional runtime signals before allowing sensitive operations.

Kryvon exists to provide those signals and turn them into a consistent security decision model.

It is **defense in depth**, not a replacement for server-side authorization, cryptographic verification, secure backend controls, attestation, or sound application security engineering.

---

## 3. The Problem We Are Solving

A collection of independent security checks is not enough.

A useful security framework must solve the complete path:

```text
Runtime observation
       ↓
Evidence
       ↓
Confidence
       ↓
Threat assessment
       ↓
Risk evaluation
       ↓
Policy decision
       ↓
Application response
```

The system must also explain its decision.

For example:

```text
Decision: RESTRICT
Reason: Multiple medium-confidence runtime signals
Evidence:
  - Root indicator detected
  - Debugger attached
Confidence: High
Recommended action: Restrict sensitive operations
```

The exact implementation may change, but the principle must remain.

---

# 4. Design Principles

## 4.1 Evidence is not a decision

A detector reports an observation. It must not silently decide that the application should terminate.

Bad:

```text
root detected → terminate application
```

Better:

```text
root indicators
    ↓
evidence
    ↓
assessment
    ↓
risk
    ↓
policy
    ↓
decision
```

This allows applications to choose different responses for different use cases.

## 4.2 A detector failure is not automatically a detected threat

If a detector throws an exception, Kryvon must distinguish:

```text
THREAT DETECTED
```

from:

```text
DETECTION FAILED
```

A failed security control can influence risk depending on policy, but it must not be falsely represented as a specific threat without evidence.

## 4.3 Confidence matters

Signals are not equally trustworthy.

A single weak emulator heuristic should not necessarily carry the same weight as multiple independent indicators of runtime instrumentation.

Every meaningful security signal should have a concept of confidence or evidence quality.

## 4.4 Correlation matters

Several related indicators may represent one underlying condition. They must not automatically be counted as independent threats simply because they produced multiple events.

The risk engine should understand signal relationships where practical.

## 4.5 Policy belongs above detection

The same runtime condition may produce different actions in different applications.

For example:

- A game may allow emulators.
- A banking application may restrict sensitive operations on rooted devices.
- A development build may intentionally allow debugging.

Kryvon should provide strong defaults but preserve explicit policy control.

## 4.6 Enforcement should be observable and controllable

Kryvon should not hide irreversible application behavior inside detection code.

The preferred model is to return a decision and provide enforcement adapters/hooks.

Hard termination may exist as an optional response, but it should not be the architectural center of Kryvon.

## 4.7 Fail safely, not blindly

Security failures need deliberate semantics.

The framework must define what happens when:

- A detector fails.
- Native communication fails.
- Configuration is invalid.
- Expected integrity data is missing.
- A platform does not support a check.
- A detector times out.
- Multiple detectors disagree.
- Policy evaluation fails.

"Fail secure" must mean something precise rather than simply terminating the application whenever anything unexpected happens.

## 4.8 Platform capability must be explicit

Kryvon should know which signals are supported on which platforms and versions.

Unsupported does not automatically mean compromised.

---

# 5. Security Model

Kryvon operates inside the application process and therefore cannot establish absolute trust in that process.

An attacker who controls the device or application runtime may potentially:

- Patch application code.
- Hook methods.
- Modify native libraries.
- Instrument the runtime.
- Suppress or alter detector results.
- Repackage or resign the application.
- Interfere with communication between layers.

Therefore:

> **Kryvon is a risk signal and decision layer, not a cryptographic root of trust.**

High-value security decisions should be reinforced by server-side controls and, where appropriate, platform attestation mechanisms.

Kryvon must document these limitations honestly.

---

# 6. Target Architecture

```text
                    ┌──────────────────────────┐
                    │       Host Flutter App   │
                    └────────────┬─────────────┘
                                 │
                          Kryvon Public API
                                 │
                    ┌────────────▼─────────────┐
                    │      Kryvon Engine        │
                    │                           │
                    │  Orchestration            │
                    │  Policy                   │
                    │  Risk                     │
                    │  Decision                 │
                    └────────────┬─────────────┘
                                 │
                 ┌───────────────┴────────────────┐
                 │                                │
        ┌────────▼────────┐              ┌────────▼────────┐
        │ Evidence Layer  │              │ Integrity Layer │
        └────────┬────────┘              └────────┬────────┘
                 │                                │
        ┌────────▼────────┐              ┌────────▼────────┐
        │ Runtime Signals │              │ App Identity    │
        │ Root            │              │ Signing         │
        │ Debugger        │              │ Package         │
        │ Hook            │              │ Tamper signals  │
        │ Emulator        │              └─────────────────┘
        └────────┬────────┘
                 │
        ┌────────▼─────────┐
        │ Native Platform  │
        │ Android          │
        └──────────────────┘
```

The architecture should remain extensible to other platforms without pretending that all platforms expose identical security signals.

---

# 7. Core Concepts

## 7.1 Evidence

Evidence is a structured observation produced by a detector.

Conceptually it should contain information such as:

- Source.
- Signal type.
- Whether it was observed.
- Confidence.
- Platform.
- Timestamp/session context where appropriate.
- Diagnostic metadata that is safe to expose.
- Detector status.

Example:

```text
Source: Root detector
Signal: su executable present
Detected: true
Confidence: high
Platform: Android
```

Evidence should avoid unnecessary sensitive device information.

## 7.2 Assessment

Assessment interprets evidence.

Example:

```text
Evidence A: su executable
Evidence B: root management artifact
Evidence C: privileged filesystem state

Assessment:
Likely rooted environment
Confidence: high
```

## 7.3 Risk

Risk is the result of assessing one or more pieces of evidence in context.

Risk should not be a simplistic sum of arbitrary numbers.

The engine should account for:

- Severity.
- Confidence.
- Independence/correlation.
- Policy.
- Platform capability.
- Signal quality.
- Potentially repeated observations.

The exact algorithm should be versioned and tested.

## 7.4 Decision

A decision is the explicit output of the policy engine.

The initial decision model should support:

```text
ALLOW
MONITOR
RESTRICT
BLOCK
```

A decision should include a reason and enough structured information for the host application to respond appropriately.

---

# 8. Runtime Signals

The initial implementation may migrate the existing signal families:

1. Root / device compromise indicators.
2. Debugger detection.
3. Runtime instrumentation / hooking indicators.
4. Emulator detection.
5. Application integrity / signing verification.

These are **signal families**, not guarantees of compromise.

Each detector must document:

- Detection strategy.
- Supported Android versions.
- Known limitations.
- False-positive risks.
- False-negative risks.
- Confidence semantics.
- Failure behavior.
- Test strategy.

New detectors should only be added when they provide meaningful security value.

---

# 9. Integrity

Integrity is broader than one certificate hash.

Depending on platform capabilities and project scope, Kryvon may evaluate:

- Application signing identity.
- Package/application identity.
- Release/debug state where meaningful.
- Tamper indicators.
- Runtime modification indicators.

Missing expected integrity configuration must have an explicit policy outcome.

For example, an application that asks Kryvon to enforce release signing should not silently behave as though integrity was verified when no expected signing identity has been configured.

---

# 10. Runtime Communication

Flutter and native code may need to communicate for platform-specific evidence.

The communication boundary must be treated as a security boundary within the application's architecture.

Requirements:

- Validate requests.
- Validate responses.
- Handle malformed data.
- Handle missing responses.
- Handle unsupported methods.
- Avoid trusting native output merely because it came from the expected channel.
- Avoid claiming that a nonce alone provides cryptographic authenticity.
- Keep the protocol versionable.
- Keep the public protocol minimal.

If stronger authenticity is required, the design must use an appropriate cryptographic mechanism rather than naming a nonce exchange as authentication.

---

# 11. Policy

Policy determines how risk should affect the application.

A policy should be able to express concepts such as:

- Which signals matter.
- Minimum confidence.
- Risk thresholds.
- Whether a detector failure is tolerable.
- Whether a decision applies globally or only to sensitive operations.
- What response is recommended.

Policy must not be hidden inside individual detectors.

---

# 12. Enforcement

Kryvon should prefer **decision + response integration** over hidden process control.

Recommended model:

```text
Kryvon Decision
      ↓
Host application
      ├── Allow
      ├── Require re-authentication
      ├── Restrict transaction
      ├── Disable sensitive feature
      └── Block session
```

Application termination can be provided as an explicit adapter for applications that require it, but the core engine should not depend on `exit()` to be useful.

---

# 13. Sensitive Operations

A major goal of Kryvon should be protecting **operations**, not merely judging the entire device.

For example:

```text
Application starts
    ↓
Kryvon performs baseline assessment
    ↓
User browses normally
    ↓
User starts high-value transaction
    ↓
Kryvon performs relevant assessment
    ↓
Decision: ALLOW / RESTRICT / BLOCK
```

This gives applications more practical control than permanently blocking an entire app because of one environmental signal.

---

# 14. Public API Goals

The public API should be:

- Small.
- Explicit.
- Difficult to misuse.
- Asynchronous where platform work requires it.
- Testable.
- Stable across internal implementation changes.

A conceptual API might look like:

```dart
final result = await Kryvon.assess();

if (result.decision == KryvonDecision.block) {
  // Application response.
}
```

Sensitive-operation assessment should be possible without forcing the host application to understand internal detectors.

The final API will be designed only after the core model is validated.

---

# 15. Error Handling

Kryvon must distinguish at least these states:

```text
SECURITY SIGNAL
DETECTOR FAILURE
PLATFORM UNSUPPORTED
CONFIGURATION ERROR
ENGINE FAILURE
```

These states must not be collapsed into one arbitrary threat type.

Security policy may choose to treat a failure as high risk, but the underlying event must preserve the truth of what actually happened.

---

# 16. Logging

Logging is for diagnostics, not for leaking sensitive information.

Requirements:

- Configurable log level.
- No secrets.
- No unnecessary device identifiers.
- No raw sensitive data.
- Structured metadata where useful.
- Production-safe defaults.
- Clear distinction between diagnostic and security events.

---

# 17. Testing Strategy

Security behavior must be testable without requiring a compromised physical device for every unit test.

Testing layers:

### Unit tests

- Evidence construction.
- Assessment.
- Risk calculations.
- Correlation.
- Policy evaluation.
- Decision mapping.
- Error states.

### Contract tests

- Dart/native protocol.
- Serialization/deserialization.
- Unsupported platform behavior.

### Android tests

- Native detector behavior.
- Platform API compatibility.
- Known fixture environments.

### Integration tests

- Full engine flow.
- Multiple simultaneous signals.
- Detector failure.
- Policy changes.
- Sensitive-operation assessment.

### Regression tests

Every discovered security bug should become a permanent regression test.

---

# 18. Performance Requirements

Runtime security checks must not unnecessarily degrade application startup or user flows.

The implementation should:

- Run independent checks concurrently where safe.
- Avoid repeated expensive native work.
- Support explicit assessment points.
- Avoid blocking the UI thread.
- Keep evidence collection bounded.
- Make caching behavior explicit.

Performance must be measured rather than assumed.

---

# 19. Privacy Requirements

Kryvon should collect the minimum information required for security decisions.

It should not become a device fingerprinting library by accident.

Telemetry must be opt-in at the application integration level and should expose only the information necessary for the application's security and observability requirements.

---

# 20. Threat Model

Kryvon should assume adversaries may have:

### Low capability

- Rooted device.
- Emulator.
- Debugger.
- Known modification tools.

### Medium capability

- Runtime hooking.
- Repackaging.
- Instrumentation.
- Detector suppression.

### High capability

- Native binary patching.
- Application modification.
- Runtime manipulation.
- Full control over the local process.

Kryvon should clearly state which attacks each control is intended to make harder and which attacks remain outside its trust model.

---

# 21. What Kryvon Is Not

Kryvon is not:

- A replacement for backend authorization.
- A replacement for TLS.
- A replacement for secure credential storage.
- A cryptographic root of trust.
- A guarantee that an application cannot be reverse engineered.
- A guarantee that root or hooks can never be bypassed.
- A generic analytics SDK.
- A device fingerprinting platform.
- A reason to blindly terminate users whenever a heuristic fires.

---

# 22. Product Direction

The useful product is not:

> "We detect five security threats."

The useful product is:

> **"Kryvon gives Flutter applications a structured, explainable runtime security posture and lets them make policy-driven decisions around sensitive operations."**

That positioning should guide architecture, documentation, API design, and feature selection.

---

# 23. Rebuild Rules

The `kryvon-rebuild` branch is a deliberate architectural reset.

Rules:

1. Do not preserve weak abstractions merely for backward compatibility.
2. Do not add detectors before the core model is correct.
3. Do not introduce complexity without a demonstrated security or engineering benefit.
4. Every security behavior must be testable.
5. Every security claim must be supportable by implementation or documentation.
6. Every discovered weakness becomes either a fix or an explicit documented limitation.
7. Public API stability is important, but correctness comes first during the rebuild.
8. Changes should be independently reviewable.
9. Main remains untouched until the rebuild is proven.
10. Security decisions must be explainable.

---

# 24. Rebuild Phases

## Phase 0 — Specification

- Define terminology.
- Define threat/evidence model.
- Define decision model.
- Define error semantics.
- Define public API goals.

## Phase 1 — Core domain

Build:

- Evidence.
- Confidence.
- Assessment.
- Risk.
- Decision.
- Policy.
- Result models.

No platform detector work until this layer is testable.

## Phase 2 — Engine

Build:

- Orchestration.
- Detector lifecycle.
- Failure handling.
- Correlation.
- Policy evaluation.
- Decision generation.

## Phase 3 — Android platform layer

Migrate and improve the existing five signal families.

Each detector must meet the new contracts.

## Phase 4 — Integration

- Flutter API.
- Native communication.
- Configuration.
- Logging.
- Example application.

## Phase 5 — Hardening

- Attack-oriented testing.
- Failure injection.
- Regression testing.
- Performance testing.
- Documentation verification.

## Phase 6 — Release readiness

- API review.
- Security review.
- CI verification.
- Package metadata.
- Changelog.
- README.
- Example validation.

---

# 25. Definition of Done

Kryvon is not ready because all detectors return `true` or `false`.

A meaningful release must demonstrate:

- Clear architecture.
- Explicit evidence model.
- Explicit confidence semantics.
- Explainable risk evaluation.
- Policy-driven decisions.
- Correct detector failure handling.
- Platform capability handling.
- Tested native communication.
- Tested enforcement integration.
- Useful documentation.
- No unsupported security claims.
- Acceptable performance.
- Regression coverage for known weaknesses.

---

# 26. Guiding Question

Every feature should answer this question before it is implemented:

> **Does this materially improve an application's ability to understand or respond to runtime security risk?**

If the answer is no, it does not belong in Kryvon.

---

# 27. Current Status

This document defines the intended direction for the rebuild.

The existing implementation on `main` is treated as a reference implementation and source of lessons, not as an architectural constraint.

The `kryvon-rebuild` branch is the working branch for the new design.

**Next milestone:** validate this specification against the existing implementation, convert known weaknesses into explicit requirements, and then implement the core domain model from a clean foundation.
