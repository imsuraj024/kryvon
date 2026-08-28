# Kryvon Threat Model

## Purpose

This document stress-tests the Kryvon domain model against realistic runtime conditions and attacker scenarios before implementation is frozen.

Kryvon is a local runtime security layer. It should improve an application's ability to recognize suspicious conditions and respond to them, while explicitly accepting that the application process itself can be attacked.

---

# 1. Security Objective

Kryvon's objective is:

> **Increase the application's ability to make informed, policy-driven decisions when runtime security conditions are uncertain or suspicious.**

Kryvon is not intended to prove that a client device is trustworthy in an absolute sense.

---

# 2. Assets to Protect

Kryvon primarily helps protect:

- Authentication sessions.
- Sensitive account operations.
- High-value transactions.
- Application secrets and sensitive runtime state.
- Proprietary application logic.
- Sensitive data exposed to the client.
- Security-sensitive workflows.
- Backend requests that originate from the application.

Kryvon itself must also protect the integrity of its decision process as far as reasonably possible within the client trust boundary.

---

# 3. Trust Boundaries

```text
                    Backend
                       ▲
                       │
                Network / API
                       │
                       ▼
┌─────────────────────────────────────────┐
│             Application Process         │
│                                         │
│  Flutter App                            │
│       │                                 │
│       ▼                                 │
│  Kryvon Engine                          │
│       │                                 │
│       ▼                                 │
│  Native Platform Layer                  │
│                                         │
└─────────────────────────────────────────┘
                       ▲
                       │
                 Device / OS
```

The application process is not fully trusted.

The operating system may expose signals, but those signals should not automatically be treated as an unforgeable root of truth.

The backend is the stronger security boundary for authoritative authorization.

---

# 4. Adversary Levels

## Level 1 — Environmental modification

Attacker capabilities may include:

- Rooted device.
- Emulator.
- Developer options.
- Debugger.
- Known modification frameworks.

Kryvon should provide useful detection and assessment for these conditions.

## Level 2 — Runtime manipulation

Attacker capabilities may include:

- Runtime instrumentation.
- Method hooking.
- Native hooking.
- Detector suppression.
- Result modification.
- Repackaged application.

Kryvon should make these attacks harder to execute silently, but must not claim complete prevention.

## Level 3 — Process compromise

Attacker capabilities may include:

- Arbitrary code execution inside the application process.
- Native binary modification.
- Patching detector code.
- Patching policy logic.
- Patching decision results.
- Replacing the application package.

Local Kryvon checks cannot provide absolute protection against an attacker with this level of control.

Server-side verification and platform attestation may be required.

---

# 5. Scenario Analysis

## Scenario A — Normal physical device

### Conditions

- No root indicators.
- No debugger.
- No hook indicators.
- No emulator indicators.
- Valid application integrity.

### Expected evidence

Mostly `NOT_DETECTED` plus verified integrity.

### Expected assessment

No material compromise indicators.

### Expected decision

```text
ALLOW
```

---

## Scenario B — Rooted device, no active instrumentation

### Conditions

Root indicators are detected, but no debugger or active instrumentation is observed.

### Interpretation

Rooting increases the ability of the environment to interfere with application execution, but does not prove that an attack is currently taking place.

### Expected behavior

For low-risk application contexts:

```text
MONITOR or ALLOW
```

For security-sensitive applications or operations:

```text
RESTRICT or BLOCK
```

The policy decides.

---

## Scenario C — Emulator

### Conditions

Strong emulator indicators are present.

### Interpretation

Emulation is not inherently malicious.

### Expected behavior

Development/QA:

```text
ALLOW
```

High-value production operation:

```text
Policy-dependent
```

This scenario proves that a detector result cannot directly equal a product decision.

---

## Scenario D — Debugger attached

### Conditions

A debugger is attached to the process.

### Interpretation

This may be expected during development and suspicious in a production release.

### Required model

The same evidence may lead to different decisions based on:

- Build type.
- Application mode.
- Context.
- Policy.

---

## Scenario E — Runtime instrumentation suspected

### Conditions

Multiple independent hook/instrumentation indicators are observed.

### Interpretation

This is substantially stronger than a single weak artifact.

### Expected assessment

```text
RUNTIME_INSTRUMENTATION
Confidence: MEDIUM/HIGH depending on evidence
```

### Expected production response

Potentially:

```text
RESTRICT
```

or

```text
BLOCK
```

for sensitive operations.

---

## Scenario F — Application integrity failure

### Conditions

Observed signing/application identity does not match expected release identity.

### Interpretation

This can indicate:

- Repackaging.
- Resigning.
- Unauthorized build.
- Incorrect configuration.

The engine must distinguish a genuine mismatch from missing or invalid configuration.

### Expected behavior

If release integrity is mandatory:

```text
BLOCK
```

If integrity is optional:

```text
Policy-dependent
```

---

## Scenario G — Detector throws an exception

### Conditions

A detector cannot complete.

### Required result

```text
Evidence status: FAILED
```

Not:

```text
Threat: HOOK_DETECTED
```

Policy may decide:

```text
FAILED + TRANSACTION + fail-closed policy
             ↓
           BLOCK
```

This preserves truth while still allowing strict security behavior.

---

## Scenario H — Native channel unavailable

### Conditions

Flutter cannot communicate with the native security layer.

### Required behavior

The engine records a communication failure.

It must not manufacture a detector result.

Policy determines whether the missing security capability is acceptable for the requested context.

---

## Scenario I — Multiple weak indicators

### Conditions

Example:

```text
Emulator indicator          LOW confidence
System property            LOW confidence
Known package artifact     MEDIUM confidence
```

### Required behavior

Correlation can increase confidence if the signals independently support the same assessment.

However, three weak correlated signals should not automatically become three independent high-severity threats.

---

## Scenario J — Conflicting evidence

### Conditions

One signal suggests a suspicious environment while another signal indicates a normal environment.

### Required behavior

The engine must preserve both observations and expose uncertainty.

Possible outcome:

```text
Posture: ELEVATED
Decision: MONITOR
Reason: Conflicting runtime evidence
```

The engine must not hide contradictory evidence merely to produce a cleaner score.

---

## Scenario K — Detector returns stale information

### Conditions

A previous assessment says no debugger is present, but a debugger becomes attached later.

### Required behavior

The framework must define assessment freshness.

Results should not be presented as continuously authoritative if the underlying signal can change during runtime.

Sensitive operations may request a fresh assessment.

---

## Scenario L — Application starts normally, attack begins later

### Conditions

Startup is clean.

Later, runtime instrumentation is introduced.

### Required behavior

Kryvon must support assessment beyond application startup.

This is one reason sensitive-operation assessment is part of the product direction.

---

## Scenario M — Attacker patches Kryvon

### Conditions

The attacker modifies the process so detectors always return safe values.

### Reality

A purely local library cannot guarantee that its own logic remains trustworthy against a fully compromised process.

### Kryvon response

Kryvon can use defense-in-depth measures to increase attacker cost, but the architecture must not claim absolute resistance.

For high-value operations, authoritative backend controls should remain in place.

---

## Scenario N — Repackaged application

### Conditions

An attacker modifies and redistributes the application.

### Detection opportunities

- Signing identity mismatch.
- Package identity anomalies.
- Integrity signals.
- Runtime modification indicators.

### Important limitation

Local integrity checks should not be treated as sufficient for server authorization by themselves.

---

## Scenario O — Legitimate developer environment

### Conditions

Debugger and emulator are active.

### Expected behavior

Development policy should be able to permit these conditions.

This validates separation between detection and policy.

---

# 6. Attack Classes and Controls

| Attack / Condition | Primary signal | Assessment | Typical policy response |
|---|---|---|---|
| Rooted device | Root signals | Device compromise | Context-dependent |
| Emulator | Emulator signals | Emulated environment | Context-dependent |
| Debugger | Debugger signals | Debugging | Usually stricter in production |
| Hooking | Hook signals | Runtime instrumentation | Restrict/block sensitive actions |
| Repackaging | Integrity | Application integrity failure | Restrict/block |
| Detector failure | Detector status | Unknown security posture | Policy-dependent |
| Native channel failure | Engine status | Security capability unavailable | Policy-dependent |
| Conflicting evidence | Multiple signals | Uncertain posture | Monitor/reassess |
| Runtime change | Fresh assessment | Current posture | Reassess |
| Full process compromise | Not reliably detectable | Trust boundary violated | Backend/attestation required |

---

# 7. Important Security Conclusions

## 7.1 No single detector is authoritative

Every detector is a source of evidence.

## 7.2 Risk must be contextual

A signal should not automatically block every application action.

## 7.3 Freshness matters

Runtime conditions can change after startup.

## 7.4 Failure must remain visible

Security control failure is itself meaningful evidence about assurance, but it is not the same as threat detection.

## 7.5 Strong claims require stronger controls

If a decision must be trusted against a fully compromised client, local Kryvon logic is insufficient by itself.

## 7.6 Correlation must be deliberate

Related signals should not create artificial risk inflation.

## 7.7 Security decisions must be explainable

A blocked sensitive operation should have a structured reason.

---

# 8. Architectural Requirements Derived From Threat Modeling

The threat model requires the implementation to support:

1. Structured evidence status.
2. Confidence.
3. Severity.
4. Assessment/correlation.
5. Context.
6. Policy.
7. Explainable decisions.
8. Detector lifecycle and failure states.
9. Fresh assessments.
10. Platform capability reporting.
11. Native communication failure handling.
12. Defense-in-depth without false security guarantees.
13. Regression tests for every discovered bypass or semantic bug.

---

# 9. Security Boundary Rule

The most important architectural rule is:

> **Kryvon can inform a security decision inside the client, but the client must not be treated as an unquestionable security authority.**

For high-value actions, Kryvon should complement rather than replace:

- Server-side authorization.
- Transaction validation.
- Session controls.
- Platform attestation where appropriate.
- Secure key management.
- Backend fraud/risk controls.

---

# 10. Exit Criteria for the Domain Model

The domain model is considered sufficiently defined when every scenario above can be represented without:

- Lying about what was detected.
- Confusing detector failure with threat detection.
- Hard-coding application policy into detectors.
- Treating unsupported platforms as compromised.
- Requiring process termination for basic security decisions.
- Hiding uncertainty.
- Producing unexplained risk scores.

Only then should the implementation model be frozen.
