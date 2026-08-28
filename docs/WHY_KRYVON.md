# Why Kryvon?

## The One-Sentence Problem

Applications run on devices and inside runtimes that the application owner does not control, yet the application still needs to make security-sensitive decisions.

Kryvon exists to help the application understand that runtime environment and respond according to explicit security policy.

---

## The Wrong Problem

Kryvon should not exist merely because applications need:

- Root detection.
- Emulator detection.
- Debugger detection.
- Hook detection.
- Integrity checks.

Those are implementation techniques and signal sources.

If Kryvon becomes a list of detectors, it becomes difficult to distinguish from a collection of existing packages and platform APIs.

---

## The Real Problem

The real problem is the gap between low-level security observations and application-level decisions.

```text
Platform observation
        ↓
What does it mean?
        ↓
How confident are we?
        ↓
How serious is it?
        ↓
Does it matter for this operation?
        ↓
What should the application do?
```

That gap is where Kryvon provides value.

---

## Why Boolean Security Checks Are Not Enough

Consider:

```text
rooted = true
```

That tells the application very little.

The same observation could occur in:

- Development.
- QA.
- A legitimate emulator workflow.
- A modified consumer device.
- A sophisticated attack environment.

A useful security system needs more information:

```text
Observation
+ confidence
+ context
+ other observations
+ policy
→ decision
```

---

## Why Context Matters

Security requirements change with the operation.

An application may tolerate a suspicious environment while a user is browsing public content but require stronger assurance before allowing a high-value transaction.

```text
                Same runtime
                     │
          ┌──────────┴──────────┐
          ↓                     ↓
       Browse              Sensitive action
          │                     │
       ALLOW                 RESTRICT
```

This is more useful than making every runtime signal an application-wide block condition.

---

## Why Explainability Matters

Security decisions affect real users.

If Kryvon returns only:

```text
BLOCK
```

the application cannot understand or properly handle the decision.

A useful result should answer:

```text
What happened?
Why does it matter?
How confident are we?
What policy caused this decision?
What should the application do?
```

Explainability is therefore part of the security design, not merely a logging feature.

---

## Why Failure Semantics Matter

Security systems fail.

A native detector can throw an exception. A platform API can be unavailable. A channel can fail. Configuration can be incomplete.

Those situations are not equivalent to detecting an attack.

Kryvon must preserve the distinction:

```text
DETECTED
NOT_DETECTED
UNKNOWN
FAILED
UNSUPPORTED
```

A policy may decide that a failure should cause a transaction to be blocked. That is legitimate.

But the framework must not lie about the reason.

---

## Why Kryvon Should Be a Decision Engine

The useful abstraction is:

```text
                    KRYVON
                       │
       ┌───────────────┴───────────────┐
       │                               │
   Evidence                        Context
       │                               │
       └───────────────┬───────────────┘
                       ↓
                   Assessment
                       ↓
                     Risk
                       ↓
                    Policy
                       ↓
                   Decision
```

The host application receives a decision rather than having to understand every detector implementation.

---

## Who Needs This?

Kryvon is most useful for applications where runtime conditions influence security decisions.

Examples include:

- Financial applications.
- Payment applications.
- Enterprise applications.
- Applications handling sensitive personal information.
- Authentication-heavy applications.
- High-value transaction applications.
- Applications with meaningful intellectual-property or abuse concerns.

It can also be useful in other applications, but security controls should always be proportional to the actual threat model.

---

## Why Flutter?

Flutter provides a productive cross-platform application layer, but security-relevant platform capabilities often remain native.

A Flutter developer should not need to implement separate Android security checks, native communication, result normalization, and policy logic for every application.

Kryvon can provide a consistent application-facing model while retaining native platform capabilities underneath.

```text
Flutter application
       ↓
Kryvon API
       ↓
Kryvon security model
       ↓
Platform implementation
```

The public API should hide unnecessary platform complexity without hiding security semantics.

---

## Why Not Just Use Platform Attestation?

Attestation and server-side controls can provide stronger security guarantees for appropriate use cases.

Kryvon should not compete with them or pretend to replace them.

A practical architecture can use multiple layers:

```text
Application runtime
       ↓
Kryvon local assessment
       ↓
Application/backend request
       ↓
Server-side authorization
       ↓
Attestation / additional controls where appropriate
```

Kryvon fills the local runtime assessment layer.

---

## Why Local Runtime Signals Still Matter

Local signals can be available immediately and can inform the application before or during sensitive operations.

They can also provide useful diagnostics and defense-in-depth signals when combined with backend controls.

The value is not that any one local signal is unbreakable.

The value is that the application has a structured way to incorporate multiple runtime observations into its security posture.

---

## The Product Promise

Kryvon should promise something it can actually deliver:

> **Kryvon helps applications understand runtime security conditions and make explainable, policy-driven decisions.**

It should not promise:

- Absolute tamper resistance.
- Impossible-to-bypass root detection.
- Guaranteed malware detection.
- Complete protection against reverse engineering.
- Client-side trust equivalent to a secure server boundary.

Honest security claims are part of the product.

---

## What Makes Kryvon Meaningful

Kryvon becomes meaningful if it provides all of these together:

### 1. Structured evidence

The application can inspect what was actually observed.

### 2. Confidence

Weak heuristics are not presented as certainty.

### 3. Correlation

Multiple related signals can be interpreted together.

### 4. Context

Risk can be evaluated against the operation being protected.

### 5. Policy

Different applications can make different decisions from the same evidence.

### 6. Explainable decisions

The application can understand why a result was produced.

### 7. Failure transparency

Detector failures are not disguised as threats.

### 8. Platform abstraction

Flutter applications get a consistent model while platform-specific capabilities remain native.

---

## The Test for Every Feature

Before adding a feature, ask:

> Does this materially improve Kryvon's ability to observe, understand, assess, or respond to runtime security risk?

If not, it should not be added simply because it sounds security-related.

---

## The Long-Term Vision

Kryvon should evolve from:

```text
A collection of runtime checks
```

to:

```text
A runtime security decision platform
```

The difference is architectural and practical.

A collection of checks tells developers what was detected.

A decision platform helps developers decide what to do.

That is why Kryvon exists.
