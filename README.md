# Kryvon

Kryvon is a runtime security assessment and policy engine for Flutter applications.

The project is currently being rebuilt from first principles. The `kryvon-rebuild` branch contains the new domain foundation; platform detectors and runtime integrations will be added only after the core contracts are stable.

## Core model

```text
Signal
  ↓
Evidence
  ↓
Assessment
  ↓
Risk
  ↓
Policy
  ↓
Decision
  ↓
Application response
```

Kryvon deliberately separates detection from application decisions.

A detector reports evidence. It does not decide whether the application should block, restrict, monitor, or allow an operation.

## Current state

Implemented:

- Evidence model.
- Assessment model.
- Risk model.
- Policy model.
- Decision result model.
- Initial domain tests.

Not yet implemented:

- Runtime detectors.
- Native platform bridge.
- Android security checks.
- Production enforcement.

## Documentation

- `KRYVON.md` — product and engineering specification.
- `docs/WHY_KRYVON.md` — problem and purpose.
- `docs/DOMAIN_MODEL.md` — domain semantics.
- `docs/THREAT_MODEL.md` — threat scenarios and security boundaries.
- `docs/IMPLEMENTATION_CONTRACT.md` — implementation rules.

## Development principle

Do not add a security feature merely because it is possible to detect something.

Every feature must have a clear place in the model:

```text
What is observed?
What evidence does it produce?
What does that evidence mean?
How does it affect risk?
Which policy controls the consequence?
What decision can result?
```

Kryvon should provide useful, explainable security decisions without claiming that client-side checks can establish absolute trust.
