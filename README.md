# Kryvon

Kryvon is a runtime security assessment and policy engine for Flutter applications. It separates local observations, threat interpretation, risk evaluation, and host-owned decisions.

## Core model

```text
Signal → Evidence → Assessment → Risk → Policy → Decision → Host application
```

Kryvon does not provide remote attestation and does not make a compromised client trustworthy. Sensitive backend operations must retain server-side authorization.

## Current implementation

- Domain models for evidence, assessment, risk, policy, decision and signal coverage.
- Detector registry and concurrency-limited orchestration with timeout/failure semantics.
- Explicit assessment generation rules with confidence thresholds and conflict handling.
- Android plugin and versioned MethodChannel `dev.kryvon/security.v1`.
- Initial Android signals:
  - `android.root.su_binary_present`: checks a fixed list of known paths for an executable `su` candidate.
  - `android.debugger.attached`: observes `Debug.isDebuggerConnected()`.
- Dart response validation and deterministic fixtures for positive, negative, conflicting, failed, unsupported, malformed and timeout cases.
- Flutter CI plus Android example build and Kotlin unit-test coverage.

The root executable signal is only an indicator. A fully checked absence of known paths is not proof that a device is unrooted. If a path check fails and no candidate was found, the result is `FAILED`, never `NOT_DETECTED`. A positive candidate remains `DETECTED` if other paths fail, with partial-failure counts in sanitized metadata.

## Example

Register the Android detector with the existing orchestrator:

```dart
import 'package:kryvon/kryvon.dart';

final detector = AndroidPlatformDetector();
final registry = DetectorRegistry([detector]);
final signalRun = await DetectorOrchestrator(registry: registry).run(
  context: AssessmentContext.transaction,
  platform: 'android',
);

final generated = AssessmentGenerator(
  rules: firstAndroidThreatRules,
).generate(signalRun);
```

This example generates assessments from local evidence only. It does not automatically execute a policy or enforce a decision.

## Security boundaries

- `DETECTED`, `NOT_DETECTED`, `UNKNOWN`, `FAILED`, and `UNSUPPORTED` remain distinct.
- Confidence describes observation certainty, not threat severity.
- Missing, duplicate, unexpected, failed or unsupported evidence must not be interpreted as safe.
- The native channel validates protocol version and request identity; the Dart adapter rejects malformed or mismatched responses.
- Local checks can be bypassed or patched in a compromised process.
- Debugger detection is time-sensitive and may be expected in development/QA.
- The host application owns enforcement; high-value operations require server-side authorization.

## Documentation

- [Domain model](docs/DOMAIN_MODEL.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Implementation contract](docs/IMPLEMENTATION_CONTRACT.md)
- [Detector orchestration contract](docs/DETECTOR_ORCHESTRATION_CONTRACT.md)
- [Native platform contract](docs/NATIVE_PLATFORM_CONTRACT.md)
- [Assessment generation contract](docs/ASSESSMENT_GENERATION_CONTRACT.md)
- [First Android threat rules](docs/FIRST_ANDROID_THREAT_RULES.md)
