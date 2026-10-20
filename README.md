# Kryvon

Kryvon is a runtime security assessment and policy engine for Flutter applications. It separates local observations, threat interpretation, risk evaluation, and host-owned decisions.

> **Release 0.4.0 is a breaking API rewrite.** It replaces the earlier guard-oriented API with evidence, assessment, risk, policy, and decision contracts.

## Install

Add Kryvon to your Flutter application's `pubspec.yaml`:

```yaml
dependencies:
  kryvon: ^0.4.0
```

Kryvon 0.4.0 requires Dart 3.9.2 or newer and Flutter 3.35.7 or newer. The native detector included in this release is Android-specific; the core domain and orchestration abstractions are written in Dart.

## Core model

```text
Signal → Evidence → Assessment → Risk → Policy → Decision → Host application
```

Kryvon does not provide remote attestation and cannot make a compromised client trustworthy. Sensitive backend operations must retain server-side authorization.

## Current implementation

- Domain models for evidence, assessment, risk, policy, decision, and signal coverage.
- Detector registry and concurrency-limited orchestration with timeout and failure semantics.
- Explicit assessment generation rules with confidence thresholds and conflict handling.
- Android plugin using the versioned MethodChannel `dev.kryvon/security.v1`.
- Initial Android signals:
  - `android.root.su_binary_present`: checks a fixed list of known paths for an executable `su` candidate.
  - `android.debugger.attached`: observes `Debug.isDebuggerConnected()`.
- Dart-side validation of native responses and test fixtures for positive, negative, conflicting, failed, unsupported, malformed, and timeout cases.

## Example

The following example runs the Android detector and generates assessments from its evidence. Put it inside an asynchronous function in an Android Flutter application:

```dart
import 'package:kryvon/kryvon.dart';

Future<void> assessRuntimeSecurity() async {
  final detector = AndroidPlatformDetector();
  final registry = DetectorRegistry([detector]);
  final signalRun = await DetectorOrchestrator(registry: registry).run(
    context: AssessmentContext.transaction,
    platform: 'android',
  );

  final generated = AssessmentGenerator(
    rules: firstAndroidThreatRules,
  ).generate(signalRun);

  final risk = const RiskEvaluator().evaluate(
    generated.assessments,
    signalRun: signalRun,
  );

  // The host application decides how to apply its policy to this risk.
  // Inspect generated.diagnostics, generated.conflicts, and risk.uncertainties
  // before treating the result as conclusive.
  print('Risk level: ${risk.level}');
}
```

This example generates assessments and evaluates risk. It does not automatically execute a policy or enforce a decision. Handle unsupported platforms and incomplete evidence explicitly in the host application.

## Security boundaries

- `DETECTED`, `NOT_DETECTED`, `UNKNOWN`, `FAILED`, and `UNSUPPORTED` are distinct outcomes.
- Confidence describes observation certainty, not threat severity.
- Missing, duplicate, unexpected, failed, or unsupported evidence must not be interpreted as safe.
- A completed absence check for known `su` paths is not proof that a device is unrooted.
- If a path check fails and no candidate is found, the result is `FAILED`, not `NOT_DETECTED`.
- Local checks can be bypassed or patched in a compromised process.
- Debugger detection is time-sensitive and may be expected in development and QA.
- The host application owns enforcement; high-value operations require server-side authorization.

## Documentation

- [Domain model](doc/DOMAIN_MODEL.md)
- [Threat model](doc/THREAT_MODEL.md)
- [Implementation contract](doc/IMPLEMENTATION_CONTRACT.md)
- [Detector orchestration contract](doc/DETECTOR_ORCHESTRATION_CONTRACT.md)
- [Native platform contract](doc/NATIVE_PLATFORM_CONTRACT.md)
- [Assessment generation contract](doc/ASSESSMENT_GENERATION_CONTRACT.md)
- [First Android threat rules](doc/FIRST_ANDROID_THREAT_RULES.md)

## Compatibility and testing

The package's Flutter and Dart minimums are intentionally aligned with the SDK used for the release baseline. Before publishing, run formatting, static analysis, tests, API documentation generation, and `dart pub publish --dry-run`. The repository CI also builds the Android example and runs native unit tests.
