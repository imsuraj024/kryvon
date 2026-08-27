<div align="center">

# KRYVON

**Flutter Security Baseline**

A guard-based runtime security layer for Android Flutter applications.

<br>

[![Dart](https://img.shields.io/badge/Dart-3.9%2B-0175C2?logo=dart&logoColor=white)](https://dart.dev/) [![Flutter](https://img.shields.io/badge/Flutter-3.3%2B-02569B?logo=flutter&logoColor=white)](https://flutter.dev/) [![Android](https://img.shields.io/badge/Android-Supported-3DDC84?logo=android&logoColor=white)](https://developer.android.com/)

**Detect → Aggregate → Enforce**

</div>

---

## Why Kryvon?

Mobile security checks are often scattered through application code. Kryvon puts them behind a small, policy-driven pipeline so security signals can be detected consistently and handled deliberately.

It runs built-in guards in parallel, aggregates threat signals, and applies configurable enforcement. The runtime is designed to fail secure: bridge failures and guard failures are treated as compromise signals.

> **Platform:** Android only. iOS support is not currently implemented.

## What it covers

| Area | Current implementation |
| --- | --- |
| Root | 6 native indicators with severity mapping |
| Debugger | 5 native debugger signals |
| Hooking | Frida, Xposed and Substrate detection |
| Emulator | QEMU, Genymotion and Android fingerprints |
| Integrity | APK signing certificate SHA-256 verification |
| Runtime | Parallel guards, risk aggregation and policy enforcement |
| Transport | Nonce-validated `MethodChannel` bridge |
| Extensibility | Custom `Guard` implementations |

## Architecture

```text
Flutter application
        │
        ▼
   Kryvon.runChecks()
        │
        ├── RootGuard ────────► native RootDetector
        ├── DebuggerGuard ────► native DebuggerDetector
        ├── HookGuard ────────► native HookDetector
        ├── EmulatorGuard ────► native EmulatorDetector
        ├── IntegrityGuard ───► native IntegrityDetector
        └── Custom guards
                │
                ▼
        ThreatEvent collection
                │
        ┌───────┴────────┐
        │                │
   Immediate        Risk aggregation
   enforcement             │
        │                  ▼
        └──────────► Policy enforcement
```

Native communication passes through `SecureRuntimeBridge`. Every request carries a cryptographically random nonce that the native side must echo. A mismatch, null response or exception becomes a compromise signal.

## Quick start

```yaml
dependencies:
  kryvon: ^0.3.0
```

```dart
Kryvon.initialize(
  policy: KryvonPolicy(
    blockThreshold: ThreatSeverity.high,
    enforcementStrategy: EnforcementStrategy.emitOnly,
    onThreat: (event) {
      print('Threat: ${event.type.name} [${event.severity.name}]');
    },
  ),
);

await Kryvon.runChecks();
```

For a stricter preset:

```dart
Kryvon.initialize(policy: KryvonPolicy.fintech());
await Kryvon.runChecks();
```

## Enforcement model

Kryvon separates **detection** from **response**. Individual events can trigger immediate handling, while the full set of signals is also aggregated into a device-compromise assessment.

Built-in defaults include immediate `blockApp` handling for hook and integrity violations, `restrictFeatures` for root detection, and configurable policy behavior for other threats.

## Engineering notes

- Guards execute concurrently with `Future.wait`.
- Individual threat events remain observable through `onThreat`.
- Risk aggregation uses weighted threat types.
- Bridge failures fail secure rather than silently continuing.
- Custom guards can extend the detection pipeline.

## API surface

```text
Kryvon.initialize(policy, logLevel)
Kryvon.registerGuard(guard)
Kryvon.runChecks()

KryvonPolicy
ThreatSeverity
ThreatType
EnforcementStrategy
LogLevel
Guard
```

See the source and tests for the complete API behavior.

## Project status

**Active development · v0.3.0 · Android**

The repository currently includes implemented root, debugger, hook, emulator and integrity detection. `insecureStorage` and `networkPinningFailure` are represented as threat types but are not yet implemented.

## Requirements

- Flutter `>=3.3.0`
- Dart SDK `^3.9.2`
- Android

## Repository

[Explore the source →](https://github.com/imsuraj024/kryvon)
