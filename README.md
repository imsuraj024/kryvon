# kryvon

A structured mobile security baseline framework for Flutter applications.

Kryvon provides runtime threat detection with a policy-based enforcement model. It detects security risks (rooted devices, debugger attachment, emulators, etc.) and lets you define how the app responds — from logging to hard termination.

> v0.0.1 — Android only. Root detection is implemented. Additional guards (debugger, emulator, network pinning) are defined but not yet active.

---

## Installation

Add to your `pubspec.yaml`:

```yaml
dependencies:
  kryvon:
    path: ../kryvon  # or pub.dev path once published
```

---

## Quick Start

```dart
import 'package:kryvon/kryvon.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  Kryvon.initialize(
    policy: KryvonPolicy.fintech(),
    logLevel: LogLevel.debug,
  );

  await Kryvon.runChecks();

  runApp(const MyApp());
}
```

Call `initialize` once before `runApp`, then `runChecks` to execute all registered guards. Root detection runs automatically.

---

## Policy Configuration

```dart
Kryvon.initialize(
  policy: KryvonPolicy(
    blockThreshold: ThreatSeverity.high,
    enforcementStrategy: EnforcementStrategy.emitOnly,
    onThreat: (event) {
      print('Threat: ${event.type.name} [${event.severity.name}]');
      // send to your analytics pipeline
    },
  ),
);
```

### Built-in presets

| Preset | Block threshold | Enforcement |
|---|---|---|
| `KryvonPolicy()` (default) | `high` | `emitOnly` |
| `KryvonPolicy.fintech()` | `medium` | `terminateApp` |

### Enforcement strategies

| Strategy | Behavior |
|---|---|
| `emitOnly` | Logs threat, calls `onThreat`, no further action |
| `terminateApp` | Logs threat, calls `onThreat`, then `exit(1)` |

---

## Threat Types

| Type | Implemented | Severity |
|---|---|---|
| `rootDetected` | Yes | medium / high / critical |
| `debuggerDetected` | No (planned) | — |
| `emulatorDetected` | No (planned) | — |
| `insecureStorage` | No (planned) | — |
| `networkPinningFailure` | No (planned) | — |

---

## Root Detection (Android)

Kryvon checks for six root indicators at the native layer:

| Indicator | Severity | What it checks |
|---|---|---|
| `suExecution` | critical | Whether `su` can be executed via shell |
| `suBinary` | high | Known `su` binary paths |
| `dangerousProps` | high | `ro.debuggable=1` or `ro.secure=0` |
| `testKeys` | medium | `Build.TAGS` contains `test-keys` |
| `writableSystem` | medium | `/system` mounted `rw` |
| `knownRootApp` | medium | Magisk, SuperSU, etc. installed |

---

## Custom Guards

Implement the `Guard` interface and register before calling `runChecks`:

```dart
class MyCustomGuard implements Guard {
  @override
  Future<List<ThreatEvent>> check() async {
    // your detection logic
    return [
      ThreatEvent(
        type: ThreatType.debuggerDetected,
        severity: ThreatSeverity.high,
      ),
    ];
  }
}

Kryvon.registerGuard(MyCustomGuard());
```

---

## Logging

```dart
Kryvon.initialize(
  policy: KryvonPolicy(),
  logLevel: LogLevel.debug, // debug | info | warning | error | silent
);
```

All log output is prefixed `[Kryvon][LEVEL]` and also emits to `dart:developer` for IDE tooling.

---

## Documentation

- [Architecture](docs/architecture.md) — component breakdown, data flow, extension guide
- [Threat Model](docs/threat_model.md) — threats, severities, limitations, out-of-scope
- [Root Detection](docs/root_detection.md) — Android root check details and policy guidance

---

## Platform Support

| Platform | Status |
|---|---|
| Android | Supported |
| iOS | Not implemented |
