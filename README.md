# Kryvon

A structured mobile security baseline framework for Flutter applications.

Kryvon provides a guard-based runtime security layer that runs checks in parallel, aggregates risk across multiple threat signals, and enforces policy through a configurable enforcement strategy — all with a minimal API surface.

> **Platform support:** Android only. iOS support is not currently implemented.

---

## Features

- Root detection — 6 native indicators (su binary, su execution, dangerous props, writable system, known root apps, test keys)
- Debugger detection — 5 native signals (tracerPid, JDWP, Android debugger, system-debuggable flag, debuggable app flag)
- Parallel guard execution — all guards run concurrently via `Future.wait`
- Risk aggregation — severity scores combined with a threat-diversity bonus
- Configurable policy — set your own block threshold, enforcement strategy, and threat callback
- Extensible — implement `Guard` to add custom detectors

---

## Installation

Add to your `pubspec.yaml`:

```yaml
dependencies:
  kryvon: ^0.1.0
```

Then run:

```sh
flutter pub get
```

---

## Quick start

```dart
import 'package:kryvon/kryvon.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

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

  runApp(const MyApp());
}
```

For high-security applications, use the pre-configured fintech policy:

```dart
Kryvon.initialize(policy: KryvonPolicy.fintech());
await Kryvon.runChecks();
```

`KryvonPolicy.fintech()` blocks at `ThreatSeverity.medium` and terminates the app when exceeded.

---

## API reference

### `Kryvon`

The static entry point. All interaction goes through this class.

| Method | Description |
|---|---|
| `Kryvon.initialize({required policy, logLevel})` | Configure and start Kryvon. Auto-registers `RootGuard` and `DebuggerGuard`. |
| `Kryvon.registerGuard(guard)` | Add a custom `Guard` to the pipeline. Call after `initialize`. |
| `Kryvon.runChecks()` | Run all guards in parallel, aggregate risk, and enforce policy. |

---

### `KryvonPolicy`

Controls detection thresholds and enforcement behaviour.

```dart
KryvonPolicy({
  ThreatSeverity blockThreshold,       // default: ThreatSeverity.high
  EnforcementStrategy enforcementStrategy, // default: EnforcementStrategy.emitOnly
  ThreatHandler? onThreat,             // callback per individual ThreatEvent
})
```

| Factory | Description |
|---|---|
| `KryvonPolicy.fintech()` | `blockThreshold: medium`, `enforcementStrategy: terminateApp` |

---

### `ThreatSeverity`

| Value | Description |
|---|---|
| `low` | Informational; no immediate risk |
| `medium` | Moderate risk; worth monitoring |
| `high` | Significant risk; consider blocking |
| `critical` | Severe risk; enforce immediately |

---

### `ThreatType`

| Value | Description |
|---|---|
| `rootDetected` | Device root indicators found |
| `debuggerDetected` | Debugger or debug signal active |
| `emulatorDetected` | App running in an emulator *(not yet implemented)* |
| `insecureStorage` | Sensitive data in insecure location *(not yet implemented)* |
| `networkPinningFailure` | Certificate/key pinning failed *(not yet implemented)* |
| `deviceCompromised` | Synthetic aggregate event emitted after all guards complete |

---

### `EnforcementStrategy`

| Value | Description |
|---|---|
| `emitOnly` | Log and call `onThreat`; no further action |
| `terminateApp` | Call `exit(1)` after logging |

---

### `LogLevel`

Pass to `Kryvon.initialize` via the `logLevel` parameter.

| Value | Description |
|---|---|
| `debug` | Verbose — guard lifecycle events |
| `info` | General operational messages (default) |
| `warning` | Non-fatal issues |
| `error` | Guard or runtime failures |
| `silent` | No output |

---

## Root detection

`RootGuard` delegates to the native `RootDetector.kt` over the `com.kryvon.runtime` method channel. Six indicators are checked and mapped to severity:

| Indicator | Severity |
|---|---|
| `suExecution` | critical |
| `suBinary` | high |
| `dangerousProps` | high |
| `writableSystem` | high |
| `knownRootApp` | medium |
| `testKeys` | medium |

The highest-priority indicator determines the event severity.

---

## Debugger detection

`DebuggerGuard` delegates to the native `DebuggerDetector.kt`. Five signals are checked and mapped to severity:

| Signal | Severity |
|---|---|
| `tracerPid` | critical |
| `androidDebugger` | high |
| `systemDebuggable` | high |
| `jdwpEnabled` | medium |
| `debuggableApp` | medium |

---

## Risk aggregation

After all guards run, `RuntimeRiskAggregator` combines their events into a single `ThreatType.deviceCompromised` event:

1. Each event is scored: `low=1`, `medium=3`, `high=6`, `critical=10`
2. A diversity bonus of **+2** is added per unique `ThreatType` present
3. The total maps to a final `ThreatSeverity`:

| Total score | Severity |
|---|---|
| < 3 | low |
| 3–5 | medium |
| 6–9 | high |
| ≥ 10 | critical |

`KryvonPolicy.shouldBlock` is evaluated against this aggregated event. Individual events still fire `onThreat` as they are produced.

---

## Custom guards

Implement the `Guard` interface to add your own detectors:

```dart
class EmulatorGuard implements Guard {
  @override
  Future<List<ThreatEvent>> check() async {
    final isEmulator = await _detectEmulator();
    if (!isEmulator) return [];

    return [
      ThreatEvent(
        type: ThreatType.emulatorDetected,
        severity: ThreatSeverity.high,
      ),
    ];
  }
}

// Register after initialize:
Kryvon.registerGuard(EmulatorGuard());
```

Guards must not throw — any unhandled exception is caught by the runtime and treated as an empty result so that other guards are not blocked.

---

## Architecture overview

```
Kryvon.runChecks()
  │
  ├── RootGuard.check()      ──► RootDetector ──► KotlinRootDetector.kt
  ├── DebuggerGuard.check()  ──► DebuggerDetector ──► KotlinDebuggerDetector.kt
  └── [custom guards] ...
        │
        ▼ (Future.wait — parallel)
  List<ThreatEvent>
        │
        ├── onThreat(event) × N   (per individual event)
        │
        ▼
  RuntimeRiskAggregator.aggregate()
        │
        ▼
  ThreatEvent(type: deviceCompromised, severity: aggregated)
        │
  KryvonPolicy.shouldBlock?
        │
        ▼
  EnforcementExecutor.execute(strategy, event)
```

---

## Requirements

- Flutter `>=3.3.0`
- Dart SDK `^3.9.2`
- Android only
