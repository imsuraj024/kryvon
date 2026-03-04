# Kryvon Architecture

## Overview

Kryvon is a Flutter plugin for Android that provides a structured mobile security baseline framework. It runs runtime threat detection and applies configurable policy-based enforcement when threats are detected.

The design separates three concerns: **detection** (Guards), **policy** (KryvonPolicy), and **enforcement** (EnforcementExecutor). This makes it straightforward to add new threat types without changing the core loop.

---

## Layer Diagram

```
┌────────────────────────────────────────────┐
│              Flutter App                   │
│         Kryvon.initialize(policy)          │
│           Kryvon.runChecks()               │
└───────────────────┬────────────────────────┘
                    │
         ┌──────────▼──────────┐
         │   KryvonPolicy      │  blockThreshold, enforcementStrategy, onThreat
         └──────────┬──────────┘
                    │
         ┌──────────▼──────────┐
         │   Guard (abstract)  │  check() → List<ThreatEvent>
         └──────────┬──────────┘
                    │
         ┌──────────▼──────────┐
         │     RootGuard       │  maps result → ThreatEvent + severity
         └──────────┬──────────┘
                    │
         ┌──────────▼──────────┐
         │    RootDetector     │  delegates to native via MethodChannel
         └──────────┬──────────┘
                    │ com.kryvon.runtime (MethodChannel)
         ┌──────────▼──────────┐
         │  KryvonRuntimePlugin│  Android FlutterPlugin
         └──────────┬──────────┘
                    │
         ┌──────────▼──────────┐
         │   RootDetector.kt   │  native checks (su binary, props, mount, etc.)
         └─────────────────────┘
                    │
         ┌──────────▼──────────┐
         │ EnforcementExecutor │  emitOnly | terminateApp
         └─────────────────────┘
```

---

## Core Components

### `Kryvon` (entry point)

Static class. Call `Kryvon.initialize(policy:)` once at app startup (before `runApp`), then call `Kryvon.runChecks()` to execute all registered guards. `RootGuard` is auto-registered on initialization.

```dart
Kryvon.initialize(policy: KryvonPolicy.fintech(), logLevel: LogLevel.debug);
await Kryvon.runChecks();
```

### `KryvonPolicy`

Defines the app's security posture:

| Field | Type | Default | Description |
|---|---|---|---|
| `blockThreshold` | `ThreatSeverity` | `high` | Minimum severity that triggers enforcement |
| `enforcementStrategy` | `EnforcementStrategy` | `emitOnly` | What happens when a threat is blocked |
| `onThreat` | `ThreatHandler?` | `null` | Optional callback for every detected threat event |

Built-in preset:
- `KryvonPolicy.fintech()` — threshold: `medium`, strategy: `terminateApp`

### `Guard` (abstract interface)

```dart
abstract class Guard {
  Future<List<ThreatEvent>> check();
}
```

All security checks implement `Guard`. `Kryvon.runChecks()` iterates every registered guard, collects `ThreatEvent`s, and feeds them through the policy pipeline. Guard failures are caught and logged; they do not crash the app.

### `ThreatEvent`

Data class emitted by guards:

```dart
ThreatEvent(
  type: ThreatType.rootDetected,
  severity: ThreatSeverity.high,
  metadata: {"indicators": ["suBinary"]},
)
```

### `EnforcementExecutor`

Executes the configured `EnforcementStrategy` when the policy decides a threat should be blocked:

| Strategy | Behavior |
|---|---|
| `emitOnly` | Logs the event, no further action |
| `terminateApp` | Logs and calls `exit(1)` |

### `RuntimeChannel`

Thin Flutter MethodChannel wrapper. Channel name: `com.kryvon.runtime`. Currently exposes one method: `checkRoot`.

### `KryvonLogger`

Internal structured logger. Levels: `debug`, `info`, `warning`, `error`, `silent`. All output is prefixed `[Kryvon][LEVEL]`. Also emits to `dart:developer` log for IDE tooling.

---

## Root Detection

### `RootGuard`

Implements `Guard`. Calls `RootDetector`, maps indicators to a `ThreatSeverity`, and returns a single `ThreatEvent` if any indicator is found.

Severity mapping:

| Indicator | Severity |
|---|---|
| `suExecution` | `critical` |
| `suBinary`, `dangerousProps` | `high` |
| `testKeys`, `writableSystem`, `knownRootApp` | `medium` |

### `RootDetector` (Dart)

Calls `RuntimeChannel.checkRoot()`, deserializes the response into `List<RootIndicatorType>`, and returns a `RootDetectionResult`.

### `RootDetector.kt` (Android native)

Performs six native checks:

| Indicator | How |
|---|---|
| `suBinary` | Checks 9 known `su` binary paths |
| `suExecution` | Executes `which su` via shell |
| `testKeys` | Checks `Build.TAGS` for `test-keys` |
| `dangerousProps` | Reads `getprop` for `ro.debuggable=1`, `ro.secure=0` |
| `writableSystem` | Parses `mount` output for `/system rw` |
| `knownRootApp` | Queries `PackageManager` for Magisk, SuperSU, etc. |

Returns: `Map<String, Any>` with key `"indicators"` containing matched indicator name strings.

---

## Data Flow

```
Kryvon.runChecks()
  │
  ├─ for each Guard:
  │     guard.check()
  │       └─ [RootGuard] → RootDetector.check()
  │               └─ RuntimeChannel.checkRoot()
  │                     └─ [MethodChannel] → KryvonRuntimePlugin.onMethodCall("checkRoot")
  │                               └─ RootDetector.kt.checkRoot()
  │                                     └─ returns {indicators: [...]}
  │
  ├─ for each ThreatEvent:
  │     KryvonLogger.threat(event)
  │     policy.onThreat?.call(event)
  │     if policy.shouldBlock(event):
  │         EnforcementExecutor.execute(strategy, event)
```

---

## Extending Kryvon

To add a new threat check (e.g., debugger detection):

1. Create a `Guard` subclass (e.g., `DebuggerGuard`) in `lib/src/runtime/debugger/`.
2. Add a native method to `KryvonRuntimePlugin.kt` and a corresponding detector class.
3. Expose the channel method in `RuntimeChannel`.
4. Register the guard: `Kryvon.registerGuard(DebuggerGuard())`.

`ThreatType` and the relevant indicator enum should be extended accordingly. The policy pipeline requires no changes.

---

## Platform Support

| Platform | Status |
|---|---|
| Android | Supported (v0.0.1) |
| iOS | Not implemented |
