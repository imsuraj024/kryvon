# Kryvon

A structured mobile security baseline framework for Flutter applications.

Kryvon provides a guard-based runtime security layer that runs checks in parallel, aggregates risk across multiple threat signals, and enforces policy through a configurable enforcement strategy — all with a minimal API surface.

> **Platform support:** Android only. iOS support is not currently implemented.

---

## Features

- Root detection — 6 native indicators (su binary, su execution, dangerous props, writable system, known root apps, test keys)
- Debugger detection — 5 native signals (tracerPid, JDWP, Android debugger, system-debuggable flag, debuggable app flag)
- Hook detection — Frida (process names, ports 27042/27043, memory maps), Xposed (reflection), Substrate (library maps)
- Emulator detection — QEMU, Genymotion, generic Android emulator fingerprints
- Integrity detection — APK signing certificate SHA-256 verification
- Parallel guard execution — all guards run concurrently via `Future.wait`
- Per-type enforcement — immediate `blockApp` on hook/tamper, `restrictFeatures` on root
- Risk aggregation — per-type flat weights combined into a final severity
- Hardened transport — nonce-validated `MethodChannel` via `SecureRuntimeBridge`; any failure → compromised
- Fail-secure — any guard failure is treated as `hookDetected/critical`
- Extensible — implement `Guard` to add custom detectors

---

## Installation

Add to your `pubspec.yaml`:

```yaml
dependencies:
  kryvon: ^0.3.0
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

To verify APK signing integrity, pass your expected certificate SHA-256:

```dart
Kryvon.initialize(
  policy: KryvonPolicy(
    expectedSignatureSha256: 'YOUR_CERT_SHA256_HERE',
    blockThreshold: ThreatSeverity.high,
    enforcementStrategy: EnforcementStrategy.blockApp,
    onThreat: (event) => print('${event.type.name}: ${event.severity.name}'),
  ),
);
```

---

## API reference

### `Kryvon`

The static entry point. All interaction goes through this class.

| Method | Description |
|---|---|
| `Kryvon.initialize({required policy, logLevel})` | Configure and start Kryvon. Auto-registers all five built-in guards. |
| `Kryvon.registerGuard(guard)` | Add a custom `Guard` to the pipeline. Call after `initialize`. |
| `Kryvon.runChecks()` | Run all guards in parallel, aggregate risk, and enforce policy. |

---

### `KryvonPolicy`

Controls detection thresholds and enforcement behaviour.

```dart
KryvonPolicy({
  ThreatSeverity blockThreshold,            // default: ThreatSeverity.high
  EnforcementStrategy enforcementStrategy,  // default: EnforcementStrategy.emitOnly
  ThreatHandler? onThreat,                  // callback per individual ThreatEvent
  String? expectedSignatureSha256,          // APK signing certificate SHA-256
})
```

`strategyForType(ThreatType)` returns the enforcement strategy for a given threat type. The built-in defaults are:

| ThreatType | Strategy |
|---|---|
| `hookDetected` | `blockApp` |
| `integrityFailure` | `blockApp` |
| `rootDetected` | `restrictFeatures` |
| all others | `enforcementStrategy` (from policy) |

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
| `hookDetected` | Frida, Xposed, or Substrate instrumentation detected |
| `emulatorDetected` | App running in an emulator |
| `integrityFailure` | APK signing certificate mismatch |
| `insecureStorage` | Sensitive data in insecure location *(not yet implemented)* |
| `networkPinningFailure` | Certificate/key pinning failed *(not yet implemented)* |
| `deviceCompromised` | Synthetic aggregate event emitted after all guards complete |

---

### `EnforcementStrategy`

| Value | Description |
|---|---|
| `emitOnly` | Log and call `onThreat`; no further action |
| `terminateApp` | Call `exit(1)` after logging |
| `blockApp` | Immediate `exit(1)` — used for hook and integrity violations |
| `restrictFeatures` | Signal via callback; host app gates features accordingly |

Hook and integrity violations trigger `blockApp` immediately — before the risk aggregator runs.

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

`RootGuard` delegates to the native `RootDetector.kt` over the obfuscated method channel. Six indicators are checked and mapped to severity:

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

## Hook detection

`HookGuard` delegates to `HookDetector.kt` and checks for active instrumentation frameworks:

| Signal | Framework |
|---|---|
| Process names in `/proc/*/cmdline` | Frida |
| Open ports 27042 / 27043 | Frida |
| Library names in `/proc/self/maps` | Frida / Substrate |
| `de.robv.android.xposed` class via reflection | Xposed |

Any positive indicator emits `hookDetected/critical`. Detection failure is also treated as `hookDetected/critical` (fail-secure).

---

## Emulator detection

`EmulatorGuard` delegates to `EmulatorDetector.kt` and checks:

| Signal | Description |
|---|---|
| `Build.FINGERPRINT` | Generic or unknown fingerprint |
| `ro.hardware` getprop | QEMU hardware |
| `Build` fields | Emulator-specific values (e.g. `BUILD_ID`, `MODEL`) |
| QEMU device files | `/dev/socket/qemud`, `/dev/qemu_pipe` |
| Genymotion properties | `ro.product.device` contains `vbox` |

---

## Integrity detection

`IntegrityGuard` delegates to `IntegrityDetector.kt` and verifies the APK signing certificate:

1. Retrieves the signing certificate via `PackageManager`
2. Computes its SHA-256 fingerprint
3. Compares (constant-time) against `KryvonPolicy.expectedSignatureSha256`

If the value is not set in policy, the check is skipped (no event emitted). A mismatch emits `integrityFailure/critical` and triggers immediate `blockApp`.

---

## Risk aggregation

After all guards complete, `RuntimeRiskAggregator` combines their events into a single `ThreatType.deviceCompromised` event using per-type flat weights:

| ThreatType | Weight |
|---|---|
| `hookDetected` | 50 |
| `integrityFailure` | 50 |
| `rootDetected` | 30 |
| `debuggerDetected` | 20 |
| `emulatorDetected` | 20 |

The highest weight across all detected threats determines the aggregated severity:

| Score | Severity |
|---|---|
| ≥ 50 | critical |
| ≥ 30 | high |
| ≥ 20 | medium |
| < 20 | low |

`KryvonPolicy.shouldBlock` is evaluated against this aggregated event. Individual events still fire `onThreat` as they are produced.

> Note: Hook and integrity violations bypass aggregation — `blockApp` fires immediately on the individual event.

---

## Transport hardening

All native calls go through `SecureRuntimeBridge` (default: `MethodChannelBridge`):

- A 16-byte cryptographically random nonce is attached to every outgoing request (`Random.secure`)
- The native side must echo the same nonce in its response
- Nonce mismatch, null response, or any exception → `{'__compromised': true}`
- The channel name is XOR-obfuscated at the source level to impede static analysis

To inject a custom bridge (e.g. in tests):

```dart
RuntimeChannel.initialize(MyMockBridge());
Kryvon.initialize(policy: ...);
```

---

## Custom guards

Implement the `Guard` interface to add your own detectors:

```dart
class NetworkPinningGuard implements Guard {
  @override
  Future<List<ThreatEvent>> check() async {
    final pinningValid = await _verifyPins();
    if (pinningValid) return [];

    return [
      ThreatEvent(
        type: ThreatType.networkPinningFailure,
        severity: ThreatSeverity.high,
      ),
    ];
  }
}

// Register after initialize:
Kryvon.registerGuard(NetworkPinningGuard());
```

Guards must not throw — any unhandled exception is caught by the runtime and treated as `hookDetected/critical` (fail-secure).

---

## Architecture overview

```
Kryvon.runChecks()
  │
  ├── RootGuard.check()       ──► RootDetector      ──► RootDetector.kt
  ├── DebuggerGuard.check()   ──► DebuggerDetector  ──► DebuggerDetector.kt
  ├── HookGuard.check()       ──► HookDetector      ──► HookDetector.kt
  ├── EmulatorGuard.check()   ──► EmulatorDetector  ──► EmulatorDetector.kt
  ├── IntegrityGuard.check()  ──► IntegrityDetector ──► IntegrityDetector.kt
  └── [custom guards] ...
        │
        ▼ (Future.wait — parallel)
  List<ThreatEvent>
        │
        ├── hook/integrity event? → blockApp immediately (exit)
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

All native calls pass through `SecureRuntimeBridge` (nonce-validated). Any bridge failure returns `__compromised: true` and is treated as `hookDetected/critical`.

---

## Requirements

- Flutter `>=3.3.0`
- Dart SDK `^3.9.2`
- Android only
