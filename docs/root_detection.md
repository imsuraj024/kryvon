# Root Detection (Android)

## Overview

Kryvon v0.0.1 implements baseline root detection on Android. Detection is performed natively in Kotlin (`RootDetector.kt`) and surfaced to Dart via the `com.kryvon.runtime` MethodChannel.

## Indicators Checked

Six indicators are evaluated on every `Kryvon.runChecks()` call:

| Indicator | Severity | What it checks |
|---|---|---|
| `suExecution` | critical | `su` binary can be executed via shell (`which su`) |
| `suBinary` | high | `su` binary exists at any of 9 known paths |
| `dangerousProps` | high | `ro.debuggable=1` or `ro.secure=0` in system properties |
| `testKeys` | medium | `Build.TAGS` contains `test-keys` |
| `writableSystem` | medium | `/system` partition is mounted read-write |
| `knownRootApp` | medium | Magisk, SuperSU, or similar package is installed |

Severity is determined by the highest-severity indicator found. All matched indicators are included in the `ThreatEvent` metadata.

## Limitations

This implementation does NOT:
- Detect Magisk with Zygisk/DenyList hiding enabled
- Detect custom or renamed `su` binaries not in the known-paths list
- Detect advanced instrumentation frameworks (Frida, Xposed)
- Prevent bypass by a sufficiently privileged attacker
- Provide tamper resistance (the detector itself can be disabled)

Root detection is a baseline control and must be combined with policy-based mitigation.

## Recommended Policy Response

- **Fintech / high-assurance apps:** use `KryvonPolicy.fintech()` to terminate on `medium` or above
- **General apps:** use `onThreat` callback to restrict sensitive operations, block login, or trigger telemetry
- Display a warning to the user where termination is not appropriate
- Treat results as signals — false positives can occur on custom ROMs and developer devices