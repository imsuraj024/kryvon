# Kryvon Threat Model

## Scope

This document describes the threats Kryvon v0.0.1 is designed to detect, the severity assigned to each, and the limitations of each control. It is intended to help integrators make informed risk decisions about when and how to apply Kryvon.

Kryvon provides a **baseline** security layer. It is not a complete security solution and does not prevent all attacks.

---

## Threat Categories

### 1. Root / Privilege Escalation

**Threat:** The device has been rooted, giving an attacker OS-level access. This allows memory inspection, SSL unpinning, hooking of app logic, and bypass of any software-enforced control.

**Status:** Detected (v0.0.1, Android only)

**Indicators checked:**

| Indicator | Severity | Signal |
|---|---|---|
| `suExecution` | critical | `su` binary is executable via shell |
| `suBinary` | high | `su` binary exists at known paths |
| `dangerousProps` | high | `ro.debuggable=1` or `ro.secure=0` system properties |
| `testKeys` | medium | Build signed with test keys (`Build.TAGS`) |
| `writableSystem` | medium | `/system` partition mounted as read-write |
| `knownRootApp` | medium | Magisk, SuperSU, or similar packages installed |

**Limitations:**
- Does not detect Magisk with Zygisk hiding enabled
- Does not detect custom root implementations not in the known-paths or known-packages lists
- `su` execution check can be bypassed by renaming the binary
- All checks are passive and can be spoofed by a sufficiently privileged attacker

**Recommended response:**
- `fintech` profile: terminate the app
- General apps: warn user, restrict sensitive operations, emit telemetry

---

### 2. Debugger Attachment

**Threat:** A debugger (e.g., Android Studio, Frida, jdwp) is attached to the app process, allowing runtime inspection and modification of app state.

**Status:** Defined in `ThreatType.debuggerDetected`. Native stub exists (`DebuggerDetector.kt`). Not yet implemented.

**Planned indicators:**
- `android.os.Debug.isDebuggerConnected()`
- JDWP process presence
- TracerPid in `/proc/self/status`

---

### 3. Emulator / Virtual Device

**Threat:** The app is running on an emulator or virtual device, which is commonly used for automated reverse engineering, testing of attack scripts, and instrumentation.

**Status:** Defined in `ThreatType.emulatorDetected`. Not yet implemented.

**Planned indicators:**
- `Build.FINGERPRINT` contains `generic` or `unknown`
- `Build.HARDWARE` contains `goldfish` or `ranchu`
- QEMU-specific system properties

---

### 4. Insecure Storage

**Threat:** Sensitive data (tokens, PII, keys) is stored in an insecure location (shared preferences without encryption, world-readable files, external storage).

**Status:** Defined in `ThreatType.insecureStorage`. Not yet implemented.

---

### 5. Network Pinning Failure

**Threat:** The app's SSL/TLS certificate pinning has been bypassed or is not configured, enabling man-in-the-middle interception of network traffic.

**Status:** Defined in `ThreatType.networkPinningFailure`. Not yet implemented.

---

## Severity Model

| Level | Index | Meaning |
|---|---|---|
| `low` | 0 | Informational. No direct exploit path. |
| `medium` | 1 | Elevated risk. Weakened environment. |
| `high` | 2 | Strong indicator of compromise or attack capability. |
| `critical` | 3 | Active exploitation likely. Terminate or restrict immediately. |

The `KryvonPolicy.blockThreshold` field controls which severity level triggers enforcement. Events below the threshold are still reported via `onThreat` but not enforced.

---

## Enforcement Actions

| Strategy | Effect | Suitable for |
|---|---|---|
| `emitOnly` | Log event, call `onThreat`, no further action | Analytics, low-sensitivity apps |
| `terminateApp` | Log event, call `exit(1)` | Fintech, healthcare, high-assurance apps |

---

## Out of Scope (v0.0.1)

The following attacks are **not** addressed by Kryvon v0.0.1:

- **Frida / dynamic instrumentation detection** — requires active process scanning
- **Repackaging / tampering detection** — requires APK signature verification at runtime
- **Overlay / tapjacking attacks** — UI-layer concern
- **Side-channel attacks** — hardware/OS level
- **iOS platform** — no implementation exists yet
- **Bypass resistance** — Kryvon does not protect itself from tampering; a sophisticated attacker can disable it

---

## Integration Risk Notes

- All detection runs at app startup via `Kryvon.runChecks()`. There is no continuous background monitoring.
- Guards run sequentially. A slow or failing native check does not block subsequent guards.
- `terminateApp` calls `exit(1)` directly. Ensure any cleanup logic (analytics flush, session close) is handled in `onThreat` before enforcement fires.
- Root detection results should be treated as signals, not proof. False positives can occur on custom ROMs and developer devices.