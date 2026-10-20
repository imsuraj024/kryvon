# First Concrete Threat Rules (Android)

**Status:** explicit rules and synthetic fixtures are implemented. The Android adapter is implemented on the feature branch and must pass Dart and Android validation before merge.

This catalog intentionally starts with narrow, observable indicators. It does not claim that a device is safe when an indicator is absent, and it does not make an authorization decision. A compromised client can tamper with local checks; sensitive backend operations must retain server-side authorization.

## Signal contracts

### `android.root.su_binary_present`

The detector checks this fixed path set, in order:

- `/system/bin/su`
- `/system/xbin/su`
- `/sbin/su`
- `/system/sbin/su`
- `/vendor/bin/su`
- `/su/bin/su`
- `/system/bin/.ext/.su`
- `/system/usr/we-need-root/su`
- `/system/bin/failsafe/su`
- `/data/local/xbin/su`
- `/data/local/bin/su`
- `/data/local/su`

The list is fixed in the native implementation. Callers cannot supply or override paths.

- **DETECTED:** At least one path resolves via `stat` to a regular file with an executable permission bit. Confidence is **MEDIUM**. If other paths failed, the result remains detected but metadata records the count of partial check failures.
- **NOT_DETECTED:** Every configured path was checked, no candidate executable was found, and no check failed. Confidence is **HIGH**.
- **FAILED:** No candidate executable was found and one or more paths could not be checked reliably. In particular, permission errors and unexpected OS errors must never be treated as absence.
- **UNKNOWN:** Reserved for an observation that runs but cannot reliably distinguish presence from absence. Current path probing maps OS errors to `FAILED` instead.
- **UNSUPPORTED:** Reserved for a platform/runtime that cannot perform this signal.
- **Absent paths:** `ENOENT` and `ENOTDIR` are ordinary absence; other `stat` errors are check failures.
- **Partial failure rule:** A positive candidate is still useful evidence even if another path is inaccessible. Without any positive candidate, a partial failure prevents a negative conclusion.
- **Privacy:** Do not return raw filesystem inventories or exact paths. Metadata contains only stable indicator/diagnostic codes and counts.
- **Limitations:** Absence of a known `su` path does not prove the device is unrooted. The check is bypassable inside a compromised process.

### `android.debugger.attached`

- **API:** `android.os.Debug.isDebuggerConnected()`, evaluated at call time.
- **DETECTED:** API returns true, confidence **HIGH**.
- **NOT_DETECTED:** API returns false, confidence **HIGH**.
- **FAILED:** API throws or cannot be evaluated; confidence is null and metadata contains a stable diagnostic code only.
- **UNKNOWN:** Not emitted by the current implementation because the API returns a boolean or throws.
- **UNSUPPORTED:** Emitted by the Dart adapter on non-Android platforms or by the native plugin for an unrecognized signal.
- **Limitations:** The observation is time-sensitive and can be hooked or patched. Debuggers may be legitimate in development/QA; this signal does not itself justify blocking an operation.

## Rule catalog

| Rule ID | Signal requirement | Threat ID | Severity | Minimum confidence | Rationale |
|---|---|---|---|---|---|
| `android.root.su-binary-indicator.v1` | `android.root.su_binary_present = DETECTED` | `ANDROID_ROOT_EXECUTABLE_INDICATOR` | MEDIUM | MEDIUM | A known root-related executable path was observed; this alone does not prove full compromise. |
| `android.debugger-attached.v1` | `android.debugger.attached = DETECTED` | `ANDROID_DEBUGGER_ATTACHED` | MEDIUM | HIGH | A debugger was reported attached at observation time; policy depends on build and operation context. |

No rule matches `NOT_DETECTED`, `UNKNOWN`, `FAILED`, or `UNSUPPORTED` as a threat. A high-confidence negative is useful evidence, but does not establish general device trust. No built-in policy or decision is defined here.

## Required fixtures

- **Positive:** each signal is `DETECTED` at or above its threshold; only the corresponding assessment is emitted.
- **Negative:** each signal is `NOT_DETECTED` with high confidence; no threat assessment is emitted.
- **Conflicting:** duplicate outcomes for the same expected signal, including detected plus not-detected; neither wins, no assessment is emitted, and `duplicateEvidence` is reported.
- **Failure:** a signal is `FAILED`; no threat assessment is emitted and `inconclusiveEvidence` is reported.
- **Unsupported/unknown:** preserve distinct statuses; neither is converted to a negative result.
- **Confidence:** a medium-confidence debugger result does not satisfy the high-confidence debugger rule.
- **Partial filesystem failure:** a positive artifact plus an inaccessible path is detected with a partial-failure count; no artifact plus an inaccessible path is failed, not not-detected.

## Native adapter contract

The Flutter channel is `dev.kryvon/security.v1`, protocol version 1. The Dart adapter validates protocol version, exact request and signal IDs, status/confidence values, platform, source, UTC timestamp, and JSON-compatible metadata. Malformed responses, channel errors, missing plugin implementations, and Dart-side timeouts become `FAILED` evidence with stable diagnostic codes. Native exception text and raw paths are never propagated.

The native plugin exposes `getCapabilities` and `evaluateSignal`; unknown signals return `UNSUPPORTED`. Caller configuration cannot alter the fixed filesystem path set. The Dart adapter owns a shorter timeout than the orchestrator so a stalled channel can be converted to explicit failed evidence without delaying unrelated detector tasks.

## Security boundary

These are local observations, not attestation. No native check proves the process is trustworthy, and no assessment automatically makes a policy decision. Keep sensitive authorization server-side.
