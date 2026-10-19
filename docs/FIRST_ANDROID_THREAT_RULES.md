# First Concrete Threat Rules (Android)

**Status:** rule semantics and synthetic fixtures defined; platform detector not implemented.

This catalog intentionally starts with narrow, observable indicators. It does not claim that a device is safe when an indicator is absent, and it does not make an authorization decision. A compromised client can tamper with local checks; sensitive backend operations must retain server-side authorization.

## Signal contracts

### `android.root.su_binary_present`

- **Meaning:** At least one file at a documented, known `su` executable path was positively observed to exist. The initial detector must publish the exact path set in its implementation notes and tests.
- **DETECTED:** One or more configured paths positively indicate a candidate `su` executable. This is an indicator, not proof that the device is fully rooted or that an attack is active.
- **NOT_DETECTED:** Every configured path was checked successfully and none contained the candidate executable.
- **FAILED:** The check could not complete reliably (for example, an unexpected platform/API error).
- **UNKNOWN:** The available observation cannot distinguish present from absent.
- **UNSUPPORTED:** The current platform/runtime cannot perform this documented check.
- **Confidence:** A positive filesystem artifact is **MEDIUM** by default because it can be a false positive or be hidden. A negative result is **HIGH** only when every configured path was checked successfully; otherwise it must not be reported as `NOT_DETECTED`.
- **Privacy:** Do not return raw filesystem inventories or unrelated file paths. Metadata may contain only a stable indicator code and a sanitized path-category identifier.
- **Limitations:** Absence of a known `su` path does not prove the device is unrooted. The check is bypassable inside a compromised process.

### `android.debugger.attached`

- **Meaning:** The Android platform debugger API reports whether a debugger is currently attached at observation time.
- **DETECTED:** The API positively reports an attached debugger.
- **NOT_DETECTED:** The API successfully reports no debugger attached at observation time.
- **FAILED:** The API call cannot be completed reliably.
- **UNKNOWN:** The adapter cannot reliably interpret the returned state.
- **UNSUPPORTED:** The platform adapter cannot provide this check.
- **Confidence:** **HIGH** for a successful direct API observation. The result is time-sensitive and does not establish whether the debugger is authorized.
- **Limitations:** A local attacker may hook or patch the API/result. Development and QA commonly use debuggers, so detection must not directly block an operation.

## Rule catalog

| Rule ID | Signal requirement | Threat ID | Severity | Minimum confidence | Rationale |
|---|---|---|---|---|---|
| `android.root.su-binary-indicator.v1` | `android.root.su_binary_present = DETECTED` | `ANDROID_ROOT_EXECUTABLE_INDICATOR` | MEDIUM | MEDIUM | A known root-related executable path was observed; this alone does not prove full compromise. |
| `android.debugger-attached.v1` | `android.debugger.attached = DETECTED` | `ANDROID_DEBUGGER_ATTACHED` | MEDIUM | HIGH | A debugger was reported attached at observation time; policy depends on build and operation context. |

No rule matches `NOT_DETECTED`, `UNKNOWN`, `FAILED`, or `UNSUPPORTED` as a threat. A high-confidence negative is useful evidence, but does not establish general device trust. No built-in policy or decision is defined here.

## Required fixtures

- **Positive:** each signal is `DETECTED` at or above its threshold; only the corresponding assessment is emitted.
- **Negative:** each signal is `NOT_DETECTED` with high confidence; no threat assessment is emitted.
- **Conflicting:** a run contains two outcomes for the same expected signal, one `DETECTED` and one `NOT_DETECTED`; neither may win, no assessment is emitted, and `duplicateEvidence` is reported.
- **Failure:** a signal is `FAILED`; no threat assessment is emitted and `inconclusiveEvidence` is reported.
- **Unsupported/unknown:** same fail-safe behavior as failure, but preserve their distinct statuses in evidence.
- **Confidence:** a medium-confidence debugger result does not satisfy the high-confidence debugger rule.

## Detector implementation gate

Before implementing the first native detector, review and approve:
1. The exact `su` path set and Android API behavior on supported SDK levels.
2. Status mapping for inaccessible paths, partial checks, API errors, and unsupported versions.
3. Timestamp, source ID, confidence, and sanitized metadata shape.
4. Positive, negative, conflicting, failure, unsupported, unknown, and confidence-boundary fixtures.
5. The explicit limitations above and the fact that this is local, non-authoritative evidence.

The detector must not be merged until its adapter tests prove these cases and the rule fixtures pass.