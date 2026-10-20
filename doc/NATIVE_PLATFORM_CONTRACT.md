# Native Platform Contract

**Status:** protocol specification only. No Android/iOS detector or MethodChannel implementation is added by this document.

## 1. Boundary and ownership

The Dart core owns detector scheduling, evidence validation, assessment, risk, policy, and the final decision. A native adapter performs only the requested platform observation and returns a normalized result. Native code must not implement product policy or decide whether the application should allow, restrict, or block an operation.

The native boundary is not an unforgeable trust boundary: an attacker controlling the application process may tamper with requests or responses.

## 2. Protocol identity

Proposed Flutter channel name: `dev.kryvon/security.v1`.

Protocol version: integer `1`.

The channel name and schema become compatibility-sensitive once implemented. Future incompatible changes require a new protocol version or an explicitly versioned migration.

## 3. Methods

### `getCapabilities`

Input:
```json
{
  "protocolVersion": 1,
  "requestId": "opaque-request-id"
}
```

Output:
```json
{
  "protocolVersion": 1,
  "requestId": "opaque-request-id",
  "platform": "android",
  "capabilities": ["stable_signal_id"]
}
```

Capability IDs are stable strings, not human-readable descriptions. An empty capability list is valid. Unsupported platform functionality must not be implied by omission alone unless the capability response was validated successfully.

### `evaluateSignal`

Input:
```json
{
  "protocolVersion": 1,
  "requestId": "opaque-request-id",
  "signalId": "stable_signal_id",
  "context": "transaction",
  "configuration": {}
}
```

Output:
```json
{
  "protocolVersion": 1,
  "requestId": "opaque-request-id",
  "signalId": "stable_signal_id",
  "status": "detected",
  "confidence": "high",
  "source": "android.platform_api",
  "platform": "android",
  "observedAt": "2026-10-19T08:00:00.000Z",
  "metadata": {}
}
```

The example is illustrative, not evidence that a real detector or capability exists. `configuration` must contain only documented, non-secret parameters.

## 4. Evidence wire schema

Required fields:
- `protocolVersion`: supported integer version.
- `requestId`: exact opaque request identifier echoed from the request.
- `signalId`: exact signal identifier requested.
- `status`: one of `detected`, `not_detected`, `unknown`, `failed`, `unsupported`.
- `confidence`: `low`, `medium`, `high`, or `null` when the result cannot provide confidence.
- `source`: non-empty stable source identifier.
- `platform`: normalized platform identifier.
- `observedAt`: RFC 3339 timestamp in UTC.
- `metadata`: optional JSON-compatible, sanitized object; defaults to an empty object.

Validation rules:
- `requestId` and `signalId` must match the request.
- Unknown protocol versions, unknown status values, malformed timestamps, wrong types, or missing required fields are protocol failures.
- `FAILED` and `UNSUPPORTED` must not be converted into a negative result.
- A detected result requires explicit confidence. If confidence is null for a detected result, the adapter response is invalid and should become a protocol failure.
- Native timestamps are observational timestamps, not proof of freshness or authenticity.
- Metadata must not contain secrets, authentication tokens, raw personal data, or unnecessary device identifiers.

## 5. Error mapping

| Condition | Normalized outcome |
|---|---|
| Requested capability is not implemented on this platform | `UNSUPPORTED` |
| Native check ran and found no indicator | `NOT_DETECTED` |
| Native check ran and observed an indicator | `DETECTED` |
| Temporary platform API error or native exception | `FAILED` |
| Method/channel unavailable or response malformed | `FAILED`, unless absence is positively identified as an unsupported capability |
| Dart-side timeout | `FAILED` |
| Result cannot reliably establish either state | `UNKNOWN` |

Native error messages may be included only as sanitized diagnostic codes, not arbitrary exception text. The host policy decides the consequence of failure or unsupported capability.

## 6. Request IDs and replay considerations

A request ID correlates a response to the request that produced it and prevents late responses from being accidentally associated with a different in-flight request. It is not a secret, cryptographic nonce, attestation, or authentication mechanism.

The adapter must echo the request ID and signal ID exactly. The Dart side must reject mismatched responses and ignore late responses after a request has timed out.

## 7. Platform implementation requirements

Each platform implementation must:
- Validate protocol version, request ID, signal ID, and argument types.
- Return the normalized schema for success, unknown, failure, and unsupported outcomes.
- Avoid hidden policy, process termination, or UI side effects.
- Use platform APIs appropriate to the signal and document platform/version limitations.
- Keep permission requirements explicit and minimize permission requests.
- Avoid collecting data not needed for the security decision.
- Include deterministic fixtures or fakes for detected, not-detected, unsupported, failed, and malformed-response paths where feasible.
- Document that local evidence can be tampered with in a compromised process.

## 8. Required contract tests

Before shipping a native implementation, test:
- Supported and unsupported protocol versions.
- Unknown method and unsupported signal behavior.
- Request/response ID mismatch.
- Signal ID mismatch.
- Every allowed status and confidence value.
- Null confidence for failed/unsupported/unknown outcomes.
- Invalid detected response without confidence.
- Malformed maps and timestamps.
- Native exceptions and channel errors.
- Timeout and late response handling.
- Metadata sanitization and absence of secrets.

## 9. Non-goals

This protocol does not provide remote attestation, cryptographic authenticity, secure storage, backend authorization, or a guarantee that a local observation is truthful under full process compromise. Such guarantees require separate platform and server-side controls.
