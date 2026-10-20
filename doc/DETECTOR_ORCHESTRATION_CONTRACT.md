# Detector Orchestration Contract

**Status:** contract only. No detector implementations, automatic assessment generator, or native adapter implementation is included.

## 1. Responsibility boundary

The orchestrator coordinates observations. It must not decide severity, infer threats, calculate risk, or apply policy.

```text
AssessmentContext + registry + platform
                  ↓
        Resolve expected signals
                  ↓
        Execute applicable detectors
                  ↓
        Normalize operational failures
                  ↓
         Preserve Evidence outcomes
                  ↓
              SignalRun
                  ↓
       Assessment / Risk / Policy
```

The current `KryvonEngine` accepts caller-supplied assessments and optional `SignalRun`; this contract does not change that API.

## 2. Detector identity and registration

Each detector declares:
- A stable, non-empty detector ID.
- One or more stable, non-empty signal IDs it can evaluate.
- Platform capability information or a platform-neutral way to report unsupported signals.
- A bounded execution timeout supplied by configuration or a documented default.

Registration must fail fast for blank detector IDs, duplicate detector IDs, blank signal IDs, or a signal ID assigned to more than one active detector in a single registry. This avoids ambiguous ownership and duplicate outcomes.

Signal IDs are compatibility-sensitive public identifiers. Renaming or changing their meaning requires an explicit compatibility change.

## 3. One assessment pass

Each pass is fresh and isolated:
1. Validate the registry and request configuration.
2. Resolve the full expected signal set for the requested pass.
3. Execute each registered detector applicable to that set.
4. Collect results without allowing completion order to affect final ordering.
5. Preserve returned evidence and operational failures.
6. Produce a `SignalRun` whose expected IDs match the declared coverage.

Do not reuse a previous pass's clean evidence as proof of current state. Caching is out of scope until freshness and invalidation rules are separately specified.

## 4. Outcome cardinality and validation

The current `SignalRun` contract requires exactly one outcome per expected signal for a complete pass.

- Missing outcome: preserve an explicit failed/incomplete result; never infer `NOT_DETECTED`.
- Duplicate outcome: preserve the anomaly for diagnostics and leave the run incomplete; never silently pick one.
- Unexpected signal ID: preserve the returned evidence and mark coverage incomplete.
- Invalid status/confidence combination: treat it as an invalid detector result and record a failure, without converting it to a negative result.
- A complete pass containing `UNKNOWN`, `FAILED`, or `UNSUPPORTED` is not complete under the current executable contract.

A detector that declares several signals must return one outcome for each declared signal, including `UNSUPPORTED` for unavailable capabilities.

## 5. Failure and timeout semantics

- A detector exception maps to `FAILED` evidence for its declared signal(s), with no invented confidence.
- A timeout maps to `FAILED` evidence. It does not mean that a threat was detected or absent.
- A missing native method/capability maps to `UNSUPPORTED` only when the adapter can establish that the capability is not implemented or available.
- A transient channel error, malformed response, or unexpected native exception maps to `FAILED`.
- The orchestration layer must not catch an error and replace it with `NOT_DETECTED`.

Dart future timeouts do not cancel the underlying native or Dart operation. A timed-out result is ignored when it arrives later; the returned `SignalRun` is immutable evidence of the orchestrator's completed pass and is not updated by late completion. The underlying operation may continue consuming resources, so detectors and native adapters should implement their own cancellation where supported. The timeout bounds asynchronous waiting; it cannot pre-empt synchronous blocking code on the same Dart isolate.

## 6. Scheduling and determinism

The implementation uses a configurable per-run concurrency limit (default: four in-flight signal evaluations) and a per-signal timeout (default: three seconds). The limit applies independently to each run; overlapping runs can multiply total in-flight work and may require a host-level admission limit. Detector implementations may be called concurrently for different signals and overlapping runs; they must be re-entrant/concurrency-safe or provide their own serialization and request/response correlation. Parallel execution is bounded within each run, and result ordering is stable by registration order then each detector's declared signal order, not completion timing. One detector's failure must not prevent unrelated signals from completing.

The orchestrator must not run duplicate instances of the same detector for the same signal in one pass. Registry IDs and signal ownership are snapshotted at registration. Request IDs are in-isolate correlation identifiers, not globally unique IDs, secrets, or authentication tokens.

## 7. Correlation and assessment generation

Correlation remains explicit metadata on an assessment. Shared threat names, similar reasons, signal prefixes, timing, or detector families do not establish correlation by themselves.

The verified current behavior is:
- Explicit, equal non-empty correlation keys group contributors for the independent-contributor count.
- Keys are trimmed for grouping.
- Missing/blank keys remain independent.
- All contributors remain visible; grouping does not erase evidence.
- The risk level currently uses highest assessment severity, not a weighted score.

Automatic assessment generation is **not** defined by this contract. It requires a separate versioned rule set specifying evidence combinations, conflicts, confidence derivation, correlation identity, and deterministic outputs, with tests for positive, negative, conflicting, missing, and failed evidence. It must not be introduced as a side effect of detector registration.

## 8. Required tests before implementation is accepted

- Registry rejects duplicate/blank IDs and ambiguous signal ownership.
- Stable result order despite different completion order.
- One detector failing does not suppress other results.
- Exception and timeout map to `FAILED`.
- Unsupported capability maps to `UNSUPPORTED`.
- Missing, duplicate, and unexpected outcomes do not produce a complete run.
- Late completion after timeout cannot replace the timeout result.
- Concurrent passes do not share mutable state.
- No correlation is inferred from similar signal IDs, threat IDs, or reasons.

## 9. Out of scope

This contract does not implement platform checks, automatic threat inference, weighted risk scoring, device fingerprinting, policy enforcement, or backend authorization. The host application remains responsible for acting on a decision; authoritative high-value authorization should remain server-side where appropriate.
