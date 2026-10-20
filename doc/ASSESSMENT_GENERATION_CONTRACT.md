# Assessment Generation Contract

**Status:** executable rule-engine specification. This contract defines how caller-authored rules interpret evidence; it does not define real-world threat rules or implement platform detectors.

## 1. Responsibility boundary

The generator converts a validated SignalRun plus an explicit ordered set of AssessmentRule definitions into assessments. It does not collect evidence, infer platform facts, calculate risk, apply policy, or make a decision.

SignalRun + explicit rule set → validate coverage and rules → evaluate requirements → derive confidence → resolve declared conflicts → assessments and diagnostics.

Concrete security rules must be added separately only after their signal semantics and platform limitations are documented.

## 2. Rule definition

Every rule must declare:
- A stable, non-empty, unique rule ID.
- A non-empty threat ID, reason, and explicit severity.
- One or more evidence requirements.
- For each requirement, a stable signal ID, expected status, and minimum confidence.
- An optional explicit correlationKey.
- An optional explicit conflictGroup.

Only DETECTED and NOT_DETECTED may satisfy a requirement. UNKNOWN, FAILED, and UNSUPPORTED never satisfy a requirement. A NOT_DETECTED requirement must require HIGH confidence; a weaker negative observation must not establish a rule.

A rule may contain at most one requirement per signal. IDs and optional grouping keys are trimmed before validation. Blank IDs, duplicate rule IDs, duplicate requirement signals, blank reasons/threats, empty requirements, and blank non-null grouping keys are configuration errors.

## 3. Matching semantics

A rule matches only when every requirement:
1. Names a signal included in the run's expected-signal set.
2. Has exactly one outcome for that signal.
3. Has the required DETECTED or NOT_DETECTED status.
4. Has a non-null confidence meeting the requirement's minimum.

Missing or duplicate outcomes, unexpected signals, inconclusive statuses, and insufficient confidence produce diagnostics and do not match the affected rule. The generator never picks the first duplicate, fills missing data, or converts failure/unsupported/unknown into a negative result.

A valid opposite status is a normal non-match, not an error. A malformed expected-signal set (empty, blank, whitespace-padded, or duplicate IDs, including duplicates after trimming) invalidates generation for that run. Partial coverage does not suppress a rule that is fully and validly supported by its own requirements; uncertainty in unrelated signals remains visible in diagnostics.

## 4. Assessment confidence

Assessment confidence is the **lowest confidence among all supporting evidence**. The ordering is LOW < MEDIUM < HIGH. The rule's minimum confidence is a matching threshold, not a confidence override. Severity is declared explicitly by the rule and is never inferred from confidence.

The generated assessment preserves the rule's threat, reason, severity, and explicit correlation key, and includes exactly the evidence used by the rule in requirement order.

## 5. Conflicting rules

Conflicts are declared only through an explicit shared, non-empty conflictGroup; the generator must not infer conflicts from shared threats, overlapping evidence, names, or reasons.

If two or more rules in one conflict group match the same run, **all matched assessments in that group are suppressed** and one deterministic conflict diagnostic lists the matched rule IDs in rule order. The generator must not select a winner based on rule order, severity, confidence, or timing. Matched rules outside the conflicted group still produce assessments.

A rule that is unresolved due to missing or inconclusive evidence is not considered a matching conflicting rule, but its diagnostic is preserved.

## 6. Correlation

Only a rule's explicitly configured correlationKey is copied to the resulting assessment. The generator must not infer correlation from a shared threat ID, conflict group, signal, source, timing, reason, or detector family. Correlation does not remove assessments or evidence; downstream risk evaluation remains responsible for grouping contributors.

## 7. Determinism and immutability

For identical run outcomes and rule definitions, output must be identical:
- Assessments follow input rule order.
- Supporting evidence follows requirement order.
- Diagnostics follow rule order and requirement order.
- Conflict groups follow first appearance in rule order; rule IDs within a conflict follow rule order.
- Returned collections are immutable snapshots.

The generator must not depend on wall-clock time, detector completion order, random values, or mutable global state.

## 8. Required tests before adding concrete threat rules

- Single-rule positive match.
- Opposite status does not match.
- Weak detected evidence fails a higher confidence threshold.
- Low/medium-confidence NOT_DETECTED rule configuration is rejected.
- Assessment confidence uses the weakest supporting confidence.
- Missing, duplicate, unexpected, failed, unknown, unsupported, and null-confidence evidence never produces a false match.
- A valid supported rule can still match when unrelated signals are incomplete.
- Two matching rules in one explicit conflict group are both suppressed.
- A conflict does not suppress independent groups.
- Correlation is copied only when explicitly configured.
- Duplicate rule IDs and invalid rule definitions fail fast.
- Rule order, evidence order, diagnostics, and conflicts are deterministic.
- Result collections cannot be mutated by consumers.

## 9. Out of scope

This contract does not define real-world threat detection logic, severity taxonomies for particular signals, native implementations, weighted scoring, implicit correlation, or policy decisions. No concrete detector or threat rule should be added without documented signal semantics, platform coverage, and test fixtures.
