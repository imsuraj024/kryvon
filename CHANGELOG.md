# Changelog

All notable changes to Kryvon will be documented in this file.

The format is based on Keep a Changelog
and the project follows Semantic Versioning.

---

## [0.2.0] - 2026-03-06

### Added

- **DebuggerGuard** for detecting debugging environments.
- Multi-signal debugger detection on Android:
  - Android debugger connection detection (`Debug.isDebuggerConnected`)
  - Native tracing detection via `TracerPid` (`/proc/self/status`)
  - JDWP debugging detection
  - Detection of debuggable application builds (`FLAG_DEBUGGABLE`)
  - Detection of system debug builds (`ro.debuggable`)
- Integration of `DebuggerGuard` with Kryvon's guard framework.
- Structured `ThreatEvent` emission for debugger-related threats.
- Severity scoring for debugger indicators.
- Compatibility with Kryvon's runtime **Risk Aggregator**.

### Security

DebuggerGuard helps detect environments where attackers may attempt:

- runtime inspection
- code stepping
- variable inspection
- reverse engineering during execution

This significantly strengthens Kryvon's runtime integrity detection and complements existing **RootGuard** protections.

### Internal

- Improved guard modularity to support additional runtime detection modules.
- Enhanced logging for debugger-related threat events.

---

## [0.1.0] - 2026-03-05

### Added

- Initial public release of Kryvon mobile security baseline framework.
- Guard-based architecture for modular security checks.
- **RootGuard** for detecting rooted Android devices.
- Multi-indicator root detection including:
  - `su` binary presence
  - `su` execution capability
  - writable system partitions
  - known root management applications
  - insecure system properties
- Runtime **Risk Aggregator** for evaluating device compromise severity.
- Policy-driven enforcement strategies.
- Structured logging system.
- Example Flutter application demonstrating Kryvon integration.

---

## [0.0.1] - 2026-03-04

* Initial release — Android only
* Policy-based threat detection framework (`Kryvon.initialize` + `Kryvon.runChecks`)
* Root detection with 6 native indicators: `suBinary`, `suExecution`, `dangerousProps`, `writableSystem`, `knownRootApp`, `testKeys`
* Severity levels: `low` → `medium` → `high` → `critical`
* Enforcement strategies: `emitOnly`, `terminateApp`
* Built-in `KryvonPolicy.fintech()` preset
* Structured logger with configurable log level
