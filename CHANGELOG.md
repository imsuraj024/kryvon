# Changelog

All notable changes to Kryvon are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## 0.4.0

### Breaking changes

- Replaced the legacy guard-oriented API with an evidence, assessment, risk,
  policy, and decision model. Existing integrations using `Kryvon.initialize()`,
  `Kryvon.runChecks()`, `HookGuard`, `EmulatorGuard`, `IntegrityGuard`,
  or the previous enforcement strategies must migrate to the exported API
  documented in the README and API reference.

### Added

- Immutable evidence and assessment snapshots with explicit confidence.
- Detector registry and concurrency-limited orchestration with timeout and
  failure handling.
- Rule-based assessment generation with confidence requirements and conflict
  reporting.
- Risk evaluation that preserves uncertainty and correlated contributors.
- Versioned Android MethodChannel adapter for root `su` path and debugger
  attachment signals.
- Native Android unit tests, Dart tests, and an Android example build in CI.

### Security notes

- A missing or failed signal is not proof of a safe device.
- Root-path checks are indicators only and cannot prove a device is unrooted.
- Debugger attachment is time-sensitive and may be expected during development.
- Kryvon performs local checks, not remote attestation. Keep authorization for
  sensitive operations on the server.

## Earlier versions

The following entries describe the earlier guard-oriented implementation and
are retained as historical release notes. They do not describe the current
0.4.0 API.

### 0.3.0 - 2026-03-19

- Earlier guard-oriented API and runtime integrity work.

### 0.2.0 - 2026-03-06

- Earlier debugger detection and guard framework.

### 0.1.0 - 2026-03-05

- Initial guard-oriented Android security framework.

### 0.0.1 - 2026-03-04

- Initial Android-only development release.
