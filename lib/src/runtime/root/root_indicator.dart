/// Identifies which root-detection signal was triggered on the device.
enum RootIndicatorType {
  /// A `su` binary was found in common system paths.
  suBinary,

  /// The `su` binary could be successfully executed (highest confidence).
  suExecution,

  /// Dangerous system properties (e.g. `ro.debuggable=1`) were detected.
  dangerousProps,

  /// The `/system` partition is mounted read-write.
  writableSystem,

  /// A known root-management app (e.g. Magisk, SuperSU) is installed.
  knownRootApp,

  /// The build is signed with test-release keys instead of production keys.
  testKeys,
}