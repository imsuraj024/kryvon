/// Categorises the kind of security threat detected on the device.
enum ThreatType {
  /// One or more root indicators were found on the device.
  rootDetected,

  /// A debugger or debug-related signal was detected at runtime.
  debuggerDetected,

  /// The app is running inside an emulator or virtual device.
  emulatorDetected,

  /// Sensitive data is stored in an insecure location.
  insecureStorage,

  /// Certificate or public-key pinning validation failed.
  networkPinningFailure,

  /// Synthetic aggregate event emitted after all guards have run.
  ///
  /// Severity reflects the combined risk score across all individual
  /// [ThreatEvent]s collected during a [Kryvon.runChecks] call.
  deviceCompromised,
}