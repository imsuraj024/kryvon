import 'threat_event.dart';

abstract class Guard {
  Future<List<ThreatEvent>> check();
}