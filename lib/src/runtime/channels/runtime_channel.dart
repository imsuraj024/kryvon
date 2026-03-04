import 'package:flutter/services.dart';

class RuntimeChannel {
  static const MethodChannel _channel =
      MethodChannel('com.kryvon.runtime');

  static Future<Map<dynamic, dynamic>> checkRoot() async {
    final result = await _channel.invokeMethod('checkRoot');
    return result as Map<dynamic, dynamic>;
  }
}