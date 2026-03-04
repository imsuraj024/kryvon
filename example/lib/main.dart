import 'package:flutter/material.dart';
import 'package:kryvon/kryvon.dart';

import 'home_page.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  Kryvon.initialize(
    policy: KryvonPolicy.fintech(),
    logLevel: LogLevel.debug,
  );

  await Kryvon.runChecks();

  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      home: HomePage(),
    );
  }
}