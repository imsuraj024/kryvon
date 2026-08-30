import 'package:flutter/material.dart';

void main() {
  runApp(const KryvonExampleApp());
}

class KryvonExampleApp extends StatelessWidget {
  const KryvonExampleApp({super.key});

  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      home: Scaffold(
        body: Center(
          child: Text('Kryvon rebuild'),
        ),
      ),
    );
  }
}
