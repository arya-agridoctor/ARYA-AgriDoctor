import 'package:flutter/material.dart';

class AryaApp extends StatelessWidget {
  const AryaApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'ARYA AgriDoctor',
      theme: ThemeData(
        useMaterial3: true,
        colorSchemeSeed: Colors.green,
      ),
      home: const AryaHomePage(),
    );
  }
}

class AryaHomePage extends StatelessWidget {
  const AryaHomePage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('ARYA AgriDoctor'),
      ),
      body: const Center(
        child: Text(
          'دستیار هوشمند کشاورزی آریا',
          style: TextStyle(fontSize: 22),
          textAlign: TextAlign.center,
        ),
      ),
    );
  }
}
