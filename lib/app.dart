import 'package:flutter/material.dart';
import 'home_page.dart';

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
