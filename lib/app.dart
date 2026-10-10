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
        colorScheme: ColorScheme.fromSeed(
          seedColor: Colors.green,
          brightness: Brightness.light,
        ),
        scaffoldBackgroundColor: const Color(0xFFF7FAF7),
        appBarTheme: const AppBarTheme(
          centerTitle: true,
          elevation: 0,
        ),
        cardTheme: const CardThemeData(
          elevation: 1,
          margin: EdgeInsets.zero,
          clipBehavior: Clip.antiAlias,
        ),
        inputDecorationTheme: const InputDecorationTheme(
          border: OutlineInputBorder(),
          contentPadding: EdgeInsets.symmetric(
            horizontal: 14,
            vertical: 12,
          ),
        ),
        filledButtonTheme: FilledButtonThemeData(
          style: FilledButton.styleFrom(
            padding: const EdgeInsets.symmetric(
              horizontal: 20,
              vertical: 14,
            ),
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(12),
            ),
          ),
        ),
      ),
      locale: const Locale('fa'),
      supportedLocales: const [
        Locale('fa'),
        Locale('en'),
      ],
      home: const Directionality(
        textDirection: TextDirection.rtl,
        child: AryaHomePage(),
      ),
    );
  }
}
