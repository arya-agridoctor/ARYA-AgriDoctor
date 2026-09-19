import 'package:flutter/material.dart';

class AryaHomePage extends StatelessWidget {
  const AryaHomePage({super.key});

  void _openPage(
    BuildContext context,
    String title,
    String description,
    IconData icon,
  ) {
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (_) => AryaModulePage(
          title: title,
          description: description,
          icon: icon,
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('ARYA AgriDoctor'),
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _menuItem(
            context,
            Icons.agriculture,
            'مزرعه و زمین',
            'مدیریت زمین‌ها و اطلاعات کشت',
          ),
          _menuItem(
            context,
            Icons.cloud,
            'آب‌وهوا',
            'بررسی شرایط جوی و هشدارها',
          ),
          _menuItem(
            context,
            Icons.science,
            'خاک و آزمایشگاه',
            'ثبت و تحلیل آزمایش خاک',
          ),
          _menuItem(
            context,
            Icons.water_drop,
            'آبیاری',
            'برنامه‌ریزی و یادآوری آبیاری',
          ),
          _menuItem(
            context,
            Icons.bug_report,
            'آفات و بیماری‌ها',
            'شناسایی و مدیریت آفات و بیماری‌ها',
          ),
          _menuItem(
            context,
            Icons.eco,
            'کود و تغذیه',
            'مدیریت کوددهی و تغذیه گیاه',
          ),
          _menuItem(
            context,
            Icons.support_agent,
            'پشتیبانی',
            'راهنما و ارتباط با پشتیبانی',
          ),
        ],
      ),
    );
  }

  Widget _menuItem(
    BuildContext context,
    IconData icon,
    String title,
    String subtitle,
  ) {
    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: ListTile(
        leading: Icon(icon, size: 32),
        title: Text(title),
        subtitle: Text(subtitle),
        trailing: const Icon(Icons.arrow_forward_ios),
        onTap: () {
          _openPage(
            context,
            title,
            subtitle,
            icon,
          );
        },
      ),
    );
  }
}

class AryaModulePage extends StatelessWidget {
  final String title;
  final String description;
  final IconData icon;

  const AryaModulePage({
    super.key,
    required this.title,
    required this.description,
    required this.icon,
  });

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(title),
      ),
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(
                icon,
                size: 80,
              ),
              const SizedBox(height: 24),
              Text(
                title,
                textAlign: TextAlign.center,
                style: const TextStyle(
                  fontSize: 26,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 12),
              Text(
                description,
                textAlign: TextAlign.center,
                style: const TextStyle(
                  fontSize: 17,
                ),
              ),
              const SizedBox(height: 30),
              const Text(
                'ARYA AgriDoctor',
                style: TextStyle(
                  fontSize: 18,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
