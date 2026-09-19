import 'package:flutter/material.dart';

class AryaHomePage extends StatelessWidget {
  const AryaHomePage({super.key});

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
            icon: Icons.agriculture,
            title: 'مزرعه و زمین',
            subtitle: 'مدیریت زمین‌ها و اطلاعات کشت',
          ),
          _menuItem(
            context,
            icon: Icons.cloud,
            title: 'آب‌وهوا',
            subtitle: 'بررسی شرایط جوی و هشدارها',
          ),
          _menuItem(
            context,
            icon: Icons.science,
            title: 'خاک و آزمایشگاه',
            subtitle: 'ثبت و تحلیل آزمایش خاک',
          ),
          _menuItem(
            context,
            icon: Icons.water_drop,
            title: 'آبیاری',
            subtitle: 'برنامه‌ریزی و یادآوری آبیاری',
          ),
          _menuItem(
            context,
            icon: Icons.bug_report,
            title: 'آفات و بیماری‌ها',
            subtitle: 'شناسایی و مدیریت آفات و بیماری‌ها',
          ),
          _menuItem(
            context,
            icon: Icons.eco,
            title: 'کود و تغذیه',
            subtitle: 'مدیریت کوددهی و تغذیه گیاه',
          ),
          _menuItem(
            context,
            icon: Icons.support_agent,
            title: 'پشتیبانی',
            subtitle: 'راهنما و ارتباط با پشتیبانی',
          ),
        ],
      ),
    );
  }

  Widget _menuItem(
    BuildContext context, {
    required IconData icon,
    required String title,
    required String subtitle,
  }) {
    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: ListTile(
        leading: Icon(icon, size: 32),
        title: Text(title),
        subtitle: Text(subtitle),
        trailing: const Icon(Icons.arrow_forward_ios),
        onTap: () {},
      ),
    );
  }
}
