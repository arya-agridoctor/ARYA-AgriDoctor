import 'package:flutter/material.dart';

class AryaMainApp extends StatelessWidget {
  const AryaMainApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'ARYA AgriDoctor',
      theme: ThemeData(
        useMaterial3: true,
        colorSchemeSeed: Colors.green,
        scaffoldBackgroundColor: const Color(0xFFF5F8F5),
      ),
      home: const AryaMainHomePage(),
    );
  }
}

class AryaMainHomePage extends StatefulWidget {
  const AryaMainHomePage({super.key});

  @override
  State<AryaMainHomePage> createState() =>
      _AryaMainHomePageState();
}

class _AryaMainHomePageState
    extends State<AryaMainHomePage> {
  int _selectedIndex = 0;

  final List<String> _titles = const [
    'خانه',
    'مزرعه',
    'ARYA AI',
    'پشتیبانی',
  ];

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(_titles[_selectedIndex]),
        centerTitle: true,
      ),
      body: IndexedStack(
        index: _selectedIndex,
        children: const [
          _HomeTab(),
          _FarmTab(),
          _AiTab(),
          _SupportTab(),
        ],
      ),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _selectedIndex,
        onDestinationSelected: (index) {
          setState(() {
            _selectedIndex = index;
          });
        },
        destinations: const [
          NavigationDestination(
            icon: Icon(Icons.home_outlined),
            selectedIcon: Icon(Icons.home),
            label: 'خانه',
          ),
          NavigationDestination(
            icon: Icon(Icons.agriculture_outlined),
            selectedIcon: Icon(Icons.agriculture),
            label: 'مزرعه',
          ),
          NavigationDestination(
            icon: Icon(Icons.smart_toy_outlined),
            selectedIcon: Icon(Icons.smart_toy),
            label: 'ARYA AI',
          ),
          NavigationDestination(
            icon: Icon(Icons.support_agent_outlined),
            selectedIcon: Icon(Icons.support_agent),
            label: 'پشتیبانی',
          ),
        ],
      ),
    );
  }
}

class _HomeTab extends StatelessWidget {
  const _HomeTab();

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: const [
        Card(
          child: Padding(
            padding: EdgeInsets.all(20),
            child: Column(
              crossAxisAlignment:
                  CrossAxisAlignment.start,
              children: [
                Text(
                  'ARYA AgriDoctor',
                  style: TextStyle(
                    fontSize: 25,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                SizedBox(height: 8),
                Text(
                  'دستیار هوشمند کشاورزی شما',
                  style: TextStyle(fontSize: 17),
                ),
              ],
            ),
          ),
        ),
        SizedBox(height: 12),
        _ModuleCard(
          icon: Icons.location_on_outlined,
          title: 'مزرعه و زمین',
          description:
              'مدیریت زمین‌ها، موقعیت و اطلاعات مزرعه',
        ),
        _ModuleCard(
          icon: Icons.eco_outlined,
          title: 'محصولات و درختان',
          description:
              'ثبت و مدیریت محصولات، درختان و کشت',
        ),
        _ModuleCard(
          icon: Icons.water_drop_outlined,
          title: 'آب و آبیاری',
          description:
              'بررسی و برنامه‌ریزی آبیاری',
        ),
        _ModuleCard(
          icon: Icons.cloud_outlined,
          title: 'آب‌وهوا',
          description:
              'اطلاعات آب‌وهوا و شرایط اقلیمی',
        ),
        _ModuleCard(
          icon: Icons.bug_report_outlined,
          title: 'آفات و بیماری‌ها',
          description:
              'تشخیص و مدیریت آفات و بیماری‌ها',
        ),
      ],
    );
  }
}

class _FarmTab extends StatelessWidget {
  const _FarmTab();

  @override
  Widget build(BuildContext context) {
    return const Center(
      child: Text(
        'مدیریت مزرعه در حال اتصال به Backend است.',
        style: TextStyle(fontSize: 17),
      ),
    );
  }
}

class _AiTab extends StatelessWidget {
  const _AiTab();

  @override
  Widget build(BuildContext context) {
    return const Center(
      child: Text(
        'ARYA AI',
        style: TextStyle(
          fontSize: 24,
          fontWeight: FontWeight.bold,
        ),
      ),
    );
  }
}

class _SupportTab extends StatelessWidget {
  const _SupportTab();

  @override
  Widget build(BuildContext context) {
    return const Center(
      child: Text(
        'پشتیبانی ARYA',
        style: TextStyle(fontSize: 20),
      ),
    );
  }
}

class _ModuleCard extends StatelessWidget {
  const _ModuleCard({
    required this.icon,
    required this.title,
    required this.description,
  });

  final IconData icon;
  final String title;
  final String description;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: ListTile(
        leading: CircleAvatar(
          child: Icon(icon),
        ),
        title: Text(
          title,
          style: const TextStyle(
            fontWeight: FontWeight.bold,
          ),
        ),
        subtitle: Text(description),
        trailing: const Icon(
          Icons.arrow_forward_ios,
          size: 16,
        ),
      ),
    );
  }
}
