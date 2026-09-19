import 'package:flutter/material.dart';

class AryaHomePage extends StatefulWidget {
  const AryaHomePage({super.key});

  @override
  State<AryaHomePage> createState() => _AryaHomePageState();
}

class _AryaHomePageState extends State<AryaHomePage> {
  int _selectedIndex = 0;

  final List<AryaModule> _modules = const [
    AryaModule(
      title: 'مزرعه و زمین',
      subtitle: 'مدیریت زمین، مرزها و اطلاعات مزرعه',
      icon: Icons.agriculture,
    ),
    AryaModule(
      title: 'محصولات و درختان',
      subtitle: 'ثبت و مدیریت محصولات، باغ و درختان',
      icon: Icons.eco,
    ),
    AryaModule(
      title: 'خاک و آزمایشگاه',
      subtitle: 'تحلیل خاک و نتایج آزمایشگاهی',
      icon: Icons.science,
    ),
    AryaModule(
      title: 'آب و آبیاری',
      subtitle: 'مدیریت منابع آب و برنامه آبیاری',
      icon: Icons.water_drop,
    ),
    AryaModule(
      title: 'آب‌وهوا',
      subtitle: 'شرایط جوی و هشدارهای کشاورزی',
      icon: Icons.cloud,
    ),
    AryaModule(
      title: 'آفات و بیماری‌ها',
      subtitle: 'شناسایی و مدیریت آفات و بیماری‌ها',
      icon: Icons.bug_report,
    ),
    AryaModule(
      title: 'کود و تغذیه',
      subtitle: 'برنامه تغذیه و مقایسه کودها',
      icon: Icons.grass,
    ),
    AryaModule(
      title: 'سموم و درمان',
      subtitle: 'مدیریت مواد مؤثره و برنامه کنترل',
      icon: Icons.local_pharmacy,
    ),
    AryaModule(
      title: 'تشخیص هوشمند',
      subtitle: 'تحلیل مسئله با موتور هوش کشاورزی',
      icon: Icons.psychology,
    ),
    AryaModule(
      title: 'تقویم کشاورزی',
      subtitle: 'کارها، زمان‌بندی و یادآوری‌ها',
      icon: Icons.calendar_month,
    ),
    AryaModule(
      title: 'اقتصاد و سود',
      subtitle: 'هزینه، درآمد، عملکرد و سود',
      icon: Icons.account_balance_wallet,
    ),
    AryaModule(
      title: 'بازار',
      subtitle: 'قیمت، فروش و تحلیل بازار',
      icon: Icons.storefront,
    ),
    AryaModule(
      title: 'آموزش',
      subtitle: 'آموزش‌های کشاورزی متنی و چندرسانه‌ای',
      icon: Icons.school,
    ),
    AryaModule(
      title: 'گزارش‌ها',
      subtitle: 'گزارش کامل وضعیت مزرعه',
      icon: Icons.assessment,
    ),
    AryaModule(
      title: 'اعلان‌ها',
      subtitle: 'هشدارها و کارهای نزدیک',
      icon: Icons.notifications,
    ),
    AryaModule(
      title: 'پشتیبانی',
      subtitle: 'راهنما، پرسش و ارتباط با پشتیبانی',
      icon: Icons.support_agent,
    ),
    AryaModule(
      title: 'نظر شما',
      subtitle: 'پیشنهاد، انتقاد و گزارش مشکل',
      icon: Icons.feedback,
    ),
    AryaModule(
      title: 'تنظیمات',
      subtitle: 'زبان، حساب، دستگاه و تنظیمات برنامه',
      icon: Icons.settings,
    ),
    AryaModule(
      title: 'OWNER / MASTER',
      subtitle: 'مدیریت مرکزی سامانه',
      icon: Icons.admin_panel_settings,
    ),
  ];

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text(
          'ARYA AgriDoctor',
          style: TextStyle(fontWeight: FontWeight.bold),
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.notifications_outlined),
            onPressed: () => _openModule(
              const AryaModule(
                title: 'اعلان‌ها',
                subtitle: 'هشدارها و کارهای نزدیک',
                icon: Icons.notifications,
              ),
            ),
          ),
        ],
      ),
      body: _selectedIndex == 0
          ? _buildDashboard()
          : _selectedIndex == 1
              ? _buildAiAssistant()
              : _buildFarmSummary(),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _selectedIndex,
        onDestinationSelected: (value) {
          setState(() {
            _selectedIndex = value;
          });
        },
        destinations: const [
          NavigationDestination(
            icon: Icon(Icons.home_outlined),
            selectedIcon: Icon(Icons.home),
            label: 'خانه',
          ),
          NavigationDestination(
            icon: Icon(Icons.psychology_outlined),
            selectedIcon: Icon(Icons.psychology),
            label: 'ARYA AI',
          ),
          NavigationDestination(
            icon: Icon(Icons.agriculture_outlined),
            selectedIcon: Icon(Icons.agriculture),
            label: 'مزرعه',
          ),
        ],
      ),
    );
  }

  Widget _buildDashboard() {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        _buildWelcomeCard(),
        const SizedBox(height: 16),
        _buildQuickAiCard(),
        const SizedBox(height: 18),
        const Text(
          'امکانات ARYA AgriDoctor',
          style: TextStyle(
            fontSize: 21,
            fontWeight: FontWeight.bold,
          ),
        ),
        const SizedBox(height: 12),
        ..._modules.map(_buildModuleCard),
      ],
    );
  }

  Widget _buildWelcomeCard() {
    return Card(
      elevation: 2,
      child: Padding(
        padding: const EdgeInsets.all(18),
        child: Row(
          children: [
            CircleAvatar(
              radius: 32,
              child: Icon(
                Icons.agriculture,
                size: 34,
              ),
            ),
            const SizedBox(width: 14),
            const Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'سلام، به ARYA AgriDoctor خوش آمدید',
                    style: TextStyle(
                      fontSize: 18,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  SizedBox(height: 6),
                  Text(
                    'دستیار هوشمند کشاورزی برای مزرعه، باغ و گلخانه',
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildQuickAiCard() {
    return Card(
      child: InkWell(
        borderRadius: BorderRadius.circular(12),
        onTap: () {
          setState(() {
            _selectedIndex = 1;
          });
        },
        child: const Padding(
          padding: EdgeInsets.all(18),
          child: Row(
            children: [
              Icon(
                Icons.auto_awesome,
                size: 42,
              ),
              SizedBox(width: 14),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'مشاور هوشمند ARYA',
                      style: TextStyle(
                        fontSize: 18,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    SizedBox(height: 5),
                    Text(
                      'مسئله کشاورزی خود را بنویسید و اطلاعات لازم را مرحله‌به‌مرحله بررسی کنید.',
                    ),
                  ],
                ),
              ),
              Icon(Icons.arrow_forward_ios),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildModuleCard(AryaModule module) {
    return Card(
      margin: const EdgeInsets.only(bottom: 10),
      child: ListTile(
        contentPadding: const EdgeInsets.symmetric(
          horizontal: 16,
          vertical: 5,
        ),
        leading: CircleAvatar(
          child: Icon(module.icon),
        ),
        title: Text(
          module.title,
          style: const TextStyle(
            fontWeight: FontWeight.bold,
          ),
        ),
        subtitle: Text(module.subtitle),
        trailing: const Icon(Icons.arrow_forward_ios),
        onTap: () => _openModule(module),
      ),
    );
  }

  Widget _buildAiAssistant() {
    return const AryaAiPage();
  }

  Widget _buildFarmSummary() {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        const Text(
          'خلاصه مزرعه',
          style: TextStyle(
            fontSize: 25,
            fontWeight: FontWeight.bold,
          ),
        ),
        const SizedBox(height: 16),
        _summaryCard(
          'زمین ثبت‌شده',
          'هنوز زمینی ثبت نشده است',
          Icons.landscape,
        ),
        _summaryCard(
          'محصول فعال',
          'هنوز محصولی ثبت نشده است',
          Icons.eco,
        ),
        _summaryCard(
          'کارهای امروز',
          '۳ کار در انتظار برنامه‌ریزی',
          Icons.task_alt,
        ),
        _summaryCard(
          'وضعیت آب',
          'نیازمند ثبت اطلاعات',
          Icons.water_drop,
        ),
        _summaryCard(
          'وضعیت خاک',
          'آزمایش ثبت نشده است',
          Icons.science,
        ),
      ],
    );
  }

  Widget _summaryCard(
    String title,
    String value,
    IconData icon,
  ) {
    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: ListTile(
        leading: Icon(icon, size: 34),
        title: Text(title),
        subtitle: Text(value),
      ),
    );
  }

  void _openModule(AryaModule module) {
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (_) => AryaModulePage(module: module),
      ),
    );
  }
}

class AryaAiPage extends StatefulWidget {
  const AryaAiPage({super.key});

  @override
  State<AryaAiPage> createState() => _AryaAiPageState();
}

class _AryaAiPageState extends State<AryaAiPage> {
  final TextEditingController _controller = TextEditingController();
  final List<AiMessage> _messages = [
    const AiMessage(
      text:
          'سلام. من موتور هوشمند ARYA هستم. مسئله کشاورزی خود را توضیح دهید. برای پاسخ دقیق‌تر می‌توانم اطلاعات محصول، زمین، آب، خاک و آب‌وهوا را بررسی کنم.',
      isAi: true,
    ),
  ];

  bool _loading = false;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _sendMessage() {
    final text = _controller.text.trim();

    if (text.isEmpty) return;

    setState(() {
      _messages.add(
        AiMessage(
          text: text,
          isAi: false,
        ),
      );
      _controller.clear();
      _loading = true;
    });

    Future.delayed(const Duration(milliseconds: 700), () {
      if (!mounted) return;

      setState(() {
        _loading = false;
        _messages.add(
          AiMessage(
            text: _generateLocalAnalysis(text),
            isAi: true,
          ),
        );
      });
    });
  }

  String _generateLocalAnalysis(String question) {
    final q = question.toLowerCase();

    if (q.contains('زرد') ||
        q.contains('زردی') ||
        q.contains('برگ')) {
      return 'برای بررسی زردی برگ، فعلاً این اطلاعات لازم است:\n\n'
          '۱. نام گیاه یا محصول\n'
          '۲. سن گیاه\n'
          '۳. مقدار و فاصله آبیاری\n'
          '۴. نوع خاک\n'
          '۵. آخرین کود مصرفی\n'
          '۶. وضعیت آب‌وهوا\n'
          '۷. در صورت امکان عکس واضح از برگ و کل گیاه\n\n'
          'بعد از دریافت این اطلاعات می‌توان علت‌های محتمل را مقایسه و اولویت‌بندی کرد.';
    }

    if (q.contains('آبیاری') || q.contains('آب')) {
      return 'برای برنامه آبیاری دقیق باید نوع محصول، سن گیاه، بافت خاک، روش آبیاری، دمای منطقه و وضعیت رطوبت خاک مشخص شود.\n\n'
          'در نسخه متصل به سرور، این اطلاعات با داده‌های آب‌وهوا و مشخصات مزرعه ترکیب خواهد شد.';
    }

    if (q.contains('کود') || q.contains('کوددهی')) {
      return 'برای توصیه کودی دقیق، ابتدا باید محصول، مرحله رشد و نتیجه آزمایش خاک و در صورت نیاز آب مشخص شود.\n\n'
          'از مصرف خودسرانه کود یا افزایش مقدار مصرف بدون بررسی شرایط مزرعه خودداری کنید.';
    }

    if (q.contains('سم') ||
        q.contains('آفت') ||
        q.contains('بیماری')) {
      return 'برای تشخیص آفت یا بیماری، عکس واضح از قسمت آسیب‌دیده، نام محصول، سن گیاه، منطقه، الگوی گسترش آسیب و سابقه سم‌پاشی بسیار مهم است.\n\n'
          'در نسخه کامل، موتور تشخیص تصویر و پایگاه داده آفات و بیماری‌ها به این بخش متصل می‌شوند.';
    }

    return 'درخواست شما ثبت شد.\n\n'
        'برای تحلیل دقیق‌تر، ARYA اطلاعات زیر را در صورت ارتباط با مسئله بررسی می‌کند:\n'
        '• محصول و مرحله رشد\n'
        '• منطقه و شرایط آب‌وهوایی\n'
        '• خاک و آزمایشگاه\n'
        '• آب و آبیاری\n'
        '• کود و سموم مصرف‌شده\n'
        '• عکس یا ویدئو\n'
        '• سابقه اقدامات مزرعه\n\n'
        'این نسخه هسته گفت‌وگویی اولیه را دارد و در معماری نهایی به موتور AI و پایگاه دانش ابری متصل می‌شود.';
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Expanded(
          child: ListView.builder(
            padding: const EdgeInsets.all(14),
            itemCount: _messages.length,
            itemBuilder: (context, index) {
              final message = _messages[index];

              return Align(
                alignment: message.isAi
                    ? Alignment.centerRight
                    : Alignment.centerLeft,
                child: Card(
                  child: Padding(
                    padding: const EdgeInsets.all(14),
                    child: Text(
                      message.text,
                      textAlign: TextAlign.right,
                      style: const TextStyle(fontSize: 16),
                    ),
                  ),
                ),
              );
            },
          ),
        ),
        if (_loading)
          const Padding(
            padding: EdgeInsets.all(8),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                  ),
                ),
                SizedBox(width: 10),
                Text('ARYA در حال بررسی است...'),
              ],
            ),
          ),
        SafeArea(
          child: Padding(
            padding: const EdgeInsets.all(10),
            child: Row(
              children: [
                IconButton(
                  icon: const Icon(Icons.photo_camera),
                  onPressed: () {
                    _showInfo(
                      'دوربین',
                      'اتصال دوربین و تحلیل تصویری در لایه AI/Backend برنامه پیش‌بینی شده است.',
                    );
                  },
                ),
                Expanded(
                  child: TextField(
                    controller: _controller,
                    textDirection: TextDirection.rtl,
                    decoration: const InputDecoration(
                      hintText: 'مسئله کشاورزی خود را بنویسید...',
                      border: OutlineInputBorder(),
                    ),
                    onSubmitted: (_) => _sendMessage(),
                  ),
                ),
                IconButton(
                  icon: const Icon(Icons.send),
                  onPressed: _sendMessage,
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }

  void _showInfo(String title, String text) {
    showDialog<void>(
      context: context,
      builder: (_) => AlertDialog(
        title: Text(title),
        content: Text(
          text,
          textAlign: TextAlign.right,
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('باشه'),
          ),
        ],
      ),
    );
  }
}

class AryaModulePage extends StatelessWidget {
  final AryaModule module;

  const AryaModulePage({
    super.key,
    required this.module,
  });

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(module.title),
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Card(
            child: Padding(
              padding: const EdgeInsets.all(22),
              child: Column(
                children: [
                  CircleAvatar(
                    radius: 40,
                    child: Icon(
                      module.icon,
                      size: 42,
                    ),
                  ),
                  const SizedBox(height: 16),
                  Text(
                    module.title,
                    textAlign: TextAlign.center,
                    style: const TextStyle(
                      fontSize: 25,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    module.subtitle,
                    textAlign: TextAlign.center,
                    style: const TextStyle(fontSize: 16),
                  ),
                  const SizedBox(height: 18),
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
          const SizedBox(height: 18),
          ..._buildModuleActions(context),
        ],
      ),
    );
  }

  List<Widget> _buildModuleActions(BuildContext context) {
    if (module.title == 'OWNER / MASTER') {
      return [
        _action(
          context,
          'مدیریت کاربران',
          Icons.people,
        ),
        _action(
          context,
          'مدیریت دانش کشاورزی',
          Icons.menu_book,
        ),
        _action(
          context,
          'تنظیمات AI',
          Icons.psychology,
        ),
        _action(
          context,
          'پرداخت و اشتراک',
          Icons.payment,
        ),
        _action(
          context,
          'امنیت و گزارش فعالیت',
          Icons.security,
        ),
        _action(
          context,
          'پشتیبان‌گیری و بازیابی',
          Icons.backup,
        ),
      ];
    }

    if (module.title == 'نظر شما') {
      return [
        _action(
          context,
          'پیشنهاد جدید',
          Icons.lightbulb_outline,
        ),
        _action(
          context,
          'انتقاد یا گزارش مشکل',
          Icons.report_problem_outlined,
        ),
        _action(
          context,
          'درخواست قابلیت جدید',
          Icons.add_circle_outline,
        ),
        _action(
          context,
          'پیگیری پاسخ پشتیبانی',
          Icons.question_answer_outlined,
        ),
      ];
    }

    if (module.title == 'تشخیص هوشمند') {
      return [
        _action(
          context,
          'تشخیص با توضیح متنی',
          Icons.text_fields,
        ),
        _action(
          context,
          'تشخیص از روی عکس',
          Icons.image_search,
        ),
        _action(
          context,
          'تحلیل آزمایش خاک',
          Icons.science,
        ),
        _action(
          context,
          'تحلیل کامل مزرعه',
          Icons.analytics,
        ),
      ];
    }

    return [
      _action(
        context,
        'ثبت اطلاعات جدید',
        Icons.add_circle_outline,
      ),
      _action(
        context,
        'مشاهده اطلاعات',
        Icons.visibility_outlined,
      ),
      _action(
        context,
        'تحلیل هوشمند ARYA',
        Icons.auto_awesome,
      ),
      _action(
        context,
        'برنامه و اقدامات',
        Icons.task_alt,
      ),
    ];
  }

  Widget _action(
    BuildContext context,
    String title,
    IconData icon,
  ) {
    return Card(
      margin: const EdgeInsets.only(bottom: 10),
      child: ListTile(
        leading: Icon(icon),
        title: Text(title),
        trailing: const Icon(Icons.arrow_forward_ios),
        onTap: () {
          showDialog<void>(
            context: context,
            builder: (_) => AlertDialog(
              title: Text(title),
              content: const Text(
                'این بخش در ساختار نهایی ARYA AgriDoctor قرار گرفته و برای اتصال به داده‌های واقعی، پایگاه دانش و سرویس‌های ابری آماده است.',
                textAlign: TextAlign.right,
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.pop(context),
                  child: const Text('باشه'),
                ),
              ],
            ),
          );
        },
      ),
    );
  }
}

class AryaModule {
  final String title;
  final String subtitle;
  final IconData icon;

  const AryaModule({
    required this.title,
    required this.subtitle,
    required this.icon,
  });
}

class AiMessage {
  final String text;
  final bool isAi;

  const AiMessage({
    required this.text,
    required this.isAi,
  });
}
