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
            tooltip: 'اعلان‌ها',
            icon: const Icon(Icons.notifications_outlined),
            onPressed: () {
              final notificationsModule = _modules.firstWhere(
                (module) => module.title == 'اعلان‌ها',
              );
              _openModule(notificationsModule);
            },
          ),
        ],
      ),
      body: IndexedStack(
        index: _selectedIndex,
        children: [
          _buildDashboard(),
          const AryaAiPage(),
          _buildFarmSummary(),
        ],
      ),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _selectedIndex,
        onDestinationSelected: (value) {
          if (value < 0 || value >= 3) return;

          if (_selectedIndex != value) {
            setState(() {
              _selectedIndex = value;
            });
          }
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
            const CircleAvatar(
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
                      'مسئله کشاورزی خود را بنویسید و اطلاعات لازم را '
                      'مرحله‌به‌مرحله بررسی کنید.',
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
        const SizedBox(height: 8),
        const Text(
          'اطلاعات این صفحه فعلاً نمونه است و هنوز از پایگاه داده '
          'خوانده نمی‌شود.',
          textAlign: TextAlign.center,
          style: TextStyle(
            fontSize: 12,
            color: Colors.grey,
          ),
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
    Navigator.of(context).push(
      MaterialPageRoute<void>(
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
  final ScrollController _scrollController = ScrollController();

  final List<AiMessage> _messages = [
    const AiMessage(
      text:
          'سلام. من دستیار ARYA هستم. مسئله کشاورزی خود را توضیح دهید. '
          'برای پاسخ دقیق‌تر می‌توانم اطلاعات محصول، زمین، آب، خاک و '
          'آب‌وهوا را بررسی کنم.',
      isAi: true,
    ),
  ];

  bool _loading = false;

  @override
  void dispose() {
    _controller.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  void _sendMessage() {
    if (_loading) return;

    final question = _controller.text.trim();

    if (question.isEmpty) return;

    setState(() {
      _messages.add(
        AiMessage(
          text: question,
          isAi: false,
        ),
      );
      _controller.clear();
      _loading = true;
    });

    _scrollToBottom();
    _processLocalMessage(question);
  }

  Future<void> _processLocalMessage(String question) async {
    try {
      // این تأخیر صرفاً برای شبیه‌سازی پردازش رابط کاربری است.
      // در این تابع درخواست شبکه‌ای به Backend ارسال نمی‌شود.
      await Future<void>.delayed(
        const Duration(milliseconds: 400),
      );

      if (!mounted) return;

      final answer = _generateLocalAnalysis(question);

      setState(() {
        _messages.add(
          AiMessage(
            text: answer,
            isAi: true,
          ),
        );
        _loading = false;
      });

      _scrollToBottom();
    } catch (_) {
      if (!mounted) return;

      setState(() {
        _loading = false;
        _messages.add(
          const AiMessage(
            text: 'در پردازش پیام خطایی رخ داد. لطفاً دوباره تلاش کنید.',
            isAi: true,
          ),
        );
      });

      _scrollToBottom();
    }
  }

  void _scrollToBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted || !_scrollController.hasClients) return;

      final position = _scrollController.position;

      _scrollController.animateTo(
        position.maxScrollExtent,
        duration: const Duration(milliseconds: 250),
        curve: Curves.easeOut,
      );
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
          'بعد از دریافت این اطلاعات می‌توان علت‌های محتمل را مقایسه '
          'و اولویت‌بندی کرد.\n\n'
          'توجه: این پاسخ محلی و اولیه است و از موتور تخصصی سرور '
          'دریافت نشده است.';
    }

    if (q.contains('آبیاری') || q.contains('آب')) {
      return 'برای برنامه آبیاری دقیق باید نوع محصول، سن گیاه، بافت خاک، '
          'روش آبیاری، دمای منطقه و وضعیت رطوبت خاک مشخص شود.\n\n'
          'برنامه آبیاری باید با توجه به نیاز محصول، رطوبت خاک و '
          'شرایط آب‌وهوایی تنظیم شود.\n\n'
          'این پاسخ محلی است و در حال حاضر از داده‌های واقعی هواشناسی '
          'یا موتور سرور استفاده نمی‌کند.';
    }

    if (q.contains('کود') || q.contains('کوددهی')) {
      return 'برای توصیه کودی دقیق، ابتدا باید محصول، مرحله رشد و '
          'نتیجه آزمایش خاک و در صورت نیاز آب مشخص شود.\n\n'
          'از مصرف خودسرانه کود یا افزایش مقدار مصرف بدون بررسی '
          'شرایط مزرعه خودداری کنید.\n\n'
          'مقدار مصرف باید بر اساس نیاز محصول، نتایج آزمایش و '
          'دستورالعمل معتبر تعیین شود.';
    }

    if (q.contains('سم') ||
        q.contains('آفت') ||
        q.contains('بیماری')) {
      return 'برای بررسی آفت یا بیماری، اطلاعات زیر مهم هستند:\n\n'
          '۱. نام محصول و مرحله رشد\n'
          '۲. عکس واضح از قسمت آسیب‌دیده\n'
          '۳. شکل و محل گسترش آسیب\n'
          '۴. منطقه و شرایط آب‌وهوایی\n'
          '۵. سابقه سم‌پاشی و مواد مصرف‌شده\n\n'
          'تا پیش از شناسایی قابل‌اعتماد عامل، از توصیه قطعی سم، '
          'مخلوط‌کردن سموم یا تعیین مقدار مصرف خودداری کنید.\n\n'
          'این پاسخ محلی است؛ تشخیص تصویری و پایگاه داده سرور '
          'از این صفحه فراخوانی نمی‌شوند.';
    }

    return 'درخواست شما ثبت شد.\n\n'
        'برای تحلیل دقیق‌تر، ARYA بسته به مسئله می‌تواند این اطلاعات '
        'را بررسی کند:\n'
        '• محصول و مرحله رشد\n'
        '• منطقه و شرایط آب‌وهوایی\n'
        '• خاک و نتایج آزمایشگاه\n'
        '• آب و آبیاری\n'
        '• کود و سموم مصرف‌شده\n'
        '• عکس یا ویدئو\n'
        '• سابقه اقدامات مزرعه\n\n'
        'وضعیت فعلی: این صفحه از پاسخ‌های محلی اولیه استفاده می‌کند. '
        'برای پاسخ تخصصی واقعی باید از طریق قرارداد معتبر API به '
        'موتور تحلیل ARYA در Backend متصل شود.';
  }

  void _showInfo(String title, String text) {
    showDialog<void>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: Text(title),
        content: Text(
          text,
          textAlign: TextAlign.right,
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext),
            child: const Text('باشه'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        const Padding(
          padding: EdgeInsets.fromLTRB(12, 8, 12, 4),
          child: Align(
            alignment: Alignment.centerRight,
            child: Text(
              'دستیار کشاورزی ARYA',
              style: TextStyle(
                fontSize: 17,
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
        ),
        Expanded(
          child: ListView.builder(
            controller: _scrollController,
            padding: const EdgeInsets.all(14),
            itemCount: _messages.length,
            itemBuilder: (context, index) {
              final message = _messages[index];

              return Align(
                alignment: message.isAi
                    ? Alignment.centerRight
                    : Alignment.centerLeft,
                child: ConstrainedBox(
                  constraints: BoxConstraints(
                    maxWidth: MediaQuery.sizeOf(context).width * 0.86,
                  ),
                  child: Card(
                    color: message.isAi
                        ? Theme.of(context).colorScheme.surface
                        : Theme.of(context).colorScheme.primaryContainer,
                    child: Padding(
                      padding: const EdgeInsets.all(14),
                      child: SelectableText(
                        message.text,
                        textAlign: TextAlign.right,
                        style: const TextStyle(fontSize: 16),
                      ),
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
          top: false,
          child: Padding(
            padding: const EdgeInsets.all(10),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.end,
              children: [
                IconButton(
                  tooltip: 'تصویر گیاه',
                  icon: const Icon(Icons.photo_camera),
                  onPressed: () {
                    _showInfo(
                      'دوربین',
                      'اتصال دوربین و تحلیل تصویری در این نسخه '
                      'فعال نیست. برای انتخاب تصویر باید قابلیت '
                      'انتخاب فایل و اتصال معتبر به سرویس تحلیل تصویر '
                      'پیاده‌سازی شود.',
                    );
                  },
                ),
                Expanded(
                  child: TextField(
                    controller: _controller,
                    textDirection: TextDirection.rtl,
                    textInputAction: TextInputAction.send,
                    minLines: 1,
                    maxLines: 4,
                    enabled: !_loading,
                    decoration: const InputDecoration(
                      hintText: 'مسئله کشاورزی خود را بنویسید...',
                      border: OutlineInputBorder(),
                    ),
                    onSubmitted: (_) => _sendMessage(),
                  ),
                ),
                IconButton(
                  tooltip: 'ارسال پیام',
                  icon: const Icon(Icons.send),
                  onPressed: _loading ? null : _sendMessage,
                ),
              ],
            ),
          ),
        ),
      ],
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
            builder: (dialogContext) => AlertDialog(
              title: Text(title),
              content: Text(
                module.title == 'OWNER / MASTER'
                    ? 'این گزینه فعلاً رابط کاربری است و عملیات مدیریتی '
                        'واقعی انجام نمی‌دهد. دسترسی مدیر باید از طریق '
                        'احراز هویت امن و مجوزهای Backend بررسی شود.'
                    : 'این گزینه فعلاً رابط کاربری اولیه است. برای ثبت، '
                        'مشاهده یا تحلیل واقعی اطلاعات، باید به سرویس '
                        'مربوط در Backend متصل شود.',
                textAlign: TextAlign.right,
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.pop(dialogContext),
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
