import 'package:flutter/material.dart';

import 'core/network/api_client.dart';
import 'features/diagnostics/arya_quality_page.dart';

const Color _aryaGreen = Color(0xFF237A45);
const Color _aryaBackground = Color(0xFFF5F8F5);

class AryaMainApp extends StatelessWidget {
  const AryaMainApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'ARYA AgriDoctor',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(
          seedColor: _aryaGreen,
          brightness: Brightness.light,
        ),
        scaffoldBackgroundColor: _aryaBackground,
        appBarTheme: const AppBarTheme(
          centerTitle: true,
          elevation: 0,
        ),
        inputDecorationTheme: const InputDecorationTheme(
          border: OutlineInputBorder(),
          filled: true,
        ),
        cardTheme: CardThemeData(
          elevation: 1,
          margin: const EdgeInsets.symmetric(vertical: 6),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16),
          ),
        ),
      ),
      home: const AryaMainHomePage(),
    );
  }
}

// ============================================================
// MAIN APPLICATION
// ============================================================

class AryaMainHomePage extends StatefulWidget {
  const AryaMainHomePage({super.key});

  @override
  State<AryaMainHomePage> createState() => _AryaMainHomePageState();
}

class _AryaMainHomePageState extends State<AryaMainHomePage> {
  final AryaApiClient _api = AryaApiClient();

  int _selectedIndex = 0;
  bool _loading = true;
  bool _loggedIn = false;
  bool _initializationError = false;

  Map<String, dynamic>? _user;

  static const List<String> _titles = [
    'خانه',
    'مزرعه',
    'ARYA AI',
    'پشتیبانی',
  ];

  @override
  void initState() {
    super.initState();
    _initialize();
  }

  Future<void> _initialize() async {
    if (mounted) {
      setState(() {
        _loading = true;
        _initializationError = false;
      });
    }

    try {
      final loggedIn = await _api.isLoggedIn();

      if (!loggedIn) {
        if (!mounted) return;

        setState(() {
          _loggedIn = false;
          _user = null;
          _loading = false;
        });

        return;
      }

      final response = await _api.me();

      Map<String, dynamic> userData;

      final rawUser = response['user'];

      if (rawUser is Map) {
        userData = Map<String, dynamic>.from(rawUser);
      } else {
        userData = Map<String, dynamic>.from(response);
      }

      if (!mounted) return;

      setState(() {
        _loggedIn = true;
        _user = userData;
        _loading = false;
      });
    } catch (_) {
      if (!mounted) return;

      // خطای موقت شبکه نباید الزاماً باعث حذف توکن شود.
      setState(() {
        _loggedIn = false;
        _user = null;
        _loading = false;
        _initializationError = true;
      });
    }
  }

  Future<void> _openLogin() async {
    final result = await Navigator.of(context).push<bool>(
      MaterialPageRoute(
        builder: (_) => AryaLoginPage(api: _api),
      ),
    );

    if (result == true) {
      await _initialize();
    }
  }

  Future<void> _openRegister() async {
    final result = await Navigator.of(context).push<bool>(
      MaterialPageRoute(
        builder: (_) => AryaRegisterPage(api: _api),
      ),
    );

    if (result == true) {
      await _openLogin();
    }
  }

  Future<void> _logout() async {
    try {
      await _api.logout();
    } catch (_) {
      await _api.clearToken();
    }

    if (!mounted) return;

    setState(() {
      _loggedIn = false;
      _user = null;
      _selectedIndex = 0;
    });
  }

  Future<void> _openQualityCenter() async {
    await Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => AryaQualityPage(
          baseUrl: _api.baseUrl,
        ),
      ),
    );
  }

  void _openAi() {
    setState(() {
      _selectedIndex = 2;
    });
  }

  void _openFarm() {
    setState(() {
      _selectedIndex = 1;
    });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const Scaffold(
        body: Center(
          child: CircularProgressIndicator(),
        ),
      );
    }

    if (!_loggedIn) {
      return AryaWelcomePage(
        onLogin: _openLogin,
        onRegister: _openRegister,
        onRetry: _initializationError ? _initialize : null,
      );
    }

    return Scaffold(
      appBar: AppBar(
        title: Text(_titles[_selectedIndex]),
        actions: [
          IconButton(
            tooltip: 'مرکز کنترل کیفیت',
            onPressed: _openQualityCenter,
            icon: const Icon(Icons.fact_check_outlined),
          ),
          IconButton(
            tooltip: 'حساب کاربری',
            onPressed: () async {
              await Navigator.of(context).push(
                MaterialPageRoute(
                  builder: (_) => AryaAccountPage(
                    user: _user,
                    onLogout: _logout,
                  ),
                ),
              );
            },
            icon: const Icon(Icons.account_circle_outlined),
          ),
        ],
      ),
      body: IndexedStack(
        index: _selectedIndex,
        children: [
          _HomeTab(
            user: _user,
            onOpenAi: _openAi,
            onOpenFarm: _openFarm,
          ),
          _FarmTab(api: _api),
          _AiTab(api: _api, user: _user),
          _SupportTab(api: _api),
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

// ============================================================
// WELCOME
// ============================================================

class AryaWelcomePage extends StatelessWidget {
  const AryaWelcomePage({
    super.key,
    required this.onLogin,
    required this.onRegister,
    this.onRetry,
  });

  final VoidCallback onLogin;
  final VoidCallback onRegister;
  final VoidCallback? onRetry;

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;

    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 480),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  CircleAvatar(
                    radius: 52,
                    backgroundColor: colorScheme.primaryContainer,
                    child: Icon(
                      Icons.agriculture,
                      size: 58,
                      color: colorScheme.primary,
                    ),
                  ),
                  const SizedBox(height: 24),
                  const Text(
                    'ARYA AgriDoctor',
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      fontSize: 30,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  const SizedBox(height: 12),
                  const Text(
                    'دستیار هوشمند کشاورزی شما',
                    textAlign: TextAlign.center,
                    style: TextStyle(fontSize: 18),
                  ),
                  const SizedBox(height: 24),
                  const Text(
                    'مدیریت مزرعه، مشاورهٔ کشاورزی، بررسی مشکلات گیاهان و دریافت راهنمایی برای خاک، آب و محصولات.',
                    textAlign: TextAlign.center,
                  ),
                  if (onRetry != null) ...[
                    const SizedBox(height: 20),
                    const Text(
                      'بررسی وضعیت حساب یا اتصال به سرور انجام نشد.',
                      textAlign: TextAlign.center,
                    ),
                    const SizedBox(height: 8),
                    OutlinedButton.icon(
                      onPressed: onRetry,
                      icon: const Icon(Icons.refresh),
                      label: const Text('تلاش مجدد'),
                    ),
                  ],
                  const SizedBox(height: 28),
                  SizedBox(
                    width: double.infinity,
                    child: FilledButton.icon(
                      onPressed: onLogin,
                      icon: const Icon(Icons.login),
                      label: const Text('ورود به حساب'),
                    ),
                  ),
                  const SizedBox(height: 12),
                  SizedBox(
                    width: double.infinity,
                    child: OutlinedButton.icon(
                      onPressed: onRegister,
                      icon: const Icon(Icons.person_add_alt_1),
                      label: const Text('ایجاد حساب جدید'),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

// ============================================================
// LOGIN
// ============================================================

class AryaLoginPage extends StatefulWidget {
  const AryaLoginPage({
    super.key,
    required this.api,
  });

  final AryaApiClient api;

  @override
  State<AryaLoginPage> createState() => _AryaLoginPageState();
}

class _AryaLoginPageState extends State<AryaLoginPage> {
  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();

  bool _loading = false;
  bool _obscurePassword = true;

  String? _error;

  @override
  void dispose() {
    _emailController.dispose();
    _passwordController.dispose();
    super.dispose();
  }

  Future<void> _login() async {
    final email = _emailController.text.trim();
    final password = _passwordController.text;

    if (email.isEmpty || password.isEmpty) {
      setState(() {
        _error = 'ایمیل و رمز عبور را وارد کنید.';
      });
      return;
    }

    setState(() {
      _loading = true;
      _error = null;
    });

    try {
      await widget.api.login(
        email: email,
        password: password,
      );

      if (!mounted) return;

      Navigator.of(context).pop(true);
    } catch (e) {
      if (!mounted) return;

      setState(() {
        _error = _friendlyError(e);
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('ورود به ARYA'),
      ),
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 480),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const Icon(Icons.lock_outline, size: 64),
                  const SizedBox(height: 20),
                  const Text(
                    'ورود به حساب کاربری',
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      fontSize: 24,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  const SizedBox(height: 24),
                  TextField(
                    controller: _emailController,
                    keyboardType: TextInputType.emailAddress,
                    textDirection: TextDirection.ltr,
                    autocorrect: false,
                    decoration: const InputDecoration(
                      labelText: 'ایمیل',
                      prefixIcon: Icon(Icons.email_outlined),
                    ),
                  ),
                  const SizedBox(height: 16),
                  TextField(
                    controller: _passwordController,
                    obscureText: _obscurePassword,
                    textDirection: TextDirection.ltr,
                    onSubmitted: (_) => _login(),
                    decoration: InputDecoration(
                      labelText: 'رمز عبور',
                      prefixIcon: const Icon(Icons.lock_outline),
                      suffixIcon: IconButton(
                        onPressed: () {
                          setState(() {
                            _obscurePassword = !_obscurePassword;
                          });
                        },
                        icon: Icon(
                          _obscurePassword
                              ? Icons.visibility_outlined
                              : Icons.visibility_off_outlined,
                        ),
                      ),
                    ),
                  ),
                  if (_error != null) ...[
                    const SizedBox(height: 16),
                    _ErrorPanel(message: _error!),
                  ],
                  const SizedBox(height: 20),
                  SizedBox(
                    height: 52,
                    child: FilledButton(
                      onPressed: _loading ? null : _login,
                      child: _loading
                          ? const SizedBox(
                              width: 22,
                              height: 22,
                              child: CircularProgressIndicator(
                                strokeWidth: 2,
                              ),
                            )
                          : const Text('ورود'),
                    ),
                  ),
                  const SizedBox(height: 12),
                  OutlinedButton.icon(
                    onPressed: _loading
                        ? null
                        : () async {
                            final result =
                                await Navigator.of(context).push<bool>(
                              MaterialPageRoute(
                                builder: (_) =>
                                    AryaRegisterPage(api: widget.api),
                              ),
                            );

                            if (result == true && context.mounted) {
                              ScaffoldMessenger.of(context).showSnackBar(
                                const SnackBar(
                                  content: Text(
                                    'ثبت‌نام انجام شد. اکنون وارد شوید.',
                                  ),
                                ),
                              );
                            }
                          },
                    icon: const Icon(Icons.person_add_outlined),
                    label: const Text('ایجاد حساب جدید'),
                  ),
                  const SizedBox(height: 12),
                  const Text(
                    'اگر ورود انجام نمی‌شود، متن خطا را نگه دارید تا اتصال برنامه به سرور بررسی شود.',
                    textAlign: TextAlign.center,
                    style: TextStyle(fontSize: 12),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

// ============================================================
// REGISTER
// ============================================================

class AryaRegisterPage extends StatefulWidget {
  const AryaRegisterPage({
    super.key,
    required this.api,
  });

  final AryaApiClient api;

  @override
  State<AryaRegisterPage> createState() => _AryaRegisterPageState();
}

class _AryaRegisterPageState extends State<AryaRegisterPage> {
  final _nameController = TextEditingController();
  final _emailController = TextEditingController();
  final _phoneController = TextEditingController();
  final _passwordController = TextEditingController();
  final _confirmPasswordController = TextEditingController();

  bool _loading = false;
  bool _obscurePassword = true;

  String? _error;

  @override
  void dispose() {
    _nameController.dispose();
    _emailController.dispose();
    _phoneController.dispose();
    _passwordController.dispose();
    _confirmPasswordController.dispose();
    super.dispose();
  }

  Future<void> _register() async {
    final name = _nameController.text.trim();
    final email = _emailController.text.trim();
    final phone = _phoneController.text.trim();
    final password = _passwordController.text;
    final confirmPassword = _confirmPasswordController.text;

    if (email.isEmpty || password.isEmpty) {
      setState(() {
        _error = 'ایمیل و رمز عبور الزامی است.';
      });
      return;
    }

    if (!email.contains('@') || !email.contains('.')) {
      setState(() {
        _error = 'قالب ایمیل را بررسی کنید.';
      });
      return;
    }

    if (password.length < 8) {
      setState(() {
        _error = 'رمز عبور باید حداقل ۸ کاراکتر باشد.';
      });
      return;
    }

    if (password != confirmPassword) {
      setState(() {
        _error = 'رمز عبور و تکرار آن یکسان نیستند.';
      });
      return;
    }

    setState(() {
      _loading = true;
      _error = null;
    });

    try {
      await widget.api.register(
        name: name,
        email: email,
        password: password,
        phone: phone,
        language: 'fa',
      );

      if (!mounted) return;

      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('حساب ایجاد شد. اکنون وارد شوید.'),
        ),
      );

      Navigator.of(context).pop(true);
    } catch (e) {
      if (!mounted) return;

      setState(() {
        _error = _friendlyError(e);
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('ایجاد حساب کاربری'),
      ),
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 480),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const Icon(Icons.person_add_alt_1, size: 60),
                  const SizedBox(height: 20),
                  TextField(
                    controller: _nameController,
                    textCapitalization: TextCapitalization.words,
                    decoration: const InputDecoration(
                      labelText: 'نام',
                      prefixIcon: Icon(Icons.person_outline),
                    ),
                  ),
                  const SizedBox(height: 14),
                  TextField(
                    controller: _emailController,
                    keyboardType: TextInputType.emailAddress,
                    textDirection: TextDirection.ltr,
                    autocorrect: false,
                    decoration: const InputDecoration(
                      labelText: 'ایمیل',
                      prefixIcon: Icon(Icons.email_outlined),
                    ),
                  ),
                  const SizedBox(height: 14),
                  TextField(
                    controller: _phoneController,
                    keyboardType: TextInputType.phone,
                    decoration: const InputDecoration(
                      labelText: 'شماره تلفن (اختیاری)',
                      prefixIcon: Icon(Icons.phone_outlined),
                    ),
                  ),
                  const SizedBox(height: 14),
                  TextField(
                    controller: _passwordController,
                    obscureText: _obscurePassword,
                    textDirection: TextDirection.ltr,
                    decoration: InputDecoration(
                      labelText: 'رمز عبور',
                      prefixIcon: const Icon(Icons.lock_outline),
                      suffixIcon: IconButton(
                        onPressed: () {
                          setState(() {
                            _obscurePassword = !_obscurePassword;
                          });
                        },
                        icon: Icon(
                          _obscurePassword
                              ? Icons.visibility_outlined
                              : Icons.visibility_off_outlined,
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(height: 14),
                  TextField(
                    controller: _confirmPasswordController,
                    obscureText: true,
                    textDirection: TextDirection.ltr,
                    decoration: const InputDecoration(
                      labelText: 'تکرار رمز عبور',
                      prefixIcon: Icon(Icons.lock_reset_outlined),
                    ),
                  ),
                  const SizedBox(height: 8),
                  const Text(
                    'برای امنیت حساب، رمز عبور حداقل ۸ کاراکتر باشد.',
                    style: TextStyle(fontSize: 12),
                  ),
                  if (_error != null) ...[
                    const SizedBox(height: 16),
                    _ErrorPanel(message: _error!),
                  ],
                  const SizedBox(height: 20),
                  SizedBox(
                    height: 52,
                    child: FilledButton(
                      onPressed: _loading ? null : _register,
                      child: _loading
                          ? const SizedBox(
                              width: 22,
                              height: 22,
                              child: CircularProgressIndicator(
                                strokeWidth: 2,
                              ),
                            )
                          : const Text('ثبت‌نام'),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

// ============================================================
// HOME TAB
// ============================================================

class _HomeTab extends StatelessWidget {
  const _HomeTab({
    required this.user,
    required this.onOpenAi,
    required this.onOpenFarm,
  });

  final Map<String, dynamic>? user;
  final VoidCallback onOpenAi;
  final VoidCallback onOpenFarm;

  @override
  Widget build(BuildContext context) {
    final name = user?['name']?.toString().trim() ?? '';

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: Container(
            width: double.infinity,
            padding: const EdgeInsets.all(20),
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(16),
              gradient: LinearGradient(
                colors: [
                  Theme.of(context).colorScheme.primaryContainer,
                  _aryaBackground,
                ],
                begin: Alignment.topRight,
                end: Alignment.bottomLeft,
              ),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  name.isEmpty
                      ? 'به ARYA خوش آمدید'
                      : 'سلام $name',
                  style: const TextStyle(
                    fontSize: 23,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 8),
                const Text(
                  'همراه هوشمند شما برای تصمیم‌گیری بهتر در کشاورزی.',
                ),
                const SizedBox(height: 18),
                SizedBox(
                  width: double.infinity,
                  child: FilledButton.icon(
                    onPressed: onOpenAi,
                    icon: const Icon(Icons.smart_toy_outlined),
                    label: const Text('مشاوره با ARYA AI'),
                  ),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 14),
        const Text(
          'خدمات کشاورزی',
          style: TextStyle(
            fontSize: 20,
            fontWeight: FontWeight.bold,
          ),
        ),
        const SizedBox(height: 8),
        _ModuleCard(
          icon: Icons.agriculture_outlined,
          title: 'مزرعه و زمین',
          description: 'مشاهده و مدیریت مزارع ثبت‌شده',
          onTap: onOpenFarm,
        ),
        _ModuleCard(
          icon: Icons.eco_outlined,
          title: 'محصولات و درختان',
          description: 'پرسش دربارهٔ کشت، رشد و نگهداری گیاهان',
          onTap: onOpenAi,
        ),
        _ModuleCard(
          icon: Icons.water_drop_outlined,
          title: 'آب و آبیاری',
          description: 'راهنمایی دربارهٔ نیاز آبی و مدیریت آبیاری',
          onTap: onOpenAi,
        ),
        _ModuleCard(
          icon: Icons.cloud_outlined,
          title: 'آب‌وهوا و اقلیم',
          description: 'دریافت راهنمایی با ذکر منطقه و شرایط جوی',
          onTap: onOpenAi,
        ),
        _ModuleCard(
          icon: Icons.bug_report_outlined,
          title: 'آفات و بیماری‌ها',
          description: 'شرح علائم گیاه برای دریافت راهنمایی اولیه',
          onTap: onOpenAi,
        ),
        _ModuleCard(
          icon: Icons.science_outlined,
          title: 'خاک و تغذیه',
          description: 'پرسش دربارهٔ آزمایش خاک، کود و عناصر غذایی',
          onTap: onOpenAi,
        ),
        const SizedBox(height: 12),
        const Card(
          child: Padding(
            padding: EdgeInsets.all(16),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Icon(Icons.info_outline),
                SizedBox(width: 12),
                Expanded(
                  child: Text(
                    'برای تشخیص دقیق‌تر، نام گیاه، منطقه، سن گیاه، علائم، زمان شروع مشکل و سابقهٔ آبیاری یا سم‌پاشی را در سؤال خود بنویسید.',
                  ),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }
}

// ============================================================
// FARM TAB
// ============================================================

class _FarmTab extends StatefulWidget {
  const _FarmTab({
    required this.api,
  });

  final AryaApiClient api;

  @override
  State<_FarmTab> createState() => _FarmTabState();
}

class _FarmTabState extends State<_FarmTab> {
  late Future<Map<String, dynamic>> _farmsFuture;

  @override
  void initState() {
    super.initState();
    _loadFarms();
  }

  void _loadFarms() {
    _farmsFuture = widget.api.get(
      '/farms',
      authenticated: true,
    );
  }

  Future<void> _refresh() async {
    setState(_loadFarms);
    try {
      await _farmsFuture;
    } catch (_) {
      // خطا در FutureBuilder نمایش داده می‌شود.
    }
  }

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<Map<String, dynamic>>(
      future: _farmsFuture,
      builder: (context, snapshot) {
        if (snapshot.connectionState == ConnectionState.waiting) {
          return const Center(
            child: CircularProgressIndicator(),
          );
        }

        if (snapshot.hasError) {
          return _StateMessage(
            icon: Icons.cloud_off_outlined,
            title: 'دریافت مزارع انجام نشد',
            message: _friendlyError(snapshot.error!),
            actionLabel: 'تلاش مجدد',
            onAction: _refresh,
          );
        }

        final response = snapshot.data ?? {};
        final rawFarms = response['data'] ??
            response['farms'] ??
            response['items'];

        final farms = rawFarms is List ? rawFarms : <dynamic>[];

        if (farms.isEmpty) {
          return _EmptyFarmView(
            onAskAi: () {
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(
                  content: Text(
                    'برای راهنمایی دربارهٔ ثبت مزرعه، از بخش ARYA AI سؤال کنید.',
                  ),
                ),
              );
            },
          );
        }

        return RefreshIndicator(
          onRefresh: _refresh,
          child: ListView(
            padding: const EdgeInsets.all(16),
            children: [
              const Text(
                'مزارع من',
                style: TextStyle(
                  fontSize: 24,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 8),
              const Text('برای به‌روزرسانی، صفحه را به پایین بکشید.'),
              const SizedBox(height: 12),
              ...farms.map((farm) {
                final map = farm is Map
                    ? Map<String, dynamic>.from(farm)
                    : <String, dynamic>{};

                final farmName =
                    _firstNonEmpty(map, ['name', 'title']) ?? 'مزرعه';

                final location = _firstNonEmpty(
                      map,
                      ['location', 'address', 'region', 'province'],
                    ) ??
                    'موقعیت ثبت نشده';

                final area = _firstNonEmpty(
                  map,
                  ['area', 'area_hectares', 'size'],
                );

                return Card(
                  child: ListTile(
                    leading: const CircleAvatar(
                      child: Icon(Icons.agriculture),
                    ),
                    title: Text(farmName),
                    subtitle: Text(
                      area == null
                          ? location
                          : '$location\nمساحت: $area',
                    ),
                    isThreeLine: area != null,
                  ),
                );
              }),
            ],
          ),
        );
      },
    );
  }
}

// ============================================================
// EMPTY FARM VIEW
// ============================================================

class _EmptyFarmView extends StatelessWidget {
  const _EmptyFarmView({
    required this.onAskAi,
  });

  final VoidCallback onAskAi;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(
              Icons.agriculture_outlined,
              size: 76,
            ),
            const SizedBox(height: 20),
            const Text(
              'هنوز مزرعه‌ای ثبت نشده است.',
              textAlign: TextAlign.center,
              style: TextStyle(
                fontSize: 20,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 12),
            const Text(
              'اگر امکان ثبت مزرعه در سرور فعال باشد، می‌توانیم فرم ثبت را به آن متصل کنیم. فعلاً می‌توانید دربارهٔ اطلاعات موردنیاز مزرعه از ARYA AI سؤال کنید.',
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 20),
            FilledButton.icon(
              onPressed: onAskAi,
              icon: const Icon(Icons.help_outline),
              label: const Text('راهنمای ثبت مزرعه'),
            ),
          ],
        ),
      ),
    );
  }
}

// ============================================================
// AI TAB
// ============================================================

class _AiTab extends StatefulWidget {
  const _AiTab({
    required this.api,
    required this.user,
  });

  final AryaApiClient api;
  final Map<String, dynamic>? user;

  @override
  State<_AiTab> createState() => _AiTabState();
}

class _AiTabState extends State<_AiTab> {
  final TextEditingController _controller = TextEditingController();
  final ScrollController _scrollController = ScrollController();

  final List<_AiMessage> _messages = [];

  bool _loading = false;

  @override
  void initState() {
    super.initState();

    _messages.add(
      const _AiMessage(
        text:
            'سلام، من ARYA AgriDoctor هستم.\n\nمی‌توانم در موضوعات کشاورزی راهنمایی کنم. لطفاً سؤال خود را همراه با نام گیاه، منطقه، سن گیاه و علائم بنویسید.\n\nبرای انتخاب روش درمان، اطلاعات دقیق و در صورت امکان نتیجهٔ آزمایش یا تصویر گیاه اهمیت دارد.',
        isUser: false,
      ),
    );
  }

  @override
  void dispose() {
    _controller.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  Future<void> _ask() async {
    final question = _controller.text.trim();

    if (question.isEmpty || _loading) return;

    final userId = _readInt(widget.user?['id']);

    if (userId == null) {
      setState(() {
        _messages.add(
          const _AiMessage(
            text:
                'شناسهٔ عددی کاربر در اطلاعات حساب پیدا نشد. لطفاً اطلاعات حساب و قرارداد API بررسی شود.',
            isUser: false,
          ),
        );
      });

      _scrollToBottom();
      return;
    }

    setState(() {
      _messages.add(
        _AiMessage(
          text: question,
          isUser: true,
        ),
      );

      _controller.clear();
      _loading = true;
    });

    _scrollToBottom();

    try {
      final response = await widget.api.askAi(
        userId: userId,
        question: question,
        language: 'fa',
      );

      final answer = _extractAnswer(response);

      if (!mounted) return;

      setState(() {
        _messages.add(
          _AiMessage(
            text: answer,
            isUser: false,
          ),
        );
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;

      setState(() {
        _messages.add(
          _AiMessage(
            text: 'ارتباط با سرویس هوش مصنوعی انجام نشد.\n\n'
                '${_friendlyError(e)}\n\n'
                'اتصال اینترنت، اعتبار حساب و وضعیت سرور باید بررسی شود.',
            isUser: false,
          ),
        );
        _loading = false;
      });
    }

    _scrollToBottom();
  }

  String _extractAnswer(Map<String, dynamic> response) {
    dynamic value = response['answer'] ??
        response['response'] ??
        response['message'] ??
        response['text'];

    if (value is Map) {
      value = value['text'] ??
          value['answer'] ??
          value['content'] ??
          value.toString();
    }

    if (value is List) {
      return value.map((item) => item.toString()).join('\n');
    }

    if (value == null || value.toString().trim().isEmpty) {
      return 'پاسخ قابل‌نمایشی دریافت نشد. لطفاً دوباره تلاش کنید.';
    }

    return value.toString();
  }

  void _scrollToBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!_scrollController.hasClients) return;

      _scrollController.animateTo(
        _scrollController.position.maxScrollExtent,
        duration: const Duration(milliseconds: 250),
        curve: Curves.easeOut,
      );
    });
  }

  void _useSuggestion(String question) {
    _controller.text = question;
    _controller.selection = TextSelection.collapsed(
      offset: _controller.text.length,
    );
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Container(
          width: double.infinity,
          padding: const EdgeInsets.symmetric(
            horizontal: 16,
            vertical: 10,
          ),
          color: Theme.of(context).colorScheme.primaryContainer,
          child: const Row(
            children: [
              Icon(Icons.eco_outlined),
              SizedBox(width: 8),
              Expanded(
                child: Text(
                  'مشاورهٔ کشاورزی؛ اطلاعات منطقه و علائم را دقیق وارد کنید.',
                ),
              ),
            ],
          ),
        ),
        Expanded(
          child: ListView.builder(
            controller: _scrollController,
            padding: const EdgeInsets.all(16),
            itemCount: _messages.length,
            itemBuilder: (context, index) {
              final message = _messages[index];

              return Align(
                alignment: message.isUser
                    ? Alignment.centerRight
                    : Alignment.centerLeft,
                child: Container(
                  constraints: const BoxConstraints(maxWidth: 650),
                  margin: const EdgeInsets.only(bottom: 12),
                  padding: const EdgeInsets.all(14),
                  decoration: BoxDecoration(
                    color: message.isUser
                        ? Theme.of(context).colorScheme.primaryContainer
                        : Theme.of(context)
                            .colorScheme
                            .surfaceContainerHighest,
                    borderRadius: BorderRadius.circular(16),
                  ),
                  child: SelectableText(message.text),
                ),
              );
            },
          ),
        ),
        if (_loading)
          const Padding(
            padding: EdgeInsets.fromLTRB(16, 0, 16, 8),
            child: Row(
              children: [
                SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(strokeWidth: 2),
                ),
                SizedBox(width: 10),
                Text('ARYA در حال بررسی سؤال است...'),
              ],
            ),
          ),
        if (_messages.length <= 1)
          SizedBox(
            height: 44,
            child: ListView(
              scrollDirection: Axis.horizontal,
              padding: const EdgeInsets.symmetric(horizontal: 8),
              children: [
                _SuggestionChip(
                  label: 'تشخیص بیماری گیاه',
                  onTap: () => _useSuggestion(
                    'علائم بیماری گیاه من چیست و برای تشخیص دقیق چه اطلاعاتی لازم است؟',
                  ),
                ),
                _SuggestionChip(
                  label: 'برنامه آبیاری',
                  onTap: () => _useSuggestion(
                    'برای تعیین برنامه آبیاری چه اطلاعاتی از محصول، خاک و آب‌وهوا لازم است؟',
                  ),
                ),
                _SuggestionChip(
                  label: 'خاک و کود',
                  onTap: () => _useSuggestion(
                    'برای تعیین نیاز کودی محصول چه اطلاعاتی لازم است؟',
                  ),
                ),
              ],
            ),
          ),
        SafeArea(
          top: false,
          child: Padding(
            padding: const EdgeInsets.fromLTRB(12, 8, 12, 12),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.end,
              children: [
                Expanded(
                  child: TextField(
                    controller: _controller,
                    minLines: 1,
                    maxLines: 5,
                    textInputAction: TextInputAction.newline,
                    decoration: const InputDecoration(
                      hintText: 'سؤال کشاورزی خود را بنویسید...',
                    ),
                  ),
                ),
                const SizedBox(width: 8),
                IconButton.filled(
                  tooltip: 'ارسال سؤال',
                  onPressed: _loading ? null : _ask,
                  icon: const Icon(Icons.send),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }
}

// ============================================================
// AI MESSAGE
// ============================================================

class _AiMessage {
  const _AiMessage({
    required this.text,
    required this.isUser,
  });

  final String text;
  final bool isUser;
}

// ============================================================
// SUPPORT TAB
// ============================================================

class _SupportTab extends StatelessWidget {
  const _SupportTab({
    required this.api,
  });

  final AryaApiClient api;

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: ListTile(
            leading: const CircleAvatar(
              child: Icon(Icons.support_agent),
            ),
            title: const Text(
              'پشتیبانی ARYA',
              style: TextStyle(fontWeight: FontWeight.bold),
            ),
            subtitle: const Text(
              'برای شروع، مشکل یا سؤال خود را از طریق دستیار هوشمند مطرح کنید.',
            ),
            trailing: const Icon(Icons.arrow_forward_ios),
            onTap: () {
              _showInfo(
                context,
                'پشتیبانی ARYA',
                'برای دریافت راهنمایی فوری، از تب ARYA AI استفاده کنید. اتصال به سامانهٔ تیکت پشتیبانی به API مربوطه نیاز دارد.',
              );
            },
          ),
        ),
        Card(
          child: ListTile(
            leading: const Icon(Icons.language),
            title: const Text('زبان برنامه'),
            subtitle: const Text(
              'زبان فعلی: فارسی',
            ),
            onTap: () {
              _showInfo(
                context,
                'زبان برنامه',
                'در این نسخه زبان رابط فارسی است. انتخاب زبان‌های دیگر به پیاده‌سازی ترجمهٔ رابط کاربری و تنظیم زبان در API نیاز دارد.',
              );
            },
          ),
        ),
        Card(
          child: ListTile(
            leading: const Icon(Icons.feedback_outlined),
            title: const Text('ارسال پیشنهاد یا مشکل'),
            subtitle: const Text(
              'ثبت توضیحات برای بررسی تیم فنی',
            ),
            onTap: () {
              Navigator.of(context).push(
                MaterialPageRoute(
                  builder: (_) => AryaFeedbackPage(api: api),
                ),
              );
            },
          ),
        ),
        Card(
          child: ListTile(
            leading: const Icon(Icons.fact_check_outlined),
            title: const Text('مرکز کنترل کیفیت'),
            subtitle: const Text(
              'بررسی وضعیت سرویس‌ها و اتصال',
            ),
            onTap: () {
              Navigator.of(context).push(
                MaterialPageRoute(
                  builder: (_) => AryaQualityPage(
                    baseUrl: api.baseUrl,
                  ),
                ),
              );
            },
          ),
        ),
        Card(
          child: ListTile(
            leading: const Icon(Icons.help_outline),
            title: const Text('راهنمای استفاده'),
            subtitle: const Text(
              'اطلاعات لازم برای دریافت پاسخ دقیق‌تر',
            ),
            onTap: () {
              _showInfo(
                context,
                'راهنمای استفاده',
                'برای سؤال کشاورزی، این موارد را بنویسید:\n\n'
                    '۱. نام محصول یا درخت\n'
                    '۲. استان، شهر یا روستا\n'
                    '۳. سن و مرحلهٔ رشد گیاه\n'
                    '۴. علائم و زمان شروع مشکل\n'
                    '۵. وضعیت خاک، آب و آبیاری\n'
                    '۶. کود یا سم مصرف‌شده\n'
                    '۷. نتیجهٔ آزمایش خاک یا آب، در صورت وجود\n\n'
                    'برای تصمیم‌های حساس، نتیجهٔ آزمایش و نظر متخصص محلی را نیز در نظر بگیرید.',
              );
            },
          ),
        ),
        const SizedBox(height: 12),
        const Card(
          child: Padding(
            padding: EdgeInsets.all(16),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Icon(Icons.privacy_tip_outlined),
                SizedBox(width: 12),
                Expanded(
                  child: Text(
                    'رمز عبور و اطلاعات محرمانه را در متن سؤال یا گزارش مشکل ارسال نکنید.',
                  ),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }
}

// ============================================================
// FEEDBACK PAGE
// ============================================================

class AryaFeedbackPage extends StatefulWidget {
  const AryaFeedbackPage({
    super.key,
    required this.api,
  });

  final AryaApiClient api;

  @override
  State<AryaFeedbackPage> createState() => _AryaFeedbackPageState();
}

class _AryaFeedbackPageState extends State<AryaFeedbackPage> {
  final _messageController = TextEditingController();

  String _category = 'مشکل فنی';

  @override
  void dispose() {
    _messageController.dispose();
    super.dispose();
  }

  void _submit() {
    final message = _messageController.text.trim();

    if (message.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('لطفاً توضیحات را وارد کنید.'),
        ),
      );
      return;
    }

    // این صفحه فعلاً اطلاعات را در رابط کاربری دریافت می‌کند.
    // ارسال واقعی باید پس از تطبیق با endpoint بازخورد در API انجام شود.
    showDialog<void>(
      context: context,
      builder: (dialogContext) {
        return AlertDialog(
          title: const Text('گزارش آماده است'),
          content: const Text(
            'فرم شما تکمیل شد، اما ارسال به سرور هنوز به اتصال endpoint بازخورد نیاز دارد.',
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(dialogContext).pop(),
              child: const Text('متوجه شدم'),
            ),
          ],
        );
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('پیشنهاد و گزارش مشکل'),
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          const Text(
            'نوع گزارش',
            style: TextStyle(fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 8),
          DropdownButtonFormField<String>(
            initialValue: selectedValue,
            decoration: const InputDecoration(
              prefixIcon: Icon(Icons.category_outlined),
            ),
            items: const [
              DropdownMenuItem(
                value: 'مشکل فنی',
                child: Text('مشکل فنی'),
              ),
              DropdownMenuItem(
                value: 'پیشنهاد',
                child: Text('پیشنهاد'),
              ),
              DropdownMenuItem(
                value: 'مشکل پاسخ هوش مصنوعی',
                child: Text('مشکل پاسخ هوش مصنوعی'),
              ),
              DropdownMenuItem(
                value: 'مشکل حساب کاربری',
                child: Text('مشکل حساب کاربری'),
              ),
            ],
            onChanged: (value) {
              if (value == null) return;
              setState(() {
                _category = value;
              });
            },
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _messageController,
            minLines: 5,
            maxLines: 10,
            maxLength: 3000,
            decoration: const InputDecoration(
              labelText: 'توضیحات',
              hintText: 'مشکل یا پیشنهاد خود را شرح دهید...',
              alignLabelWithHint: true,
            ),
          ),
          const SizedBox(height: 16),
          FilledButton.icon(
            onPressed: _submit,
            icon: const Icon(Icons.send),
            label: const Text('ثبت گزارش'),
          ),
        ],
      ),
    );
  }
}

// ============================================================
// ACCOUNT PAGE
// ============================================================

class AryaAccountPage extends StatelessWidget {
  const AryaAccountPage({
    super.key,
    required this.user,
    required this.onLogout,
  });

  final Map<String, dynamic>? user;
  final Future<void> Function() onLogout;

  @override
  Widget build(BuildContext context) {
    final id = user?['id']?.toString() ??
        user?['user_id']?.toString() ??
        '';

    final name = user?['name']?.toString() ?? '';
    final email = user?['email']?.toString() ?? '';
    final phone = user?['phone']?.toString() ?? '';
    final role = user?['role']?.toString() ??
        user?['account_type']?.toString() ??
        'کاربر';

    return Scaffold(
      appBar: AppBar(
        title: const Text('حساب کاربری'),
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          const SizedBox(height: 12),
          const CircleAvatar(
            radius: 44,
            child: Icon(Icons.person, size: 46),
          ),
          const SizedBox(height: 16),
          Text(
            name.isEmpty ? 'حساب ARYA' : name,
            textAlign: TextAlign.center,
            style: const TextStyle(
              fontSize: 22,
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 6),
          Text(
            email,
            textAlign: TextAlign.center,
            textDirection: TextDirection.ltr,
          ),
          const SizedBox(height: 20),
          Card(
            child: Column(
              children: [
                _AccountInfoTile(
                  icon: Icons.badge_outlined,
                  title: 'شناسه کاربر',
                  value: id.isEmpty ? 'دریافت نشده' : id,
                ),
                const Divider(height: 1),
                _AccountInfoTile(
                  icon: Icons.person_outline,
                  title: 'نام',
                  value: name.isEmpty ? 'ثبت نشده' : name,
                ),
                const Divider(height: 1),
                _AccountInfoTile(
                  icon: Icons.email_outlined,
                  title: 'ایمیل',
                  value: email.isEmpty ? 'ثبت نشده' : email,
                ),
                const Divider(height: 1),
                _AccountInfoTile(
                  icon: Icons.phone_outlined,
                  title: 'تلفن',
                  value: phone.isEmpty ? 'ثبت نشده' : phone,
                ),
                const Divider(height: 1),
                _AccountInfoTile(
                  icon: Icons.security_outlined,
                  title: 'نوع حساب',
                  value: role,
                ),
              ],
            ),
          ),
          const SizedBox(height: 20),
          OutlinedButton.icon(
            onPressed: () {
              _showInfo(
                context,
                'امنیت حساب',
                'برای تغییر رمز عبور یا بازیابی حساب، باید مسیرهای واقعی مربوط به مدیریت رمز عبور در API متصل شوند.',
              );
            },
            icon: const Icon(Icons.lock_reset_outlined),
            label: const Text('راهنمای بازیابی حساب'),
          ),
          const SizedBox(height: 12),
          FilledButton.icon(
            style: FilledButton.styleFrom(
              backgroundColor: Theme.of(context).colorScheme.error,
              foregroundColor: Theme.of(context).colorScheme.onError,
            ),
            onPressed: () async {
              final confirmed = await showDialog<bool>(
                context: context,
                builder: (dialogContext) {
                  return AlertDialog(
                    title: const Text('خروج از حساب'),
                    content: const Text(
                      'آیا می‌خواهید از حساب کاربری خود خارج شوید؟',
                    ),
                    actions: [
                      TextButton(
                        onPressed: () {
                          Navigator.of(dialogContext).pop(false);
                        },
                        child: const Text('انصراف'),
                      ),
                      FilledButton(
                        onPressed: () {
                          Navigator.of(dialogContext).pop(true);
                        },
                        child: const Text('خروج'),
                      ),
                    ],
                  );
                },
              );

              if (confirmed != true || !context.mounted) return;

              await onLogout();

              if (context.mounted) {
                Navigator.of(context).pop();
              }
            },
            icon: const Icon(Icons.logout),
            label: const Text('خروج از حساب'),
          ),
        ],
      ),
    );
  }
}

// ============================================================
// REUSABLE WIDGETS
// ============================================================

class _AccountInfoTile extends StatelessWidget {
  const _AccountInfoTile({
    required this.icon,
    required this.title,
    required this.value,
  });

  final IconData icon;
  final String title;
  final String value;

  @override
  Widget build(BuildContext context) {
    return ListTile(
      leading: Icon(icon),
      title: Text(title),
      subtitle: SelectableText(value),
    );
  }
}

class _ModuleCard extends StatelessWidget {
  const _ModuleCard({
    required this.icon,
    required this.title,
    required this.description,
    required this.onTap,
  });

  final IconData icon;
  final String title;
  final String description;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: ListTile(
        contentPadding: const EdgeInsets.all(14),
        leading: CircleAvatar(
          backgroundColor:
              Theme.of(context).colorScheme.primaryContainer,
          child: Icon(
            icon,
            color: Theme.of(context).colorScheme.primary,
          ),
        ),
        title: Text(
          title,
          style: const TextStyle(fontWeight: FontWeight.bold),
        ),
        subtitle: Padding(
          padding: const EdgeInsets.only(top: 4),
          child: Text(description),
        ),
        trailing: const Icon(Icons.chevron_left),
        onTap: onTap,
      ),
    );
  }
}

class _SuggestionChip extends StatelessWidget {
  const _SuggestionChip({
    required this.label,
    required this.onTap,
  });

  final String label;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 4),
      child: ActionChip(
        label: Text(label),
        onPressed: onTap,
      ),
    );
  }
}

class _ErrorPanel extends StatelessWidget {
  const _ErrorPanel({
    required this.message,
  });

  final String message;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.errorContainer,
        borderRadius: BorderRadius.circular(12),
      ),
      child: SelectableText(
        message,
        textAlign: TextAlign.center,
        style: TextStyle(
          color: Theme.of(context).colorScheme.onErrorContainer,
        ),
      ),
    );
  }
}

class _StateMessage extends StatelessWidget {
  const _StateMessage({
    required this.icon,
    required this.title,
    required this.message,
    this.actionLabel,
    this.onAction,
  });

  final IconData icon;
  final String title;
  final String message;
  final String? actionLabel;
  final VoidCallback? onAction;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(icon, size: 64),
            const SizedBox(height: 16),
            Text(
              title,
              textAlign: TextAlign.center,
              style: const TextStyle(
                fontSize: 20,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 12),
            SelectableText(
              message,
              textAlign: TextAlign.center,
            ),
            if (onAction != null && actionLabel != null) ...[
              const SizedBox(height: 20),
              FilledButton.icon(
                onPressed: onAction,
                icon: const Icon(Icons.refresh),
                label: Text(actionLabel!),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

// ============================================================
// HELPERS
// ============================================================

int? _readInt(dynamic value) {
  if (value is int) return value;
  if (value is num) return value.toInt();
  if (value is String) return int.tryParse(value.trim());
  return null;
}

String? _firstNonEmpty(
  Map<String, dynamic> data,
  List<String> keys,
) {
  for (final key in keys) {
    final value = data[key]?.toString().trim();

    if (value != null && value.isNotEmpty) {
      return value;
    }
  }

  return null;
}

String _friendlyError(Object error) {
  final text = error.toString();

  if (text.contains('SocketException') ||
      text.contains('Failed host lookup') ||
      text.contains('Connection refused')) {
    return 'اتصال به سرور برقرار نشد. اینترنت و آدرس سرور را بررسی کنید.';
  }

  if (text.contains('TimeoutException') ||
      text.toLowerCase().contains('timeout')) {
    return 'پاسخ سرور دیر رسید. چند لحظه بعد دوباره تلاش کنید.';
  }

  if (text.contains('401')) {
    return 'ورود یا اعتبار حساب تأیید نشد. دوباره وارد شوید.';
  }

  if (text.contains('403')) {
    return 'دسترسی به این بخش مجاز نیست.';
  }

  if (text.contains('404')) {
    return 'مسیر درخواست در سرور پیدا نشد.';
  }

  if (text.contains('422')) {
    return 'اطلاعات ارسال‌شده با قالب مورد انتظار سرور سازگار نیست.';
  }

  if (text.contains('429')) {
    return 'تعداد درخواست‌ها زیاد است. کمی بعد دوباره تلاش کنید.';
  }

  if (text.contains('500') ||
      text.contains('502') ||
      text.contains('503') ||
      text.contains('504')) {
    return 'سرویس سرور موقتاً با مشکل روبه‌رو شده است.';
  }

  return text;
}

void _showInfo(
  BuildContext context,
  String title,
  String message,
) {
  showDialog<void>(
    context: context,
    builder: (dialogContext) {
      return AlertDialog(
        title: Text(title),
        content: SingleChildScrollView(
          child: SelectableText(message),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(),
            child: const Text('بستن'),
          ),
        ],
      );
    },
  );
}
