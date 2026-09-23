import 'package:flutter/material.dart';

import 'core/network/api_client.dart';

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
        appBarTheme: const AppBarTheme(
          centerTitle: true,
        ),
      ),
      home: const AryaMainHomePage(),
    );
  }
}

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
  Map<String, dynamic>? _user;
  String? _error;

  final List<String> _titles = const [
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
    setState(() {
      _loading = true;
      _error = null;
    });

    try {
      final loggedIn = await _api.isLoggedIn();

      if (!loggedIn) {
        if (!mounted) return;

        setState(() {
          _loggedIn = false;
          _loading = false;
        });

        return;
      }

      final result = await _api.me();

      if (!mounted) return;

      setState(() {
        _loggedIn = true;
        _user = result;
        _loading = false;
      });
    } catch (e) {
      await _api.clearToken();

      if (!mounted) return;

      setState(() {
        _loggedIn = false;
        _loading = false;
        _error = e.toString();
      });
    }
  }

  Future<void> _openLogin() async {
    final result = await Navigator.of(context).push<bool>(
      MaterialPageRoute(
        builder: (_) => AryaLoginPage(
          api: _api,
        ),
      ),
    );

    if (result == true) {
      await _initialize();
    }
  }

  Future<void> _logout() async {
    try {
      await _api.logout();
    } finally {
      if (!mounted) return;

      setState(() {
        _loggedIn = false;
        _user = null;
        _selectedIndex = 0;
      });
    }
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
        onRegister: _openLogin,
        error: _error,
      );
    }

    return Scaffold(
      appBar: AppBar(
        title: Text(_titles[_selectedIndex]),
        actions: [
          IconButton(
            tooltip: 'حساب کاربری',
            icon: const Icon(Icons.account_circle_outlined),
            onPressed: () {
              Navigator.of(context).push(
                MaterialPageRoute(
                  builder: (_) => AryaAccountPage(
                    user: _user,
                    onLogout: _logout,
                  ),
                ),
              );
            },
          ),
        ],
      ),
      body: IndexedStack(
        index: _selectedIndex,
        children: [
          _HomeTab(
            user: _user,
            onOpenAi: () {
              setState(() {
                _selectedIndex = 2;
              });
            },
            onOpenFarm: () {
              setState(() {
                _selectedIndex = 1;
              });
            },
          ),
          _FarmTab(
            api: _api,
            user: _user,
          ),
          _AiTab(
            api: _api,
            user: _user,
          ),
          _SupportTab(
            api: _api,
            user: _user,
          ),
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

class AryaWelcomePage extends StatelessWidget {
  const AryaWelcomePage({
    super.key,
    required this.onLogin,
    required this.onRegister,
    this.error,
  });

  final VoidCallback onLogin;
  final VoidCallback onRegister;
  final String? error;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(
                maxWidth: 500,
              ),
              child: Column(
                children: [
                  const SizedBox(height: 40),
                  CircleAvatar(
                    radius: 48,
                    backgroundColor:
                        Theme.of(context).colorScheme.primaryContainer,
                    child: Icon(
                      Icons.agriculture,
                      size: 52,
                      color: Theme.of(context).colorScheme.primary,
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
                  const SizedBox(height: 10),
                  const Text(
                    'دستیار هوشمند کشاورزی شما',
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      fontSize: 18,
                    ),
                  ),
                  const SizedBox(height: 32),
                  if (error != null)
                    Card(
                      child: Padding(
                        padding: const EdgeInsets.all(14),
                        child: Text(
                          'نیاز به ورود مجدد دارید.',
                          textAlign: TextAlign.center,
                          style: TextStyle(
                            color: Theme.of(context).colorScheme.error,
                          ),
                        ),
                      ),
                    ),
                  const SizedBox(height: 12),
                  SizedBox(
                    width: double.infinity,
                    child: FilledButton.icon(
                      onPressed: onLogin,
                      icon: const Icon(Icons.login),
                      label: const Text('ورود / ثبت‌نام'),
                    ),
                  ),
                  const SizedBox(height: 16),
                  const Text(
                    'مدیریت مزرعه، محصولات، آب، خاک، آب‌وهوا و دریافت راهنمایی هوشمند کشاورزی در یک برنامه.',
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 40),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

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
        _error = e.toString();
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
              constraints: const BoxConstraints(
                maxWidth: 500,
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const Icon(
                    Icons.lock_outline,
                    size: 64,
                  ),
                  const SizedBox(height: 24),
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
                    decoration: const InputDecoration(
                      labelText: 'ایمیل',
                      prefixIcon: Icon(Icons.email_outlined),
                      border: OutlineInputBorder(),
                    ),
                  ),
                  const SizedBox(height: 16),
                  TextField(
                    controller: _passwordController,
                    obscureText: _obscurePassword,
                    textDirection: TextDirection.ltr,
                    decoration: InputDecoration(
                      labelText: 'رمز عبور',
                      prefixIcon: const Icon(Icons.lock_outline),
                      border: const OutlineInputBorder(),
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
                  const SizedBox(height: 16),
                  if (_error != null)
                    Text(
                      _error!,
                      textAlign: TextAlign.center,
                      style: TextStyle(
                        color: Theme.of(context).colorScheme.error,
                      ),
                    ),
                  const SizedBox(height: 16),
                  SizedBox(
                    height: 52,
                    child: FilledButton(
                      onPressed: _loading ? null : _login,
                      child: _loading
                          ? const SizedBox(
                              width: 24,
                              height: 24,
                              child: CircularProgressIndicator(
                                strokeWidth: 2,
                              ),
                            )
                          : const Text('ورود'),
                    ),
                  ),
                  const SizedBox(height: 16),
                  OutlinedButton.icon(
                    onPressed: _loading
                        ? null
                        : () {
                            Navigator.of(context).push(
                              MaterialPageRoute(
                                builder: (_) => AryaRegisterPage(
                                  api: widget.api,
                                ),
                              ),
                            );
                          },
                    icon: const Icon(Icons.person_add_outlined),
                    label: const Text('ایجاد حساب جدید'),
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
  final _passwordController = TextEditingController();
  final _phoneController = TextEditingController();

  bool _loading = false;
  String? _error;

  @override
  void dispose() {
    _nameController.dispose();
    _emailController.dispose();
    _passwordController.dispose();
    _phoneController.dispose();
    super.dispose();
  }

  Future<void> _register() async {
    final email = _emailController.text.trim();
    final password = _passwordController.text;

    if (email.isEmpty || password.isEmpty) {
      setState(() {
        _error = 'ایمیل و رمز عبور الزامی است.';
      });
      return;
    }

    if (password.length < 8) {
      setState(() {
        _error = 'رمز عبور باید حداقل ۸ کاراکتر باشد.';
      });
      return;
    }

    setState(() {
      _loading = true;
      _error = null;
    });

    try {
      await widget.api.register(
        name: _nameController.text.trim(),
        email: email,
        password: password,
        phone: _phoneController.text.trim(),
        language: 'fa',
      );

      if (!mounted) return;

      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text(
            'حساب با موفقیت ایجاد شد. اکنون وارد شوید.',
          ),
        ),
      );

      Navigator.of(context).pop();
    } catch (e) {
      if (!mounted) return;

      setState(() {
        _error = e.toString();
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('ثبت‌نام'),
      ),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(
                maxWidth: 500,
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  TextField(
                    controller: _nameController,
                    decoration: const InputDecoration(
                      labelText: 'نام',
                      prefixIcon: Icon(Icons.person_outline),
                      border: OutlineInputBorder(),
                    ),
                  ),
                  const SizedBox(height: 16),
                  TextField(
                    controller: _emailController,
                    keyboardType: TextInputType.emailAddress,
                    textDirection: TextDirection.ltr,
                    decoration: const InputDecoration(
                      labelText: 'ایمیل',
                      prefixIcon: Icon(Icons.email_outlined),
                      border: OutlineInputBorder(),
                    ),
                  ),
                  const SizedBox(height: 16),
                  TextField(
                    controller: _phoneController,
                    keyboardType: TextInputType.phone,
                    decoration: const InputDecoration(
                      labelText: 'شماره تلفن',
                      prefixIcon: Icon(Icons.phone_outlined),
                      border: OutlineInputBorder(),
                    ),
                  ),
                  const SizedBox(height: 16),
                  TextField(
                    controller: _passwordController,
                    obscureText: true,
                    textDirection: TextDirection.ltr,
                    decoration: const InputDecoration(
                      labelText: 'رمز عبور',
                      prefixIcon: Icon(Icons.lock_outline),
                      border: OutlineInputBorder(),
                    ),
                  ),
                  const SizedBox(height: 8),
                  const Text(
                    'رمز عبور حداقل ۸ کاراکتر باشد.',
                  ),
                  const SizedBox(height: 16),
                  if (_error != null)
                    Text(
                      _error!,
                      textAlign: TextAlign.center,
                      style: TextStyle(
                        color: Theme.of(context).colorScheme.error,
                      ),
                    ),
                  const SizedBox(height: 16),
                  SizedBox(
                    height: 52,
                    child: FilledButton(
                      onPressed: _loading ? null : _register,
                      child: _loading
                          ? const SizedBox(
                              width: 24,
                              height: 24,
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
    final name = user?['name']?.toString();

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: Padding(
            padding: const EdgeInsets.all(20),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  name == null || name.isEmpty
                      ? 'سلام، به ARYA خوش آمدید'
                      : 'سلام $name',
                  style: const TextStyle(
                    fontSize: 23,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 8),
                const Text(
                  'دستیار هوشمند کشاورزی شما',
                  style: TextStyle(fontSize: 17),
                ),
                const SizedBox(height: 16),
                FilledButton.icon(
                  onPressed: onOpenAi,
                  icon: const Icon(Icons.smart_toy),
                  label: const Text('مشاوره با ARYA AI'),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 12),
        _ModuleCard(
          icon: Icons.location_on_outlined,
          title: 'مزرعه و زمین',
          description: 'مدیریت زمین‌ها، موقعیت و اطلاعات مزرعه',
          onTap: onOpenFarm,
        ),
        _ModuleCard(
          icon: Icons.eco_outlined,
          title: 'محصولات و درختان',
          description: 'ثبت و مدیریت محصولات، درختان و کشت',
          onTap: onOpenFarm,
        ),
        _ModuleCard(
          icon: Icons.water_drop_outlined,
          title: 'آب و آبیاری',
          description: 'مدیریت منابع آب و برنامه آبیاری',
          onTap: onOpenFarm,
        ),
        _ModuleCard(
          icon: Icons.cloud_outlined,
          title: 'آب‌وهوا',
          description: 'بررسی شرایط جوی و اقلیمی',
          onTap: onOpenFarm,
        ),
        _ModuleCard(
          icon: Icons.bug_report_outlined,
          title: 'آفات و بیماری‌ها',
          description: 'بررسی و مدیریت آفات و بیماری‌های گیاهی',
          onTap: onOpenAi,
        ),
      ],
    );
  }
}

class _FarmTab extends StatelessWidget {
  const _FarmTab({
    required this.api,
    required this.user,
  });

  final AryaApiClient api;
  final Map<String, dynamic>? user;

  @override
  Widget build(BuildContext context) {
    final userId = _readInt(user?['id']);

    if (userId == null) {
      return const Center(
        child: Text('اطلاعات کاربر هنوز آماده نیست.'),
      );
    }

    return FutureBuilder<Map<String, dynamic>>(
      future: api.get(
        '/farms/$userId',
        authenticated: true,
      ),
      builder: (context, snapshot) {
        if (snapshot.connectionState == ConnectionState.waiting) {
          return const Center(
            child: CircularProgressIndicator(),
          );
        }

        if (snapshot.hasError) {
          return Center(
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: Text(
                'دریافت اطلاعات مزرعه انجام نشد.\n\n${snapshot.error}',
                textAlign: TextAlign.center,
              ),
            ),
          );
        }

        final data = snapshot.data ?? {};
        final farms = data['farms'];

        if (farms is! List || farms.isEmpty) {
          return _EmptyFarmView(
            onAdd: () {
              _showComingSoon(
                context,
                'ثبت مزرعه در مرحله بعدی به صورت کامل فعال می‌شود.',
              );
            },
          );
        }

        return ListView(
          padding: const EdgeInsets.all(16),
          children: [
            const Text(
              'مزارع من',
              style: TextStyle(
                fontSize: 24,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 16),
            ...farms.map(
              (farm) => Card(
                child: ListTile(
                  leading: const CircleAvatar(
                    child: Icon(Icons.agriculture),
                  ),
                  title: Text(
                    farm is Map
                        ? farm['name']?.toString() ?? 'مزرعه'
                        : 'مزرعه',
                  ),
                  subtitle: Text(
                    farm is Map
                        ? farm['location']?.toString() ?? 'موقعیت ثبت نشده'
                        : '',
                  ),
                ),
              ),
            ),
          ],
        );
      },
    );
  }
}

class _EmptyFarmView extends StatelessWidget {
  const _EmptyFarmView({
    required this.onAdd,
  });

  final VoidCallback onAdd;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(
              Icons.agriculture_outlined,
              size: 72,
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
            const SizedBox(height: 10),
            const Text(
              'در مرحله بعد می‌توانید زمین و اطلاعات کشت خود را ثبت کنید.',
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 20),
            FilledButton.icon(
              onPressed: onAdd,
              icon: const Icon(Icons.add),
              label: const Text('ثبت مزرعه'),
            ),
          ],
        ),
      ),
    );
  }
}

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
  final _controller = TextEditingController();
  final _scrollController = ScrollController();

  final List<_AiMessage> _messages = [];

  bool _loading = false;

  @override
  void initState() {
    super.initState();

    _messages.add(
      const _AiMessage(
        text:
            'سلام. من ARYA AgriDoctor هستم.\nسؤال کشاورزی خود را بنویسید تا بررسی کنم.',
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
      final result = await widget.api.askAi(
        userId: userId,
        question: question,
        language: 'fa',
      );

      final answer = result['answer'] ??
          result['response'] ??
          result['message'] ??
          'پاسخی از ARYA دریافت نشد.';

      if (!mounted) return;

      setState(() {
        _messages.add(
          _AiMessage(
            text: answer.toString(),
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
            text: 'خطا در ارتباط با ARYA AI:\n$e',
            isUser: false,
          ),
        );
        _loading = false;
      });
    }

    _scrollToBottom();
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

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
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
                  constraints: const BoxConstraints(
                    maxWidth: 600,
                  ),
                  margin: const EdgeInsets.only(bottom: 12),
                  padding: const EdgeInsets.all(14),
                  decoration: BoxDecoration(
                    color: message.isUser
                        ? Theme.of(context)
                            .colorScheme
                            .primaryContainer
                        : Theme.of(context)
                            .colorScheme
                            .surfaceContainerHighest,
                    borderRadius: BorderRadius.circular(16),
                  ),
                  child: Text(message.text),
                ),
              );
            },
          ),
        ),
        if (_loading)
          const Padding(
            padding: EdgeInsets.only(
              left: 16,
              right: 16,
              bottom: 8,
            ),
            child: LinearProgressIndicator(),
          ),
        SafeArea(
          top: false,
          child: Padding(
            padding: const EdgeInsets.fromLTRB(
              12,
              8,
              12,
              12,
            ),
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
                      hintText: 'سؤال خود را بنویسید...',
                      border: OutlineInputBorder(),
                    ),
                    onSubmitted: (_) => _ask(),
                  ),
                ),
                const SizedBox(width: 8),
                IconButton.filled(
                  onPressed: _loading ? null : _ask,
                  icon: const Icon(Icons.send),
                  tooltip: 'ارسال',
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }
}

class _AiMessage {
  const _AiMessage({
    required this.text,
    required this.isUser,
  });

  final String text;
  final bool isUser;
}

class _SupportTab extends StatelessWidget {
  const _SupportTab({
    required this.api,
    required this.user,
  });

  final AryaApiClient api;
  final Map<String, dynamic>? user;

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
              style: TextStyle(
                fontWeight: FontWeight.bold,
              ),
            ),
            subtitle: const Text(
              'راهنمای استفاده و ارتباط با پشتیبانی',
            ),
            trailing: const Icon(Icons.arrow_forward_ios),
            onTap: () {
              _showComingSoon(
                context,
                'مرکز پشتیبانی کامل در مرحله بعد فعال می‌شود.',
              );
            },
          ),
        ),
        Card(
          child: ListTile(
            leading: const Icon(Icons.language),
            title: const Text('زبان برنامه'),
            subtitle: const Text('فارسی'),
            onTap: () {
              _showComingSoon(
                context,
                'انتخاب زبان‌های مختلف در مرحله چندزبانه‌سازی فعال می‌شود.',
              );
            },
          ),
        ),
        Card(
          child: ListTile(
            leading: const Icon(Icons.feedback_outlined),
            title: const Text('ارسال پیشنهاد یا مشکل'),
            subtitle: const Text(
              'ارسال بازخورد برای تیم ARYA',
            ),
            onTap: () {
              _showComingSoon(
                context,
                'سیستم بازخورد در مرحله پشتیبانی فعال می‌شود.',
              );
            },
          ),
        ),
        Card(
          child: ListTile(
            leading: const Icon(Icons.help_outline),
            title: const Text('راهنمای استفاده'),
            onTap: () {
              _showComingSoon(
                context,
                'راهنمای کامل استفاده در حال آماده‌سازی است.',
              );
            },
          ),
        ),
      ],
    );
  }
}

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
    final name = user?['name']?.toString() ?? '';
    final email = user?['email']?.toString() ?? '';
    final phone = user?['phone']?.toString() ?? '';

    return Scaffold(
      appBar: AppBar(
        title: const Text('حساب کاربری'),
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          const CircleAvatar(
            radius: 42,
            child: Icon(
              Icons.person,
              size: 42,
            ),
          ),
          const SizedBox(height: 20),
          Card(
            child: Column(
              children: [
                ListTile(
                  leading: const Icon(Icons.person_outline),
                  title: const Text('نام'),
                  subtitle: Text(
                    name.isEmpty ? 'ثبت نشده' : name,
                  ),
                ),
                ListTile(
                  leading: const Icon(Icons.email_outlined),
                  title: const Text('ایمیل'),
                  subtitle: Text(email),
                ),
                ListTile(
                  leading: const Icon(Icons.phone_outlined),
                  title: const Text('تلفن'),
                  subtitle: Text(
                    phone.isEmpty ? 'ثبت نشده' : phone,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 20),
          FilledButton.icon(
            onPressed: () async {
              final confirmed = await showDialog<bool>(
                context: context,
                builder: (context) {
                  return AlertDialog(
                    title: const Text('خروج از حساب'),
                    content: const Text(
                      'آیا می‌خواهید از حساب کاربری خارج شوید؟',
                    ),
                    actions: [
                      TextButton(
                        onPressed: () {
                          Navigator.pop(context, false);
                        },
                        child: const Text('انصراف'),
                      ),
                      FilledButton(
                        onPressed: () {
                          Navigator.pop(context, true);
                        },
                        child: const Text('خروج'),
                      ),
                    ],
                  );
                },
              );

              if (confirmed == true) {
                await onLogout();

                if (context.mounted) {
                  Navigator.pop(context);
                }
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
        onTap: onTap,
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

int? _readInt(dynamic value) {
  if (value is int) {
    return value;
  }

  return int.tryParse(
    value?.toString() ?? '',
  );
}

void _showComingSoon(
  BuildContext context,
  String message,
) {
  ScaffoldMessenger.of(context).showSnackBar(
    SnackBar(
      content: Text(message),
    ),
  );
}
