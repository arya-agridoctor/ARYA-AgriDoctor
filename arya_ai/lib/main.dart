import 'package:flutter/material.dart';

import 'ai/arya_ai_service.dart';
import 'arya_ai_models.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const AryaAiApp());
}

class AryaAiApp extends StatelessWidget {
  const AryaAiApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'ARYA AI',
      theme: ThemeData(
        useMaterial3: true,
        colorSchemeSeed: Colors.green,
        scaffoldBackgroundColor: const Color(0xFFF5F8F5),
      ),
      home: const AryaAiHomePage(),
    );
  }
}

class AryaAiHomePage extends StatefulWidget {
  const AryaAiHomePage({super.key});

  @override
  State<AryaAiHomePage> createState() => _AryaAiHomePageState();
}

class _AryaAiHomePageState extends State<AryaAiHomePage> {
  final AryaAiService _aiService = AryaAiService();
  final TextEditingController _controller = TextEditingController();
  final ScrollController _scrollController = ScrollController();

  final List<_ChatMessage> _messages = <_ChatMessage>[
    const _ChatMessage(
      text:
          'سلام، من ARYA AI هستم.\n'
          'برای تحلیل دقیق‌تر مزرعه، محصول، خاک، آب، آب‌وهوا و آفات '
          'هرچه اطلاعات بیشتری بدهید، نتیجه دقیق‌تر خواهد بود.',
      isUser: false,
    ),
  ];

  bool _loading = false;

  @override
  void dispose() {
    _controller.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  Future<void> _askAi() async {
    final message = _controller.text.trim();

    if (message.isEmpty || _loading) {
      return;
    }

    setState(() {
      _messages.add(
        _ChatMessage(
          text: message,
          isUser: true,
        ),
      );
      _controller.clear();
      _loading = true;
    });

    _scrollToBottom();

    try {
      final response = await _aiService.ask(
        message: message,
        language: 'fa',
      );

      if (!mounted) {
        return;
      }

      setState(() {
        _messages.add(
          _ChatMessage(
            text: response.answer,
            isUser: false,
            confidence: response.confidence,
            requiresValidation: response.requiresValidation,
            mode: response.mode,
          ),
        );
        _loading = false;
      });
    } catch (e) {
      if (!mounted) {
        return;
      }

      setState(() {
        _messages.add(
          const _ChatMessage(
            text:
                'در ارتباط با سامانه ARYA خطایی رخ داد.\n'
                'لطفاً دوباره تلاش کنید.',
            isUser: false,
          ),
        );
        _loading = false;
      });
    }

    _scrollToBottom();
  }

  void _sendSuggestion(String text) {
    _controller.text = text;
    _controller.selection = TextSelection.fromPosition(
      TextPosition(
        offset: _controller.text.length,
      ),
    );
  }

  void _scrollToBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!_scrollController.hasClients) {
        return;
      }

      _scrollController.animateTo(
        _scrollController.position.maxScrollExtent,
        duration: const Duration(milliseconds: 250),
        curve: Curves.easeOut,
      );
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Row(
          children: [
            CircleAvatar(
              radius: 18,
              child: Icon(Icons.agriculture),
            ),
            SizedBox(width: 10),
            Text('ARYA AI'),
          ],
        ),
        actions: [
          IconButton(
            tooltip: 'وضعیت Backend',
            onPressed: () async {
              final result = await _aiService.health();

              if (!context.mounted) {
                return;
              }

              final message = result['ok'] == true
                  ? 'اتصال به Backend برقرار است.'
                  : result['message']?.toString() ??
                      'Backend در دسترس نیست.';

              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(
                  content: Text(message),
                ),
              );
            },
            icon: const Icon(Icons.cloud_outlined),
          ),
        ],
      ),
      body: SafeArea(
        child: Column(
          children: [
            _buildStatusBanner(),
            Expanded(
              child: ListView.builder(
                controller: _scrollController,
                padding: const EdgeInsets.all(12),
                itemCount: _messages.length,
                itemBuilder: (context, index) {
                  return _buildMessage(_messages[index]);
                },
              ),
            ),
            if (_loading) _buildLoadingIndicator(),
            _buildSuggestions(),
            _buildInputArea(),
          ],
        ),
      ),
    );
  }

  Widget _buildStatusBanner() {
    final configured = _aiService.isBackendConfigured;

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(
        horizontal: 14,
        vertical: 8,
      ),
      color: configured
          ? Colors.green.withOpacity(0.10)
          : Colors.orange.withOpacity(0.10),
      child: Row(
        children: [
          Icon(
            configured
                ? Icons.cloud_done_outlined
                : Icons.cloud_off_outlined,
            size: 19,
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              configured
                  ? 'ARYA AI متصل به Backend است.'
                  : 'حالت محلی: Backend هنوز تنظیم نشده است.',
              style: const TextStyle(fontSize: 12),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildMessage(_ChatMessage message) {
    final alignment = message.isUser
        ? Alignment.centerRight
        : Alignment.centerLeft;

    final background = message.isUser
        ? Theme.of(context).colorScheme.primaryContainer
        : Colors.white;

    return Align(
      alignment: alignment,
      child: Container(
        constraints: const BoxConstraints(maxWidth: 700),
        margin: const EdgeInsets.only(bottom: 10),
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: background,
          borderRadius: BorderRadius.circular(18),
          border: Border.all(
            color: Colors.black.withOpacity(0.06),
          ),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              message.text,
              style: const TextStyle(
                fontSize: 15,
                height: 1.55,
              ),
            ),
            if (!message.isUser &&
                (message.confidence > 0 ||
                    message.requiresValidation ||
                    message.mode != null)) ...[
              const SizedBox(height: 10),
              Wrap(
                spacing: 8,
                runSpacing: 6,
                children: [
                  if (message.confidence > 0)
                    _InfoChip(
                      icon: Icons.analytics_outlined,
                      text:
                          'اطمینان: ${(message.confidence * 100).round()}٪',
                    ),
                  if (message.requiresValidation)
                    const _InfoChip(
                      icon: Icons.warning_amber_outlined,
                      text: 'نیازمند بررسی اطلاعات',
                    ),
                  if (message.mode != null)
                    _InfoChip(
                      icon: Icons.settings_outlined,
                      text: message.mode!,
                    ),
                ],
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildLoadingIndicator() {
    return const Padding(
      padding: EdgeInsets.fromLTRB(16, 4, 16, 8),
      child: Row(
        children: [
          SizedBox(
            width: 18,
            height: 18,
            child: CircularProgressIndicator(
              strokeWidth: 2,
            ),
          ),
          SizedBox(width: 10),
          Text(
            'ARYA AI در حال تحلیل است...',
            style: TextStyle(fontSize: 12),
          ),
        ],
      ),
    );
  }

  Widget _buildSuggestions() {
    const suggestions = [
      'بررسی بیماری گیاه',
      'برنامه آبیاری',
      'بررسی خاک',
      'انتخاب محصول مناسب',
    ];

    return SizedBox(
      height: 48,
      child: ListView.separated(
        padding: const EdgeInsets.symmetric(horizontal: 12),
        scrollDirection: Axis.horizontal,
        itemCount: suggestions.length,
        separatorBuilder: (_, __) =>
            const SizedBox(width: 8),
        itemBuilder: (context, index) {
          return ActionChip(
            label: Text(suggestions[index]),
            onPressed: () {
              _sendSuggestion(suggestions[index]);
            },
          );
        },
      ),
    );
  }

  Widget _buildInputArea() {
    return Container(
      padding: const EdgeInsets.fromLTRB(10, 8, 10, 10),
      decoration: BoxDecoration(
        color: Colors.white,
        boxShadow: [
          BoxShadow(
            blurRadius: 8,
            color: Colors.black.withOpacity(0.06),
          ),
        ],
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
              decoration: InputDecoration(
                hintText: 'سؤال کشاورزی خود را بنویسید...',
                filled: true,
                fillColor: const Color(0xFFF5F7F5),
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(18),
                  borderSide: BorderSide.none,
                ),
                contentPadding:
                    const EdgeInsets.symmetric(
                  horizontal: 16,
                  vertical: 12,
                ),
              ),
              onSubmitted: (_) {
                _askAi();
              },
            ),
          ),
          const SizedBox(width: 8),
          IconButton.filled(
            tooltip: 'ارسال',
            onPressed: _loading ? null : _askAi,
            icon: const Icon(Icons.send),
          ),
        ],
      ),
    );
  }
}

class _ChatMessage {
  const _ChatMessage({
    required this.text,
    required this.isUser,
    this.confidence = 0,
    this.requiresValidation = false,
    this.mode,
  });

  final String text;
  final bool isUser;
  final double confidence;
  final bool requiresValidation;
  final String? mode;
}

class _InfoChip extends StatelessWidget {
  const _InfoChip({
    required this.icon,
    required this.text,
  });

  final IconData icon;
  final String text;

  @override
  Widget build(BuildContext context) {
    return Chip(
      avatar: Icon(
        icon,
        size: 17,
      ),
      label: Text(
        text,
        style: const TextStyle(fontSize: 11),
      ),
      visualDensity: VisualDensity.compact,
    );
  }
}
