import 'package:flutter/material.dart';

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
  final TextEditingController _controller = TextEditingController();

  final List<_AiMessage> _messages = [
    const _AiMessage(
      text:
          'سلام، من ARYA AI هستم. '
          'هسته هوش مصنوعی کشاورزی ARYA برای تحلیل مزرعه، خاک، آب، '
          'هوا، محصول، آفات، بیماری‌ها، تغذیه، آبیاری و اقتصاد طراحی شده‌ام.',
      isUser: false,
    ),
  ];

  bool _isProcessing = false;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Future<void> _sendMessage() async {
    final text = _controller.text.trim();

    if (text.isEmpty || _isProcessing) {
      return;
    }

    setState(() {
      _messages.add(
        _AiMessage(
          text: text,
          isUser: true,
        ),
      );
      _controller.clear();
      _isProcessing = true;
    });

    await Future<void>.delayed(
      const Duration(milliseconds: 500),
    );

    if (!mounted) {
      return;
    }

    setState(() {
      _messages.add(
        _AiMessage(
          text: _localAgriculturalResponse(text),
          isUser: false,
        ),
      );
      _isProcessing = false;
    });
  }

  String _localAgriculturalResponse(String text) {
    final value = text.toLowerCase();

    if (value.contains('زرد') ||
        value.contains('زردی') ||
        value.contains('برگ')) {
      return 'برای تشخیص دقیق زردی یا تغییر رنگ برگ، '
          'ARYA AI باید اطلاعات گیاه، سن، مرحله رشد، آبیاری، '
          'نوع خاک، شرایط آب‌وهوا و در صورت امکان تصویر برگ را بررسی کند.';
    }

    if (value.contains('آبیاری') ||
        value.contains('آب')) {
      return 'برای پیشنهاد آبیاری، نوع گیاه، مرحله رشد، '
          'بافت خاک، دمای هوا، رطوبت، بارندگی و روش آبیاری باید بررسی شود.';
    }

    if (value.contains('کود') ||
        value.contains('کوددهی')) {
      return 'برای توصیه کودی، اطلاعات آزمایش خاک و در صورت نیاز آب، '
          'نوع محصول، مرحله رشد و هدف تولید باید بررسی شود.';
    }

    if (value.contains('سم') ||
        value.contains('آفت') ||
        value.contains('بیماری')) {
      return 'برای تشخیص آفت یا بیماری، تصویر، علائم، محصول، '
          'مرحله رشد، شرایط آب‌وهوایی و سابقه تیمارها اهمیت دارد. '
          'توصیه نهایی باید پس از اعتبارسنجی اطلاعات ارائه شود.';
    }

    return 'درخواست شما دریافت شد. برای تحلیل دقیق‌تر، '
        'ARYA AI اطلاعات موردنیاز را جمع‌آوری و اعتبارسنجی می‌کند '
        'و سپس نتیجه، میزان اطمینان و گزینه‌های پیشنهادی را ارائه خواهد کرد.';
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('ARYA AI'),
        centerTitle: true,
        actions: [
          IconButton(
            tooltip: 'اطلاعات هسته',
            onPressed: () {
              showAboutDialog(
                context: context,
                applicationName: 'ARYA AI',
                applicationVersion: '1.0.0',
                applicationLegalese:
                    'ARYA AgriDoctor Commercial Agricultural Intelligence',
              );
            },
            icon: const Icon(Icons.info_outline),
          ),
        ],
      ),
      body: Column(
        children: [
          _buildStatusCard(),
          Expanded(
            child: ListView.builder(
              padding: const EdgeInsets.fromLTRB(
                12,
                4,
                12,
                12,
              ),
              itemCount: _messages.length,
              itemBuilder: (context, index) {
                return _MessageBubble(
                  message: _messages[index],
                );
              },
            ),
          ),
          _buildInputArea(),
        ],
      ),
    );
  }

  Widget _buildStatusCard() {
    return Container(
      width: double.infinity,
      margin: const EdgeInsets.fromLTRB(
        12,
        12,
        12,
        8,
      ),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(18),
        border: Border.all(
          color: Colors.green.withValues(alpha: 0.15),
        ),
      ),
      child: Row(
        children: [
          CircleAvatar(
            backgroundColor: Colors.green.shade100,
            child: Icon(
              Icons.psychology,
              color: Colors.green.shade800,
            ),
          ),
          const SizedBox(width: 12),
          const Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'هسته ARYA AI',
                  style: TextStyle(
                    fontWeight: FontWeight.bold,
                  ),
                ),
                SizedBox(height: 3),
                Text(
                  'آماده دریافت اطلاعات کشاورزی',
                  style: TextStyle(
                    fontSize: 12,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildInputArea() {
    return SafeArea(
      top: false,
      child: Container(
        padding: const EdgeInsets.fromLTRB(
          10,
          8,
          10,
          10,
        ),
        decoration: BoxDecoration(
          color: Colors.white,
          boxShadow: [
            BoxShadow(
              blurRadius: 8,
              color: Colors.black.withValues(alpha: 0.06),
            ),
          ],
        ),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.end,
          children: [
            IconButton(
              tooltip: 'ورودی تصویر',
              onPressed: () {
                _showComingSoon(
                  'ورودی تصویر برای تحلیل گیاه، برگ، آفت و بیماری '
                  'در هسته کامل ARYA AI فعال خواهد شد.',
                );
              },
              icon: const Icon(Icons.camera_alt_outlined),
            ),
            IconButton(
              tooltip: 'ورودی صوت',
              onPressed: () {
                _showComingSoon(
                  'ورودی صوتی و تبدیل گفتار به درخواست کشاورزی '
                  'در نسخه کامل ARYA AI فعال خواهد شد.',
                );
              },
              icon: const Icon(Icons.mic_none),
            ),
            Expanded(
              child: TextField(
                controller: _controller,
                minLines: 1,
                maxLines: 4,
                textInputAction: TextInputAction.send,
                onSubmitted: (_) => _sendMessage(),
                decoration: InputDecoration(
                  hintText: 'سؤال کشاورزی خود را بنویسید...',
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(18),
                  ),
                  filled: true,
                ),
              ),
            ),
            const SizedBox(width: 6),
            IconButton.filled(
              tooltip: 'ارسال',
              onPressed: _isProcessing ? null : _sendMessage,
              icon: _isProcessing
                  ? const SizedBox(
                      width: 20,
                      height: 20,
                      child: CircularProgressIndicator(
                        strokeWidth: 2,
                      ),
                    )
                  : const Icon(Icons.send),
            ),
          ],
        ),
      ),
    );
  }

  void _showComingSoon(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        duration: const Duration(seconds: 3),
      ),
    );
  }
}

class _AiMessage {
  final String text;
  final bool isUser;

  const _AiMessage({
    required this.text,
    required this.isUser,
  });
}

class _MessageBubble extends StatelessWidget {
  final _AiMessage message;

  const _MessageBubble({
    required this.message,
  });

  @override
  Widget build(BuildContext context) {
    final alignment = message.isUser
        ? Alignment.centerRight
        : Alignment.centerLeft;

    final background = message.isUser
        ? Colors.green.shade100
        : Colors.white;

    return Align(
      alignment: alignment,
      child: Container(
        constraints: const BoxConstraints(
          maxWidth: 360,
        ),
        margin: const EdgeInsets.symmetric(
          vertical: 5,
        ),
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: background,
          borderRadius: BorderRadius.circular(18),
          border: Border.all(
            color: Colors.green.withValues(alpha: 0.10),
          ),
        ),
        child: Text(
          message.text,
          textAlign: TextAlign.right,
        ),
      ),
    );
  }
}
