import 'package:flutter/material.dart';
import '../../core/diagnostics/arya_quality_center.dart';
class AryaQualityPage extends StatefulWidget {
  const AryaQualityPage({
    super.key,
    required this.baseUrl,
  });

  final String baseUrl;

  @override
  State<AryaQualityPage> createState() =>
      _AryaQualityPageState();
}

class _AryaQualityPageState extends State<AryaQualityPage> {
  late final AryaQualityCenter _center;

  AryaQualityReport? _report;
  bool _running = false;
  String? _error;

  @override
  void initState() {
    super.initState();

    _center = AryaQualityCenter(
      baseUrl: widget.baseUrl,
    );
  }

  Future<void> _run() async {
    setState(() {
      _running = true;
      _error = null;
      _report = null;
    });

    try {
      final report = await _center.runDiagnostics();

      if (!mounted) return;

      setState(() {
        _report = report;
      });
    } catch (_) {
      if (!mounted) return;

      setState(() {
        _error = 'بررسی برنامه با خطا مواجه شد.';
      });
    } finally {
      if (mounted) {
        setState(() {
          _running = false;
        });
      }
    }
  }

  @override
  void dispose() {
    _center.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('مرکز کنترل کیفیت ARYA'),
      ),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            SizedBox(
              width: double.infinity,
              child: FilledButton.icon(
                onPressed: _running ? null : _run,
                icon: const Icon(Icons.fact_check),
                label: Text(
                  _running
                      ? 'در حال بررسی...'
                      : 'بررسی برنامه',
                ),
              ),
            ),
            if (_error != null) ...[
              const SizedBox(height: 12),
              Text(
                _error!,
                style: const TextStyle(color: Colors.red),
              ),
            ],
            if (_report != null) ...[
              const SizedBox(height: 16),
              Text(
                'موفق: ${_report!.passedCount} | '
                'ناموفق: ${_report!.failedCount} | '
                'نیازمند ورود: '
                '${_report!.authenticationRequiredCount} | '
                'بررسی‌نشده: ${_report!.skippedCount}',
              ),
              const SizedBox(height: 12),
              Expanded(
                child: ListView.builder(
                  itemCount: _report!.results.length,
                  itemBuilder: (context, index) {
                    final item = _report!.results[index];

                    final icon = switch (item.status) {
                      AryaCheckStatus.passed =>
                        Icons.check_circle,
                      AryaCheckStatus.failed =>
                        Icons.error,
                      AryaCheckStatus.needsAuthentication =>
                        Icons.lock,
                      AryaCheckStatus.skipped =>
                        Icons.remove_circle_outline,
                      AryaCheckStatus.notImplemented =>
                        Icons.pending_actions,
                    };

                    final color = switch (item.status) {
                      AryaCheckStatus.passed => Colors.green,
                      AryaCheckStatus.failed => Colors.red,
                      AryaCheckStatus.needsAuthentication =>
                        Colors.orange,
                      AryaCheckStatus.skipped =>
                        Colors.grey,
                      AryaCheckStatus.notImplemented =>
                        Colors.blueGrey,
                    };

                    return Card(
                      child: ListTile(
                        leading: Icon(
                          icon,
                          color: color,
                        ),
                        title: Text(item.title),
                        subtitle: Text(
                          [
                            item.message,
                            if (item.httpStatus != null)
                              'HTTP: ${item.httpStatus}',
                            if (item.recommendation != null)
                              item.recommendation!,
                          ].join('\n'),
                        ),
                      ),
                    );
                  },
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
