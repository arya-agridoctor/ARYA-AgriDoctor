import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

/// ARYA AgriDoctor - Quality Center
///
/// هدف:
/// - بررسی سلامت ارتباط با Backend
/// - بررسی نشست کاربر
/// - تشخیص خطاهای HTTP و JSON
/// - بررسی دسترسی به مسیرهای اصلی
/// - ارائه گزارش ساختاریافته
/// - عدم ثبت رمز عبور و توکن در گزارش‌ها
///
/// نکته:
/// این ماژول آزمون تشخیصی است؛ وجود یک endpoint را فقط
/// با پاسخ واقعی سرور می‌توان تأیید کرد.

enum AryaCheckStatus {
  passed,
  failed,
  skipped,
  needsAuthentication,
  notImplemented,
}

enum AryaCheckCategory {
  configuration,
  connectivity,
  authentication,
  registration,
  farm,
  artificialIntelligence,
  imageAnalysis,
  weather,
  agriculturalData,
  payments,
  support,
  security,
  general,
}

class AryaCheckResult {
  const AryaCheckResult({
    required this.id,
    required this.title,
    required this.category,
    required this.status,
    required this.message,
    this.httpStatus,
    this.duration,
    this.recommendation,
  });

  final String id;
  final String title;
  final AryaCheckCategory category;
  final AryaCheckStatus status;
  final String message;
  final int? httpStatus;
  final Duration? duration;
  final String? recommendation;

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'title': title,
      'category': category.name,
      'status': status.name,
      'message': message,
      if (httpStatus != null) 'http_status': httpStatus,
      if (duration != null)
        'duration_ms': duration!.inMilliseconds,
      if (recommendation != null)
        'recommendation': recommendation,
    };
  }
}

class AryaQualityReport {
  const AryaQualityReport({
    required this.startedAt,
    required this.finishedAt,
    required this.results,
  });

  final DateTime startedAt;
  final DateTime finishedAt;
  final List<AryaCheckResult> results;

  int get passedCount => results
      .where((r) => r.status == AryaCheckStatus.passed)
      .length;

  int get failedCount => results
      .where((r) => r.status == AryaCheckStatus.failed)
      .length;

  int get skippedCount => results
      .where((r) =>
          r.status == AryaCheckStatus.skipped ||
          r.status == AryaCheckStatus.notImplemented)
      .length;

  int get authenticationRequiredCount => results
      .where(
        (r) => r.status == AryaCheckStatus.needsAuthentication,
      )
      .length;

  bool get hasFailures => failedCount > 0;

  Map<String, dynamic> toJson() {
    return {
      'application': 'ARYA AgriDoctor',
      'report_version': 1,
      'started_at': startedAt.toUtc().toIso8601String(),
      'finished_at': finishedAt.toUtc().toIso8601String(),
      'duration_ms':
          finishedAt.difference(startedAt).inMilliseconds,
      'summary': {
        'total': results.length,
        'passed': passedCount,
        'failed': failedCount,
        'skipped': skippedCount,
        'needs_authentication': authenticationRequiredCount,
      },
      'results': results.map((r) => r.toJson()).toList(),
    };
  }

  String toPrettyJson() {
    return const JsonEncoder.withIndent('  ').convert(toJson());
  }
}

typedef AryaProgressCallback = void Function(
  AryaCheckResult result,
);

class AryaQualityCenter {
  AryaQualityCenter({
    required this.baseUrl,
    http.Client? client,
    this.timeout = const Duration(seconds: 15),
  }) : _client = client ?? http.Client();

  final String baseUrl;
  final http.Client _client;
  final Duration timeout;

  static const String _tokenKey = 'arya_access_token';

  static const Map<String, String> _safeGetEndpoints = {
    'health': '/health',
    'pricing': '/pricing',
    'farms': '/farms',
    'weather': '/weather',
    'subscriptions': '/subscriptions',
    'support': '/support',
    'recommendations': '/recommendations',
  };

  bool get isConfigured {
    final uri = Uri.tryParse(baseUrl);

    return uri != null &&
        (uri.scheme == 'https' || uri.scheme == 'http') &&
        uri.host.isNotEmpty &&
        uri.userInfo.isEmpty;
  }

  Uri _uri(String path) {
    if (!isConfigured) {
      throw StateError('Backend URL is invalid.');
    }

    final base = Uri.parse(baseUrl);
    final normalizedPath =
        path.startsWith('/') ? path : '/$path';

    final basePath = base.path.replaceFirst(
      RegExp(r'/+$'),
      '',
    );

    return base.replace(
      path: '$basePath$normalizedPath',
      query: null,
      fragment: null,
    );
  }

  Future<String?> _readToken() async {
    final prefs = await SharedPreferences.getInstance();
    final token = prefs.getString(_tokenKey);

    if (token == null || token.trim().isEmpty) {
      return null;
    }

    return token.trim();
  }

  Future<Map<String, String>> _headers({
    bool authenticated = false,
  }) async {
    final headers = <String, String>{
      'Accept': 'application/json',
    };

    if (authenticated) {
      final token = await _readToken();

      if (token != null) {
        headers['Authorization'] = 'Bearer $token';
      }
    }

    return headers;
  }

  AryaCheckResult _result({
    required String id,
    required String title,
    required AryaCheckCategory category,
    required AryaCheckStatus status,
    required String message,
    int? httpStatus,
    Duration? duration,
    String? recommendation,
  }) {
    return AryaCheckResult(
      id: id,
      title: title,
      category: category,
      status: status,
      message: message,
      httpStatus: httpStatus,
      duration: duration,
      recommendation: recommendation,
    );
  }

  Future<AryaCheckResult> _checkConfiguration() async {
    if (!isConfigured) {
      return _result(
        id: 'configuration.backend_url',
        title: 'Backend URL',
        category: AryaCheckCategory.configuration,
        status: AryaCheckStatus.failed,
        message: 'نشانی سرور معتبر نیست.',
        recommendation:
            'نشانی Backend را در تنظیمات برنامه بررسی کنید.',
      );
    }

    return _result(
      id: 'configuration.backend_url',
      title: 'Backend URL',
      category: AryaCheckCategory.configuration,
      status: AryaCheckStatus.passed,
      message: 'ساختار نشانی سرور معتبر است.',
    );
  }

  Future<AryaCheckResult> _checkTokenStorage() async {
    try {
      final token = await _readToken();

      return _result(
        id: 'authentication.token_storage',
        title: 'ذخیره نشست',
        category: AryaCheckCategory.authentication,
        status: token == null
            ? AryaCheckStatus.skipped
            : AryaCheckStatus.passed,
        message: token == null
            ? 'توکنی ذخیره نشده است؛ کاربر احتمالاً وارد نشده.'
            : 'یک توکن در فضای محلی موجود است.',
        recommendation: token == null
            ? 'برای بررسی نشست، ابتدا وارد حساب شوید.'
            : 'اعتبار توکن هنوز در این مرحله تأیید نشده است.',
      );
    } catch (_) {
      return _result(
        id: 'authentication.token_storage',
        title: 'ذخیره نشست',
        category: AryaCheckCategory.authentication,
        status: AryaCheckStatus.failed,
        message: 'خواندن وضعیت نشست با خطا مواجه شد.',
        recommendation:
            'تنظیمات ذخیره‌سازی محلی برنامه را بررسی کنید.',
      );
    }
  }

  Future<AryaCheckResult> _checkHealth() async {
    final stopwatch = Stopwatch()..start();

    try {
      final response = await _client
          .get(
            _uri('/health'),
            headers: await _headers(),
          )
          .timeout(timeout);

      stopwatch.stop();

      dynamic data;

      try {
        data = jsonDecode(
          utf8.decode(response.bodyBytes),
        );
      } catch (_) {
        data = null;
      }

      if (response.statusCode >= 200 &&
          response.statusCode < 300 &&
          data is Map) {
        final isHealthy = data['ok'] == true ||
            data['status'] == 'ok' ||
            data['status'] == 'online';

        return _result(
          id: 'connectivity.backend_health',
          title: 'سلامت Backend',
          category: AryaCheckCategory.connectivity,
          status: isHealthy
              ? AryaCheckStatus.passed
              : AryaCheckStatus.failed,
          message: isHealthy
              ? 'سرور پاسخ سالم ارائه کرده است.'
              : 'سرور پاسخ داده، اما سلامت آن تأیید نشد.',
          httpStatus: response.statusCode,
          duration: stopwatch.elapsed,
          recommendation: isHealthy
              ? null
              : 'فیلدهای پاسخ مسیر /health را بررسی کنید.',
        );
      }

      return _result(
        id: 'connectivity.backend_health',
        title: 'سلامت Backend',
        category: AryaCheckCategory.connectivity,
        status: AryaCheckStatus.failed,
        message: data == null
            ? 'پاسخ سرور JSON معتبر نیست.'
            : 'سرور پاسخ مورد انتظار را ارائه نکرد.',
        httpStatus: response.statusCode,
        duration: stopwatch.elapsed,
        recommendation:
            'گزارش سلامت سرویس را در محیط استقرار بررسی کنید.',
      );
    } on TimeoutException {
      stopwatch.stop();

      return _result(
        id: 'connectivity.backend_health',
        title: 'سلامت Backend',
        category: AryaCheckCategory.connectivity,
        status: AryaCheckStatus.failed,
        message: 'مهلت انتظار برای پاسخ سرور تمام شد.',
        duration: stopwatch.elapsed,
        recommendation:
            'وضعیت سرویس، اینترنت و زمان پاسخ را بررسی کنید.',
      );
    } catch (_) {
      stopwatch.stop();

      return _result(
        id: 'connectivity.backend_health',
        title: 'سلامت Backend',
        category: AryaCheckCategory.connectivity,
        status: AryaCheckStatus.failed,
        message: 'اتصال به سرور برقرار نشد.',
        duration: stopwatch.elapsed,
        recommendation:
            'اینترنت، نشانی Backend و وضعیت سرویس را بررسی کنید.',
      );
    }
  }

  Future<AryaCheckResult> _checkEndpoint({
    required String id,
    required String title,
    required String path,
    required AryaCheckCategory category,
    required bool authenticated,
  }) async {
    final stopwatch = Stopwatch()..start();

    try {
      final token = authenticated ? await _readToken() : null;

      if (authenticated && token == null) {
        return _result(
          id: id,
          title: title,
          category: category,
          status: AryaCheckStatus.needsAuthentication,
          message: 'برای بررسی این مسیر ورود لازم است.',
          recommendation: 'ابتدا وارد حساب کاربری شوید.',
        );
      }

      final response = await _client
          .get(
            _uri(path),
            headers: await _headers(
              authenticated: authenticated,
            ),
          )
          .timeout(timeout);

      stopwatch.stop();

      if (response.statusCode >= 200 &&
          response.statusCode < 300) {
        return _result(
          id: id,
          title: title,
          category: category,
          status: AryaCheckStatus.passed,
          message: 'مسیر پاسخ موفق ارائه کرده است.',
          httpStatus: response.statusCode,
          duration: stopwatch.elapsed,
        );
      }

      if (response.statusCode == 401 ||
          response.statusCode == 403) {
        return _result(
          id: id,
          title: title,
          category: category,
          status: authenticated
              ? AryaCheckStatus.needsAuthentication
              : AryaCheckStatus.failed,
          message: response.statusCode == 401
              ? 'سرور احراز هویت را نپذیرفت.'
              : 'دسترسی به این مسیر مجاز نیست.',
          httpStatus: response.statusCode,
          duration: stopwatch.elapsed,
          recommendation:
              'توکن، نقش کاربر و مجوزهای این مسیر را بررسی کنید.',
        );
      }

      return _result(
        id: id,
        title: title,
        category: category,
        status: AryaCheckStatus.failed,
        message: 'مسیر با وضعیت HTTP ناموفق پاسخ داد.',
        httpStatus: response.statusCode,
        duration: stopwatch.elapsed,
        recommendation:
            'روش درخواست، قرارداد API و مجوزهای مسیر را بررسی کنید.',
      );
    } on TimeoutException {
      stopwatch.stop();

      return _result(
        id: id,
        title: title,
        category: category,
        status: AryaCheckStatus.failed,
        message: 'مهلت درخواست به پایان رسید.',
        duration: stopwatch.elapsed,
        recommendation:
            'زمان پاسخ سرور و اتصال اینترنت را بررسی کنید.',
      );
    } catch (_) {
      stopwatch.stop();

      return _result(
        id: id,
        title: title,
        category: category,
        status: AryaCheckStatus.failed,
        message: 'بررسی مسیر انجام نشد.',
        duration: stopwatch.elapsed,
        recommendation:
            'نشانی مسیر و اتصال به Backend را بررسی کنید.',
      );
    }
  }

  /// بررسی مستقل و غیرمخرب.
  ///
  /// این متد درخواست POST، ثبت‌نام، پرداخت یا حذف داده اجرا نمی‌کند.
  /// مسیرهای GET باید با API واقعی پروژه مطابقت داشته باشند.
  Future<AryaQualityReport> runDiagnostics({
    AryaProgressCallback? onProgress,
  }) async {
    final startedAt = DateTime.now();
    final results = <AryaCheckResult>[];

    Future<void> add(Future<AryaCheckResult> future) async {
      final result = await future;
      results.add(result);
      onProgress?.call(result);
    }

    await add(_checkConfiguration());

    if (!isConfigured) {
      results.addAll([
        _result(
          id: 'connectivity.backend_health',
          title: 'سلامت Backend',
          category: AryaCheckCategory.connectivity,
          status: AryaCheckStatus.skipped,
          message: 'به علت نامعتبر بودن URL بررسی نشد.',
        ),
        _result(
          id: 'general.api_endpoints',
          title: 'مسیرهای API',
          category: AryaCheckCategory.general,
          status: AryaCheckStatus.skipped,
          message: 'به علت نامعتبر بودن URL بررسی نشد.',
        ),
      ]);

      return AryaQualityReport(
        startedAt: startedAt,
        finishedAt: DateTime.now(),
        results: List.unmodifiable(results),
      );
    }

    await add(_checkHealth());
    await add(_checkTokenStorage());

    final endpoints = <({
      String id,
      String title,
      String path,
      AryaCheckCategory category,
      bool authenticated,
    })>[
      (
        id: 'registration.register_endpoint',
        title: 'مسیر ثبت‌نام',
        path: '/auth/register',
        category: AryaCheckCategory.registration,
        authenticated: false,
      ),
      (
        id: 'authentication.me_endpoint',
        title: 'اطلاعات حساب کاربری',
        path: '/auth/me',
        category: AryaCheckCategory.authentication,
        authenticated: true,
      ),
      (
        id: 'farm.list_endpoint',
        title: 'فهرست مزارع',
        path: '/farms',
        category: AryaCheckCategory.farm,
        authenticated: true,
      ),
      (
        id: 'ai.recommendations_endpoint',
        title: 'توصیه‌های کشاورزی',
        path: '/recommendations',
        category: AryaCheckCategory.artificialIntelligence,
        authenticated: true,
      ),
      (
        id: 'weather.endpoint',
        title: 'آب‌وهوا',
        path: '/weather',
        category: AryaCheckCategory.weather,
        authenticated: true,
      ),
      (
        id: 'payments.pricing_endpoint',
        title: 'تعرفه‌ها',
        path: '/pricing',
        category: AryaCheckCategory.payments,
        authenticated: false,
      ),
      (
        id: 'payments.subscription_endpoint',
        title: 'اشتراک',
        path: '/subscriptions',
        category: AryaCheckCategory.payments,
        authenticated: true,
      ),
    ];

    for (final endpoint in endpoints) {
      await add(
        _checkEndpoint(
          id: endpoint.id,
          title: endpoint.title,
          path: endpoint.path,
          category: endpoint.category,
          authenticated: endpoint.authenticated,
        ),
      );
    }

    // مواردی که با GET ساده قابل تأیید نیستند.
    // تا زمان اتصال آزمون اختصاصی، بررسی‌نشده می‌مانند.
    const unverifiedFeatures = <({
      String id,
      String title,
      AryaCheckCategory category,
      String message,
    })>[
      (
        id: 'ai.answer_quality',
        title: 'کیفیت پاسخ هوش مصنوعی',
        category: AryaCheckCategory.artificialIntelligence,
        message:
            'نیازمند آزمون واقعی پرسش و ارزیابی پاسخ است.',
      ),
      (
        id: 'image.analysis',
        title: 'تحلیل تصویر گیاه',
        category: AryaCheckCategory.imageAnalysis,
        message:
            'نیازمند آزمون آپلود تصویر و دریافت تحلیل است.',
      ),
      (
        id: 'agriculture.soil_water',
        title: 'اطلاعات خاک و آب',
        category: AryaCheckCategory.agriculturalData,
        message:
            'نیازمند آزمون ثبت و بازیابی اطلاعات است.',
      ),
      (
        id: 'payments.transaction',
        title: 'پرداخت واقعی',
        category: AryaCheckCategory.payments,
        message:
            'نیازمند آزمون امن چرخه پرداخت در محیط آزمایشی است.',
      ),
      (
        id: 'support.workflow',
        title: 'گردش کار پشتیبانی',
        category: AryaCheckCategory.support,
        message:
            'نیازمند آزمون ثبت پیام و دریافت پاسخ است.',
      ),
      (
        id: 'security.authorization',
        title: 'کنترل دسترسی سمت سرور',
        category: AryaCheckCategory.security,
        message:
            'نیازمند آزمون نقش‌ها و مجوزها در Backend است.',
      ),
    ];

    for (final feature in unverifiedFeatures) {
      results.add(
        _result(
          id: feature.id,
          title: feature.title,
          category: feature.category,
          status: AryaCheckStatus.notImplemented,
          message: feature.message,
          recommendation:
              'برای این قابلیت آزمون اختصاصی اضافه کنید.',
        ),
      );
    }

    return AryaQualityReport(
      startedAt: startedAt,
      finishedAt: DateTime.now(),
      results: List.unmodifiable(results),
    );
  }

  void dispose() {
    _client.close();
  }
}
