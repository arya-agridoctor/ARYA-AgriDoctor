import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

class ApiClient {
  ApiClient._();

  // آدرس Backend را پس از مشخص‌شدن سرور نهایی وارد کن.
  // نمونه: https://your-backend.example.com
  static const String baseUrl = '';

  static const Duration _healthTimeout = Duration(seconds: 15);
  static const Duration _requestTimeout = Duration(seconds: 30);

  static String? _accessToken;

  /// ذخیره توکن دریافتی از Backend برای درخواست‌های بعدی.
  static void setAccessToken(String? token) {
    final value = token?.trim();
    _accessToken = (value == null || value.isEmpty) ? null : value;
  }

  /// پاک‌کردن توکن هنگام خروج کاربر.
  static void clearAccessToken() {
    _accessToken = null;
  }

  /// بررسی اتصال به Backend.
  static Future<Map<String, dynamic>> healthCheck() async {
    if (!_isConfigured) {
      return {
        'ok': false,
        'configured': false,
        'message': 'Backend URL is not configured yet.',
      };
    }

    try {
      final response = await http
          .get(
            _buildUri('/health'),
            headers: _headers(),
          )
          .timeout(_healthTimeout);

      return _decodeResponse(response);
    } on TimeoutException {
      return {
        'ok': false,
        'configured': true,
        'message': 'Backend connection timed out.',
      };
    } catch (e) {
      return {
        'ok': false,
        'configured': true,
        'message': 'Could not connect to Backend.',
        'error': e.toString(),
      };
    }
  }

  /// درخواست GET.
  static Future<Map<String, dynamic>> get(
    String path, {
    Map<String, String>? queryParameters,
  }) async {
    _ensureConfigured();

    try {
      var uri = _buildUri(path);

      if (queryParameters != null && queryParameters.isNotEmpty) {
        uri = uri.replace(
          queryParameters: {
            ...uri.queryParameters,
            ...queryParameters,
          },
        );
      }

      final response = await http
          .get(uri, headers: _headers())
          .timeout(_requestTimeout);

      return _decodeResponse(response);
    } on TimeoutException {
      return _networkError('Request timed out.');
    } catch (e) {
      return _networkError('Could not complete GET request.', e);
    }
  }

  /// درخواست POST با بدنه JSON.
  static Future<Map<String, dynamic>> post(
    String path, {
    Map<String, dynamic>? body,
  }) async {
    _ensureConfigured();

    try {
      final response = await http
          .post(
            _buildUri(path),
            headers: _headers(json: true),
            body: jsonEncode(body ?? <String, dynamic>{}),
          )
          .timeout(_requestTimeout);

      return _decodeResponse(response);
    } on TimeoutException {
      return _networkError('Request timed out.');
    } catch (e) {
      return _networkError('Could not complete POST request.', e);
    }
  }

  /// ساخت URI؛ از ترکیب اشتباه اسلش‌ها جلوگیری می‌کند.
  static Uri _buildUri(String path) {
    final normalizedBase = baseUrl.trim().replaceFirst(
      RegExp(r'/+$'),
      '',
    );

    final normalizedPath = path.startsWith('/') ? path : '/$path';

    return Uri.parse('$normalizedBase$normalizedPath');
  }

  static bool get _isConfigured {
    final value = baseUrl.trim();

    if (value.isEmpty) return false;

    final uri = Uri.tryParse(value);

    return uri != null &&
        (uri.scheme == 'https' || uri.scheme == 'http') &&
        uri.host.isNotEmpty;
  }

  static void _ensureConfigured() {
    if (!_isConfigured) {
      throw StateError(
        'ARYA Backend URL is empty or invalid. '
        'Configure ApiClient.baseUrl first.',
      );
    }
  }

  /// ساخت هدرهای درخواست.
  static Map<String, String> _headers({bool json = false}) {
    final headers = <String, String>{
      'Accept': 'application/json',
    };

    if (json) {
      headers['Content-Type'] = 'application/json; charset=utf-8';
    }

    final token = _accessToken;

    if (token != null && token.isNotEmpty) {
      headers['Authorization'] = 'Bearer $token';
    }

    return headers;
  }

  /// تبدیل پاسخ سرور به Map و حفظ خطاهای HTTP.
  static Map<String, dynamic> _decodeResponse(
    http.Response response,
  ) {
    dynamic decoded;

    try {
      if (response.body.trim().isNotEmpty) {
        decoded = jsonDecode(utf8.decode(response.bodyBytes));
      }
    } catch (_) {
      decoded = null;
    }

    final success =
        response.statusCode >= 200 && response.statusCode < 300;

    if (success) {
      if (decoded is Map<String, dynamic>) {
        return {
          ...decoded,
          'status_code': response.statusCode,
        };
      }

      return {
        'ok': true,
        'status_code': response.statusCode,
        'data': decoded,
      };
    }

    String message = 'Request failed.';

    if (decoded is Map) {
      final detail = decoded['detail'] ?? decoded['message'];

      if (detail != null) {
        message = detail is String ? detail : jsonEncode(detail);
      }
    } else if (decoded is String && decoded.isNotEmpty) {
      message = decoded;
    }

    return {
      'ok': false,
      'status_code': response.statusCode,
      'message': message,
      if (decoded != null) 'data': decoded,
    };
  }

  static Map<String, dynamic> _networkError(
    String message, [
    Object? error,
  ]) {
    return {
      'ok': false,
      'message': message,
      if (error != null) 'error': error.toString(),
    };
  }
}
