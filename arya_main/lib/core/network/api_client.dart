import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

class AryaApiException implements Exception {
  AryaApiException({
    required this.statusCode,
    required this.message,
  });

  final int statusCode;
  final String message;

  @override
  String toString() => 'AryaApiException($statusCode): $message';
}

class AryaApiClient {
  AryaApiClient({String? baseUrl})
      : baseUrl = (baseUrl ??
                const String.fromEnvironment(
                  'ARYA_API_URL',
                  defaultValue: 'https://arya-agridoctor.onrender.com',
                ))
            .trim()
            .replaceFirst(RegExp(r'/+$'), '');

  final String baseUrl;

  static const String _tokenKey = 'arya_access_token';

  bool get isConfigured {
    final uri = Uri.tryParse(baseUrl);
    return uri != null &&
        (uri.scheme == 'https' || uri.scheme == 'http') &&
        uri.host.isNotEmpty;
  }

  Uri _buildUri(
    String path, {
    Map<String, String>? queryParameters,
  }) {
    _ensureConfigured();

    final baseUri = Uri.parse(baseUrl);
    final normalizedPath = path.startsWith('/') ? path : '/$path';

    final resolvedUri = baseUri.replace(
      path: '${baseUri.path.replaceFirst(RegExp(r'/+$'), '')}$normalizedPath',
      query: null,
      fragment: null,
    );

    final mergedQuery = <String, String>{
      ...baseUri.queryParameters,
      if (queryParameters != null) ...queryParameters,
    };

    return resolvedUri.replace(
      queryParameters: mergedQuery.isEmpty ? null : mergedQuery,
    );
  }

  Future<Map<String, String>> _headers({
    bool json = false,
    bool authenticated = true,
  }) async {
    final headers = <String, String>{
      'Accept': 'application/json',
    };

    if (json) {
      headers['Content-Type'] = 'application/json; charset=utf-8';
    }

    if (authenticated) {
      final token = await getToken();
      if (token != null && token.trim().isNotEmpty) {
        headers['Authorization'] = 'Bearer ${token.trim()}';
      }
    }

    return headers;
  }

  Future<String?> getToken() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_tokenKey);
  }

  Future<void> saveToken(String token) async {
    final normalizedToken = token.trim();

    if (normalizedToken.isEmpty) {
      throw ArgumentError.value(token, 'token', 'Token cannot be empty.');
    }

    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_tokenKey, normalizedToken);
  }

  Future<void> clearToken() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_tokenKey);
  }

  Future<bool> isLoggedIn() async {
    final token = await getToken();
    return token != null && token.trim().isNotEmpty;
  }

  Future<Map<String, dynamic>> get(
    String path, {
    Map<String, String>? queryParameters,
    bool authenticated = true,
  }) async {
    final response = await http
        .get(
          _buildUri(path, queryParameters: queryParameters),
          headers: await _headers(authenticated: authenticated),
        )
        .timeout(const Duration(seconds: 30));

    return _decode(response);
  }

  Future<Map<String, dynamic>> post(
    String path, {
    Map<String, dynamic>? body,
    bool authenticated = true,
  }) async {
    final response = await http
        .post(
          _buildUri(path),
          headers: await _headers(
            json: true,
            authenticated: authenticated,
          ),
          body: jsonEncode(body ?? <String, dynamic>{}),
        )
        .timeout(const Duration(seconds: 60));

    return _decode(response);
  }

  Future<Map<String, dynamic>> put(
    String path, {
    Map<String, dynamic>? body,
    bool authenticated = true,
  }) async {
    final response = await http
        .put(
          _buildUri(path),
          headers: await _headers(
            json: true,
            authenticated: authenticated,
          ),
          body: jsonEncode(body ?? <String, dynamic>{}),
        )
        .timeout(const Duration(seconds: 60));

    return _decode(response);
  }

  Future<Map<String, dynamic>> delete(
    String path, {
    Map<String, String>? queryParameters,
    bool authenticated = true,
  }) async {
    final response = await http
        .delete(
          _buildUri(path, queryParameters: queryParameters),
          headers: await _headers(authenticated: authenticated),
        )
        .timeout(const Duration(seconds: 30));

    return _decode(response);
  }

  Future<Map<String, dynamic>> login({
    required String email,
    required String password,
  }) async {
    final result = await post(
      '/auth/login',
      authenticated: false,
      body: {
        'email': email.trim(),
        'password': password,
      },
    );

    final token = result['access_token'];

    if (token is! String || token.trim().isEmpty) {
      throw AryaApiException(
        statusCode: 502,
        message: 'Backend did not return a valid access token.',
      );
    }

    await saveToken(token);
    return result;
  }

  /// ورود به حساب کاربری.
  ///
  /// دسترسی OWNER باید توسط بک‌اند تعیین و تأیید شود.
  /// این متد به‌تنهایی مجوز مدیریت ایجاد نمی‌کند.
  Future<Map<String, dynamic>> adminLogin({
    required String email,
    required String password,
  }) async {
    // ورود از همان مسیر امن ورود عادی انجام می‌شود.
    // نقش مدیر باید در پاسخ معتبر بک‌اند مشخص شده باشد.
    final result = await login(
      email: email,
      password: password,
    );

    final user = result['user'];
    final role = user is Map ? user['role'] : result['role'];

    if (role is! String ||
        !{'owner', 'admin', 'super_admin'}.contains(role.toLowerCase())) {
      await clearToken();
      throw AryaApiException(
        statusCode: 403,
        message: 'این حساب دسترسی مدیریت ندارد.',
      );
    }

    return result;
  }

  Future<Map<String, dynamic>> register({
    String? name,
    required String email,
    required String password,
    String? phone,
    String? country,
    String language = 'fa',
  }) async {
    return post(
      '/auth/register',
      authenticated: false,
      body: {
        'name': name?.trim() ?? '',
        'email': email.trim(),
        'password': password,
        'phone': phone?.trim() ?? '',
        'country': country?.trim() ?? '',
        'language': language,
      },
    );
  }

  Future<Map<String, dynamic>> me() async {
    return get('/auth/me');
  }

  Future<void> logout() async {
    try {
      if (await isLoggedIn()) {
        await post('/auth/logout');
      }
    } finally {
      await clearToken();
    }
  }

  Future<Map<String, dynamic>> health() async {
    if (!isConfigured) {
      return {
        'ok': false,
        'configured': false,
        'message': 'ARYA Backend URL is not configured.',
      };
    }

    try {
      final result = await get(
        '/health',
        authenticated: false,
      );

      return {
        ...result,
        'configured': true,
        'ok': result['ok'] == true,
      };
    } catch (e) {
      return {
        'ok': false,
        'configured': true,
        'message': 'Could not connect to ARYA Backend.',
        'error': e.toString(),
      };
    }
  }

  Future<Map<String, dynamic>> pricing({
    required String country,
  }) async {
    return get(
      '/pricing',
      authenticated: false,
      queryParameters: {'country': country},
    );
  }

  Future<Map<String, dynamic>> subscription(int userId) async {
    return get('/subscriptions/$userId');
  }

  Future<Map<String, dynamic>> askAi({
    required int userId,
    required String question,
    int? farmId,
    String? crop,
    String? region,
    String language = 'fa',
    double? latitude,
    double? longitude,
  }) async {
    final normalizedQuestion = question.trim();

    if (normalizedQuestion.isEmpty) {
      throw ArgumentError.value(
        question,
        'question',
        'Question cannot be empty.',
      );
    }

    if ((latitude == null) != (longitude == null)) {
      throw ArgumentError(
        'Latitude and longitude must either both be supplied or both be null.',
      );
    }

    if (latitude != null && (latitude < -90 || latitude > 90)) {
      throw ArgumentError.value(latitude, 'latitude');
    }

    if (longitude != null && (longitude < -180 || longitude > 180)) {
      throw ArgumentError.value(longitude, 'longitude');
    }

    return post(
      '/ai/ask',
      body: {
        'user_id': userId,
        'question': normalizedQuestion,
        'farm_id': farmId,
        'crop': crop,
        'region': region,
        'language': language,
        'latitude': latitude,
        'longitude': longitude,
      },
    );
  }

  /// درخواست بازیابی رمز عبور.
  ///
  /// مسیر و فیلدها باید با endpoint واقعی بک‌اند تطبیق داده شوند.
  Future<Map<String, dynamic>> requestPasswordReset({
    required String email,
  }) async {
    return post(
    '/auth/password/reset/request',
      authenticated: false,
      body: {'email': email.trim()},
    );
  }

  /// ثبت رمز جدید با توکن یک‌بارمصرف صادرشده از بک‌اند.
  Future<Map<String, dynamic>> resetPassword({
    required String token,
    required String newPassword,
  }) async {
    if (token.trim().isEmpty) {
      throw ArgumentError.value(token, 'token', 'Token cannot be empty.');
    }

    if (newPassword.length < 8) {
      throw ArgumentError.value(
        newPassword,
        'newPassword',
        'Password must contain at least 8 characters.',
      );
    }

    return post(
    '/auth/password/reset/confirm',
      authenticated: false,
      body: {
        'token': token.trim(),
        'new_password': newPassword,
      },
    );
  }

  void _ensureConfigured() {
    if (!isConfigured) {
      throw StateError(
        'ARYA Backend URL is invalid or not configured.',
      );
    }
  }

  Map<String, dynamic> _decode(http.Response response) {
    dynamic decoded;

    try {
      decoded = jsonDecode(utf8.decode(response.bodyBytes));
    } catch (_) {
      decoded = null;
    }

    if (response.statusCode >= 200 && response.statusCode < 300) {
      if (decoded is Map<String, dynamic>) {
        return decoded;
      }

      if (decoded is Map) {
        return Map<String, dynamic>.from(decoded);
      }

      return {
        'ok': true,
        'data': decoded,
      };
    }

    var message = 'ARYA Backend request failed.';

    if (decoded is Map) {
      final detail = decoded['detail'];
      final serverMessage = decoded['message'];

      if (detail is String && detail.trim().isNotEmpty) {
        message = detail;
      } else if (serverMessage is String &&
          serverMessage.trim().isNotEmpty) {
        message = serverMessage;
      } else if (detail is List) {
        message = detail.map((item) {
          if (item is Map && item['msg'] != null) {
            return item['msg'].toString();
          }
          return item.toString();
        }).join('\n');
      }
    }

    throw AryaApiException(
      statusCode: response.statusCode,
      message: message,
    );
  }
}
