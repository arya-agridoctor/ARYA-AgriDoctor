import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

class AryaApiClient {
  AryaApiClient({
    String? baseUrl,
    http.Client? client,
    Duration? connectTimeout,
    Duration? readTimeout,
  })  : baseUrl = _normalizeBaseUrl(
          baseUrl ??
              const String.fromEnvironment(
                'ARYA_API_URL',
                defaultValue: 'https://arya-agridoctor.onrender.com',
              ),
        ),
        _client = client ?? http.Client(),
        _connectTimeout = connectTimeout ?? const Duration(seconds: 20),
        _readTimeout = readTimeout ?? const Duration(seconds: 90);

  final String baseUrl;
  final http.Client _client;
  final Duration _connectTimeout;
  final Duration _readTimeout;

  String? _token;

  bool get isConfigured {
    final uri = Uri.tryParse(baseUrl);

    return uri != null &&
        (uri.scheme == 'https' || uri.scheme == 'http') &&
        uri.host.isNotEmpty;
  }

  String get configuredHost {
    final uri = Uri.tryParse(baseUrl);
    return uri?.host ?? '';
  }

  void setToken(String? token) {
    final cleanToken = token?.trim();
    _token = (cleanToken == null || cleanToken.isEmpty)
        ? null
        : cleanToken;
  }

  Map<String, String> _headers({
    bool authenticated = false,
  }) {
    final headers = <String, String>{
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'X-ARYA-Client': 'arya-main',
    };

    if (authenticated && _token != null) {
      headers['Authorization'] = 'Bearer $_token';
    }

    return headers;
  }

  Uri _buildUri(
    String path, {
    Map<String, String>? queryParameters,
  }) {
    _ensureConfigured();

    final normalizedPath = path.startsWith('/') ? path : '/$path';

    final baseUri = Uri.parse(baseUrl);
    final basePath = baseUri.path.replaceFirst(RegExp(r'/$'), '');
    final requestedPath = '$basePath$normalizedPath';

    final uri = baseUri.replace(
      path: requestedPath,
      query: null,
      fragment: null,
    );

    if (queryParameters == null || queryParameters.isEmpty) {
      return uri;
    }

    final mergedQuery = <String, String>{
      ...baseUri.queryParameters,
      ...queryParameters,
    };

    return uri.replace(queryParameters: mergedQuery);
  }

  Future<Map<String, dynamic>> get(
    String path, {
    Map<String, String>? queryParameters,
    bool authenticated = false,
  }) async {
    final uri = _buildUri(
      path,
      queryParameters: queryParameters,
    );

    try {
      final response = await _client
          .get(
            uri,
            headers: _headers(authenticated: authenticated),
          )
          .timeout(_readTimeout);

      return _decode(
        response,
        requestUri: uri,
      );
    } on TimeoutException {
      return _networkError(
        uri,
        'زمان پاسخ‌گویی سرور به پایان رسید.',
        code: 'timeout',
      );
    } on http.ClientException {
      return _networkError(
        uri,
        'ارتباط با سرور برقرار نشد. اتصال اینترنت و وضعیت Backend را بررسی کنید.',
        code: 'client_error',
      );
    } catch (e) {
      return _networkError(
        uri,
        'خطای غیرمنتظره هنگام ارتباط با سرور رخ داد.',
        code: 'unexpected_error',
        error: e,
      );
    }
  }

  Future<Map<String, dynamic>> post(
    String path, {
    Map<String, dynamic>? body,
    bool authenticated = false,
  }) async {
    final uri = _buildUri(path);

    try {
      final response = await _client
          .post(
            uri,
            headers: _headers(authenticated: authenticated),
            body: jsonEncode(body ?? <String, dynamic>{}),
          )
          .timeout(_readTimeout);

      return _decode(
        response,
        requestUri: uri,
      );
    } on TimeoutException {
      return _networkError(
        uri,
        'زمان پاسخ‌گویی سرور به پایان رسید.',
        code: 'timeout',
      );
    } on http.ClientException {
      return _networkError(
        uri,
        'ارتباط با سرور برقرار نشد. اتصال اینترنت و وضعیت Backend را بررسی کنید.',
        code: 'client_error',
      );
    } catch (e) {
      return _networkError(
        uri,
        'خطای غیرمنتظره هنگام ارسال درخواست رخ داد.',
        code: 'unexpected_error',
        error: e,
      );
    }
  }

  Future<Map<String, dynamic>> health() async {
    final result = await get('/health');

    return {
      ...result,
      'configured': isConfigured,
      'backend_host': configuredHost,
      'checked_at': DateTime.now().toUtc().toIso8601String(),
    };
  }

  Future<Map<String, dynamic>> login({
    required String username,
    required String password,
  }) {
    return post(
      '/auth/login',
      body: {
        'username': username,
        'password': password,
      },
    );
  }

  Future<Map<String, dynamic>> register({
    required String username,
    required String password,
    String? fullName,
    String language = 'fa',
  }) {
    return post(
      '/auth/register',
      body: {
        'username': username,
        'password': password,
        'full_name': fullName,
        'language': language,
      },
    );
  }

  Future<Map<String, dynamic>> me() {
    return get(
      '/auth/me',
      authenticated: true,
    );
  }

  Future<Map<String, dynamic>> logout() {
    return post(
      '/auth/logout',
      authenticated: true,
    );
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
    String? address,
    bool useCurrentLocation = false,
    bool useUserProvidedData = true,
    bool useGlobalKnowledge = true,
  }) {
    return post(
      '/ai/ask',
      authenticated: true,
      body: {
        'user_id': userId,
        'question': question,
        'farm_id': farmId,
        'crop': crop,
        'region': region,
        'language': language,
        'latitude': latitude,
        'longitude': longitude,
        'address': address,
        'use_current_location': useCurrentLocation,
        'use_user_provided_data': useUserProvidedData,
        'use_global_knowledge': useGlobalKnowledge,
      },
    );
  }

  Future<Map<String, dynamic>> resolveLocation({
    required String query,
    String language = 'fa',
  }) {
    return post(
      '/location/resolve',
      authenticated: true,
      body: {
        'query': query,
        'language': language,
      },
    );
  }

  Future<Map<String, dynamic>> analyzeRegion({
    required String location,
    double? latitude,
    double? longitude,
    String? crop,
    String? plant,
    String? soil,
    String? water,
    String language = 'fa',
  }) {
    return post(
      '/ai/region-analysis',
      authenticated: true,
      body: {
        'location': location,
        'latitude': latitude,
        'longitude': longitude,
        'crop': crop,
        'plant': plant,
        'soil': soil,
        'water': water,
        'language': language,
      },
    );
  }

  Future<Map<String, dynamic>> getWeather({
    required double latitude,
    required double longitude,
  }) {
    return get(
      '/weather',
      queryParameters: {
        'latitude': latitude.toString(),
        'longitude': longitude.toString(),
      },
      authenticated: true,
    );
  }

  Future<Map<String, dynamic>> getPricing() {
    return get('/pricing');
  }

  Future<Map<String, dynamic>> getSubscription({
    required int userId,
  }) {
    return get(
      '/subscriptions/$userId',
      authenticated: true,
    );
  }

  Map<String, dynamic> _decode(
    http.Response response, {
    required Uri requestUri,
  }) {
    dynamic decoded;

    try {
      decoded = jsonDecode(utf8.decode(response.bodyBytes));
    } catch (_) {
      decoded = null;
    }

    final requestInfo = <String, dynamic>{
      'request_path': requestUri.path,
      'backend_host': requestUri.host,
      'status_code': response.statusCode,
    };

    if (response.statusCode >= 200 &&
        response.statusCode < 300) {
      if (decoded is Map) {
        return {
          ...Map<String, dynamic>.from(decoded),
          ...requestInfo,
        };
      }

      return {
        'ok': true,
        'data': decoded,
        ...requestInfo,
      };
    }

    String message = 'درخواست به Backend ناموفق بود.';

    if (decoded is Map && decoded['detail'] != null) {
      message = decoded['detail'].toString();
    } else if (decoded is Map && decoded['message'] != null) {
      message = decoded['message'].toString();
    } else if (decoded is Map && decoded['error'] != null) {
      message = decoded['error'].toString();
    }

    return {
      'ok': false,
      'message': message,
      ...requestInfo,
    };
  }

  Map<String, dynamic> _networkError(
    Uri uri,
    String message, {
    required String code,
    Object? error,
  }) {
    return {
      'ok': false,
      'configured': isConfigured,
      'backend_host': uri.host,
      'request_path': uri.path,
      'error_code': code,
      'message': message,
      if (error != null) 'error': error.toString(),
    };
  }

  void _ensureConfigured() {
    if (!isConfigured) {
      throw StateError(
        'ARYA Backend URL is not configured correctly.',
      );
    }
  }

  static String _normalizeBaseUrl(String value) {
    var normalized = value.trim();

    while (normalized.endsWith('/')) {
      normalized = normalized.substring(
        0,
        normalized.length - 1,
      );
    }

    return normalized;
  }

  void dispose() {
    _client.close();
  }
}
