import 'dart:convert';

import 'package:http/http.dart' as http;

class AryaApiClient {
  AryaApiClient({
    String? baseUrl,
  }) : baseUrl = (baseUrl ??
            const String.fromEnvironment(
              'ARYA_API_URL',
              defaultValue: 'https://arya-agridoctor.onrender.com',
            ))
            .trim()
            .replaceAll(RegExp(r'/$'), '');

  final String baseUrl;

  String? _token;

  bool get isConfigured => baseUrl.isNotEmpty;

  void setToken(String? token) {
    _token = token;
  }

  Map<String, String> _headers({
    bool authenticated = false,
  }) {
    final headers = <String, String>{
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    };

    if (authenticated && _token != null && _token!.isNotEmpty) {
      headers['Authorization'] = 'Bearer $_token';
    }

    return headers;
  }

  Future<Map<String, dynamic>> get(
    String path, {
    Map<String, String>? queryParameters,
    bool authenticated = false,
  }) async {
    _ensureConfigured();

    final uri = Uri.parse('$baseUrl$path').replace(
      queryParameters: queryParameters,
    );

    final response = await http
        .get(
          uri,
          headers: _headers(authenticated: authenticated),
        )
        .timeout(const Duration(seconds: 60));

    return _decode(response);
  }

  Future<Map<String, dynamic>> post(
    String path, {
    Map<String, dynamic>? body,
    bool authenticated = false,
  }) async {
    _ensureConfigured();

    final uri = Uri.parse('$baseUrl$path');

    final response = await http
        .post(
          uri,
          headers: _headers(authenticated: authenticated),
          body: jsonEncode(body ?? <String, dynamic>{}),
        )
        .timeout(const Duration(seconds: 90));

    return _decode(response);
  }

  Future<Map<String, dynamic>> health() async {
    try {
      return await get('/health');
    } catch (e) {
      return {
        'ok': false,
        'configured': isConfigured,
        'message': 'Could not connect to ARYA Backend.',
        'error': e.toString(),
      };
    }
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

  void _ensureConfigured() {
    if (!isConfigured) {
      throw StateError(
        'ARYA Backend URL is not configured.',
      );
    }
  }

  Map<String, dynamic> _decode(
    http.Response response,
  ) {
    dynamic decoded;

    try {
      decoded = jsonDecode(response.body);
    } catch (_) {
      decoded = null;
    }

    if (response.statusCode >= 200 &&
        response.statusCode < 300) {
      if (decoded is Map<String, dynamic>) {
        return decoded;
      }

      return {
        'ok': true,
        'data': decoded,
      };
    }

    String message = 'ARYA Backend request failed.';

    if (decoded is Map &&
        decoded['detail'] != null) {
      message = decoded['detail'].toString();
    } else if (decoded is Map &&
        decoded['message'] != null) {
      message = decoded['message'].toString();
    }

    return {
      'ok': false,
      'status_code': response.statusCode,
      'message': message,
    };
  }
}
