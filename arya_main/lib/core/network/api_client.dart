import 'dart:convert';

import 'package:http/http.dart' as http;

class AryaApiClient {
  AryaApiClient({
    String? baseUrl,
  }) : baseUrl = (baseUrl ??
            const String.fromEnvironment(
              'ARYA_API_URL',
              defaultValue: '',
            ))
            .trim()
            .replaceAll(RegExp(r'/$'), '');

  final String baseUrl;

  bool get isConfigured => baseUrl.isNotEmpty;

  Future<Map<String, dynamic>> get(
    String path, {
    Map<String, String>? queryParameters,
  }) async {
    _ensureConfigured();

    final uri = Uri.parse('$baseUrl$path').replace(
      queryParameters: queryParameters,
    );

    final response = await http
        .get(
          uri,
          headers: const {
            'Accept': 'application/json',
          },
        )
        .timeout(
          const Duration(seconds: 30),
        );

    return _decode(response);
  }

  Future<Map<String, dynamic>> post(
    String path, {
    Map<String, dynamic>? body,
  }) async {
    _ensureConfigured();

    final uri = Uri.parse('$baseUrl$path');

    final response = await http
        .post(
          uri,
          headers: const {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
          },
          body: jsonEncode(
            body ?? <String, dynamic>{},
          ),
        )
        .timeout(
          const Duration(seconds: 60),
        );

    return _decode(response);
  }

  Future<Map<String, dynamic>> put(
    String path, {
    Map<String, dynamic>? body,
  }) async {
    _ensureConfigured();

    final uri = Uri.parse('$baseUrl$path');

    final response = await http
        .put(
          uri,
          headers: const {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
          },
          body: jsonEncode(
            body ?? <String, dynamic>{},
          ),
        )
        .timeout(
          const Duration(seconds: 60),
        );

    return _decode(response);
  }

  Future<Map<String, dynamic>> delete(
    String path, {
    Map<String, String>? queryParameters,
  }) async {
    _ensureConfigured();

    final uri = Uri.parse('$baseUrl$path').replace(
      queryParameters: queryParameters,
    );

    final response = await http
        .delete(
          uri,
          headers: const {
            'Accept': 'application/json',
          },
        )
        .timeout(
          const Duration(seconds: 30),
        );

    return _decode(response);
  }

  Future<Map<String, dynamic>> health() async {
    if (!isConfigured) {
      return {
        'ok': false,
        'configured': false,
        'message':
            'ARYA Backend URL is not configured.',
      };
    }

    try {
      return await get('/health');
    } catch (e) {
      return {
        'ok': false,
        'configured': true,
        'message':
            'Could not connect to ARYA Backend.',
        'error': e.toString(),
      };
    }
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

    String message =
        'ARYA Backend request failed.';

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
