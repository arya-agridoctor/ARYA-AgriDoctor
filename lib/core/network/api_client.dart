import 'dart:convert';
import 'package:http/http.dart' as http;

class ApiClient {
  // بعد از استقرار Backend، فقط این آدرس تغییر می‌کند.
  // آدرس واقعی را فعلاً وارد نمی‌کنیم.
  static const String baseUrl = '';

  static Future<Map<String, dynamic>> healthCheck() async {
    if (baseUrl.isEmpty) {
      return {
        'ok': false,
        'configured': false,
        'message': 'Backend URL is not configured yet.',
      };
    }

    try {
      final response = await http
          .get(
            Uri.parse('$baseUrl/health'),
            headers: {
              'Accept': 'application/json',
            },
          )
          .timeout(const Duration(seconds: 15));

      if (response.statusCode >= 200 && response.statusCode < 300) {
        final data = jsonDecode(response.body);

        if (data is Map<String, dynamic>) {
          return data;
        }

        return {
          'ok': true,
          'data': data,
        };
      }

      return {
        'ok': false,
        'status_code': response.statusCode,
        'message': 'Backend returned an error.',
      };
    } catch (e) {
      return {
        'ok': false,
        'message': 'Could not connect to Backend.',
        'error': e.toString(),
      };
    }
  }

  static Future<Map<String, dynamic>> get(
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
          headers: {
            'Accept': 'application/json',
          },
        )
        .timeout(const Duration(seconds: 30));

    return _decodeResponse(response);
  }

  static Future<Map<String, dynamic>> post(
    String path, {
    Map<String, dynamic>? body,
  }) async {
    _ensureConfigured();

    final uri = Uri.parse('$baseUrl$path');

    final response = await http
        .post(
          uri,
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
          },
          body: jsonEncode(body ?? {}),
        )
        .timeout(const Duration(seconds: 30));

    return _decodeResponse(response);
  }

  static Map<String, dynamic> _decodeResponse(
    http.Response response,
  ) {
    dynamic decoded;

    try {
      decoded = jsonDecode(response.body);
    } catch (_) {
      decoded = null;
    }

    if (response.statusCode >= 200 && response.statusCode < 300) {
      if (decoded is Map<String, dynamic>) {
        return decoded;
      }

      return {
        'ok': true,
        'data': decoded,
      };
    }

    return {
      'ok': false,
      'status_code': response.statusCode,
      'message': decoded is Map && decoded['detail'] != null
          ? decoded['detail'].toString()
          : 'Request failed.',
    };
  }

  static void _ensureConfigured() {
    if (baseUrl.isEmpty) {
      throw StateError(
        'ARYA Backend URL has not been configured yet.',
      );
    }
  }
}
