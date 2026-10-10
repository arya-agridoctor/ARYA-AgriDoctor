import '../core/network/api_client.dart';
import '../arya_ai_models.dart';

class AryaAiService {
  AryaAiService({
    AryaApiClient? apiClient,
  }) : _apiClient = apiClient ?? AryaApiClient();

  final AryaApiClient _apiClient;

  Future<AryaAiResponse> ask({
    required String message,
    String language = 'fa',
    int? userId,
    AryaAiContext? context,
  }) async {
    final cleanMessage = message.trim();

    if (cleanMessage.isEmpty) {
      throw ArgumentError('پیام نمی‌تواند خالی باشد.');
    }

    final request = AryaAiRequest(
      message: cleanMessage,
      language: language,
      userId: userId,
      context: context?.toMap() ?? const <String, dynamic>{},
    );

    if (!_apiClient.isConfigured) {
      return const AryaAiResponse(
        ok: false,
        answer: 'آدرس Backend مربوط به ARYA AI تنظیم نشده است.',
        confidence: 0,
        requiresValidation: true,
        mode: 'offline',
      );
    }

    try {
      final result = await _apiClient.post(
        '/ai/ask',
        authenticated: true,
        body: {
          ...request.toMap(),
          'use_current_location': true,
          'use_global_knowledge': true,
          'use_user_provided_data': true,
          'deep_agricultural_analysis': true,
          'validate_user_information': true,
          'generate_alternatives': true,
          'generate_action_plan': true,
          'generate_schedule': true,
          'generate_alerts': true,
          'weather_analysis': true,
          'climate_analysis': true,
          'soil_analysis': true,
          'water_analysis': true,
          'crop_suitability': true,
          'pest_disease_analysis': true,
          'fertilizer_analysis': true,
          'image_analysis_ready': true,
        },
      );

      final normalized = _normalizeResponse(result);

      if (normalized['ok'] == false) {
        return AryaAiResponse(
          ok: false,
          answer: _errorMessage(normalized),
          confidence: 0,
          requiresValidation: true,
          mode: 'backend_error',
          error: normalized['error']?.toString() ??
              normalized['message']?.toString(),
        );
      }

      return AryaAiResponse.fromMap(normalized);
    } catch (e) {
      return AryaAiResponse(
        ok: false,
        answer:
            'ارتباط با هسته مرکزی ARYA AI برقرار نشد.\n'
            'اتصال اینترنت و وضعیت Backend را بررسی کنید.',
        confidence: 0,
        requiresValidation: true,
        mode: 'connection_error',
        error: e.toString(),
      );
    }
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
  }) async {
    return _apiClient.post(
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
        'deep_analysis': true,
        'weather': true,
        'climate': true,
        'crop_suitability': true,
        'alternatives': true,
        'planning': true,
        'schedule': true,
        'alerts': true,
      },
    );
  }

  Future<Map<String, dynamic>> resolveLocation({
    required String query,
    String language = 'fa',
  }) async {
    final cleanQuery = query.trim();

    if (cleanQuery.isEmpty) {
      return {
        'ok': false,
        'message': 'برای تعیین موقعیت، نام منطقه را وارد کنید.',
      };
    }

    return _apiClient.post(
      '/location/resolve',
      authenticated: true,
      body: {
        'query': cleanQuery,
        'language': language,
        'global_location_search': true,
        'validate_location': true,
      },
    );
  }

  Future<Map<String, dynamic>> weather({
    required double latitude,
    required double longitude,
  }) {
    if (latitude < -90 ||
        latitude > 90 ||
        longitude < -180 ||
        longitude > 180) {
      return Future<Map<String, dynamic>>.value({
        'ok': false,
        'message': 'مختصات جغرافیایی معتبر نیست.',
      });
    }

    return _apiClient.get(
      '/weather',
      authenticated: true,
      queryParameters: {
        'latitude': latitude.toString(),
        'longitude': longitude.toString(),
      },
    );
  }

  Future<Map<String, dynamic>> health() {
    return _apiClient.health();
  }

  bool get isBackendConfigured {
    return _apiClient.isConfigured;
  }

  String _errorMessage(Map<String, dynamic> result) {
    final message = result['message'] ??
        result['detail'] ??
        result['error'];

    if (message == null || message.toString().trim().isEmpty) {
      return 'سرور ARYA نتوانست درخواست را با موفقیت پردازش کند.';
    }

    return message.toString();
  }

  Map<String, dynamic> _normalizeResponse(
    Map<String, dynamic> result,
  ) {
    final data = result['data'];

    if (data is Map) {
      return {
        ...result,
        ...Map<String, dynamic>.from(data),
      };
    }

    return result;
  }
}
