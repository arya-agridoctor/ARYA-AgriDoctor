
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
      throw ArgumentError(
        'پیام نمی‌تواند خالی باشد.',
      );
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
        answer:
            'هسته ARYA AI آماده است، اما Backend هنوز متصل نشده است.',
        confidence: 0,
        requiresValidation: true,
        mode: 'offline',
      );
    }

    try {
      final result = await _apiClient.post(
        '/ai/ask',
        body: request.toMap(),
      );

      return AryaAiResponse.fromMap(result);
    } catch (e) {
      return AryaAiResponse(
        ok: false,
        answer:
            'ارتباط با هسته مرکزی ARYA AI برقرار نشد. '
            'لطفاً اتصال اینترنت و وضعیت سرور را بررسی کنید.',
        confidence: 0,
        requiresValidation: true,
        mode: 'connection_error',
        error: e.toString(),
      );
    }
  }

  Future<Map<String, dynamic>> health() {
    return _apiClient.health();
  }

  bool get isBackendConfigured {
    return _apiClient.isConfigured;
  }
}
