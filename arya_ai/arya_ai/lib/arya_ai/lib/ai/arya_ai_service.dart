import '../core/network/api_client.dart';

class AryaAiService {
  AryaAiService({
    AryaApiClient? apiClient,
  }) : _apiClient = apiClient ?? AryaApiClient();

  final AryaApiClient _apiClient;

  Future<AryaAiResult> ask({
    required String message,
    String language = 'fa',
    int? userId,
    Map<String, dynamic>? context,
  }) async {
    final cleanMessage = message.trim();

    if (cleanMessage.isEmpty) {
      throw ArgumentError(
        'پیام نمی‌تواند خالی باشد.',
      );
    }

    if (!_apiClient.isConfigured) {
      return AryaAiResult(
        ok: false,
        configured: false,
        answer:
            'هسته ARYA AI آماده است، اما Backend هنوز متصل نشده است.',
        confidence: 0,
        requiresValidation: true,
      );
    }

    try {
      final result = await _apiClient.post(
        '/ai/ask',
        body: {
          'user_id': userId,
          'message': cleanMessage,
          'language': language,
          'context': context ?? <String, dynamic>{},
        },
      );

      return AryaAiResult.fromMap(result);
    } catch (e) {
      return AryaAiResult(
        ok: false,
        configured: true,
        answer:
            'ارتباط با هسته مرکزی ARYA AI برقرار نشد. '
            'لطفاً اتصال اینترنت و وضعیت سرور را بررسی کنید.',
        confidence: 0,
        requiresValidation: true,
        error: e.toString(),
      );
    }
  }

  Future<Map<String, dynamic>> health() {
    return _apiClient.health();
  }
}

class AryaAiResult {
  const AryaAiResult({
    required this.ok,
    required this.configured,
    required this.answer,
    required this.confidence,
    required this.requiresValidation,
    this.mode,
    this.error,
    this.rawData,
  });

  final bool ok;
  final bool configured;
  final String answer;
  final double confidence;
  final bool requiresValidation;
  final String? mode;
  final String? error;
  final Map<String, dynamic>? rawData;

  factory AryaAiResult.fromMap(
    Map<String, dynamic> data,
  ) {
    return AryaAiResult(
      ok: data['ok'] == true,
      configured: true,
      answer: data['answer']?.toString() ??
          data['message']?.toString() ??
          'پاسخی از هسته ARYA دریافت نشد.',
      confidence: _readConfidence(
        data['confidence'],
      ),
      requiresValidation:
          data['requires_validation'] != false,
      mode: data['mode']?.toString(),
      error: data['error']?.toString(),
      rawData: Map<String, dynamic>.from(data),
    );
  }

  static double _readConfidence(
    dynamic value,
  ) {
    if (value is num) {
      final number = value.toDouble();

      if (number < 0) {
        return 0;
      }

      if (number > 1) {
        return 1;
      }

      return number;
    }

    return 0;
  }
}
