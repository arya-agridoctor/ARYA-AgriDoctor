class AryaAiRequest {
  const AryaAiRequest({
    required this.message,
    this.language = 'fa',
    this.userId,
    this.context = const <String, dynamic>{},
  });

  final String message;
  final String language;
  final int? userId;
  final Map<String, dynamic> context;

  Map<String, dynamic> toMap() {
    return {
      'message': message,
      'language': language,
      'user_id': userId,
      'context': context,
    };
  }
}

class AryaAiResponse {
  const AryaAiResponse({
    required this.ok,
    required this.answer,
    this.confidence = 0,
    this.requiresValidation = true,
    this.mode,
    this.error,
    this.sources = const <String>[],
    this.actions = const <String>[],
    this.warnings = const <String>[],
    this.rawData,
  });

  final bool ok;
  final String answer;
  final double confidence;
  final bool requiresValidation;
  final String? mode;
  final String? error;
  final List<String> sources;
  final List<String> actions;
  final List<String> warnings;
  final Map<String, dynamic>? rawData;

  factory AryaAiResponse.fromMap(
    Map<String, dynamic> data,
  ) {
    return AryaAiResponse(
      ok: data['ok'] == true,
      answer: _stringValue(
        data['answer'] ??
            data['message'] ??
            'پاسخی از ARYA AI دریافت نشد.',
      ),
      confidence: _confidence(data['confidence']),
      requiresValidation:
          data['requires_validation'] != false,
      mode: _nullableString(data['mode']),
      error: _nullableString(data['error']),
      sources: _stringList(data['sources']),
      actions: _stringList(data['actions']),
      warnings: _stringList(data['warnings']),
      rawData: Map<String, dynamic>.from(data),
    );
  }

  Map<String, dynamic> toMap() {
    return {
      'ok': ok,
      'answer': answer,
      'confidence': confidence,
      'requires_validation': requiresValidation,
      'mode': mode,
      'error': error,
      'sources': sources,
      'actions': actions,
      'warnings': warnings,
      'raw_data': rawData,
    };
  }

  static double _confidence(dynamic value) {
    if (value is num) {
      final result = value.toDouble();

      if (result < 0) {
        return 0;
      }

      if (result > 1) {
        return 1;
      }

      return result;
    }

    return 0;
  }

  static String _stringValue(dynamic value) {
    if (value == null) {
      return '';
    }

    return value.toString();
  }

  static String? _nullableString(dynamic value) {
    if (value == null) {
      return null;
    }

    final result = value.toString().trim();

    return result.isEmpty ? null : result;
  }

  static List<String> _stringList(dynamic value) {
    if (value is! List) {
      return const <String>[];
    }

    return value
        .map(
          (item) => item?.toString() ?? '',
        )
        .where(
          (item) => item.trim().isNotEmpty,
        )
        .toList();
  }
}

class AryaAiContext {
  const AryaAiContext({
    this.country,
    this.region,
    this.city,
    this.latitude,
    this.longitude,
    this.farmId,
    this.landId,
    this.crop,
    this.tree,
    this.soilData,
    this.waterData,
    this.weatherData,
    this.labData,
    this.additionalData =
        const <String, dynamic>{},
  });

  final String? country;
  final String? region;
  final String? city;
  final double? latitude;
  final double? longitude;
  final int? farmId;
  final int? landId;
  final String? crop;
  final String? tree;
  final Map<String, dynamic>? soilData;
  final Map<String, dynamic>? waterData;
  final Map<String, dynamic>? weatherData;
  final Map<String, dynamic>? labData;
  final Map<String, dynamic> additionalData;

  Map<String, dynamic> toMap() {
    return {
      'country': country,
      'region': region,
      'city': city,
      'latitude': latitude,
      'longitude': longitude,
      'farm_id': farmId,
      'land_id': landId,
      'crop': crop,
      'tree': tree,
      'soil_data': soilData,
      'water_data': waterData,
      'weather_data': weatherData,
      'lab_data': labData,
      'additional_data': additionalData,
    };
  }
}

class AryaAiAnalysis {
  const AryaAiAnalysis({
    required this.summary,
    this.confidence = 0,
    this.risks = const <String>[],
    this.options = const <String>[],
    this.recommendations = const <String>[],
    this.actionPlan = const <String>[],
    this.validationRequired = true,
  });

  final String summary;
  final double confidence;
  final List<String> risks;
  final List<String> options;
  final List<String> recommendations;
  final List<String> actionPlan;
  final bool validationRequired;

  Map<String, dynamic> toMap() {
    return {
      'summary': summary,
      'confidence': confidence,
      'risks': risks,
      'options': options,
      'recommendations': recommendations,
      'action_plan': actionPlan,
      'validation_required': validationRequired,
    };
  }
}
