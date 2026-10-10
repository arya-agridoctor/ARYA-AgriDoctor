import 'dart:convert';

import '../core/network/api_client.dart';

class PaymentService {
  PaymentService._();

  /// دریافت کیف پول‌های فعال.
  static Future<List<Map<String, dynamic>>> getActiveWallets({
    String? currency,
    String? network,
  }) async {
    final result = await ApiClient.get(
      '/wallets/active',
      queryParameters: {
        if (currency != null && currency.trim().isNotEmpty)
          'currency': currency.trim(),
        if (network != null && network.trim().isNotEmpty)
          'network': network.trim(),
      },
    );

    _ensureSuccess(result, 'دریافت کیف پول‌های فعال ناموفق بود.');

    final rawWallets = result['wallets'] ?? result['data'];

    if (rawWallets is List) {
      return rawWallets
          .whereType<Map>()
          .map((item) => Map<String, dynamic>.from(item))
          .where(_isValidWallet)
          .toList();
    }

    // پشتیبانی از پاسخ‌هایی که کیف پول‌ها را داخل data برمی‌گردانند.
    if (rawWallets is Map && rawWallets['wallets'] is List) {
      return (rawWallets['wallets'] as List)
          .whereType<Map>()
          .map((item) => Map<String, dynamic>.from(item))
          .where(_isValidWallet)
          .toList();
    }

    throw Exception('قالب پاسخ کیف پول‌ها از سرور معتبر نیست.');
  }

  /// ایجاد درخواست پرداخت.
  static Future<Map<String, dynamic>> createPaymentIntent({
    int? userId,
    required String currency,
    required String network,
    required String amount,
  }) async {
    final normalizedAmount = amount.trim();
    final parsedAmount = double.tryParse(normalizedAmount);

    if (currency.trim().isEmpty) {
      throw ArgumentError('ارز پرداخت مشخص نشده است.');
    }

    if (network.trim().isEmpty) {
      throw ArgumentError('شبکه پرداخت مشخص نشده است.');
    }

    if (parsedAmount == null ||
        !parsedAmount.isFinite ||
        parsedAmount <= 0) {
      throw ArgumentError('مبلغ پرداخت معتبر نیست.');
    }

    final result = await ApiClient.post(
      '/wallets/payment-intent',
      body: {
        if (userId != null) 'user_id': userId,
        'currency': currency.trim(),
        'network': network.trim(),
        'amount': normalizedAmount,
      },
    );

    _ensureSuccess(result, 'ایجاد درخواست پرداخت ناموفق بود.');

    return _extractPayment(result);
  }

  /// دریافت آخرین وضعیت درخواست پرداخت.
  static Future<Map<String, dynamic>> getPaymentIntent(
    int paymentId,
  ) async {
    if (paymentId <= 0) {
      throw ArgumentError('شناسه پرداخت معتبر نیست.');
    }

    final result = await ApiClient.get(
      '/wallets/payment-intent/$paymentId',
    );

    _ensureSuccess(result, 'دریافت وضعیت پرداخت ناموفق بود.');

    return _extractPayment(result);
  }

  static void _ensureSuccess(
    Map<String, dynamic> result,
    String defaultMessage,
  ) {
    if (result['ok'] == false) {
      throw Exception(
        result['message']?.toString() ?? defaultMessage,
      );
    }

    final statusCode = result['status_code'];
    if (statusCode is num && statusCode >= 400) {
      throw Exception(
        result['message']?.toString() ?? defaultMessage,
      );
    }
  }

  static Map<String, dynamic> _extractPayment(
    Map<String, dynamic> result,
  ) {
    dynamic payment = result['payment'];

    if (payment == null && result['data'] is Map) {
      final data = result['data'];
      payment = data is Map && data.containsKey('payment')
          ? data['payment']
          : data;
    }

    if (payment is Map) {
      final normalized = Map<String, dynamic>.from(payment);

      if (normalized['payment_id'] == null &&
          normalized['id'] != null) {
        normalized['payment_id'] = normalized['id'];
      }

      return normalized;
    }

    // بعضی APIها خود اطلاعات پرداخت را در ریشه پاسخ می‌دهند.
    if (result['payment_id'] != null || result['id'] != null) {
      final normalized = Map<String, dynamic>.from(result);

      if (normalized['payment_id'] == null &&
          normalized['id'] != null) {
        normalized['payment_id'] = normalized['id'];
      }

      return normalized;
    }

    throw Exception('اطلاعات پرداخت در پاسخ سرور وجود ندارد.');
  }

  static bool _isValidWallet(Map<String, dynamic> wallet) {
    final currency = wallet['currency']?.toString().trim() ?? '';
    final network = wallet['network']?.toString().trim() ?? '';

    return currency.isNotEmpty && network.isNotEmpty;
  }

  static String walletAddress(Map<String, dynamic> payment) {
    return _firstValue(payment, [
      'wallet_address',
      'address',
      'payment_address',
    ]);
  }

  static String currency(Map<String, dynamic> payment) {
    return _firstValue(payment, ['currency', 'asset']);
  }

  static String network(Map<String, dynamic> payment) {
    return _firstValue(payment, ['network', 'network_name']);
  }

  static String amount(Map<String, dynamic> payment) {
    return _firstValue(payment, ['amount', 'pay_amount']);
  }

  static String status(Map<String, dynamic> payment) {
    return _firstValue(
      payment,
      ['status', 'payment_status'],
      fallback: 'unknown',
    );
  }

  static String _firstValue(
    Map<String, dynamic> data,
    List<String> keys, {
    String fallback = '',
  }) {
    for (final key in keys) {
      final value = data[key];

      if (value != null && value.toString().trim().isNotEmpty) {
        return value.toString();
      }
    }

    return fallback;
  }

  static String paymentAsJson(
    Map<String, dynamic> payment,
  ) {
    return const JsonEncoder.withIndent('  ').convert(payment);
  }
}
