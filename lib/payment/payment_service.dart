import 'dart:convert';

import '../core/network/api_client.dart';

class PaymentService {
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

    if (result['ok'] != true) {
      throw Exception(
        result['message']?.toString() ??
            'Could not load payment wallets.',
      );
    }

    final wallets = result['wallets'];

    if (wallets is! List) {
      return [];
    }

    return wallets
        .whereType<Map>()
        .map(
          (item) => Map<String, dynamic>.from(item),
        )
        .toList();
  }

  static Future<Map<String, dynamic>> createPaymentIntent({
    int? userId,
    required String currency,
    required String network,
    required String amount,
  }) async {
    final result = await ApiClient.post(
      '/wallets/payment-intent',
      body: {
        'user_id': userId,
        'currency': currency,
        'network': network,
        'amount': amount,
      },
    );

    if (result['ok'] != true) {
      throw Exception(
        result['message']?.toString() ??
            'Could not create payment intent.',
      );
    }

    final payment = result['payment'];

    if (payment is Map<String, dynamic>) {
      return payment;
    }

    if (payment is Map) {
      return Map<String, dynamic>.from(payment);
    }

    throw Exception('Invalid payment response.');
  }

  static Future<Map<String, dynamic>> getPaymentIntent(
    int paymentId,
  ) async {
    final result = await ApiClient.get(
      '/wallets/payment-intent/$paymentId',
    );

    if (result['ok'] != true) {
      throw Exception(
        result['message']?.toString() ??
            'Could not load payment information.',
      );
    }

    final payment = result['payment'];

    if (payment is Map<String, dynamic>) {
      return payment;
    }

    if (payment is Map) {
      return Map<String, dynamic>.from(payment);
    }

    throw Exception('Invalid payment response.');
  }

  static String walletAddress(
    Map<String, dynamic> payment,
  ) {
    return payment['wallet_address']?.toString() ?? '';
  }

  static String currency(
    Map<String, dynamic> payment,
  ) {
    return payment['currency']?.toString() ?? '';
  }

  static String network(
    Map<String, dynamic> payment,
  ) {
    return payment['network']?.toString() ?? '';
  }

  static String amount(
    Map<String, dynamic> payment,
  ) {
    return payment['amount']?.toString() ?? '';
  }

  static String status(
    Map<String, dynamic> payment,
  ) {
    return payment['status']?.toString() ?? 'unknown';
  }

  static String paymentAsJson(
    Map<String, dynamic> payment,
  ) {
    return const JsonEncoder.withIndent('  ').convert(payment);
  }
}
