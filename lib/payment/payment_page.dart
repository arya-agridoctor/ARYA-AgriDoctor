import 'package:flutter/material.dart';

import 'payment_service.dart';

class PaymentPage extends StatefulWidget {
  const PaymentPage({
    super.key,
    this.userId,
  });

  final int? userId;

  @override
  State<PaymentPage> createState() => _PaymentPageState();
}

class _PaymentPageState extends State<PaymentPage> {
  final TextEditingController _amountController =
      TextEditingController();

  List<Map<String, dynamic>> _wallets = [];

  Map<String, dynamic>? _payment;

  String? _selectedCurrency;
  String? _selectedNetwork;

  bool _loadingWallets = false;
  bool _creatingPayment = false;
  bool _checkingPayment = false;

  String? _error;

  @override
  void initState() {
    super.initState();
    _loadWallets();
  }

  @override
  void dispose() {
    _amountController.dispose();
    super.dispose();
  }

  Future<void> _loadWallets() async {
    setState(() {
      _loadingWallets = true;
      _error = null;
    });

    try {
      final wallets =
          await PaymentService.getActiveWallets();

      if (!mounted) return;

      setState(() {
        _wallets = wallets;

        if (_wallets.isNotEmpty) {
          _selectedCurrency =
              _wallets.first['currency']?.toString();

          _selectedNetwork =
              _wallets.first['network']?.toString();
        }
      });
    } catch (e) {
      if (!mounted) return;

      setState(() {
        _error = e.toString();
      });
    } finally {
      if (!mounted) return;

      setState(() {
        _loadingWallets = false;
      });
    }
  }

  List<Map<String, dynamic>> get _availableNetworks {
    if (_selectedCurrency == null) {
      return [];
    }

    return _wallets
        .where(
          (wallet) =>
              wallet['currency']?.toString() ==
              _selectedCurrency,
        )
        .toList();
  }

  Future<void> _createPayment() async {
    final amount = _amountController.text.trim();

    if (amount.isEmpty) {
      _showMessage('مبلغ پرداخت را وارد کنید.');
      return;
    }

    if (_selectedCurrency == null ||
        _selectedNetwork == null) {
      _showMessage(
        'ارز و شبکه پرداخت را انتخاب کنید.',
      );
      return;
    }

    setState(() {
      _creatingPayment = true;
      _error = null;
    });

    try {
      final payment =
          await PaymentService.createPaymentIntent(
        userId: widget.userId,
        currency: _selectedCurrency!,
        network: _selectedNetwork!,
        amount: amount,
      );

      if (!mounted) return;

      setState(() {
        _payment = payment;
      });
    } catch (e) {
      if (!mounted) return;

      setState(() {
        _error = e.toString();
      });
    } finally {
      if (!mounted) return;

      setState(() {
        _creatingPayment = false;
      });
    }
  }

  Future<void> _refreshPayment() async {
    if (_payment == null ||
        _payment!['payment_id'] == null) {
      return;
    }

    final paymentId =
        int.tryParse(
          _payment!['payment_id'].toString(),
        );

    if (paymentId == null) {
      return;
    }

    setState(() {
      _checkingPayment = true;
      _error = null;
    });

    try {
      final payment =
          await PaymentService.getPaymentIntent(
        paymentId,
      );

      if (!mounted) return;

      setState(() {
        _payment = payment;
      });
    } catch (e) {
      if (!mounted) return;

      setState(() {
        _error = e.toString();
      });
    } finally {
      if (!mounted) return;

      setState(() {
        _checkingPayment = false;
      });
    }
  }

  void _showMessage(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
      ),
    );
  }

  Widget _buildPaymentForm() {
    final currencies = _wallets
        .map(
          (wallet) =>
              wallet['currency']?.toString() ?? '',
        )
        .where(
          (currency) => currency.isNotEmpty,
        )
        .toSet()
        .toList();

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment:
              CrossAxisAlignment.stretch,
          children: [
            const Text(
              'پرداخت اشتراک',
              style: TextStyle(
                fontSize: 20,
                fontWeight: FontWeight.bold,
              ),
            ),

            const SizedBox(height: 16),

            DropdownButtonFormField<String>(
              value: currencies.contains(
                _selectedCurrency,
              )
                  ? _selectedCurrency
                  : null,
              decoration: const InputDecoration(
                labelText: 'ارز پرداخت',
                border: OutlineInputBorder(),
              ),
              items: currencies
                  .map(
                    (currency) =>
                        DropdownMenuItem<String>(
                      value: currency,
                      child: Text(currency),
                    ),
                  )
                  .toList(),
              onChanged: (value) {
                setState(() {
                  _selectedCurrency = value;

                  final matching =
                      _wallets.where(
                    (wallet) =>
                        wallet['currency']
                            ?.toString() ==
                        value,
                  );

                  _selectedNetwork =
                      matching.isNotEmpty
                          ? matching.first['network']
                              ?.toString()
                          : null;
                });
              },
            ),

            const SizedBox(height: 12),

            DropdownButtonFormField<String>(
              value: _availableNetworks.any(
                (wallet) =>
                    wallet['network']?.toString() ==
                    _selectedNetwork,
              )
                  ? _selectedNetwork
                  : null,
              decoration: const InputDecoration(
                labelText: 'شبکه',
                border: OutlineInputBorder(),
              ),
              items: _availableNetworks
                  .map(
                    (wallet) {
                      final network =
                          wallet['network']
                              ?.toString() ??
                          '';

                      return DropdownMenuItem<String>(
                        value: network,
                        child: Text(network),
                      );
                    },
                  )
                  .toList(),
              onChanged: (value) {
                setState(() {
                  _selectedNetwork = value;
                });
              },
            ),

            const SizedBox(height: 12),

            TextField(
              controller: _amountController,
              keyboardType:
                  const TextInputType.numberWithOptions(
                decimal: true,
              ),
              decoration: const InputDecoration(
                labelText: 'مبلغ',
                hintText: 'مثلاً 10',
                border: OutlineInputBorder(),
              ),
            ),

            const SizedBox(height: 16),

            FilledButton.icon(
              onPressed: _creatingPayment
                  ? null
                  : _createPayment,
              icon: _creatingPayment
                  ? const SizedBox(
                      width: 18,
                      height: 18,
                      child:
                          CircularProgressIndicator(
                        strokeWidth: 2,
                      ),
                    )
                  : const Icon(
                      Icons.payment,
                    ),
              label: const Text(
                'ایجاد پرداخت',
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildPaymentDetails() {
    if (_payment == null) {
      return const SizedBox.shrink();
    }

    final address =
        PaymentService.walletAddress(
      _payment!,
    );

    final currency =
        PaymentService.currency(
      _payment!,
    );

    final network =
        PaymentService.network(
      _payment!,
    );

    final amount =
        PaymentService.amount(
      _payment!,
    );

    final status =
        PaymentService.status(
      _payment!,
    );

    final paymentId =
        _payment!['payment_id']?.toString() ??
            '-';

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment:
              CrossAxisAlignment.stretch,
          children: [
            const Text(
              'اطلاعات پرداخت',
              style: TextStyle(
                fontSize: 20,
                fontWeight: FontWeight.bold,
              ),
            ),

            const SizedBox(height: 16),

            _infoRow(
              'شناسه پرداخت',
              paymentId,
            ),

            _infoRow(
              'ارز',
              currency,
            ),

            _infoRow(
              'شبکه',
              network,
            ),

            _infoRow(
              'مبلغ',
              amount,
            ),

            _infoRow(
              'وضعیت',
              status,
            ),

            const SizedBox(height: 12),

            const Text(
              'آدرس کیف پول',
              style: TextStyle(
                fontWeight: FontWeight.bold,
              ),
            ),

            const SizedBox(height: 6),

            SelectableText(
              address.isEmpty
                  ? 'آدرس دریافت نشد'
                  : address,
            ),

            const SizedBox(height: 16),

            OutlinedButton.icon(
              onPressed: _checkingPayment
                  ? null
                  : _refreshPayment,
              icon: _checkingPayment
                  ? const SizedBox(
                      width: 18,
                      height: 18,
                      child:
                          CircularProgressIndicator(
                        strokeWidth: 2,
                      ),
                    )
                  : const Icon(
                      Icons.refresh,
                    ),
              label: const Text(
                'بررسی وضعیت پرداخت',
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _infoRow(
    String title,
    String value,
  ) {
    return Padding(
      padding:
          const EdgeInsets.symmetric(
        vertical: 5,
      ),
      child: Row(
        crossAxisAlignment:
            CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 100,
            child: Text(
              title,
              style: const TextStyle(
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
          Expanded(
            child: Text(value),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text(
          'پرداخت ARYA',
        ),
      ),
      body: RefreshIndicator(
        onRefresh: _loadWallets,
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            if (_loadingWallets)
              const Padding(
                padding: EdgeInsets.all(24),
                child: Center(
                  child:
                      CircularProgressIndicator(),
                ),
              ),

            if (_error != null)
              Card(
                child: Padding(
                  padding:
                      const EdgeInsets.all(16),
                  child: Text(
                    _error!,
                    style: const TextStyle(
                      color: Colors.red,
                    ),
                  ),
                ),
              ),

            if (!_loadingWallets &&
                _wallets.isEmpty &&
                _error == null)
              const Card(
                child: Padding(
                  padding: EdgeInsets.all(16),
                  child: Text(
                    'در حال حاضر کیف پول فعالی برای پرداخت تنظیم نشده است.',
                  ),
                ),
              ),

            if (_wallets.isNotEmpty)
              _buildPaymentForm(),

            const SizedBox(height: 16),

            _buildPaymentDetails(),
          ],
        ),
      ),
    );
  }
}
