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
    if (_loadingWallets) return;

    setState(() {
      _loadingWallets = true;
      _error = null;
    });

    try {
      final wallets = await PaymentService.getActiveWallets();

      if (!mounted) return;

      final validWallets = wallets.where((wallet) {
        final currency = wallet['currency']?.toString().trim();
        final network = wallet['network']?.toString().trim();
        final address = PaymentService.walletAddress(wallet);

        return currency != null &&
            currency.isNotEmpty &&
            network != null &&
            network.isNotEmpty &&
            address.isNotEmpty;
      }).toList();

      setState(() {
        _wallets = validWallets;

        final currencies = _availableCurrencies;

        if (!currencies.contains(_selectedCurrency)) {
          _selectedCurrency =
              currencies.isNotEmpty ? currencies.first : null;
        }

        final networks = _availableNetworks
            .map((wallet) => wallet['network'].toString())
            .toSet()
            .toList();

        if (!networks.contains(_selectedNetwork)) {
          _selectedNetwork =
              networks.isNotEmpty ? networks.first : null;
        }
      });
    } catch (e) {
      if (!mounted) return;

      setState(() {
        _error = 'دریافت کیف پول‌های فعال ناموفق بود: $e';
      });
    } finally {
      if (mounted) {
        setState(() {
          _loadingWallets = false;
        });
      }
    }
  }

  List<String> get _availableCurrencies {
    return _wallets
        .map((wallet) => wallet['currency']?.toString() ?? '')
        .where((currency) => currency.isNotEmpty)
        .toSet()
        .toList()
      ..sort();
  }

  List<Map<String, dynamic>> get _availableNetworks {
    if (_selectedCurrency == null) return [];

    return _wallets.where((wallet) {
      return wallet['currency']?.toString() == _selectedCurrency;
    }).toList();
  }

  List<String> get _networkNames {
    return _availableNetworks
        .map((wallet) => wallet['network']?.toString() ?? '')
        .where((network) => network.isNotEmpty)
        .toSet()
        .toList()
      ..sort();
  }

  Future<void> _createPayment() async {
    if (_creatingPayment || _checkingPayment) return;

    final amountText = _amountController.text.trim();
    final amount = double.tryParse(amountText);

    if (amountText.isEmpty || amount == null || !amount.isFinite ||
        amount <= 0) {
      _showMessage('مبلغ معتبر و بزرگ‌تر از صفر وارد کنید.');
      return;
    }

    if (_selectedCurrency == null ||
        _selectedNetwork == null) {
      _showMessage('ارز و شبکه پرداخت را انتخاب کنید.');
      return;
    }

    final walletExists = _availableNetworks.any((wallet) {
      return wallet['network']?.toString() == _selectedNetwork;
    });

    if (!walletExists) {
      _showMessage('کیف پول انتخاب‌شده معتبر نیست.');
      return;
    }

    setState(() {
      _creatingPayment = true;
      _error = null;
    });

    try {
      final payment = await PaymentService.createPaymentIntent(
        userId: widget.userId,
        currency: _selectedCurrency!,
        network: _selectedNetwork!,
        amount: amountText,
      );

      if (!mounted) return;

      if (payment['payment_id'] == null) {
        setState(() {
          _error = 'سرور شناسه پرداخت معتبری برنگرداند.';
        });
        return;
      }

      setState(() {
        _payment = payment;
      });

      _showMessage('درخواست پرداخت ایجاد شد.');
    } catch (e) {
      if (!mounted) return;

      setState(() {
        _error = 'ایجاد پرداخت ناموفق بود: $e';
      });
    } finally {
      if (mounted) {
        setState(() {
          _creatingPayment = false;
        });
      }
    }
  }

  Future<void> _refreshPayment() async {
    if (_checkingPayment || _creatingPayment) return;

    final rawPaymentId = _payment?['payment_id'];

    if (rawPaymentId == null) {
      _showMessage('شناسه پرداخت موجود نیست.');
      return;
    }

    final paymentId = int.tryParse(rawPaymentId.toString());

    if (paymentId == null) {
      _showMessage('شناسه پرداخت با قالب مورد انتظار سازگار نیست.');
      return;
    }

    setState(() {
      _checkingPayment = true;
      _error = null;
    });

    try {
      final payment =
          await PaymentService.getPaymentIntent(paymentId);

      if (!mounted) return;

      setState(() {
        _payment = payment;
      });
    } catch (e) {
      if (!mounted) return;

      setState(() {
        _error = 'بررسی وضعیت پرداخت ناموفق بود: $e';
      });
    } finally {
      if (mounted) {
        setState(() {
          _checkingPayment = false;
        });
      }
    }
  }

  void _showMessage(String message) {
    if (!mounted) return;

    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(
        SnackBar(content: Text(message)),
      );
  }

  Widget _buildPaymentForm() {
    final currencies = _availableCurrencies;
    final networks = _networkNames;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
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
              value: currencies.contains(_selectedCurrency)
                  ? _selectedCurrency
                  : null,
              isExpanded: true,
              decoration: const InputDecoration(
                labelText: 'ارز پرداخت',
                border: OutlineInputBorder(),
              ),
              items: currencies.map((currency) {
                return DropdownMenuItem<String>(
                  value: currency,
                  child: Text(currency),
                );
              }).toList(),
              onChanged: _creatingPayment || _checkingPayment
                  ? null
                  : (value) {
                      setState(() {
                        _selectedCurrency = value;

                        final matchingNetworks = _wallets
                            .where((wallet) =>
                                wallet['currency']?.toString() == value)
                            .map((wallet) =>
                                wallet['network']?.toString() ?? '')
                            .where((network) => network.isNotEmpty)
                            .toSet()
                            .toList()
                          ..sort();

                        _selectedNetwork =
                            matchingNetworks.isNotEmpty
                                ? matchingNetworks.first
                                : null;
                      });
                    },
            ),
            const SizedBox(height: 12),
            DropdownButtonFormField<String>(
              value: networks.contains(_selectedNetwork)
                  ? _selectedNetwork
                  : null,
              isExpanded: true,
              decoration: const InputDecoration(
                labelText: 'شبکه',
                border: OutlineInputBorder(),
              ),
              items: networks.map((network) {
                return DropdownMenuItem<String>(
                  value: network,
                  child: Text(network),
                );
              }).toList(),
              onChanged: _creatingPayment || _checkingPayment
                  ? null
                  : (value) {
                      setState(() {
                        _selectedNetwork = value;
                      });
                    },
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _amountController,
              enabled: !_creatingPayment && !_checkingPayment,
              keyboardType:
                  const TextInputType.numberWithOptions(decimal: true),
              decoration: const InputDecoration(
                labelText: 'مبلغ',
                hintText: 'مثلاً 10',
                helperText: 'واحد مبلغ باید با واحد مورد انتظار سرور سازگار باشد.',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 16),
            FilledButton.icon(
              onPressed: _creatingPayment ||
                      _checkingPayment ||
                      _loadingWallets ||
                      _wallets.isEmpty
                  ? null
                  : _createPayment,
              icon: _creatingPayment
                  ? const SizedBox(
                      width: 18,
                      height: 18,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.payment),
              label: Text(
                _creatingPayment ? 'در حال ایجاد پرداخت...' : 'ایجاد پرداخت',
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildPaymentDetails() {
    final payment = _payment;

    if (payment == null) return const SizedBox.shrink();

    final address = PaymentService.walletAddress(payment);
    final currency = PaymentService.currency(payment);
    final network = PaymentService.network(payment);
    final amount = PaymentService.amount(payment);
    final status = PaymentService.status(payment);
    final paymentId = payment['payment_id']?.toString() ?? '-';

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Text(
              'اطلاعات پرداخت',
              style: TextStyle(
                fontSize: 20,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 16),
            _infoRow('شناسه پرداخت', paymentId),
            _infoRow('ارز', currency),
            _infoRow('شبکه', network),
            _infoRow('مبلغ', amount),
            _infoRow('وضعیت', status),
            const SizedBox(height: 12),
            const Text(
              'آدرس کیف پول',
              style: TextStyle(fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 6),
            SelectableText(
              address.isEmpty ? 'آدرس دریافت نشد' : address,
            ),
            const SizedBox(height: 16),
            OutlinedButton.icon(
              onPressed: _checkingPayment || _creatingPayment
                  ? null
                  : _refreshPayment,
              icon: _checkingPayment
                  ? const SizedBox(
                      width: 18,
                      height: 18,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.refresh),
              label: Text(
                _checkingPayment
                    ? 'در حال بررسی...'
                    : 'بررسی وضعیت پرداخت',
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _infoRow(String title, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 5),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 100,
            child: Text(
              title,
              style: const TextStyle(fontWeight: FontWeight.bold),
            ),
          ),
          Expanded(
            child: SelectableText(value),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('پرداخت ARYA'),
      ),
      body: RefreshIndicator(
        onRefresh: _loadWallets,
        child: ListView(
          physics: const AlwaysScrollableScrollPhysics(),
          padding: const EdgeInsets.all(16),
          children: [
            if (_loadingWallets)
              const Padding(
                padding: EdgeInsets.all(24),
                child: Center(
                  child: CircularProgressIndicator(),
                ),
              ),
            if (_error != null)
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: SelectableText(
                    _error!,
                    style: const TextStyle(color: Colors.red),
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
            if (_wallets.isNotEmpty) _buildPaymentForm(),
            const SizedBox(height: 16),
            _buildPaymentDetails(),
          ],
        ),
      ),
    );
  }
}
