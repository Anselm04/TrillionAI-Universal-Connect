import 'dart:convert';

import 'package:http/http.dart' as http;

class ConnectionApiException implements Exception {
  const ConnectionApiException(this.message);
  final String message;
  @override
  String toString() => message;
}

class ConnectionApi {
  ConnectionApi({
    required this.baseUri,
    required this.accessToken,
    http.Client? client,
  }) : _client = client ?? http.Client();

  final Uri baseUri;
  final Future<String> Function() accessToken;
  final http.Client _client;

  Uri _endpoint(String connectionId, String suffix) {
    if (baseUri.scheme != 'https' ||
        baseUri.hasQuery ||
        baseUri.hasFragment ||
        baseUri.path != '/') {
      throw const ConnectionApiException('HTTPS API origin required');
    }
    return baseUri.resolve('/connections/$connectionId$suffix');
  }

  Future<Map<String, dynamic>> _request({
    required String method,
    required String connectionId,
    required String tenantId,
    required String suffix,
    Map<String, dynamic>? body,
  }) async {
    final token = await accessToken();
    if (token.isEmpty) {
      throw const ConnectionApiException('Sign in before connecting an account.');
    }
    final uri = _endpoint(connectionId, suffix);
    late http.Response response;
    try {
      final headers = {
        'authorization': 'Bearer $token',
        'x-organisation-id': tenantId,
        'accept': 'application/json',
        if (body != null) 'content-type': 'application/json',
      };
      final request = http.Request(method, uri)
        ..headers.addAll(headers);
      if (body != null) request.body = jsonEncode(body);
      final streamed = await _client.send(request);
      response = await http.Response.fromStream(streamed);
    } catch (_) {
      throw const ConnectionApiException('Connection service unavailable.');
    }
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw ConnectionApiException(
        response.statusCode == 403
            ? 'Identity, consent, organization or connection authorization denied.'
            : 'Connection service returned HTTP ${response.statusCode}.',
      );
    }
    try {
      final data = jsonDecode(response.body);
      if (data is Map<String, dynamic>) return data;
    } catch (_) {
      // Do not include untrusted server response or secret fields in errors.
    }
    throw const ConnectionApiException('Invalid connection response.');
  }

  Future<Uri> start(String tenantId, String connectionId, String permission) async {
    final result = await _request(
      method: 'POST',
      tenantId: tenantId,
      connectionId: connectionId,
      suffix: '/start',
      body: {'consent': true, 'requestedAccess': permission},
    );
    final value = result['authorizationUrl'];
    if (value is! String) {
      throw const ConnectionApiException('Provider authorization URL missing.');
    }
    return Uri.parse(value);
  }

  Future<void> complete(String tenantId, String connectionId, String state, String code) async {
    final result = await _request(
      method: 'POST',
      tenantId: tenantId,
      connectionId: connectionId,
      suffix: '/complete',
      body: {'state': state, 'code': code},
    );
    if (result['connected'] != true) {
      throw const ConnectionApiException('Provider did not confirm connection.');
    }
  }

  Future<bool> disconnect(String tenantId, String connectionId) async {
    final result = await _request(
      method: 'DELETE',
      tenantId: tenantId,
      connectionId: connectionId,
      suffix: '',
    );
    return result['disconnected'] == true;
  }

  void close() => _client.close();
}
