import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:trillionai_connect_portal/connection_api.dart';

void main() {
  test('start includes authenticated tenant, explicit consent, and scoped permission', () async {
    final calls = <http.Request>[];
    final api = ConnectionApi(
      baseUri: Uri.parse('https://app.example.com/'),
      accessToken: () async => 'verified-identity-token',
      client: MockClient((req) async {
        calls.add(req);
        return http.Response(jsonEncode({
          'authorizationUrl': 'https://github.com/login/oauth/authorize'
              '?response_type=code&state=abcdefghijklmnopqrstuvwxyz0123456789'
              '&code_challenge_method=S256',
        }), 200, headers: {'content-type': 'application/json'});
      }),
    );
    await api.start('11111111-1111-4111-8111-111111111111', 'connection_1', 'profile');
    expect(calls.single.url.path, '/connections/connection_1/start');
    expect(calls.single.method, 'POST');
    expect(calls.single.headers['authorization'], 'Bearer verified-identity-token');
    expect(calls.single.headers['x-organisation-id'], '11111111-1111-4111-8111-111111111111');
    expect(jsonDecode(calls.single.body)['consent'], true);
    expect(jsonDecode(calls.single.body)['requestedAccess'], 'profile');
    api.close();
  });
  test('complete POSTs state and code, disconnect uses DELETE', () async {
    final calls = <http.Request>[];
    final api = ConnectionApi(
      baseUri: Uri.parse('https://app.example.com/'),
      accessToken: () async => 'token',
      client: MockClient((req) async {
        calls.add(req);
        return http.Response(req.method == 'DELETE'
            ? '{"disconnected":true}' : '{"connected":true}', 200);
      }),
    );
    const tenant = '11111111-1111-4111-8111-111111111111';
    await api.complete(tenant, 'connection_1', 'state123', 'code123');
    expect(jsonDecode(calls.first.body), {'state': 'state123', 'code': 'code123'});
    expect(await api.disconnect(tenant, 'connection_1'), isTrue);
    expect(calls.last.method, 'DELETE');
    api.close();
  });
  test('failure never includes token or provider raw body in error', () async {
    final api = ConnectionApi(
      baseUri: Uri.parse('https://app.example.com/'),
      accessToken: () async => 'secret-token',
      client: MockClient((req) async => http.Response('provider-secret-raw-body', 503)),
    );
    await expectLater(
      api.start('11111111-1111-4111-8111-111111111111', 'connection_1', 'profile'),
      throwsA(predicate((e) =>
        e is ConnectionApiException &&
        !e.toString().contains('secret-token') &&
        !e.toString().contains('provider-secret-raw-body'))),
    );
    api.close();
  });
}
