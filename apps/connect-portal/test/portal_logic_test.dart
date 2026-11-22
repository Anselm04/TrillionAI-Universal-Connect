import 'package:flutter_test/flutter_test.dart';
import 'package:trillionai_connect_portal/portal_logic.dart';

void main() {
  const tenant = '11111111-1111-4111-8111-111111111111';
  const pending = PendingAuthorization(
    tenantId: tenant, connectionId: 'connection_1',
    state: 'AbCdEf1234567890AbCdEf1234567890AbCdEf1234',
  );
  test('pending state survives a browser authorization round trip', () {
    final restored = PendingAuthorization.decode(pending.encode());
    expect(restored?.state, pending.state);
    expect(restored?.tenantId, tenant);
    expect(restored?.connectionId, pending.connectionId);
    expect(PendingAuthorization.decode('{"state":"bad"}'), isNull);
  });
  test('callback requires same one-time state and valid code', () {
    expect(callbackMatches(Uri.parse(
      'https://app.example.com/oauth/callback?code=valid&state=${pending.state}',
    ), pending), isTrue);
    expect(callbackMatches(Uri.parse(
      'https://app.example.com/oauth/callback?code=valid&state=attacker',
    ), pending), isFalse);
    expect(callbackMatches(Uri.parse(
      'https://app.example.com/oauth/callback?state=${pending.state}',
    ), pending), isFalse);
    expect(callbackMatches(Uri.parse(
      'https://app.example.com/oauth/callback?error=access_denied&state=${pending.state}',
    ), pending), isFalse);
  });
  test('GitHub authorization URL must be HTTPS PKCE with valid state', () {
    final valid = 'https://github.com/login/oauth/authorize'
        '?response_type=code&code_challenge_method=S256&state=${pending.state}';
    expect(requireGitHubAuthorizationUrl(valid).host, 'github.com');
    expect(
      () => requireGitHubAuthorizationUrl(valid.replaceFirst(
        'github.com', 'evil.example.com')),
      throwsFormatException,
    );
    expect(() => requireGitHubAuthorizationUrl(
      'http://github.com/login/oauth/authorize?state=${pending.state}'),
      throwsFormatException);
  });
  test('least privilege and explicit broader scope descriptions', () {
    expect(permissionKey(RequestedAccess.profile), 'profile');
    expect(permissionKey(RequestedAccess.repositories), 'repositories');
    expect(permissionDescription(RequestedAccess.repositories), contains('broad'));
    expect(validTenantId(tenant), isTrue);
    expect(validConnectionId('a/b'), isFalse);
  });
}
