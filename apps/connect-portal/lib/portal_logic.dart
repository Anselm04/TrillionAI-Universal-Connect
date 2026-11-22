import 'dart:convert';

enum RequestedAccess { profile, repositories }

String permissionKey(RequestedAccess access) =>
    access == RequestedAccess.profile ? 'profile' : 'repositories';

String permissionDescription(RequestedAccess access) {
  if (access == RequestedAccess.profile) {
    return 'Read your GitHub profile information. No repository access.';
  }
  return 'Read repository information. The GitHub OAuth repo scope may '
      'grant broad private and public repository access. '
      'Only select this if you understand and approve that permission.';
}

class PendingAuthorization {
  const PendingAuthorization({
    required this.tenantId,
    required this.connectionId,
    required this.state,
  });

  final String tenantId;
  final String connectionId;
  final String state;

  String encode() => jsonEncode({
        'tenantId': tenantId,
        'connectionId': connectionId,
        'state': state,
      });

  static PendingAuthorization? decode(String? json) {
    if (json == null) return null;
    try {
      final object = jsonDecode(json);
      if (object is! Map<String, dynamic>) return null;
      final tenant = object['tenantId'];
      final connection = object['connectionId'];
      final state = object['state'];
      if (tenant is! String ||
          connection is! String ||
          state is! String ||
          !validTenantId(tenant) ||
          !validConnectionId(connection) ||
          !validState(state)) {
        return null;
      }
      return PendingAuthorization(
        tenantId: tenant,
        connectionId: connection,
        state: state,
      );
    } catch (_) {
      return null;
    }
  }
}

bool validTenantId(String value) => RegExp(
  r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$',
).hasMatch(value);

bool validConnectionId(String value) =>
    value.length <= 128 &&
    RegExp(r'^[a-zA-Z0-9_-]+$').hasMatch(value);

bool validState(String value) =>
    value.length >= 32 &&
    value.length <= 128 &&
    RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(value);

bool callbackMatches(Uri url, PendingAuthorization pending) =>
    url.path == '/oauth/callback' &&
    url.queryParameters['state'] == pending.state &&
    (url.queryParameters['code']?.isNotEmpty ?? false) &&
    !(url.queryParameters.containsKey('error'));

Uri requireGitHubAuthorizationUrl(String raw) {
  final uri = Uri.tryParse(raw);
  if (uri == null ||
      uri.scheme != 'https' ||
      uri.host != 'github.com' ||
      uri.path != '/login/oauth/authorize' ||
      !validState(uri.queryParameters['state'] ?? '') ||
      uri.queryParameters['response_type'] != 'code' ||
      uri.queryParameters['code_challenge_method'] != 'S256') {
    throw const FormatException('Invalid GitHub authorization URL');
  }
  return uri;
}
