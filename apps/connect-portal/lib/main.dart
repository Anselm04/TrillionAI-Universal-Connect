import 'dart:html' as html;

import 'package:flutter/material.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

import 'connection_api.dart';
import 'portal_logic.dart';

const _supabaseUrl = String.fromEnvironment('SUPABASE_URL');
const _supabaseAnonKey = String.fromEnvironment('SUPABASE_ANON_KEY');

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  if (_supabaseUrl.isEmpty || _supabaseAnonKey.isEmpty) {
    runApp(const MaterialApp(
      home: Scaffold(body: Center(
        child: Text('Missing SUPABASE_URL and SUPABASE_ANON_KEY build settings.'),
      )),
    ));
    return;
  }
  await Supabase.initialize(
    url: _supabaseUrl,
    anonKey: _supabaseAnonKey,
  );
  runApp(const ConnectApplication());
}

class ConnectApplication extends StatelessWidget {
  const ConnectApplication({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'TrillionAI Connect',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xff2663eb),
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
        scaffoldBackgroundColor: const Color(0xff0d1424),
      ),
      home: const ConnectHome(),
    );
  }
}

class ConnectHome extends StatefulWidget {
  const ConnectHome({super.key});

  @override
  State<ConnectHome> createState() => _ConnectHomeState();
}

class _ConnectHomeState extends State<ConnectHome> {
  final _email = TextEditingController();
  final _password = TextEditingController();
  final _tenant = TextEditingController();
  final _connection = TextEditingController();
  bool _busy = false;
  bool _consent = false;
  bool _connectedThisSession = false;
  RequestedAccess _access = RequestedAccess.profile;
  String? _message;
  late final ConnectionApi _api;
  late final Uri _initialUri;

  @override
  void initState() {
    super.initState();
    _initialUri = Uri.base;
    _api = ConnectionApi(
      baseUri: Uri.parse('${html.window.location.origin}/'),
      accessToken: () async {
        final client = Supabase.instance.client;
        final session = client.auth.currentSession;
        if (session == null) return '';
        if (session.isExpired) {
          final response = await client.auth.refreshSession();
          return response.session?.accessToken ?? '';
        }
        return session.accessToken;
      },
    );
    _tenant.text = html.window.sessionStorage['uc.tenant'] ?? '';
    _connection.text = html.window.sessionStorage['uc.connection'] ?? '';
    if (_initialUri.path == '/oauth/callback') {
      // Remove provider code/state immediately from URL, navigation and referrers.
      html.window.history.replaceState(null, '', '/oauth/callback');
      WidgetsBinding.instance.addPostFrameCallback((_) => _completeCallback());
    }
  }

  Future<void> _completeCallback() async {
    final pending = PendingAuthorization.decode(html.window.sessionStorage['uc.pending']);
    html.window.sessionStorage.remove('uc.pending');
    if (_initialUri.queryParameters.containsKey('error')) {
      setState(() => _message = 'GitHub authorization was declined or cancelled.');
      return;
    }
    if (pending == null || !callbackMatches(_initialUri, pending)) {
      setState(() => _message = 'Authorization state could not be verified. Please connect again.');
      return;
    }
    if (Supabase.instance.client.auth.currentSession == null) {
      setState(() => _message = 'Your login expired during authorization. Sign in and restart the connection.');
      return;
    }
    _tenant.text = pending.tenantId;
    _connection.text = pending.connectionId;
    await _execute(() async {
      await _api.complete(
        pending.tenantId,
        pending.connectionId,
        pending.state,
        _initialUri.queryParameters['code']!,
      );
      setState(() {
        _connectedThisSession = true;
        _message = 'GitHub connection authorized successfully.';
      });
    });
  }

  Future<void> _execute(Future<void> Function() action) async {
    if (_busy) return;
    setState(() {
      _busy = true;
      _message = null;
    });
    try {
      await action();
    } catch (_) {
      // Never surface provider authorization codes, tokens or raw error data.
      if (mounted) {
        setState(() => _message = 'Action failed. Check your sign-in, permissions and connection configuration.');
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _signIn() => _execute(() async {
    await Supabase.instance.client.auth.signInWithPassword(
      email: _email.text.trim(),
      password: _password.text,
    );
    setState(() => _message = 'Signed in. You can now authorize GitHub.');
  });

  Future<void> _signOut() => _execute(() async {
    await Supabase.instance.client.auth.signOut();
    html.window.sessionStorage.remove('uc.pending');
    _connectedThisSession = false;
    setState(() => _message = 'Signed out.');
  });

  Future<void> _start() async {
    final tenant = _tenant.text.trim();
    final connection = _connection.text.trim();
    if (!_consent || !validTenantId(tenant) || !validConnectionId(connection)) {
      setState(() => _message = 'Select consent and provide a valid organization and connection ID.');
      return;
    }
    await _execute(() async {
      final url = requireGitHubAuthorizationUrl(
        (await _api.start(tenant, connection, permissionKey(_access))).toString(),
      );
      final state = url.queryParameters['state']!;
      html.window.sessionStorage['uc.pending'] = PendingAuthorization(
        tenantId: tenant,
        connectionId: connection,
        state: state,
      ).encode();
      html.window.sessionStorage['uc.tenant'] = tenant;
      html.window.sessionStorage['uc.connection'] = connection;
      html.window.location.assign(url.toString());
    });
  }

  Future<void> _disconnect() async {
    final tenant = _tenant.text.trim();
    final connection = _connection.text.trim();
    if (!validTenantId(tenant) || !validConnectionId(connection)) return;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Disconnect GitHub?'),
        content: const Text(
          'Local credentials will be deleted. GitHub provider-side token '
          'revocation is not yet implemented. You may also revoke access '
          'under GitHub Settings → Applications.',
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(context, true), child: const Text('Disconnect')),
        ],
      ),
    );
    if (confirmed != true) return;
    await _execute(() async {
      final deleted = await _api.disconnect(tenant, connection);
      setState(() {
        _connectedThisSession = false;
        _message = deleted
            ? 'Local credentials removed. Revoke the OAuth app in GitHub settings to invalidate provider access.'
            : 'No local credentials were found for that connection.';
      });
    });
  }

  @override
  void dispose() {
    _email.dispose();
    _password.dispose();
    _tenant.dispose();
    _connection.dispose();
    _api.close();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final signedIn = Supabase.instance.client.auth.currentSession != null;
    return Scaffold(
      appBar: AppBar(
        title: const Text('TrillionAI Connect'),
        actions: [
          if (signedIn)
            TextButton(
              onPressed: _busy ? null : _signOut,
              child: const Text('Sign out'),
            ),
        ],
      ),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 700),
          child: ListView(
            padding: const EdgeInsets.all(24),
            children: [
              const Icon(Icons.hub, size: 54, color: Color(0xff79a8ff)),
              const SizedBox(height: 12),
              Text('Connect your GitHub account',
                textAlign: TextAlign.center,
                style: Theme.of(context).textTheme.headlineMedium),
              const SizedBox(height: 12),
              const Text(
                'Authorize read-only GitHub access through your verified '
                'TrillionAI Identity account. You control the permissions.',
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 24),
              if (!signedIn) ...[
                TextField(
                  controller: _email,
                  keyboardType: TextInputType.emailAddress,
                  decoration: const InputDecoration(labelText: 'Identity account email'),
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: _password,
                  obscureText: true,
                  decoration: const InputDecoration(labelText: 'Password'),
                ),
                const SizedBox(height: 12),
                FilledButton(
                  onPressed: _busy ? null : _signIn,
                  child: const Text('Sign in with TrillionAI Identity'),
                ),
              ] else ...[
                Text('Signed in as ${Supabase.instance.client.auth.currentUser?.email ?? 'verified user'}'),
                const SizedBox(height: 16),
                TextField(
                  controller: _tenant,
                  decoration: const InputDecoration(
                    labelText: 'Organization ID (UUID)',
                    helperText: 'Provided by your authorized organization account.',
                  ),
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: _connection,
                  decoration: const InputDecoration(
                    labelText: 'Connection ID',
                    helperText: 'An existing connection provisioned by the backend.',
                  ),
                ),
                const SizedBox(height: 20),
                const Text('Requested GitHub permissions'),
                RadioListTile<RequestedAccess>(
                  title: const Text('GitHub profile only'),
                  subtitle: Text(permissionDescription(RequestedAccess.profile)),
                  value: RequestedAccess.profile,
                  groupValue: _access,
                  onChanged: _busy ? null : (value) {
                    if (value != null) setState(() => _access = value);
                  },
                ),
                RadioListTile<RequestedAccess>(
                  title: const Text('Repository metadata (additional permission)'),
                  subtitle: Text(permissionDescription(RequestedAccess.repositories)),
                  value: RequestedAccess.repositories,
                  groupValue: _access,
                  onChanged: _busy ? null : (value) {
                    if (value != null) setState(() => _access = value);
                  },
                ),
                CheckboxListTile(
                  title: const Text('I authorize the selected GitHub access.'),
                  subtitle: const Text(
                    'TrillionAI will store the provider tokens encrypted. '
                    'You can disconnect local credentials at any time.',
                  ),
                  value: _consent,
                  onChanged: _busy ? null : (value) => setState(() => _consent = value ?? false),
                ),
                const SizedBox(height: 12),
                FilledButton.icon(
                  icon: const Icon(Icons.link),
                  onPressed: _busy ? null : _start,
                  label: const Text('Authorize GitHub'),
                ),
                const SizedBox(height: 10),
                OutlinedButton.icon(
                  icon: const Icon(Icons.link_off),
                  onPressed: _busy ? null : _disconnect,
                  label: const Text('Disconnect GitHub'),
                ),
                if (_connectedThisSession)
                  const Padding(
                    padding: EdgeInsets.only(top: 12),
                    child: Text('Connection confirmed in this session.'),
                  ),
              ],
              if (_busy) const Padding(
                padding: EdgeInsets.only(top: 14),
                child: LinearProgressIndicator(),
              ),
              if (_message != null)
                Padding(
                  padding: const EdgeInsets.only(top: 18),
                  child: SelectableText(_message!, textAlign: TextAlign.center),
                ),
              const SizedBox(height: 28),
              const Text(
                'This portal does not publish repositories, modify GitHub content, '
                'or initiate paid services. Organization membership and provider '
                'permission are always enforced by the backend.',
                textAlign: TextAlign.center,
              ),
            ],
          ),
        ),
      ),
    );
  }
}
