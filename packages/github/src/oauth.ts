import type {OAuthProvider} from '../../oauth/src/index.ts';

/** GitHub.com OAuth App. Repo scope is opt-in and grants broad access: disclose in consent UI. */
export function githubOAuthProvider(config:{
  clientId:string;
  redirectUri:string;
  includePrivateRepositories?:boolean;
}):OAuthProvider{
  if(!config?.clientId||!/^[a-zA-Z0-9_-]{8,256}$/.test(config.clientId))
    throw new Error('GitHub OAuth client ID invalid');
  return {
    id:'github.oauth',
    authorizationUrl:'https://github.com/login/oauth/authorize',
    tokenUrl:'https://github.com/login/oauth/access_token',
    clientId:config.clientId,redirectUri:config.redirectUri,
    scopes:config.includePrivateRepositories?['read:user','repo']:['read:user'],
    requiresClientSecret:true
    // GitHub revocation requires a separate privileged OAuth application API,
    // not the generic RFC 7009 revocation endpoint.
  };
}
