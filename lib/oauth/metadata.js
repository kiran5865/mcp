/**
 * Pure builders for the OAuth documents that front an MCP endpoint:
 * RFC 9728 protected-resource metadata, RFC 8414 authorization-server metadata,
 * and the RFC 7591 client registration response.
 *
 * Kept free of `cds` and of request handling so they can be unit-tested directly.
 */

// Trailing slashes are stripped without a regex: /\/+$/ backtracks super-linearly on a long run
// of slashes, and every value passed here originates in request headers.
function stripTrailingSlashes(value) {
  let end = value.length
  while (end > 0 && value.charCodeAt(end - 1) === 47 /* '/' */) end--
  return value.slice(0, end)
}

function header(headers, name) {
  const value = headers[name] ?? headers[name.toLowerCase()]
  if (Array.isArray(value)) return typeof value[0] === 'string' ? value[0] : undefined
  return typeof value === 'string' ? value : undefined
}

/**
 * The externally visible host. Behind an approuter this is the *subscriber* hostname, which is
 * what makes both the metadata documents and the tenant lookup correct without configuration.
 */
function publicHost(headers) {
  const forwardedHost = header(headers, 'x-forwarded-host')?.split(',')[0]?.trim()
  return forwardedHost || header(headers, 'host') || 'localhost'
}

/**
 * The externally visible base URL. Behind an approuter and Cloud Foundry's router the app sees
 * plain http internally, so the forwarded protocol wins when present.
 */
function publicBaseUrl(headers) {
  const forwardedProto = header(headers, 'x-forwarded-proto')?.split(',')[0]?.trim()
  const host = publicHost(headers)
  // Anything that is not plainly localhost is reached over TLS in every deployed environment.
  const proto = forwardedProto || (/^(localhost|127\.0\.0\.1)(:|$)/.test(host) ? 'http' : 'https')
  return `${proto}://${host}`
}

/**
 * RFC 9728 protected-resource metadata for one MCP endpoint.
 *
 * `authorizationServers` is passed in rather than derived, because it differs by auth kind:
 * with XSUAA it must name *this app* (the proxy in ./index.js), since XSUAA offers no Dynamic
 * Client Registration and clients that require RFC 7591 would otherwise stop. With IAS it names
 * the IAS tenant directly, which already speaks PKCE and needs no proxy.
 */
function protectedResourceMetadata(baseUrl, resourcePath, authorizationServers) {
  const trimmedBase = stripTrailingSlashes(baseUrl)
  const path = resourcePath.startsWith('/') ? resourcePath : `/${resourcePath}`

  return {
    resource: `${trimmedBase}${path}`,
    authorization_servers: authorizationServers,
    bearer_methods_supported: ['header']
  }
}

/**
 * Escapes a value for an RFC 9110 §5.6.4 quoted-string. The base URL is reconstructed from
 * request headers, so a Host / X-Forwarded-Host carrying a quote or a backslash would otherwise
 * close the parameter early and let the caller append auth-params of their own to the challenge.
 */
function quoteString(value) {
  return value.replace(/[\\"]/g, '\\$&')
}

/**
 * The WWW-Authenticate value pointing a client at the document above.
 *
 * It names the *endpoint-specific* metadata URL. A CAP app can expose several MCP endpoints and
 * a single protected-resource document can only describe one `resource`, so the challenge is
 * what disambiguates them.
 */
function challengeHeader(baseUrl, resourcePath) {
  const trimmedBase = stripTrailingSlashes(baseUrl)
  const path = resourcePath.startsWith('/') ? resourcePath : `/${resourcePath}`
  const url = `${trimmedBase}/.well-known/oauth-protected-resource${path}`
  return `Bearer resource_metadata="${quoteString(url)}"`
}

/**
 * RFC 8414 authorization-server metadata for the proxy this plugin exposes (XSUAA only).
 *
 * `issuer` is **this app**, not XSUAA. RFC 8414 §3.3 requires the issuer to correspond to the
 * location the document was fetched from, and the protected-resource document names this same
 * base URL in `authorization_servers`; advertising XSUAA's issuer from our own host makes the two
 * documents disagree, and strict clients reject that.
 *
 * `scopes_supported` is deliberately absent: the proxy ignores client-requested scopes and sends
 * the server-configured `cds.mcp.oauth.scopes` to XSUAA instead.
 */
function authorizationServerMetadata(baseUrl) {
  const trimmedBase = stripTrailingSlashes(baseUrl)

  return {
    issuer: trimmedBase,
    authorization_endpoint: `${trimmedBase}/oauth/authorize`,
    token_endpoint: `${trimmedBase}/oauth/token`,
    registration_endpoint: `${trimmedBase}/oauth/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    // The proxy holds the client secret and attaches it when it calls XSUAA, so the client
    // authenticates with PKCE alone and never has to be given a credential.
    token_endpoint_auth_methods_supported: ['none']
  }
}

/**
 * RFC 7591 registration response.
 *
 * XSUAA has no Dynamic Client Registration endpoint, and clients that require one stop there.
 * The app's own pre-configured clientid is handed back instead, which is legitimate: XSUAA still
 * validates the redirect URI against `redirect-uris` in xs-security.json, so an arbitrary caller
 * cannot register a redirect of their choosing and harvest codes.
 *
 * The client secret is deliberately withheld — see `authorizationServerMetadata`.
 */
function clientRegistrationResponse(clientId, redirectUris) {
  return {
    client_id: clientId,
    token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    redirect_uris: redirectUris
  }
}

module.exports = {
  stripTrailingSlashes,
  publicHost,
  publicBaseUrl,
  protectedResourceMetadata,
  quoteString,
  challengeHeader,
  authorizationServerMetadata,
  clientRegistrationResponse
}
