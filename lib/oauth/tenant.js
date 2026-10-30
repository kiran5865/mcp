/**
 * Maps an incoming request host onto the XSUAA authorization server of the *subscriber* tenant.
 *
 * Without this, OAuth discovery built from the bound service credentials always names the
 * *provider* subaccount's XSUAA, so every MCP login is sent there regardless of which tenant the
 * request came from. Users who exist only in a subscriber subaccount fail with "BTP shadow user
 * not found", and even a user who does exist in the provider subaccount receives a provider-zoned
 * token — a dead end for a multitenant app, where each subscriber has its own HDI container.
 *
 * The approuter already solves this with TENANT_HOST_PATTERN. We reproduce the same derivation
 * from CDS_MULTITENANCY_APPUI_URL / CDS_MULTITENANCY_APPUI_TENANTSEPARATOR, which the standard
 * `app-api` dependency passes to the backend module. The tenant subdomain is exactly the host
 * prefix, because the subscription URL is built as `${tenant_subdomain}${separator}${app-uri}`.
 */

const { stripTrailingSlashes } = require('./metadata')

const DEFAULT_TENANT_SEPARATOR = '-'

// Bare lowercase hostname: no scheme, no port, no path. Written without a regex so it cannot
// backtrack on hostile input — these values come from request headers.
function hostOf(value) {
  const schemeAt = value.indexOf('://')
  const withoutScheme = schemeAt === -1 ? value : value.slice(schemeAt + 3)
  const pathAt = withoutScheme.indexOf('/')
  const authority = pathAt === -1 ? withoutScheme : withoutScheme.slice(0, pathAt)
  const portAt = authority.lastIndexOf(':')
  const host = portAt === -1 ? authority : authority.slice(0, portAt)
  return host.trim().toLowerCase()
}

/**
 * The subscriber tenant's subdomain, or undefined when the request is for the provider tenant
 * (or when the app is not deployed behind an approuter, e.g. local development).
 *
 * `subscriber1-myapp-dev-srv.cfapps.eu10.hana.ondemand.com` against an app UI host of
 * `myapp-dev-srv.cfapps.eu10.hana.ondemand.com` yields `subscriber1`.
 *
 * @param {string} host request host, with or without scheme and port
 * @param {{appUiUrl?: string, separator?: string}} config
 */
function tenantSubdomainFromHost(host, config) {
  const appUiHost = config.appUiUrl ? hostOf(config.appUiUrl) : ''
  if (!appUiHost) return undefined

  const requestHost = hostOf(host)
  // The provider tenant is reached on the bare app host, with no prefix to strip.
  if (!requestHost || requestHost === appUiHost) return undefined

  const suffix = `${config.separator || DEFAULT_TENANT_SEPARATOR}${appUiHost}`
  if (!requestHost.endsWith(suffix)) return undefined

  return requestHost.slice(0, requestHost.length - suffix.length) || undefined
}

/**
 * Rewrites the bound XSUAA URL onto a tenant's own subdomain.
 *
 * Every subaccount gets its own `<subdomain>.authentication.<region>.hana.ondemand.com` host, and
 * the provider's clientid stays valid across all of them — that is precisely how the approuter
 * authenticates subscribers. Falls back to the provider URL when there is no tenant to swap in.
 */
function tenantAuthorizationServerUrl(providerUrl, tenantSubdomain) {
  const trimmed = stripTrailingSlashes(providerUrl)
  if (!tenantSubdomain) return trimmed

  try {
    const url = new URL(trimmed)
    const labels = url.hostname.split('.')
    // A single-label host (localhost, a mock) has no subdomain position to replace.
    if (labels.length < 2) return trimmed

    labels[0] = tenantSubdomain
    url.hostname = labels.join('.')
    return stripTrailingSlashes(url.toString())
  } catch {
    return trimmed
  }
}

module.exports = { tenantSubdomainFromHost, tenantAuthorizationServerUrl }
