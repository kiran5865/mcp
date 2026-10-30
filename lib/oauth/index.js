/**
 * Makes MCP endpoints reachable by an OAuth-capable MCP client.
 *
 * The plugin handles *authorization* but not authentication *discovery*: an unauthenticated call
 * to an MCP endpoint is answered with a bare JSON-RPC 401 and no WWW-Authenticate header, so a
 * client has no way to find out where to sign in. Hosted clients are the case that really needs
 * this — they are configured with the server URL alone, so there is no local config file in which
 * to work around a server that does not advertise its authorization server.
 *
 * With XSUAA there are two further gaps: it exposes no Dynamic Client Registration endpoint, which
 * clients that insist on RFC 7591 treat as fatal, and it requires the client secret at the token
 * endpoint, which PKCE-only clients will not send. Both are closed by proxying authorize/token/
 * register here and attaching the secret server-side.
 *
 * Registered from cds.on('bootstrap'), which runs before CAP installs its auth middleware: every
 * route here is fetched by a client that does not yet have a token, so none of them may require
 * one.
 */

const cds = require('@sap/cds')
const express = require('express')

const {
  authorizationServerMetadata,
  clientRegistrationResponse,
  protectedResourceMetadata,
  publicBaseUrl,
  publicHost,
  stripTrailingSlashes
} = require('./metadata')
const { tenantAuthorizationServerUrl, tenantSubdomainFromHost } = require('./tenant')

const LOG = cds.log('mcp')

const PROTECTED_RESOURCE_PATH = '/.well-known/oauth-protected-resource'
const AUTHORIZATION_SERVER_PATH = '/.well-known/oauth-authorization-server'

/**
 * How the bridge should behave for the configured auth kind, or null when it stays out of the way.
 *
 *   'proxy'     — XSUAA: serve discovery *and* proxy authorize/token/register.
 *   'discovery' — IAS: serve protected-resource metadata pointing straight at IAS, which already
 *                 speaks authorization-code + PKCE and needs no proxy in front of it.
 *
 * Read lazily rather than at module load, because cds.env is only fully resolved at bootstrap.
 */
function oauthConfig() {
  if (cds.env.mcp?.oauth === false) return null

  const auth = cds.env.requires?.auth ?? {}
  const credentials = auth.credentials ?? {}

  if (auth.kind === 'xsuaa' && credentials.clientid && credentials.url) {
    return { mode: 'proxy', credentials }
  }
  if (auth.kind === 'ias' && credentials.url) {
    return { mode: 'discovery', credentials }
  }
  return null
}

/** Paths of every MCP endpoint currently served, resolved per request — services are up by then. */
function mcpEndpointPaths() {
  const paths = []
  for (const srv of cds.service.providers ?? []) {
    for (const ep of srv.endpoints ?? []) {
      if (ep.kind === 'mcp' && ep.path) paths.push(ep.path)
    }
  }
  return paths
}

/**
 * Which MCP endpoint a protected-resource request is asking about.
 *
 * Clients append the resource path to the well-known path (RFC 9728 §3.1). The bare path is also
 * answered when the app serves exactly one MCP endpoint, since some clients only try that form;
 * with several endpoints it would be ambiguous, so it is left to 404 and the WWW-Authenticate
 * challenge — which always names the endpoint-specific URL — is what clients follow.
 */
function resolveResourcePath(requestPath) {
  const endpoints = mcpEndpointPaths()
  const candidate = stripTrailingSlashes(requestPath || '')

  if (!candidate) return endpoints.length === 1 ? endpoints[0] : undefined
  return endpoints.includes(candidate) ? candidate : undefined
}

/** The XSUAA host that should serve *this* request, which for a subscriber is not the bound one. */
function authorizationServerFor(req, credentials) {
  const tenant = tenantSubdomainFromHost(publicHost(req.headers), {
    appUiUrl: process.env.CDS_MULTITENANCY_APPUI_URL,
    separator: process.env.CDS_MULTITENANCY_APPUI_TENANTSEPARATOR
  })
  return tenantAuthorizationServerUrl(credentials.url ?? '', tenant)
}

function basicAuthHeader(credentials) {
  const raw = `${credentials.clientid ?? ''}:${credentials.clientsecret ?? ''}`
  return `Basic ${Buffer.from(raw).toString('base64')}`
}

// The metadata documents and the PKCE token endpoint are fetched cross-origin by browser-based
// clients. Nothing here is cookie-authenticated, so a wildcard origin exposes nothing.
function allowCrossOrigin(res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, MCP-Protocol-Version')
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
}

// XSUAA answers errors as HTML unless Accept says otherwise, and even then not always — so parse
// defensively and never let a stray HTML body surface as an unhandled throw.
async function readJson(response) {
  const text = await response.text()
  try {
    return JSON.parse(text)
  } catch {
    return { error: 'invalid_response', error_description: text.slice(0, 500) }
  }
}

function isString(value) {
  return typeof value === 'string'
}

// `app.use` rather than `app.get` with a wildcard: the route syntax for trailing segments differs
// between Express 4 and 5, and this plugin supports both.
function registerMetadataRoutes(app, config) {
  app.use(PROTECTED_RESOURCE_PATH, (req, res, next) => {
    if (req.method !== 'GET' && req.method !== 'OPTIONS') return next()
    allowCrossOrigin(res)
    if (req.method === 'OPTIONS') return res.status(204).end()

    const resourcePath = resolveResourcePath(req.path)
    if (!resourcePath) return next()

    const baseUrl = publicBaseUrl(req.headers)
    // With XSUAA the authorization server is this app, because the proxy below is what supplies
    // the registration endpoint XSUAA lacks. With IAS it is the IAS tenant itself.
    const authorizationServers =
      config.mode === 'proxy' ? [baseUrl] : [stripTrailingSlashes(config.credentials.url)]

    const metadata = protectedResourceMetadata(baseUrl, resourcePath, authorizationServers)
    LOG.debug('served protected-resource metadata', { resource: metadata.resource })
    res.status(200).json(metadata)
  })

  if (config.mode !== 'proxy') return

  app.use(AUTHORIZATION_SERVER_PATH, (req, res, next) => {
    if (req.method !== 'GET' && req.method !== 'OPTIONS') return next()
    allowCrossOrigin(res)
    if (req.method === 'OPTIONS') return res.status(204).end()

    res.status(200).json(authorizationServerMetadata(publicBaseUrl(req.headers)))
  })
}

function registerRegistrationRoute(app, credentials) {
  app.all('/oauth/register', (req, res) => {
    allowCrossOrigin(res)
    if (req.method === 'OPTIONS') return res.status(204).end()

    const clientId = credentials.clientid
    if (!clientId) {
      return res
        .status(500)
        .json({ error: 'server_error', error_description: 'No XSUAA client bound' })
    }

    const requested = req.body?.redirect_uris
    const redirectUris = Array.isArray(requested) ? requested.filter(isString) : []
    LOG.debug('issued client registration', { redirectUris })

    res.status(201).json(clientRegistrationResponse(clientId, redirectUris))
  })
}

function registerAuthorizeRoute(app, credentials) {
  app.get('/oauth/authorize', (req, res) => {
    const params = new URLSearchParams({
      response_type: 'code',
      // Always our own client. XSUAA only knows this one, and it is what /oauth/register hands out.
      client_id: credentials.clientid ?? ''
    })

    // `scope` and `resource` are dropped on purpose: XSUAA narrows the token to a requested scope
    // (losing the role scope the MCP endpoint requires), and rejects the RFC 8707 resource
    // indicator as an unknown parameter.
    for (const key of ['redirect_uri', 'state', 'code_challenge', 'code_challenge_method']) {
      const value = req.query[key]
      if (isString(value) && value) params.set(key, value)
    }

    const authorizationServer = authorizationServerFor(req, credentials)
    LOG.debug('redirecting to tenant authorization server', {
      host: publicHost(req.headers),
      authorizationServer
    })
    res.redirect(`${authorizationServer}/oauth/authorize?${params.toString()}`)
  })
}

function registerTokenRoute(app, credentials) {
  app.post('/oauth/token', async (req, res) => {
    allowCrossOrigin(res)
    const params = { ...req.query, ...req.body }
    const body = new URLSearchParams()

    if (params.grant_type === 'authorization_code') {
      if (!isString(params.code) || !isString(params.redirect_uri)) {
        return res
          .status(400)
          .json({ error: 'invalid_request', error_description: 'Missing code or redirect_uri' })
      }
      body.set('grant_type', 'authorization_code')
      body.set('code', params.code)
      body.set('redirect_uri', params.redirect_uri)
      if (isString(params.code_verifier)) body.set('code_verifier', params.code_verifier)
    } else if (params.grant_type === 'refresh_token') {
      if (!isString(params.refresh_token)) {
        return res
          .status(400)
          .json({ error: 'invalid_request', error_description: 'Missing refresh_token' })
      }
      body.set('grant_type', 'refresh_token')
      body.set('refresh_token', params.refresh_token)
    } else {
      return res.status(400).json({
        error: 'unsupported_grant_type',
        error_description: 'Only authorization_code and refresh_token are supported'
      })
    }

    try {
      // The client authenticated with PKCE alone; the secret is attached here, server side.
      const response = await fetch(`${authorizationServerFor(req, credentials)}/oauth/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
          Authorization: basicAuthHeader(credentials)
        },
        body
      })

      const payload = await readJson(response)
      if (!response.ok) LOG.warn('token exchange rejected by XSUAA', { status: response.status })
      res.status(response.status).json(payload)
    } catch (err) {
      LOG.error('token exchange failed:', err.message)
      res.status(502).json({
        error: 'temporarily_unavailable',
        error_description: 'Could not reach the authorization server'
      })
    }
  })
}

/** Whether a 401 from an MCP endpoint should carry a WWW-Authenticate challenge. */
function isEnabled() {
  return oauthConfig() !== null
}

function registerOAuthBridge(app) {
  const config = oauthConfig()
  if (!config) {
    LOG.debug('MCP OAuth bridge not registered: no xsuaa or ias binding')
    return
  }

  registerMetadataRoutes(app, config)

  if (config.mode !== 'proxy') {
    LOG.info('MCP OAuth discovery registered', { issuer: config.credentials.url })
    return
  }

  app.use('/oauth', express.urlencoded({ extended: false }), express.json())
  registerRegistrationRoute(app, config.credentials)
  registerAuthorizeRoute(app, config.credentials)
  registerTokenRoute(app, config.credentials)

  LOG.info('MCP OAuth bridge registered', { issuer: config.credentials.url })
}

module.exports = { registerOAuthBridge, isEnabled, resolveResourcePath, oauthConfig }
