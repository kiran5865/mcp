const cds = require('@sap/cds')
const express = require('express')

const { registerOAuthBridge } = require('../../lib/oauth')

const CREDENTIALS = {
  clientid: 'sb-test',
  clientsecret: 'secret',
  url: 'https://tenant.authentication.example.com',
  xsappname: 'test-app'
}

const REDIRECT_URI = 'http://localhost:18766/mcp-callback'

describe('OAuth bridge gating', () => {
  let server
  let baseUrl
  let originalAuth
  let originalProviders

  const serveMcpEndpoint = () => {
    cds.service.providers.length = 0
    cds.service.providers.push({ endpoints: [{ kind: 'mcp', path: '/mcp' }] })
  }
  const serveNoMcpEndpoint = () => {
    cds.service.providers.length = 0
    cds.service.providers.push({ endpoints: [{ kind: 'odata-v4', path: '/odata/v4/other' }] })
  }

  const register = () =>
    fetch(`${baseUrl}/oauth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ redirect_uris: [REDIRECT_URI] })
    })

  beforeAll(async () => {
    originalAuth = cds.env.requires.auth
    originalProviders = [...cds.service.providers]
    cds.env.requires.auth = { kind: 'xsuaa', credentials: CREDENTIALS }

    const app = express()
    registerOAuthBridge(app)
    app.use((_req, res) => res.status(404).json({ fallthrough: true }))

    await new Promise((resolve) => {
      server = app.listen(0, resolve)
    })
    baseUrl = `http://localhost:${server.address().port}`
  })

  afterAll(async () => {
    await new Promise((resolve) => server.close(resolve))
    cds.env.requires.auth = originalAuth
    cds.service.providers.length = 0
    cds.service.providers.push(...originalProviders)
  })

  describe('in a process that serves no MCP endpoint', () => {
    beforeEach(serveNoMcpEndpoint)

    it.each([
      ['POST', '/oauth/register'],
      ['GET', '/oauth/authorize'],
      ['POST', '/oauth/token'],
      ['GET', '/.well-known/oauth-authorization-server'],
      ['GET', '/.well-known/oauth-protected-resource/mcp']
    ])('does not answer %s %s', async (method, path) => {
      const res = await fetch(`${baseUrl}${path}`, { method })
      expect(res.status).toBe(404)
      expect(await res.json()).toEqual({ fallthrough: true })
    })
  })

  describe('in a process that serves an MCP endpoint', () => {
    beforeEach(serveMcpEndpoint)

    it('serves authorization server metadata', async () => {
      const res = await fetch(`${baseUrl}/.well-known/oauth-authorization-server`)
      expect(res.status).toBe(200)
      expect((await res.json()).token_endpoint).toMatch(/\/oauth\/token$/)
    })

    it('serves protected resource metadata for the MCP path', async () => {
      const res = await fetch(`${baseUrl}/.well-known/oauth-protected-resource/mcp`)
      expect(res.status).toBe(200)
      expect((await res.json()).resource).toMatch(/\/mcp$/)
    })

    it('registers a client for an allowed loopback redirect', async () => {
      const res = await register()
      expect(res.status).toBe(201)
      expect((await res.json()).redirect_uris).toEqual([REDIRECT_URI])
    })
  })

  describe('redirect URI allow-list', () => {
    let originalMcpEnv

    const registerWith = (redirectUri) =>
      fetch(`${baseUrl}/oauth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ redirect_uris: [redirectUri] })
      })

    beforeEach(() => {
      serveMcpEndpoint()
      originalMcpEnv = cds.env.mcp
    })
    afterEach(() => {
      cds.env.mcp = originalMcpEnv
    })

    describe('pinned to http://localhost:18766/*', () => {
      beforeEach(() => {
        cds.env.mcp = { oauth: { redirect_uris: ['http://localhost:18766/*'] } }
      })

      it.each([
        'http://localhost:18766/mcp-callback',
        'http://localhost:18766/',
        'http://localhost:18766/a/b?x=1'
      ])('accepts %s', async (uri) => {
        expect((await registerWith(uri)).status).toBe(201)
      })

      it.each([
        'http://localhost:18767/mcp-callback',
        'http://127.0.0.1:18766/mcp-callback',
        'http://localhost:18766.evil.example/x',
        'http://localhost:18766@evil.example/',
        'http://localhost:18766/x#frag',
        'https://evil.example/mcp-callback',
        'myapp://callback'
      ])('rejects %s', async (uri) => {
        expect((await registerWith(uri)).status).toBe(400)
      })
    })

    describe('with no list configured', () => {
      beforeEach(() => {
        cds.env.mcp = { oauth: { redirect_uris: [] } }
      })

      it('accepts a loopback redirect on any port', async () => {
        expect((await registerWith('http://localhost:54321/cb')).status).toBe(201)
      })

      it('rejects an unlisted https redirect', async () => {
        expect((await registerWith('https://evil.example/cb')).status).toBe(400)
      })
    })
  })

  describe('token scope guard', () => {
    const jwt = (claims) =>
      ['e30', Buffer.from(JSON.stringify(claims)).toString('base64url'), 'sig'].join('.')

    let originalMcpEnv
    let originalFetch
    let xsuaaPayload

    const exchange = () =>
      originalFetch(`${baseUrl}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          grant_type: 'authorization_code',
          code: 'abc',
          redirect_uri: REDIRECT_URI,
          code_verifier: 'verifier'
        })
      })

    beforeEach(() => {
      serveMcpEndpoint()
      originalMcpEnv = cds.env.mcp
      cds.env.mcp = {
        oauth: {
          redirect_uris: ['http://localhost:18766/*'],
          scopes: ['obligation-view', 'risks-view']
        }
      }
      originalFetch = globalThis.fetch
      vi.spyOn(globalThis, 'fetch').mockImplementation((url, init) =>
        String(url).startsWith(CREDENTIALS.url)
          ? Promise.resolve(Response.json(xsuaaPayload))
          : originalFetch(url, init)
      )
    })
    afterEach(() => {
      vi.restoreAllMocks()
      cds.env.mcp = originalMcpEnv
    })

    it('passes through a token limited to the configured scopes', async () => {
      xsuaaPayload = {
        access_token: jwt({ scope: ['test-app.obligation-view'] }),
        scope: 'test-app.obligation-view test-app.risks-view'
      }
      const res = await exchange()
      expect(res.status).toBe(200)
      expect((await res.json()).access_token).toBe(xsuaaPayload.access_token)
    })

    it('ignores scopes that do not belong to the app', async () => {
      xsuaaPayload = { access_token: 'opaque', scope: 'openid test-app.obligation-view uaa.user' }
      expect((await exchange()).status).toBe(200)
    })

    it('withholds a token whose response scope is wider than configured', async () => {
      xsuaaPayload = {
        access_token: 'opaque',
        scope: 'test-app.obligation-view test-app.obligation-edit'
      }
      const res = await exchange()
      expect(res.status).toBe(403)
      expect(await res.json()).not.toHaveProperty('access_token')
    })

    it('withholds a token whose JWT scope claim is wider than configured', async () => {
      xsuaaPayload = { access_token: jwt({ scope: ['test-app.obligation-delete'] }) }
      expect((await exchange()).status).toBe(403)
    })

    it('withholds a token when no scope can be determined', async () => {
      xsuaaPayload = { access_token: 'opaque' }
      expect((await exchange()).status).toBe(403)
    })
  })
})
