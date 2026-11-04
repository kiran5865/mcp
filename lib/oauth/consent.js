/**
 * Consent gate for the MCP OAuth authorize flow.
 *
 * /oauth/authorize validates the request and redirects here with a short-lived nonce.
 * The user sees a consent page, ticks the acknowledgements, and clicks Allow — only
 * then is the request forwarded to XSUAA. Deny redirects back to the client with
 * error=access_denied. The nonce expires after NONCE_TTL_MS to prevent replay.
 */

const crypto = require('crypto')

const NONCE_TTL_MS = 5 * 60 * 1000 // 5 minutes

// In-memory store: nonce → { params, expiresAt }
const store = new Map()

// redirect_uri → client_name, populated at registration time
const clientNameStore = new Map()

function setClientName(redirectUri, clientName) {
  if (clientName) clientNameStore.set(redirectUri, clientName)
}

function getClientName(redirectUri) {
  return clientNameStore.get(redirectUri) ?? ''
}

function createNonce(params) {
  const nonce = crypto.randomBytes(16).toString('hex')
  store.set(nonce, { params, expiresAt: Date.now() + NONCE_TTL_MS })
  return nonce
}

function consumeNonce(nonce) {
  const entry = store.get(nonce)
  if (!entry) return null
  store.delete(nonce)
  if (Date.now() > entry.expiresAt) return null
  return entry.params
}

function peekNonce(nonce) {
  const entry = store.get(nonce)
  if (!entry || Date.now() > entry.expiresAt) return null
  return entry.params
}

// Purge stale entries lazily on each write.
function purgeExpired() {
  const now = Date.now()
  for (const [key, entry] of store) {
    if (now > entry.expiresAt) store.delete(key)
  }
}

function esc(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
}

function renderConsentPage(nonce, details = {}) {
  const { clientName = '', redirectUri = '' } = details

  const advancedRows = [
    ['Application Name', clientName || 'N/A'],
    ['Redirect URI', redirectUri]
  ]
    .map(([label, value]) => `<tr><th>${esc(label)}</th><td>${esc(value)}</td></tr>`)
    .join('\n        ')

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Application Access Request</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: "72", "72full", Arial, Helvetica, sans-serif;
      background: #f5f6f7;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 1rem;
    }
    .card {
      background: #fff;
      border-radius: 0.5rem;
      box-shadow: 0 0.125rem 0.5rem rgba(0,0,0,.12);
      padding: 2rem;
      width: 100%;
      max-width: 30rem;
    }
    .icon {
      display: flex;
      align-items: center;
      justify-content: center;
      width: 3.5rem;
      height: 3.5rem;
      border-radius: 50%;
      background: #e8f0fd;
      margin: 0 auto 1.25rem;
    }
    .icon svg { width: 1.75rem; height: 1.75rem; }
    h1 {
      font-size: 1.125rem;
      font-weight: 700;
      text-align: center;
      color: #1a1a1a;
      margin-bottom: 0.5rem;
    }
    .subtitle {
      font-size: 0.875rem;
      color: #556070;
      text-align: center;
      margin-bottom: 1.5rem;
      line-height: 1.5;
    }
    .checks {
      border-left: 3px solid #e8a000;
      background: #fef7ec;
      border-radius: 0 0.25rem 0.25rem 0;
      padding: 0.875rem 1rem;
      margin-bottom: 1rem;
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
    }
    .check-item {
      display: flex;
      align-items: flex-start;
      gap: 0.625rem;
      cursor: pointer;
    }
    .check-item input[type="checkbox"] {
      margin-top: 0.125rem;
      width: 1rem;
      height: 1rem;
      flex-shrink: 0;
      accent-color: #0a6ed1;
      cursor: pointer;
    }
    .check-item span {
      font-size: 0.8125rem;
      color: #1a1a1a;
      line-height: 1.5;
      user-select: none;
    }
    details {
      margin-bottom: 1.5rem;
      border: 1px solid #e5e5e5;
      border-radius: 0.375rem;
      overflow: hidden;
    }
    summary {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.625rem 0.875rem;
      font-size: 0.8125rem;
      font-weight: 600;
      color: #32363a;
      cursor: pointer;
      list-style: none;
      user-select: none;
      background: #f7f7f7;
    }
    summary::-webkit-details-marker { display: none; }
    summary .arrow {
      display: inline-block;
      width: 0.5rem;
      height: 0.5rem;
      border-right: 1.5px solid #556070;
      border-bottom: 1.5px solid #556070;
      transform: rotate(-45deg);
      transition: transform 0.2s;
      flex-shrink: 0;
      margin-top: 0.125rem;
    }
    details[open] summary .arrow { transform: rotate(45deg); margin-top: -0.125rem; }
    .details-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.8125rem;
    }
    .details-table tr { border-top: 1px solid #e5e5e5; }
    .details-table th {
      text-align: left;
      font-weight: 600;
      color: #556070;
      padding: 0.5rem 0.875rem;
      white-space: nowrap;
      width: 40%;
      vertical-align: top;
    }
    .details-table td {
      color: #1a1a1a;
      padding: 0.5rem 0.875rem;
      word-break: break-all;
    }
    .actions {
      display: flex;
      gap: 0.75rem;
    }
    button {
      flex: 1;
      padding: 0.625rem 1rem;
      border-radius: 0.375rem;
      font-size: 0.875rem;
      font-weight: 600;
      cursor: pointer;
      border: none;
      transition: background 0.15s, opacity 0.15s;
    }
    .btn-allow {
      background: #0a6ed1;
      color: #fff;
    }
    .btn-allow:disabled {
      background: #c5d8f0;
      cursor: not-allowed;
    }
    .btn-allow:not(:disabled):hover { background: #085caf; }
    .btn-deny {
      background: #2b3648;
      color: #fff;
    }
    .btn-deny:hover { background: #1a2230; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">
      <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M12 2L4 6v6c0 5.25 3.4 10.15 8 11.35C16.6 22.15 20 17.25 20 12V6l-8-4z"
          fill="#c8daf5" stroke="#0a6ed1" stroke-width="1.5"/>
        <polyline points="9,12 11,14 15,10" stroke="#0a6ed1" stroke-width="1.75"
          stroke-linecap="round" stroke-linejoin="round" fill="none"/>
      </svg>
    </div>
    <h1>Application Access Request</h1>
    <p class="subtitle">
      An application is requesting access to <strong>RCT Compliance Data</strong>.
      Please review and acknowledge the following before granting access.
    </p>
    <form method="POST" action="/oauth/consent" id="consent-form">
      <input type="hidden" name="nonce" value="${esc(nonce)}" />
      <div class="checks">
        <label class="check-item">
          <input type="checkbox" name="ack" value="ai" required />
          <span>I acknowledge that this connector is powered by AI and results may be inaccurate.</span>
        </label>
        <label class="check-item">
          <input type="checkbox" name="ack" value="verify" required />
          <span>I acknowledge that I must verify all results using mandatory tools and processes.</span>
        </label>
        <label class="check-item">
          <input type="checkbox" name="ack" value="data" required />
          <span>I acknowledge that I must not enter any personal or confidential data.</span>
        </label>
      </div>
      <details>
        <summary><span class="arrow"></span>Advanced Details</summary>
        <table class="details-table">
        ${advancedRows}
        </table>
      </details>
      <div class="actions">
        <button type="submit" name="action" value="deny" class="btn-deny" formnovalidate>Deny</button>
        <button type="submit" name="action" value="allow" class="btn-allow" id="allow-btn" disabled>Allow Access</button>
      </div>
    </form>
  </div>
  <script>
    const checkboxes = document.querySelectorAll('input[type="checkbox"]')
    const allowBtn = document.getElementById('allow-btn')
    function update() {
      allowBtn.disabled = ![...checkboxes].every(c => c.checked)
    }
    checkboxes.forEach(c => c.addEventListener('change', update))
  </script>
</body>
</html>`
}

module.exports = { createNonce, consumeNonce, peekNonce, purgeExpired, setClientName, getClientName, renderConsentPage }
