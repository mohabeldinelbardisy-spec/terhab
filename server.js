import crypto from 'node:crypto';
import express from 'express';
import { requireBearerAuth } from '@modelcontextprotocol/express';
import { toNodeHandler } from '@modelcontextprotocol/node';
import {
  createMcpHandler,
  McpServer,
  OAuthError,
  OAuthErrorCode,
} from '@modelcontextprotocol/server';
import * as z from 'zod/v4';

const PORT = Number.parseInt(process.env.PORT || '3000', 10);

function publicBaseUrl() {
  if (process.env.MCP_PUBLIC_URL) return process.env.MCP_PUBLIC_URL.replace(/\/$/, '');
  if (process.env.RENDER_EXTERNAL_HOSTNAME) return `https://${process.env.RENDER_EXTERNAL_HOSTNAME}`;
  return `http://127.0.0.1:${PORT}`;
}

const BASE_URL = publicBaseUrl();
const MCP_URL = new URL('/mcp', BASE_URL);
const RESOURCE_METADATA_URL = new URL('/.well-known/oauth-protected-resource/mcp', BASE_URL);

const GET_PATH_ALLOWLIST = [
  /^\/api\/v2\/users(?:\/|$)/,
  /^\/api\/v2\/routing\/queues(?:\/|$)/,
  /^\/api\/v2\/presencedefinitions(?:\/|$)/,
  /^\/api\/v2\/analytics\/conversations\/[^/]+\/details$/,
];

const ANALYTICS_POST_ALLOWLIST = new Set([
  '/api/v2/analytics/conversations/details/query',
  '/api/v2/analytics/conversations/aggregates/query',
  '/api/v2/analytics/queues/observations/query',
  '/api/v2/analytics/users/aggregates/query',
  '/api/v2/analytics/users/details/query',
  '/api/v2/analytics/users/observations/query',
]);

let genesysTokenCache = null;

function configuredGenesys() {
  return Boolean(
    process.env.GENESYS_CLIENT_ID &&
      process.env.GENESYS_CLIENT_SECRET &&
      process.env.GENESYS_LOGIN_URL &&
      process.env.GENESYS_API_BASE_URL,
  );
}

function oauthConfigured() {
  return Boolean(process.env.BRIDGE_PASSWORD);
}

function oauthSigningSecret() {
  const secret = process.env.BRIDGE_PASSWORD;
  if (!secret) throw new Error('BRIDGE_PASSWORD is not configured');
  return secret;
}

function base64urlJson(value) {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function signPayload(payload) {
  const body = base64urlJson(payload);
  const signature = crypto.createHmac('sha256', oauthSigningSecret()).update(body).digest('base64url');
  return `${body}.${signature}`;
}

function verifySignedPayload(token) {
  if (!token || typeof token !== 'string') throw new Error('Missing token');
  const [body, signature] = token.split('.');
  if (!body || !signature) throw new Error('Malformed token');

  const expected = crypto.createHmac('sha256', oauthSigningSecret()).update(body).digest();
  const actual = Buffer.from(signature, 'base64url');
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
    throw new Error('Invalid token signature');
  }

  const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  if (!payload.exp || payload.exp <= Math.floor(Date.now() / 1000)) throw new Error('Token expired');
  return payload;
}

function sha256Base64url(value) {
  return crypto.createHash('sha256').update(value).digest('base64url');
}

function getSingle(value) {
  return Array.isArray(value) ? value[0] : value;
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function isAllowedRedirectUri(uri) {
  try {
    const url = new URL(uri);
    if (url.protocol === 'https:') return true;
    return url.protocol === 'http:' && ['127.0.0.1', 'localhost', '::1'].includes(url.hostname);
  } catch {
    return false;
  }
}

function isAllowedMcpOrigin(origin) {
  if (!origin) return true;
  try {
    const { hostname, protocol } = new URL(origin);
    if (protocol !== 'https:' && protocol !== 'http:') return false;
    return (
      hostname === 'chatgpt.com' ||
      hostname.endsWith('.chatgpt.com') ||
      hostname === 'openai.com' ||
      hostname.endsWith('.openai.com') ||
      hostname === 'localhost' ||
      hostname === '127.0.0.1'
    );
  } catch {
    return false;
  }
}

async function getGenesysAccessToken() {
  if (!configuredGenesys()) {
    throw new Error('Genesys credentials are not configured on the server');
  }

  const now = Date.now();
  if (genesysTokenCache?.accessToken && genesysTokenCache.expiresAt > now + 60_000) {
    return genesysTokenCache.accessToken;
  }

  const loginBase = process.env.GENESYS_LOGIN_URL.replace(/\/$/, '');
  const tokenUrl = `${loginBase}/oauth/token`;
  const basic = Buffer.from(`${process.env.GENESYS_CLIENT_ID}:${process.env.GENESYS_CLIENT_SECRET}`, 'utf8').toString('base64');

  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${basic}`,
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: new URLSearchParams({ grant_type: 'client_credentials' }),
    signal: AbortSignal.timeout(30_000),
  });

  const text = await response.text();
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    payload = { raw: text };
  }

  if (!response.ok || !payload.access_token) {
    throw new Error(`Genesys OAuth failed (${response.status}): ${JSON.stringify(payload)}`);
  }

  genesysTokenCache = {
    accessToken: payload.access_token,
    expiresAt: now + Number(payload.expires_in || 3600) * 1000,
  };
  return genesysTokenCache.accessToken;
}

function assertAllowedGetPath(pathname) {
  if (!GET_PATH_ALLOWLIST.some((rule) => rule.test(pathname))) {
    throw new Error(`GET path is not allowed by the read-only bridge: ${pathname}`);
  }
}

async function genesysRequest({ method, path, query, body }) {
  const apiBase = process.env.GENESYS_API_BASE_URL?.replace(/\/$/, '');
  if (!apiBase) throw new Error('GENESYS_API_BASE_URL is not configured');

  const url = new URL(path, `${apiBase}/`);
  if (url.origin !== new URL(apiBase).origin) throw new Error('Cross-origin Genesys requests are not allowed');

  if (method === 'GET') {
    assertAllowedGetPath(url.pathname);
  } else if (method === 'POST') {
    if (!ANALYTICS_POST_ALLOWLIST.has(url.pathname)) {
      throw new Error(`POST path is not allowed by the read-only bridge: ${url.pathname}`);
    }
  } else {
    throw new Error('Only GET and analytics POST requests are supported');
  }

  if (query && typeof query === 'object') {
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null) continue;
      if (Array.isArray(value)) {
        for (const item of value) url.searchParams.append(key, String(item));
      } else {
        url.searchParams.set(key, String(value));
      }
    }
  }

  const token = await getGenesysAccessToken();
  const response = await fetch(url, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
      ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}),
      'User-Agent': 'Genesys-WFM-MCP-Bridge/0.1.0',
    },
    ...(method === 'POST' ? { body: JSON.stringify(body ?? {}) } : {}),
    signal: AbortSignal.timeout(60_000),
  });

  const text = await response.text();
  let payload;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    payload = { raw: text };
  }

  if (!response.ok) {
    throw new Error(`Genesys API failed (${response.status}) on ${url.pathname}: ${JSON.stringify(payload)}`);
  }

  return payload;
}

function toolResult(value) {
  let text = JSON.stringify(value, null, 2);
  const MAX = 900_000;
  if (text.length > MAX) {
    text = `${text.slice(0, MAX)}\n\n[Response truncated by bridge. Narrow the date range, filters, or pagination.]`;
  }
  return { content: [{ type: 'text', text }] };
}

function toolError(error) {
  return {
    isError: true,
    content: [{ type: 'text', text: error instanceof Error ? error.message : String(error) }],
  };
}

function buildMcpServer() {
  const server = new McpServer({ name: 'genesys-wfm', version: '0.1.0' });

  server.registerTool(
    'genesys_connection_status',
    {
      title: 'Genesys connection status',
      description: 'Check whether the read-only Genesys bridge has its required server-side configuration. Does not reveal secrets.',
      inputSchema: z.object({}),
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    async () =>
      toolResult({
        bridge: 'ok',
        genesysConfigured: configuredGenesys(),
        oauthConfigured: oauthConfigured(),
        apiBaseUrl: process.env.GENESYS_API_BASE_URL || null,
      }),
  );

  server.registerTool(
    'genesys_get',
    {
      title: 'Read Genesys Cloud API',
      description:
        'Perform an allowlisted read-only GET against Genesys Cloud. Supported families include users, routing queues, presence definitions, and individual conversation analytics details. Use query for pagination and filters.',
      inputSchema: z.object({
        path: z.string().describe('Genesys API path beginning with /api/v2/'),
        query: z.record(z.string(), z.any()).optional().describe('Optional URL query parameters'),
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
    },
    async ({ path, query }) => {
      try {
        return toolResult(await genesysRequest({ method: 'GET', path, query }));
      } catch (error) {
        return toolError(error);
      }
    },
  );

  server.registerTool(
    'genesys_analytics_query',
    {
      title: 'Query Genesys analytics',
      description:
        'Run an allowlisted read-only Genesys analytics POST query. Use this for queue KPIs, user/agent KPIs, interaction details, AHT, volumes, SLA-related metrics, and interval or date-range analytics. POST is permitted only for analytics query endpoints; no mutation endpoints are exposed.',
      inputSchema: z.object({
        endpoint: z.enum([
          '/api/v2/analytics/conversations/details/query',
          '/api/v2/analytics/conversations/aggregates/query',
          '/api/v2/analytics/queues/observations/query',
          '/api/v2/analytics/users/aggregates/query',
          '/api/v2/analytics/users/details/query',
          '/api/v2/analytics/users/observations/query',
        ]),
        body: z.record(z.string(), z.any()).describe('Genesys analytics query body'),
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
    },
    async ({ endpoint, body }) => {
      try {
        return toolResult(await genesysRequest({ method: 'POST', path: endpoint, body }));
      } catch (error) {
        return toolError(error);
      }
    },
  );

  return server;
}

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: false, limit: '256kb' }));

app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    service: 'genesys-wfm-mcp-bridge',
    mcpUrl: MCP_URL.href,
    genesysConfigured: configuredGenesys(),
    oauthConfigured: oauthConfigured(),
  });
});

function oauthMetadata() {
  return {
    issuer: BASE_URL,
    authorization_endpoint: `${BASE_URL}/authorize`,
    token_endpoint: `${BASE_URL}/token`,
    registration_endpoint: `${BASE_URL}/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['none'],
    code_challenge_methods_supported: ['S256'],
    scopes_supported: ['mcp'],
    authorization_response_iss_parameter_supported: true,
  };
}

function resourceMetadata() {
  return {
    resource: MCP_URL.href,
    authorization_servers: [BASE_URL],
    scopes_supported: ['mcp'],
    bearer_methods_supported: ['header'],
    resource_name: 'Genesys WFM MCP',
  };
}

app.get('/.well-known/oauth-authorization-server', (_req, res) => res.json(oauthMetadata()));
app.get('/.well-known/oauth-protected-resource', (_req, res) => res.json(resourceMetadata()));
app.get('/.well-known/oauth-protected-resource/mcp', (_req, res) => res.json(resourceMetadata()));

app.post('/register', (req, res) => {
  const redirectUris = Array.isArray(req.body?.redirect_uris) ? req.body.redirect_uris : [];
  if (!redirectUris.length || !redirectUris.every(isAllowedRedirectUri)) {
    return res.status(400).json({ error: 'invalid_redirect_uri' });
  }

  const registrationFingerprint = crypto
    .createHash('sha256')
    .update(JSON.stringify({ redirectUris, clientName: req.body?.client_name || '' }))
    .digest('hex')
    .slice(0, 32);

  return res.status(201).json({
    client_id: `chatgpt-${registrationFingerprint}`,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    redirect_uris: redirectUris,
    token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
  });
});

function renderLoginPage(params, message = '') {
  const fields = [
    'response_type',
    'client_id',
    'redirect_uri',
    'scope',
    'state',
    'code_challenge',
    'code_challenge_method',
    'resource',
  ];

  const hidden = fields
    .map((name) => `<input type="hidden" name="${name}" value="${escapeHtml(params[name] || '')}">`)
    .join('\n');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect Genesys WFM</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#f5f5f5;margin:0;display:grid;place-items:center;min-height:100vh;color:#171717}
.card{width:min(420px,calc(100vw - 40px));background:white;border:1px solid #ddd;border-radius:16px;padding:28px;box-shadow:0 8px 30px rgba(0,0,0,.08)}
h1{font-size:22px;margin:0 0 8px}.sub{color:#666;margin:0 0 22px;line-height:1.5}.error{background:#fff0f0;color:#a00000;padding:10px 12px;border-radius:8px;margin-bottom:14px}
label{display:block;font-weight:600;margin-bottom:8px}input[type=password]{width:100%;box-sizing:border-box;padding:12px;border:1px solid #bbb;border-radius:9px;font-size:16px}
button{width:100%;margin-top:16px;padding:12px;border:0;border-radius:9px;background:#111;color:white;font-size:16px;font-weight:650;cursor:pointer}.note{font-size:12px;color:#777;margin-top:16px;line-height:1.4}
</style>
</head>
<body><main class="card"><h1>Genesys WFM</h1><p class="sub">Authorize your private ChatGPT connection to the read-only Genesys bridge.</p>${
    message ? `<div class="error">${escapeHtml(message)}</div>` : ''
  }<form method="post" action="/authorize">${hidden}<label for="password">Bridge password</label><input id="password" name="password" type="password" autocomplete="current-password" required autofocus><button type="submit">Connect</button></form><p class="note">This password is stored only as a Render environment variable and is never stored in the plugin package.</p></main></body></html>`;
}

function validateAuthorizeParams(params) {
  if (params.response_type !== 'code') return 'Unsupported response_type';
  if (!params.client_id) return 'Missing client_id';
  if (!isAllowedRedirectUri(params.redirect_uri)) return 'Invalid redirect_uri';
  if (!params.code_challenge || params.code_challenge_method !== 'S256') return 'PKCE S256 is required';
  return null;
}

app.get('/authorize', (req, res) => {
  if (!oauthConfigured()) return res.status(503).send('BRIDGE_PASSWORD is not configured on Render.');
  const params = Object.fromEntries(Object.entries(req.query).map(([k, v]) => [k, getSingle(v)]));
  const error = validateAuthorizeParams(params);
  if (error) return res.status(400).send(error);
  return res.type('html').send(renderLoginPage(params));
});

app.post('/authorize', (req, res) => {
  if (!oauthConfigured()) return res.status(503).send('BRIDGE_PASSWORD is not configured on Render.');
  const params = {
    response_type: req.body.response_type,
    client_id: req.body.client_id,
    redirect_uri: req.body.redirect_uri,
    scope: req.body.scope || 'mcp',
    state: req.body.state || '',
    code_challenge: req.body.code_challenge,
    code_challenge_method: req.body.code_challenge_method,
    resource: req.body.resource || MCP_URL.href,
  };

  const error = validateAuthorizeParams(params);
  if (error) return res.status(400).send(error);
  if (req.body.password !== process.env.BRIDGE_PASSWORD) {
    return res.status(401).type('html').send(renderLoginPage(params, 'Incorrect bridge password.'));
  }

  const code = signPayload({
    type: 'code',
    clientId: params.client_id,
    redirectUri: params.redirect_uri,
    codeChallenge: params.code_challenge,
    scope: 'mcp',
    resource: MCP_URL.href,
    exp: Math.floor(Date.now() / 1000) + 300,
    nonce: crypto.randomUUID(),
  });

  const redirect = new URL(params.redirect_uri);
  redirect.searchParams.set('code', code);
  if (params.state) redirect.searchParams.set('state', params.state);
  redirect.searchParams.set('iss', BASE_URL);
  return res.redirect(302, redirect.href);
});

function issueAccessToken({ clientId, resource = MCP_URL.href }) {
  const now = Math.floor(Date.now() / 1000);
  const accessToken = signPayload({
    type: 'access',
    clientId,
    scopes: ['mcp'],
    resource,
    iat: now,
    exp: now + 3600,
    nonce: crypto.randomUUID(),
  });
  const refreshToken = signPayload({
    type: 'refresh',
    clientId,
    resource,
    iat: now,
    exp: now + 30 * 24 * 3600,
    nonce: crypto.randomUUID(),
  });
  return { accessToken, refreshToken };
}

app.post('/token', (req, res) => {
  if (!oauthConfigured()) return res.status(503).json({ error: 'temporarily_unavailable' });

  try {
    if (req.body.grant_type === 'authorization_code') {
      const payload = verifySignedPayload(req.body.code);
      if (payload.type !== 'code') throw new Error('Invalid authorization code');
      if (payload.redirectUri !== req.body.redirect_uri) throw new Error('redirect_uri mismatch');
      if (payload.clientId !== req.body.client_id) throw new Error('client_id mismatch');
      if (!req.body.code_verifier || sha256Base64url(req.body.code_verifier) !== payload.codeChallenge) {
        throw new Error('PKCE verification failed');
      }

      const { accessToken, refreshToken } = issueAccessToken({
        clientId: payload.clientId,
        resource: payload.resource,
      });
      return res.json({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: 3600,
        refresh_token: refreshToken,
        scope: 'mcp',
      });
    }

    if (req.body.grant_type === 'refresh_token') {
      const payload = verifySignedPayload(req.body.refresh_token);
      if (payload.type !== 'refresh') throw new Error('Invalid refresh token');
      if (req.body.client_id && payload.clientId !== req.body.client_id) throw new Error('client_id mismatch');

      const { accessToken, refreshToken } = issueAccessToken({
        clientId: payload.clientId,
        resource: payload.resource,
      });
      return res.json({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: 3600,
        refresh_token: refreshToken,
        scope: 'mcp',
      });
    }

    return res.status(400).json({ error: 'unsupported_grant_type' });
  } catch (error) {
    return res.status(400).json({ error: 'invalid_grant', error_description: error.message });
  }
});

const tokenVerifier = {
  async verifyAccessToken(token) {
    try {
      const payload = verifySignedPayload(token);
      if (payload.type !== 'access') throw new Error('Not an access token');
      if (payload.resource !== MCP_URL.href) throw new Error('Wrong resource');
      return {
        token,
        clientId: payload.clientId,
        scopes: payload.scopes || [],
        expiresAt: payload.exp,
        resource: new URL(payload.resource),
      };
    } catch (error) {
      throw new OAuthError(OAuthErrorCode.InvalidToken, error.message);
    }
  },
};

const auth = requireBearerAuth({
  verifier: tokenVerifier,
  requiredScopes: ['mcp'],
  resourceMetadataUrl: RESOURCE_METADATA_URL,
  expectedResource: MCP_URL,
});

const mcpHandler = createMcpHandler(() => buildMcpServer());
const nodeHandler = toNodeHandler(mcpHandler);

app.all(
  '/mcp',
  (req, res, next) => {
    if (!isAllowedMcpOrigin(req.get('origin'))) return res.status(403).json({ error: 'origin_not_allowed' });
    return next();
  },
  auth,
  (req, res) => void nodeHandler(req, res, req.body),
);

app.listen(PORT, '0.0.0.0', () => {
  console.error(`Genesys WFM MCP bridge listening on ${BASE_URL}`);
  console.error(`MCP endpoint: ${MCP_URL.href}`);
});
