// ============================================================
// src/index.js — Worker: serve os arquivos estáticos e cuida
// do login com Google via OAuth 2.0 + OpenID Connect + PKCE
// ============================================================

const GOOGLE_AUTH_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';
const GOOGLE_JWKS_ENDPOINT = 'https://www.googleapis.com/oauth2/v3/certs';
const GOOGLE_ISSUER = 'https://accounts.google.com';

const TRANSACTION_TTL_SECONDS = 600; // 10 minutos
const SESSION_TTL_SECONDS = 8 * 60 * 60; // 8 horas

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (url.pathname === '/oauth/login/google') return await handleLogin(env);
      if (url.pathname === '/oauth/callback/google') return await handleCallback(request, env, url);
      if (url.pathname === '/oauth/logout') return await handleLogout(request, env);
      if (url.pathname === '/api/me') return await handleMe(request, env);
    } catch (err) {
      console.error(err);
      return new Response('Erro interno: ' + err.message, { status: 500 });
    }
    // Qualquer outra rota cai nos arquivos estáticos (HTML/CSS/JS)
    return env.ASSETS.fetch(request);
  },
};

// ------------------------------------------------------------
// 1. /oauth/login/google — inicia o fluxo
// ------------------------------------------------------------
async function handleLogin(env) {
  const state = randomToken();
  const nonce = randomToken();
  const codeVerifier = randomToken(64);
  const codeChallenge = await sha256Base64Url(codeVerifier);

  const transactionId = randomToken();
  const idHash = await sha256Hex(transactionId);
  const stateHash = await sha256Hex(state);
  const expiresAt = Math.floor(Date.now() / 1000) + TRANSACTION_TTL_SECONDS;

  await env.DB.prepare(
    `INSERT INTO oauth_transactions (id_hash, provider, state_hash, nonce, code_verifier, expires_at)
     VALUES (?, 'google', ?, ?, ?, ?)`
  ).bind(idHash, stateHash, nonce, codeVerifier, expiresAt).run();

  const redirectUri = `${env.PUBLIC_BASE_URL}/oauth/callback/google`;
  const authUrl = new URL(GOOGLE_AUTH_ENDPOINT);
  authUrl.searchParams.set('client_id', env.GOOGLE_CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', 'openid email profile');
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('nonce', nonce);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');

  const headers = new Headers();
  headers.set('Location', authUrl.toString());
  headers.append('Set-Cookie', buildCookie('__Host-oauth-tx', transactionId, TRANSACTION_TTL_SECONDS));
  return new Response(null, { status: 302, headers });
}

// ------------------------------------------------------------
// 2. /oauth/callback/google — recebe a volta do Google
// ------------------------------------------------------------
async function handleCallback(request, env, url) {
  const code = url.searchParams.get('code');
  const returnedState = url.searchParams.get('state');
  const error = url.searchParams.get('error');

  if (error) return new Response('Login cancelado ou negado: ' + error, { status: 400 });
  if (!code || !returnedState) return new Response('Parâmetros de retorno ausentes.', { status: 400 });

  const transactionId = getCookie(request, '__Host-oauth-tx');
  if (!transactionId) return new Response('Cookie de transação ausente ou expirado. Tente entrar de novo.', { status: 400 });

  const idHash = await sha256Hex(transactionId);
  const row = await env.DB.prepare(`SELECT * FROM oauth_transactions WHERE id_hash = ?`).bind(idHash).first();
  if (!row) return new Response('Transação não encontrada, expirada ou já usada.', { status: 400 });

  await env.DB.prepare(`DELETE FROM oauth_transactions WHERE id_hash = ?`).bind(idHash).run();

  if (Math.floor(Date.now() / 1000) > row.expires_at) return new Response('Transação expirada.', { status: 400 });

  const stateHash = await sha256Hex(returnedState);
  if (stateHash !== row.state_hash) return new Response('State inválido (possível CSRF).', { status: 400 });

  const redirectUri = `${env.PUBLIC_BASE_URL}/oauth/callback/google`;
  const tokenResponse = await fetch(GOOGLE_TOKEN_ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      code_verifier: row.code_verifier,
    }),
  });

  if (!tokenResponse.ok) return new Response('Falha ao trocar o código pelo token: ' + await tokenResponse.text(), { status: 400 });

  const tokens = await tokenResponse.json();
  const claims = await verifyGoogleIdToken(tokens.id_token, env.GOOGLE_CLIENT_ID);
  if (claims.nonce !== row.nonce) return new Response('Nonce inválido no ID token.', { status: 400 });

  const sessionId = randomToken();
  const sessionHash = await sha256Hex(sessionId);
  const now = Math.floor(Date.now() / 1000);

  await env.DB.prepare(
    `INSERT INTO sessions (id_hash, issuer, subject, email, display_name, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).bind(sessionHash, claims.iss, claims.sub, claims.email || null, claims.name || null, now + SESSION_TTL_SECONDS, now).run();

  const headers = new Headers();
  headers.set('Location', '/');
  headers.append('Set-Cookie', buildCookie('__Host-oauth-tx', '', 0));
  headers.append('Set-Cookie', buildCookie('__Host-session', sessionId, SESSION_TTL_SECONDS));
  return new Response(null, { status: 302, headers });
}

// ------------------------------------------------------------
// 3. /api/me — devolve quem está logado
// ------------------------------------------------------------
async function handleMe(request, env) {
  const sessionId = getCookie(request, '__Host-session');
  if (!sessionId) return Response.json({ error: 'not_authenticated' }, { status: 401 });

  const sessionHash = await sha256Hex(sessionId);
  const row = await env.DB.prepare(`SELECT * FROM sessions WHERE id_hash = ?`).bind(sessionHash).first();
  if (!row || Math.floor(Date.now() / 1000) > row.expires_at) {
    return Response.json({ error: 'not_authenticated' }, { status: 401 });
  }
  return Response.json({ email: row.email, name: row.display_name });
}

// ------------------------------------------------------------
// 4. /oauth/logout — encerra a sessão
// ------------------------------------------------------------
async function handleLogout(request, env) {
  const sessionId = getCookie(request, '__Host-session');
  if (sessionId) {
    const sessionHash = await sha256Hex(sessionId);
    await env.DB.prepare(`DELETE FROM sessions WHERE id_hash = ?`).bind(sessionHash).run();
  }
  const headers = new Headers();
  headers.set('Location', '/');
  headers.append('Set-Cookie', buildCookie('__Host-session', '', 0));
  return new Response(null, { status: 302, headers });
}

// ------------------------------------------------------------
// 5. Validação do ID token do Google (JWT assinado com RS256)
// ------------------------------------------------------------
async function verifyGoogleIdToken(idToken, expectedAudience) {
  const [headerB64, payloadB64, signatureB64] = idToken.split('.');
  if (!headerB64 || !payloadB64 || !signatureB64) throw new Error('ID token malformado.');

  const header = JSON.parse(base64UrlDecode(headerB64));
  const payload = JSON.parse(base64UrlDecode(payloadB64));

  if (payload.iss !== GOOGLE_ISSUER && payload.iss !== 'accounts.google.com') throw new Error('Emissor (iss) inesperado.');
  if (payload.aud !== expectedAudience) throw new Error('Audiência (aud) não corresponde ao Client ID.');
  if (payload.exp < Math.floor(Date.now() / 1000)) throw new Error('ID token expirado.');

  const jwks = await (await fetch(GOOGLE_JWKS_ENDPOINT)).json();
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error('Chave pública correspondente não encontrada.');

  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const signedData = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = base64UrlToArrayBuffer(signatureB64);

  const valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, signedData);
  if (!valid) throw new Error('Assinatura do ID token inválida.');

  return payload;
}

// ------------------------------------------------------------
// 6. Utilitários: cookies, hashes e tokens aleatórios
// ------------------------------------------------------------
function buildCookie(name, value, maxAgeSeconds) {
  return `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${maxAgeSeconds}`;
}
function getCookie(request, name) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? match[1] : null;
}
function randomToken(bytes = 32) {
  const array = new Uint8Array(bytes);
  crypto.getRandomValues(array);
  return base64UrlEncode(array);
}
async function sha256Hex(input) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return [...new Uint8Array(hashBuffer)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
async function sha256Base64Url(input) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return base64UrlEncode(new Uint8Array(hashBuffer));
}
function base64UrlEncode(bytes) {
  let binary = '';
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return atob(str);
}
function base64UrlToArrayBuffer(str) {
  const binary = base64UrlDecode(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
