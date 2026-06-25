// /api/check-code.js
// Vercel serverless function — verifies an invite code against a LIST of
// valid codes, without ever sending that list to the browser. The codes
// live only in the INVITE_CODES environment variable on Vercel's servers.
//
// On success, returns a short-lived signed token (not just `true`). The
// front-end stores this token and the server can verify it again later
// without needing to re-send any code. A bare `{ ok: true }` response would
// be just as fake as a client-side check, since anyone could replay it —
// signing a token ties the "unlocked" state to something only the server
// could have produced.

const crypto = require('crypto');

function sign(payload, secret) {
  const data = JSON.stringify(payload);
  const sig = crypto.createHmac('sha256', secret).update(data).digest('hex');
  return Buffer.from(data).toString('base64url') + '.' + sig;
}

function verify(token, secret) {
  try {
    const [dataB64, sig] = token.split('.');
    const data = Buffer.from(dataB64, 'base64url').toString('utf8');
    const expectedSig = crypto.createHmac('sha256', secret).update(data).digest('hex');
    if (sig !== expectedSig) return null;
    const payload = JSON.parse(data);
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

// Constant-time-ish comparison between two strings of possibly different
// length. Pads both to the length of the longer one before comparing, so
// the comparison itself doesn't short-circuit on length mismatch alone.
function safeEqual(a, b) {
  const len = Math.max(a.length, b.length, 1);
  const bufA = Buffer.from(a.padEnd(len, '\0'));
  const bufB = Buffer.from(b.padEnd(len, '\0'));
  return a.length === b.length && crypto.timingSafeEqual(bufA, bufB);
}

function getValidCodes() {
  const raw = process.env.INVITE_CODES || process.env.INVITE_CODE || '';
  return raw
    .split(',')
    .map(c => c.trim())
    .filter(c => c.length > 0);
}

module.exports = async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  if (req.method !== 'POST') {
    res.statusCode = 405;
    return res.end(JSON.stringify({ ok: false, error: 'Method not allowed' }));
  }

  const SECRET_KEY = process.env.SECRET_KEY;
  const validCodes = getValidCodes();

  if (!SECRET_KEY || validCodes.length === 0) {
    res.statusCode = 500;
    return res.end(JSON.stringify({
      ok: false,
      error: 'Server is not configured. Set INVITE_CODES and SECRET_KEY environment variables in Vercel.'
    }));
  }

  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch (e) { body = {}; }
  }
  body = body || {};

  // Mode 1: verifying a session token (page reload / revisit)
  if (body.token) {
    const payload = verify(body.token, SECRET_KEY);
    if (payload && payload.unlocked) {
      res.statusCode = 200;
      return res.end(JSON.stringify({ ok: true }));
    }
    res.statusCode = 401;
    return res.end(JSON.stringify({ ok: false, error: 'Session expired or invalid' }));
  }

  // Mode 2: checking a freshly entered invite code against the full list.
  // Every candidate is checked (no early return on first match) so the
  // response time doesn't hint at which position in the list matched.
  const submitted = (body.code || '').trim();
  let matched = false;
  for (const candidate of validCodes) {
    if (submitted.length > 0 && safeEqual(submitted, candidate)) {
      matched = true;
    }
  }

  if (!matched) {
    res.statusCode = 401;
    return res.end(JSON.stringify({ ok: false, error: 'Invalid invite code' }));
  }

  // Issue a signed token valid for 24 hours so the visitor isn't asked
  // again on every reload, without storing any code client-side.
  const token = sign({ unlocked: true, exp: Date.now() + 24 * 60 * 60 * 1000 }, SECRET_KEY);

  res.statusCode = 200;
  return res.end(JSON.stringify({ ok: true, token }));
};
