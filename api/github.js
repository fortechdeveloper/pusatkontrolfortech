/* =========================================================
   FORTECH CONTROL — GitHub Proxy
   Fix: robust body forwarding + detailed error
   ========================================================= */

const GITHUB_API = 'https://api.github.com';

const ALLOWED_PREFIXES = [
  '/repos/',
  '/user',
  '/rate_limit',
  '/orgs/',
  '/users/'
];

/* ---------- Ambil raw body dari request (support semua format) ---------- */
async function getRawBody(req) {
  // Kalau Vercel udah parse jadi object
  if (req.body !== undefined && req.body !== null && req.body !== '') {
    if (typeof req.body === 'string') return req.body;
    if (Buffer.isBuffer(req.body)) return req.body.toString('utf8');
    // Object → stringify
    try { return JSON.stringify(req.body); }
    catch { return ''; }
  }

  // Fallback: baca stream manual
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
    // Timeout biar gak hang
    setTimeout(() => resolve(''), 5000);
  });
}

export default async function handler(req, res) {
  // ---------- CORS ----------
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(204).end();

  // ---------- ENV ----------
  const token = process.env.GITHUB_TOKEN;
  if (!token) {
    return res.status(500).json({
      error: 'GITHUB_TOKEN belum di-set di Vercel Environment Variables.'
    });
  }

  // ---------- PATH VALIDATION ----------
  const rawPath = req.query.path;
  if (!rawPath || typeof rawPath !== 'string') {
    return res.status(400).json({ error: 'Parameter "path" wajib diisi.' });
  }

  const ghPath = rawPath.startsWith('/') ? rawPath : '/' + rawPath;

  const isAllowed = ALLOWED_PREFIXES.some(p => ghPath.startsWith(p));
  if (!isAllowed) {
    return res.status(403).json({ error: 'Path tidak diizinkan oleh proxy.' });
  }

  if (ghPath.includes('..') || ghPath.includes('//')) {
    return res.status(400).json({ error: 'Path tidak valid.' });
  }

  // ---------- BUILD TARGET ----------
  const targetUrl = GITHUB_API + ghPath;

  const headers = {
    'Accept': 'application/vnd.github+json',
    'Authorization': `Bearer ${token}`,
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'Fortech-Control'
  };

  const fetchOpts = {
    method: req.method,
    headers
  };

  // ---------- FORWARD BODY ----------
  const hasBody = ['PUT', 'POST', 'DELETE', 'PATCH'].includes(req.method);

  if (hasBody) {
    try {
      const bodyStr = await getRawBody(req);
      if (bodyStr) {
        fetchOpts.body = bodyStr;
        headers['Content-Type'] = 'application/json';
      }
    } catch (e) {
      console.error('[proxy] body read error:', e);
      return res.status(400).json({ error: 'Gagal baca body request: ' + e.message });
    }
  }

  // ---------- FORWARD KE GITHUB ----------
  try {
    console.log(`[proxy] ${req.method} ${ghPath}`);

    const ghRes = await fetch(targetUrl, fetchOpts);
    const text = await ghRes.text();

    const ct = ghRes.headers.get('content-type') || 'application/json';
    res.setHeader('Content-Type', ct);

    // Teruskan rate limit
    const rlRemaining = ghRes.headers.get('x-ratelimit-remaining');
    const rlLimit = ghRes.headers.get('x-ratelimit-limit');
    if (rlRemaining) res.setHeader('X-RateLimit-Remaining', rlRemaining);
    if (rlLimit) res.setHeader('X-RateLimit-Limit', rlLimit);

    // Log error dari GitHub biar keliatan di Vercel logs
    if (ghRes.status >= 400) {
      console.error(`[proxy] GitHub ${ghRes.status}:`, text.slice(0, 500));
    }

    return res.status(ghRes.status).send(text);
  } catch (err) {
    console.error('[proxy error]', err);
    return res.status(502).json({
      error: 'Gagal menghubungi GitHub: ' + err.message
    });
  }
}

// Naikin limit durasi
export const config = {
  maxDuration: 30
};