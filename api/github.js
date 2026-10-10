/* =========================================================
   FORTECH CONTROL - GitHub API Proxy
   Vercel Serverless Function
   Token disimpan di ENV: GITHUB_TOKEN
   ========================================================= */

const GITHUB_API = 'https://api.github.com';

// Path yang diizinkan dilewatkan (security filter)
const ALLOWED_PREFIXES = [
  '/repos/',
  '/user',
  '/rate_limit',
  '/orgs/'
];

export default async function handler(req, res) {
  // ---------- CORS ----------
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  // ---------- ENV CHECK ----------
  const token = process.env.GITHUB_TOKEN;
  if (!token) {
    return res.status(500).json({
      error: 'GITHUB_TOKEN belum di-set di Vercel Environment Variables.'
    });
  }

  // ---------- VALIDASI PATH ----------
  const rawPath = req.query.path;
  if (!rawPath || typeof rawPath !== 'string') {
    return res.status(400).json({ error: 'Parameter "path" wajib diisi.' });
  }

  // Normalisasi: pastikan path dimulai dari /
  const ghPath = rawPath.startsWith('/') ? rawPath : '/' + rawPath;

  // Security: hanya izinkan prefix tertentu
  const isAllowed = ALLOWED_PREFIXES.some(p => ghPath.startsWith(p));
  if (!isAllowed) {
    return res.status(403).json({
      error: 'Path tidak diizinkan oleh proxy.'
    });
  }

  // Cegah double-slash / traversal aneh
  if (ghPath.includes('..') || ghPath.includes('//')) {
    return res.status(400).json({ error: 'Path tidak valid.' });
  }

  // ---------- BUILD REQUEST ----------
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

  // Body untuk PUT/POST/DELETE
  if (['PUT', 'POST', 'DELETE', 'PATCH'].includes(req.method)) {
    headers['Content-Type'] = 'application/json';

    if (req.body) {
      fetchOpts.body =
        typeof req.body === 'string'
          ? req.body
          : JSON.stringify(req.body);
    }
  }

  // ---------- FORWARD ----------
  try {
    const ghRes = await fetch(targetUrl, fetchOpts);
    const text = await ghRes.text();

    // Teruskan content-type asli
    const ct = ghRes.headers.get('content-type') || 'application/json';
    res.setHeader('Content-Type', ct);

    // Teruskan rate-limit headers biar bisa dimonitor
    const rlRemaining = ghRes.headers.get('x-ratelimit-remaining');
    const rlLimit = ghRes.headers.get('x-ratelimit-limit');
    if (rlRemaining) res.setHeader('X-RateLimit-Remaining', rlRemaining);
    if (rlLimit) res.setHeader('X-RateLimit-Limit', rlLimit);

    return res.status(ghRes.status).send(text);
  } catch (err) {
    console.error('[proxy error]', err);
    return res.status(502).json({
      error: 'Gagal menghubungi GitHub: ' + err.message
    });
  }
}
