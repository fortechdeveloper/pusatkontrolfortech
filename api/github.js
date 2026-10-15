const crypto = require('crypto');

const GH_API = 'https://api.github.com';
const SESSION_TTL = 24 * 60 * 60 * 1000;

function sign(data) {
  return crypto
    .createHmac('sha256', process.env.SESSION_SECRET || 'default-secret')
    .update(data)
    .digest('hex');
}

function makeToken(user) {
  const payload = Buffer.from(
    JSON.stringify({ u: user, t: Date.now() })
  ).toString('base64url');
  const sig = sign(payload);
  return payload + '.' + sig;
}

function verifyToken(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payload, sig] = parts;
  if (sign(payload) !== sig) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (Date.now() - data.t > SESSION_TTL) return null;
    return data.u;
  } catch (e) {
    return null;
  }
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach(function (pair) {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  });
  return out;
}

function readRawBody(req) {
  return new Promise(function (resolve) {
    let data = '';
    req.on('data', function (chunk) { data += chunk; });
    req.on('end', function () { resolve(data); });
    req.on('error', function () { resolve(''); });
  });
}

async function parseBody(req) {
  // Vercel kadang sudah parse otomatis
  if (req.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body)) {
    return req.body;
  }
  if (typeof req.body === 'string' && req.body.length > 0) {
    try { return JSON.parse(req.body); } catch (e) { return {}; }
  }
  if (Buffer.isBuffer(req.body)) {
    try { return JSON.parse(req.body.toString('utf-8')); } catch (e) { return {}; }
  }
  // Fallback: baca raw stream
  try {
    const raw = await readRawBody(req);
    if (!raw) return {};
    return JSON.parse(raw);
  } catch (e) {
    return {};
  }
}

async function ghFetch(path, options) {
  options = options || {};
  const url = GH_API + path;
  const res = await fetch(url, {
    method: options.method || 'GET',
    headers: Object.assign(
      {
        Authorization: 'Bearer ' + process.env.GITHUB_TOKEN,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'fortech-panel'
      },
      options.headers || {}
    ),
    body: options.body
  });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); }
  catch (e) { data = { raw: text }; }
  return { ok: res.ok, status: res.status, data: data };
}

function buildContentUrl(base, path) {
  const clean = (path || '').replace(/^\/+|\/+$/g, '');
  if (!clean) return base;
  return base + '/' + clean;
}

module.exports = async function handler(req, res) {
  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    return res.status(200).end();
  }

  const body = await parseBody(req);
  const action = (body && body.action) ? String(body.action) : '';
  const cookies = parseCookies(req);

  // ============ PUBLIC ACTIONS ============
  if (action === 'login') {
    const username = String(body.username || '').trim();
    const password = String(body.password || '').trim();

    if (
      username === process.env.ADMIN_USER &&
      password === process.env.ADMIN_PASS
    ) {
      const token = makeToken(username);
      res.setHeader(
        'Set-Cookie',
        'session=' + token +
        '; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax; Secure'
      );
      return res.status(200).json({ ok: true });
    }
    return res.status(401).json({
      ok: false,
      error: 'Username atau password salah'
    });
  }

  if (action === 'logout') {
    res.setHeader(
      'Set-Cookie',
      'session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax; Secure'
    );
    return res.status(200).json({ ok: true });
  }

  if (action === 'check') {
    const user = verifyToken(cookies.session);
    return res.status(200).json({
      ok: true,
      loggedIn: !!user,
      user: user
    });
  }

  // ============ AUTH REQUIRED ============
  const user = verifyToken(cookies.session);
  if (!user) {
    return res.status(401).json({ ok: false, error: 'Belum login' });
  }

  if (!action) {
    return res.status(400).json({
      ok: false,
      error: 'Action wajib diisi'
    });
  }

  const owner = process.env.GITHUB_OWNER;
  const repo = process.env.GITHUB_REPO;
  const branch = process.env.GITHUB_BRANCH || 'main';

  if (!owner || !repo) {
    return res.status(500).json({
      ok: false,
      error: 'GITHUB_OWNER atau GITHUB_REPO belum di-set di env Vercel'
    });
  }

  if (!process.env.GITHUB_TOKEN) {
    return res.status(500).json({
      ok: false,
      error: 'GITHUB_TOKEN belum di-set di env Vercel'
    });
  }

  const base = '/repos/' + owner + '/' + repo + '/contents';

  try {
    // ============ LIST ============
    if (action === 'list') {
      const path = String(body.path || '').replace(/^\/+|\/+$/g, '');
      const url = buildContentUrl(base, path) + '?ref=' + encodeURIComponent(branch);
      const r = await ghFetch(url);
      if (!r.ok) {
        return res.status(r.status).json({
          ok: false,
          error: r.data.message || 'Gagal membaca folder',
          detail: r.data
        });
      }
      const items = Array.isArray(r.data) ? r.data : [r.data];
      return res.status(200).json({
        ok: true,
        items: items.map(function (i) {
          return {
            name: i.name,
            path: i.path,
            type: i.type,
            size: i.size,
            sha: i.sha
          };
        })
      });
    }

    // ============ READ ============
    if (action === 'read') {
      const path = String(body.path || '').replace(/^\/+|\/+$/g, '');
      if (!path) {
        return res.status(400).json({
          ok: false,
          error: 'Path file wajib diisi'
        });
      }
      const url = base + '/' + path + '?ref=' + encodeURIComponent(branch);
      const r = await ghFetch(url);
      if (!r.ok) {
        return res.status(r.status).json({
          ok: false,
          error: r.data.message || 'File tidak ditemukan',
          detail: r.data
        });
      }
      if (r.data.type !== 'file') {
        return res.status(400).json({
          ok: false,
          error: 'Yang dipilih bukan file'
        });
      }
      const content = Buffer.from(r.data.content || '', 'base64').toString('utf-8');
      return res.status(200).json({
        ok: true,
        content: content,
        sha: r.data.sha,
        path: r.data.path
      });
    }

    // ============ WRITE ============
    if (action === 'write') {
      const path = String(body.path || '').replace(/^\/+|\/+$/g, '');
      const content = body.content === undefined ? '' : String(body.content);
      const message = String(body.message || 'Update ' + path + ' via Fortech Panel');

      if (!path) {
        return res.status(400).json({
          ok: false,
          error: 'Path file wajib diisi'
        });
      }

      let sha;
      const g = await ghFetch(base + '/' + path + '?ref=' + encodeURIComponent(branch));
      if (g.ok && g.data && g.data.sha) sha = g.data.sha;

      const payload = {
        message: message,
        content: Buffer.from(content, 'utf-8').toString('base64'),
        branch: branch
      };
      if (sha) payload.sha = sha;

      const r = await ghFetch(base + '/' + path, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (!r.ok) {
        return res.status(r.status).json({
          ok: false,
          error: r.data.message || 'Gagal menyimpan',
          detail: r.data
        });
      }
      return res.status(200).json({ ok: true });
    }

    // ============ DELETE ============
    if (action === 'delete') {
      const path = String(body.path || '').replace(/^\/+|\/+$/g, '');
      if (!path) {
        return res.status(400).json({
          ok: false,
          error: 'Path file wajib diisi'
        });
      }
      const g = await ghFetch(base + '/' + path + '?ref=' + encodeURIComponent(branch));
      if (!g.ok) {
        return res.status(404).json({
          ok: false,
          error: 'File tidak ditemukan'
        });
      }
      const r = await ghFetch(base + '/' + path, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: 'Delete ' + path + ' via Fortech Panel',
          sha: g.data.sha,
          branch: branch
        })
      });
      if (!r.ok) {
        return res.status(r.status).json({
          ok: false,
          error: r.data.message || 'Gagal menghapus',
          detail: r.data
        });
      }
      return res.status(200).json({ ok: true });
    }

    // ============ EXISTS ============
    if (action === 'exists') {
      const path = String(body.path || '').replace(/^\/+|\/+$/g, '');
      if (!path) {
        return res.status(400).json({
          ok: false,
          error: 'Path file wajib diisi'
        });
      }
      const g = await ghFetch(base + '/' + path + '?ref=' + encodeURIComponent(branch));
      return res.status(200).json({
        ok: true,
        exists: !!g.ok
      });
    }

    return res.status(400).json({
      ok: false,
      error: 'Action tidak dikenal: ' + action
    });

  } catch (e) {
    return res.status(500).json({
      ok: false,
      error: e && e.message ? e.message : 'Server error'
    });
  }
};
