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
    if (req.readableEnded || req.complete) {
      return resolve('');
    }
    let data = '';
    req.on('data', function (chunk) { data += chunk.toString(); });
    req.on('end', function () { resolve(data); });
    req.on('error', function () { resolve(''); });
  });
}

async function parseBody(req) {
  // 1. Cek kalau Vercel sudah parse
  if (req.body) {
    if (typeof req.body === 'object' && !Buffer.isBuffer(req.body)) {
      return req.body;
    }
    if (typeof req.body === 'string') {
      try { return JSON.parse(req.body); } catch (e) {}
    }
    if (Buffer.isBuffer(req.body)) {
      try { return JSON.parse(req.body.toString('utf-8')); } catch (e) {}
    }
  }
  // 2. Fallback: baca stream
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
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const body = await parseBody(req);
  const action = (body && body.action) ? String(body.action) : '';
  const cookies = parseCookies(req);

  // ============ DEBUG (HAPUS SETELAH BERES) ============
  if (action === 'debug') {
    return res.status(200).json({
      ok: true,
      debug: {
        method: req.method,
        bodyRaw: req.body,
        bodyParsed: body,
        action: action,
        env: {
          hasAdminUser: !!process.env.ADMIN_USER,
          hasAdminPass: !!process.env.ADMIN_PASS,
          adminUserLength: process.env.ADMIN_USER ? process.env.ADMIN_USER.length : 0,
          adminPassLength: process.env.ADMIN_PASS ? process.env.ADMIN_PASS.length : 0,
          adminUserFirst: process.env.ADMIN_USER ? process.env.ADMIN_USER[0] : null,
          adminUserLast: process.env.ADMIN_USER ? process.env.ADMIN_USER[process.env.ADMIN_USER.length - 1] : null,
          hasGithubToken: !!process.env.GITHUB_TOKEN,
          hasOwner: !!process.env.GITHUB_OWNER,
          hasRepo: !!process.env.GITHUB_REPO,
          hasSessionSecret: !!process.env.SESSION_SECRET,
          owner: process.env.GITHUB_OWNER || null,
          repo: process.env.GITHUB_REPO || null,
          branch: process.env.GITHUB_BRANCH || null
        }
      }
    });
  }

  // ============ LOGIN ============
  if (action === 'login') {
    const username = String(body.username || '').trim();
    const password = String(body.password || '').trim();

    const expectedUser = String(process.env.ADMIN_USER || '').trim();
    const expectedPass = String(process.env.ADMIN_PASS || '').trim();

    if (!expectedUser || !expectedPass) {
      return res.status(500).json({
        ok: false,
        error: 'ADMIN_USER atau ADMIN_PASS belum di-set di Vercel Environment Variables. Set dulu lalu Redeploy.'
      });
    }

    if (username === expectedUser && password === expectedPass) {
      const token = makeToken(username);
      res.setHeader(
        'Set-Cookie',
        'session=' + token +
        '; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax; Secure'
      );
      return res.status(200).json({ ok: true });
    }

    // Debug info kalau gagal (jangan expose value asli)
    return res.status(401).json({
      ok: false,
      error: 'Username atau password salah',
      debug: {
        inputUserLength: username.length,
        inputPassLength: password.length,
        expectedUserLength: expectedUser.length,
        expectedPassLength: expectedPass.length,
        userMatch: username === expectedUser,
        passMatch: password === expectedPass,
        hint: 'Panjang karakter beda? Berarti ada spasi/tipografi di env. Cek ulang.'
      }
    });
  }

  // ============ LOGOUT ============
  if (action === 'logout') {
    res.setHeader(
      'Set-Cookie',
      'session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax; Secure'
    );
    return res.status(200).json({ ok: true });
  }

  // ============ CHECK ============
  if (action === 'check') {
    const user = verifyToken(cookies.session);
    return res.status(200).json({
      ok: true,
      loggedIn: !!user,
      user: user
    });
  }

  // ============ PROTECTED ============
  const user = verifyToken(cookies.session);
  if (!user) {
    return res.status(401).json({ ok: false, error: 'Belum login' });
  }

  if (!action) {
    return res.status(400).json({ ok: false, error: 'Action wajib diisi' });
  }

  const owner = process.env.GITHUB_OWNER;
  const repo = process.env.GITHUB_REPO;
  const branch = process.env.GITHUB_BRANCH || 'main';

  if (!owner || !repo) {
    return res.status(500).json({
      ok: false,
      error: 'GITHUB_OWNER / GITHUB_REPO belum di-set'
    });
  }

  if (!process.env.GITHUB_TOKEN) {
    return res.status(500).json({
      ok: false,
      error: 'GITHUB_TOKEN belum di-set'
    });
  }

  const base = '/repos/' + owner + '/' + repo + '/contents';

  try {
    if (action === 'list') {
      const path = String(body.path || '').replace(/^\/+|\/+$/g, '');
      const url = buildContentUrl(base, path) + '?ref=' + encodeURIComponent(branch);
      const r = await ghFetch(url);
      if (!r.ok) {
        return res.status(r.status).json({
          ok: false,
          error: r.data.message || 'Gagal membaca folder'
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

    if (action === 'read') {
      const path = String(body.path || '').replace(/^\/+|\/+$/g, '');
      if (!path) {
        return res.status(400).json({ ok: false, error: 'Path file wajib diisi' });
      }
      const r = await ghFetch(base + '/' + path + '?ref=' + encodeURIComponent(branch));
      if (!r.ok) {
        return res.status(r.status).json({
          ok: false,
          error: r.data.message || 'File tidak ditemukan'
        });
      }
      if (r.data.type !== 'file') {
        return res.status(400).json({ ok: false, error: 'Bukan file' });
      }
      const content = Buffer.from(r.data.content || '', 'base64').toString('utf-8');
      return res.status(200).json({
        ok: true,
        content: content,
        sha: r.data.sha,
        path: r.data.path
      });
    }

    if (action === 'write') {
      const path = String(body.path || '').replace(/^\/+|\/+$/g, '');
      const content = body.content === undefined ? '' : String(body.content);
      const message = String(body.message || 'Update ' + path + ' via Fortech Panel');

      if (!path) {
        return res.status(400).json({ ok: false, error: 'Path file wajib diisi' });
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
          error: r.data.message || 'Gagal menyimpan'
        });
      }
      return res.status(200).json({ ok: true });
    }

    if (action === 'delete') {
      const path = String(body.path || '').replace(/^\/+|\/+$/g, '');
      if (!path) {
        return res.status(400).json({ ok: false, error: 'Path file wajib diisi' });
      }
      const g = await ghFetch(base + '/' + path + '?ref=' + encodeURIComponent(branch));
      if (!g.ok) {
        return res.status(404).json({ ok: false, error: 'File tidak ditemukan' });
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
          error: r.data.message || 'Gagal menghapus'
        });
      }
      return res.status(200).json({ ok: true });
    }

    if (action === 'exists') {
      const path = String(body.path || '').replace(/^\/+|\/+$/g, '');
      if (!path) {
        return res.status(400).json({ ok: false, error: 'Path file wajib diisi' });
      }
      const g = await ghFetch(base + '/' + path + '?ref=' + encodeURIComponent(branch));
      return res.status(200).json({ ok: true, exists: !!g.ok });
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
