const crypto = require('crypto');

const GH_API = 'https://api.github.com';
const SESSION_TTL = 24 * 60 * 60 * 1000;

function sign(data) {
  return crypto
    .createHmac('sha256', process.env.SESSION_SECRET || 'default-secret')
    .update(data)
    .digest('hex');
}

function makeToken() {
  const payload = Buffer.from(
    JSON.stringify({ t: Date.now() })
  ).toString('base64url');
  return payload + '.' + sign(payload);
}

function verifyToken(token) {
  if (!token) return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [payload, sig] = parts;
  if (sign(payload) !== sig) return false;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (Date.now() - data.t > SESSION_TTL) return false;
    return true;
  } catch (e) {
    return false;
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
    if (req.readableEnded || req.complete) return resolve('');
    let data = '';
    req.on('data', function (c) { data += c.toString(); });
    req.on('end', function () { resolve(data); });
    req.on('error', function () { resolve(''); });
  });
}

async function parseBody(req) {
  if (req.body) {
    if (typeof req.body === 'object' && !Buffer.isBuffer(req.body)) return req.body;
    if (typeof req.body === 'string') {
      try { return JSON.parse(req.body); } catch (e) {}
    }
    if (Buffer.isBuffer(req.body)) {
      try { return JSON.parse(req.body.toString('utf-8')); } catch (e) {}
    }
  }
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
  const res = await fetch(GH_API + path, {
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

function cleanPath(p) {
  return String(p || '').replace(/^\/+|\/+$/g, '');
}

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') return res.status(200).end();

  const body = await parseBody(req);
  const action = String(body.action || '');
  const cookies = parseCookies(req);

  // ============ LOGIN (password only) ============
  if (action === 'login') {
    const password = String(body.password || '').trim();
    const expected = String(process.env.AKSES_PW || '').trim();

    if (!expected) {
      return res.status(500).json({
        ok: false,
        error: 'AKSES_PW belum di-set di Vercel Environment Variables. Set dulu lalu Redeploy (uncheck cache).'
      });
    }

    if (password === expected) {
      const token = makeToken();
      res.setHeader(
        'Set-Cookie',
        'session=' + token +
        '; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax; Secure'
      );
      return res.status(200).json({ ok: true });
    }

    return res.status(401).json({
      ok: false,
      error: 'Password salah'
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
    const loggedIn = verifyToken(cookies.session);
    return res.status(200).json({ ok: true, loggedIn: loggedIn });
  }

  // ============ PROTECTED ============
  if (!verifyToken(cookies.session)) {
    return res.status(401).json({ ok: false, error: 'Belum login' });
  }

  if (!process.env.GITHUB_TOKEN) {
    return res.status(500).json({
      ok: false,
      error: 'GITHUB_TOKEN belum di-set di Vercel'
    });
  }

  try {
    // ============ LIST REPOS ============
    if (action === 'listRepos') {
      const r = await ghFetch(
        '/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member'
      );
      if (!r.ok) {
        return res.status(r.status).json({
          ok: false,
          error: r.data.message || 'Gagal ambil daftar repo. Cek scope token (harus `repo`).'
        });
      }
      const items = Array.isArray(r.data) ? r.data : [];
      return res.status(200).json({
        ok: true,
        repos: items.map(function (x) {
          return {
            full_name: x.full_name,
            name: x.name,
            owner: x.owner ? x.owner.login : '',
            private: !!x.private,
            default_branch: x.default_branch || 'main',
            updated_at: x.updated_at,
            language: x.language,
            description: x.description
          };
        })
      });
    }

    // ============ FILE ACTIONS ============
    const repoFull = String(body.repo || '').trim();
    if (!repoFull || repoFull.indexOf('/') === -1) {
      return res.status(400).json({ ok: false, error: 'Repo belum dipilih' });
    }

    const parts = repoFull.split('/');
    const owner = parts[0];
    const repo = parts.slice(1).join('/');
    const branch = String(body.branch || 'main');
    const base = '/repos/' + owner + '/' + repo + '/contents';

    if (action === 'list') {
      const path = cleanPath(body.path);
      const url = (path ? base + '/' + path : base) +
        '?ref=' + encodeURIComponent(branch);
      const r = await ghFetch(url);
      if (!r.ok) {
        return res.status(r.status).json({
          ok: false,
          error: r.data.message || 'Gagal baca folder',
          notFound: r.status === 404
        });
      }
      const arr = Array.isArray(r.data) ? r.data : [r.data];
      return res.status(200).json({
        ok: true,
        items: arr.map(function (i) {
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
      const path = cleanPath(body.path);
      if (!path) return res.status(400).json({ ok: false, error: 'Path file wajib diisi' });

      const r = await ghFetch(
        base + '/' + path + '?ref=' + encodeURIComponent(branch)
      );
      if (!r.ok) {
        return res.status(r.status).json({
          ok: false,
          error: r.data.message || 'File tidak ditemukan',
          notFound: r.status === 404
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
      const path = cleanPath(body.path);
      const content = body.content === undefined ? '' : String(body.content);
      const message = String(body.message || 'Update ' + path + ' via Fortech Panel');

      if (!path) return res.status(400).json({ ok: false, error: 'Path file wajib diisi' });

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
          error: r.data.message || 'Gagal simpan'
        });
      }
      return res.status(200).json({ ok: true });
    }

    if (action === 'delete') {
      const path = cleanPath(body.path);
      if (!path) return res.status(400).json({ ok: false, error: 'Path file wajib diisi' });

      const g = await ghFetch(base + '/' + path + '?ref=' + encodeURIComponent(branch));
      if (!g.ok) return res.status(404).json({ ok: false, error: 'File tidak ditemukan' });

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
          error: r.data.message || 'Gagal hapus'
        });
      }
      return res.status(200).json({ ok: true });
    }

    if (action === 'exists') {
      const path = cleanPath(body.path);
      if (!path) return res.status(400).json({ ok: false, error: 'Path file wajib diisi' });
      const g = await ghFetch(base + '/' + path + '?ref=' + encodeURIComponent(branch));
      return res.status(200).json({ ok: true, exists: !!g.ok });
    }

    return res.status(400).json({ ok: false, error: 'Action tidak dikenal' });

  } catch (e) {
    return res.status(500).json({
      ok: false,
      error: e && e.message ? e.message : 'Server error'
    });
  }
};
