/* =========================================================
   FORTECH CONTROL — Auth Proxy
   Vercel Serverless Function
   ENV: AKSES_PW (wajib di-set di Vercel)
   ========================================================= */

import crypto from 'crypto';

const TOKEN_SALT = 'fortech-control-auth-v1';

export default async function handler(req, res) {
  // ---------- CORS ----------
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // ---------- ENV CHECK ----------
  const expected = process.env.AKSES_PW;
  if (!expected) {
    return res.status(500).json({
      ok: false,
      error: 'AKSES_PW belum di-set di Vercel Environment Variables.'
    });
  }

  // ---------- PARSE BODY ----------
  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body || '{}'); } catch { body = {}; }
  }
  body = body || {};

  const { password, token } = body;

  // ---------- MODE 1: verify token (auto-login) ----------
  if (token && typeof token === 'string') {
    const expectedToken = crypto
      .createHmac('sha256', expected)
      .update(TOKEN_SALT)
      .digest('hex');

    const a = Buffer.from(token);
    const b = Buffer.from(expectedToken);

    if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
      return res.status(200).json({ ok: true, valid: true });
    }
    return res.status(401).json({ ok: false, valid: false, error: 'Token tidak valid.' });
  }

  // ---------- MODE 2: verify password ----------
  if (!password || typeof password !== 'string') {
    return res.status(400).json({ ok: false, error: 'Password wajib diisi.' });
  }

  const a = Buffer.from(password);
  const b = Buffer.from(expected);

  let match = false;
  if (a.length === b.length) {
    match = crypto.timingSafeEqual(a, b);
  }

  if (!match) {
    return res.status(401).json({ ok: false, error: 'Password salah.' });
  }

  // Generate token buat auto-login
  const newToken = crypto
    .createHmac('sha256', expected)
    .update(TOKEN_SALT)
    .digest('hex');

  return res.status(200).json({ ok: true, token: newToken });
}