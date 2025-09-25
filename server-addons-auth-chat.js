// server-addons-auth-chat.js
// Add email+password member auth (keeps your admin PIN), plus a simple "All Members" group chat.
// ───────────────────────────────────────────────────────────────────────────────
// Install deps (once):  npm i bcryptjs jsonwebtoken
// Mount in your server:
//   const createAuthChat = require('./server-addons-auth-chat');
//   const store = { members: [], meetings: [], messages: [] }; // replace with your DB
//   app.use(createAuthChat({ store, adminPin: process.env.ADMIN_PIN, jwtSecret: process.env.JWT_SECRET || 'change-me' }));
//
// Endpoints provided:
//
//  Auth (members):
//   - POST /auth/signup-email        {email, password, name?, phone?} → {ok, status:'pending', memberId}
//   - POST /auth/login-email         {email, password} → {ok, token, member}
//   - POST /auth/change-password     (Bearer) {current, newPassword} → {ok}
//
//  Admin (PIN header):
//   - POST /admin/create-member      (x-admin-pin) {name?, email, phone?, tempPassword, isAdmin?} → {ok, memberId}
//   - POST /admin/set-password       (x-admin-pin) {memberId, password} → {ok}
//
//  Member info / meetings (member Bearer):
//   - GET  /me                       (Bearer) → {ok, member}
//   - GET  /meetings                 (Bearer) → {ok, meetings}   // uses store.meetings if you don’t already have this
//
//  Chat (admin via x-admin-pin OR member via Bearer):
//   - GET  /chat/rooms               → [{id:'all', name:'All Members'}]
//   - GET  /chat/messages?roomId=all&cursor=ISO8601 → {messages:[...], cursor}
//   - POST /chat/send                {roomId:'all', text} → {ok, id}
//
// Replace the in-memory "store" with your real DB when ready (keep the same shapes).

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

module.exports = function createAuthChat({ store, adminPin, jwtSecret }) {
  if (!store) throw new Error('createAuthChat: "store" is required');
  if (!adminPin) console.warn('[auth-chat] Warning: adminPin not provided');
  if (!jwtSecret) console.warn('[auth-chat] Warning: jwtSecret not provided');

  const r = express.Router();
  r.use(express.json());

  // ───────────────────────── Helpers
  const sign = (m) =>
    jwt.sign(
      { sub: m.id, email: m.email, role: m.isAdmin ? 'admin' : 'member' },
      jwtSecret,
      { expiresIn: '12h' }
    );

  function bearer(req) {
    const h = req.headers.authorization || '';
    return h.startsWith('Bearer ') ? h.slice(7) : null;
  }

  function requireAuth(req, res, next) {
    const tok = bearer(req);
    if (!tok) return res.status(401).json({ ok: false, error: 'auth required' });
    try {
      req.user = jwt.verify(tok, jwtSecret);
      next();
    } catch {
      return res.status(401).json({ ok: false, error: 'invalid token' });
    }
  }

  function requireApproved(req, res, next) {
    const m = (store.members || []).find((x) => x.id === req.user.sub);
    if (!m) return res.status(401).json({ ok: false, error: 'auth required' });
    if (m.status !== 'approved') return res.status(403).json({ ok: false, error: 'pending' });
    req.member = m;
    next();
  }

  function requireAdmin(req, res, next) {
    const pin = req.headers['x-admin-pin'];
    if (!pin || pin !== adminPin) return res.status(401).json({ ok: false, error: 'admin auth required' });
    next();
  }

  // Allow either admin (via PIN) or member (via Bearer) to use chat endpoints.
  function requireAdminOrMember(req, res, next) {
    const pin = req.headers['x-admin-pin'];
    if (pin && pin === adminPin) {
      req.from = 'admin';
      return next();
    }
    return requireAuth(req, res, () => requireApproved(req, res, () => {
      req.from = 'member';
      next();
    }));
  }

  // Normalize email to lowercase for uniqueness checks
  function normEmail(e) {
    return String(e || '').trim().toLowerCase();
  }

  // ───────────────────────── Email + Password auth

  // Self-signup (pending until approved in your existing admin flow)
  r.post('/auth/signup-email', async (req, res) => {
    try {
      const { email, password, name, phone } = req.body || {};
      if (!email || !password) return res.status(400).json({ ok: false, error: 'email & password required' });
      const lower = normEmail(email);
      store.members = store.members || [];
      if (store.members.find((m) => normEmail(m.email) === lower)) {
        return res.status(409).json({ ok: false, error: 'email exists' });
      }
      const id = 'm_' + Date.now().toString(36);
      const passwordHash = await bcrypt.hash(String(password), 10);
      store.members.push({
        id,
        email: lower,
        phone: phone || null,
        name: name || '',
        status: 'pending',
        isAdmin: false,
        passwordHash,
        mustChangePassword: false,
        createdAt: new Date().toISOString(),
      });
      res.json({ ok: true, status: 'pending', memberId: id });
    } catch (e) {
      res.status(500).json({ ok: false, error: 'server error' });
    }
  });

  // Email login (approved members only)
  r.post('/auth/login-email', async (req, res) => {
    try {
      const { email, password } = req.body || {};
      const lower = normEmail(email);
      const m = (store.members || []).find((x) => normEmail(x.email) === lower);
      if (!m || !m.passwordHash) return res.status(400).json({ ok: false, error: 'invalid credentials' });
      const ok = await bcrypt.compare(String(password || ''), m.passwordHash);
      if (!ok) return res.status(400).json({ ok: false, error: 'invalid credentials' });
      if (m.status !== 'approved') return res.status(403).json({ ok: false, error: 'pending' });
      const token = sign(m);
      res.json({ ok: true, token, member: { id: m.id, name: m.name, email: m.email, isAdmin: !!m.isAdmin } });
    } catch (e) {
      res.status(500).json({ ok: false, error: 'server error' });
    }
  });

  // Member change password (requires current password)
  r.post('/auth/change-password', requireAuth, requireApproved, async (req, res) => {
    try {
      const { current, newPassword } = req.body || {};
      if (!newPassword) return res.status(400).json({ ok: false, error: 'newPassword required' });
      const m = req.member;
      if (m.passwordHash) {
        const ok = await bcrypt.compare(String(current || ''), m.passwordHash);
        if (!ok) return res.status(400).json({ ok: false, error: 'bad current password' });
      }
      m.passwordHash = await bcrypt.hash(String(newPassword), 10);
      m.mustChangePassword = false;
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ ok: false, error: 'server error' });
    }
  });

  // ───────────────────────── Admin creates/updates credentials

  // Create an approved member with a temp password (optionally make admin)
  r.post('/admin/create-member', requireAdmin, async (req, res) => {
    try {
      const { name, email, phone, tempPassword, isAdmin } = req.body || {};
      if (!email || !tempPassword)
        return res.status(400).json({ ok: false, error: 'email & tempPassword required' });
      const lower = normEmail(email);
      store.members = store.members || [];
      if (store.members.find((m) => normEmail(m.email) === lower))
        return res.status(409).json({ ok: false, error: 'email exists' });
      const id = 'm_' + Date.now().toString(36);
      const passwordHash = await bcrypt.hash(String(tempPassword), 10);
      store.members.push({
        id,
        name: name || '',
        email: lower,
        phone: phone || null,
        status: 'approved',
        isAdmin: !!isAdmin,
        passwordHash,
        mustChangePassword: true,
        createdAt: new Date().toISOString(),
      });
      res.json({ ok: true, memberId: id });
    } catch (e) {
      res.status(500).json({ ok: false, error: 'server error' });
    }
  });

  // Set/Reset a member password (forces change on next login if you want to check that flag in UI)
  r.post('/admin/set-password', requireAdmin, async (req, res) => {
    try {
      const { memberId, password } = req.body || {};
      const m = (store.members || []).find((x) => x.id === memberId);
      if (!m) return res.status(404).json({ ok: false, error: 'not found' });
      m.passwordHash = await bcrypt.hash(String(password), 10);
      m.mustChangePassword = true;
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ ok: false, error: 'server error' });
    }
  });

  // ───────────────────────── Member profile & meetings

  r.get('/me', requireAuth, requireApproved, (req, res) => {
    const m = req.member;
    res.json({
      ok: true,
      member: {
        id: m.id,
        name: m.name,
        email: m.email,
        isAdmin: !!m.isAdmin,
        mustChangePassword: !!m.mustChangePassword,
      },
    });
  });

  // If your app already has GET /meetings (Bearer) implemented, Express will use the first match.
  // You can remove this handler if it conflicts with your existing one.
  r.get('/meetings', requireAuth, requireApproved, (req, res) => {
    res.json({ ok: true, meetings: store.meetings || [] });
  });

  // ───────────────────────── Group chat (single "All Members" room)

  r.get('/chat/rooms', requireAdminOrMember, (req, res) => {
    res.json([{ id: 'all', name: 'All Members' }]);
  });

  // Cursor is an ISO8601 timestamp; returns messages after that timestamp (up to last 200)
  r.get('/chat/messages', requireAdminOrMember, (req, res) => {
    const { roomId = 'all', cursor } = req.query || {};
    store.messages = store.messages || [];
    const all = store.messages.filter((m) => m.roomId === roomId);
    const since = cursor ? new Date(cursor).getTime() : 0;
    const out = all.filter((m) => new Date(m.ts).getTime() > since).slice(-200);
    const last = out.at(-1)?.ts || cursor || new Date(0).toISOString();
    res.json({ messages: out, cursor: last });
  });

  r.post('/chat/send', requireAdminOrMember, (req, res) => {
    const { roomId = 'all', text } = req.body || {};
    if (!text) return res.status(400).json({ ok: false, error: 'text required' });

    let author = { id: 'admin', name: 'Admin', role: 'admin' };
    if (req.from === 'member') {
      const m = (store.members || []).find((x) => x.id === req.user.sub);
      author = { id: m.id, name: m.name || m.email, role: 'member' };
    }

    const msg = {
      id: 'msg_' + Date.now().toString(36),
      roomId,
      text: String(text),
      fromId: author.id,
      fromName: author.name,
      role: author.role,
      ts: new Date().toISOString(),
    };
    store.messages = store.messages || [];
    store.messages.push(msg);
    res.json({ ok: true, id: msg.id });
  });

  return r;
};
export default createAuthChat;

