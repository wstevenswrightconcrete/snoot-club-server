// server-addons-auth-chat.js
// Add-on router that provides email/password auth (JWT) and REST chat endpoints,
// wired to your existing LowDB store via the adapter you pass in.
//
// Usage in index.js:
//   import createAuthChat from './server-addons-auth-chat.js'
//   app.use('/addons', createAuthChat({ store, adminPin: ADMIN_PIN, jwtSecret: process.env.JWT_SECRET, io }))
//
// Requires deps: bcryptjs, jsonwebtoken, express, nanoid

import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { nanoid } from 'nanoid';

/**
 * @typedef {Object} StoreAdapter
 * @property {() => Promise<void>} read
 * @property {() => Promise<void>} write
 * @property {() => any[]} getMembers
 * @property {(arr:any[]) => void} setMembers
 * @property {() => any[]} getMessages
 * @property {(arr:any[]) => void} setMessages
 */

/**
 * @param {Object} opts
 * @param {StoreAdapter} opts.store
 * @param {string} opts.adminPin
 * @param {string} opts.jwtSecret
 * @param {import('socket.io').Server} [opts.io]
 * @returns {import('express').Router}
 */
export function createAuthChat({ store, adminPin, jwtSecret = 'dev', io } = {}) {
  const router = express.Router();

  // ------------- helpers -------------
  const now = () => Date.now();

  const isAdminReq = (req) => {
    const pin = (req.headers['x-admin-pin'] || req.query.pin || '').toString().trim();
    return !!pin && pin === adminPin;
  };

  const normalizeEmail = (email) => (email || '').trim().toLowerCase();

  async function findMemberByEmail(emailLower) {
    await store.read();
    const members = store.getMembers();
    return members.find(m => (m.email || '').toLowerCase() === emailLower) || null;
  }

  function signJwt(member) {
    // 30d token; index.js already knows how to accept JWTs for chat/socket
    return jwt.sign(
      { sub: member.id, email: member.email || '', name: member.name || '' },
      jwtSecret,
      { expiresIn: '30d' }
    );
  }

  function requireJwt(req, res, next) {
    try {
      const hdr = req.headers.authorization || '';
      const token = hdr.replace(/^Bearer\s+/i, '');
      if (!token) return res.status(401).json({ ok: false, error: 'auth required' });
      req.jwt = jwt.verify(token, jwtSecret);
      next();
    } catch {
      return res.status(401).json({ ok: false, error: 'invalid token' });
    }
  }

  // ------------- AUTH (email/password + JWT) -------------

  // Self-register (PENDING by default).
  // If called with correct X-Admin-Pin, you can create/approve and/or set password for someone.
  router.post('/auth/register-email', async (req, res) => {
    try {
      const { name = '', email, password, approve = false } = req.body || {};
      const emailLower = normalizeEmail(email);
      if (!emailLower) return res.status(400).json({ ok: false, error: 'email required' });
      if (!password || String(password).length < 6) {
        return res.status(400).json({ ok: false, error: 'password must be ≥ 6 chars' });
      }

      const adminMode = isAdminReq(req);

      await store.read();
      const members = store.getMembers();
      let m = members.find(x => (x.email || '').toLowerCase() === emailLower);

      const pwHash = await bcrypt.hash(String(password), 10);

      if (!m) {
        m = {
          id: nanoid(),
          name: name || '',
          email: emailLower,
          phone: '',
          status: adminMode && approve ? 'approved' : 'pending',
          isAdmin: false,
          createdAt: now(),
          expoTokens: [],
          sessionTokens: [],
          passwordHash: pwHash,
        };
        members.push(m);
      } else {
        // Update existing member's password. If not admin, only allow if they had no password yet.
        if (m.passwordHash && !adminMode) {
          return res.status(409).json({ ok: false, error: 'account already exists' });
        }
        m.name = m.name || name || '';
        m.email = emailLower; // normalized
        m.passwordHash = pwHash;
        if (adminMode && approve) m.status = 'approved';
        // keep all other fields as-is
      }

      store.setMembers(members);
      await store.write();

      return res.json({
        ok: true,
        member: { id: m.id, email: m.email, name: m.name, status: m.status }
      });
    } catch (e) {
      console.error('register-email error', e?.message || e);
      res.status(500).json({ ok: false, error: 'server error' });
    }
  });

  // Admin helper: set/reset a member's password (and optionally approve)
  router.post('/admin/set-password', async (req, res) => {
    if (!isAdminReq(req)) return res.status(401).json({ ok: false, error: 'admin auth required' });
    try {
      const { memberId, email, password, approve = false } = req.body || {};
      const emailLower = normalizeEmail(email);

      if (!password) return res.status(400).json({ ok: false, error: 'password required' });

      await store.read();
      const members = store.getMembers();
      let m = null;

      if (memberId) m = members.find(x => x.id === memberId);
      if (!m && emailLower) m = members.find(x => (x.email || '').toLowerCase() === emailLower);

      if (!m) return res.status(404).json({ ok: false, error: 'member not found' });

      m.passwordHash = await bcrypt.hash(String(password), 10);
      if (approve) m.status = 'approved';

      store.setMembers(members);
      await store.write();

      res.json({ ok: true });
    } catch (e) {
      console.error('admin set-password error', e?.message || e);
      res.status(500).json({ ok: false, error: 'server error' });
    }
  });

  // Email/password login -> JWT
  router.post('/auth/login-email', async (req, res) => {
    try {
      const { email, password } = req.body || {};
      const emailLower = normalizeEmail(email);
      if (!emailLower || !password) return res.status(400).json({ ok: false, error: 'email & password required' });

      const m = await findMemberByEmail(emailLower);
      if (!m || !m.passwordHash) return res.status(401).json({ ok: false, error: 'bad credentials' });
      if (m.status !== 'approved') return res.status(403).json({ ok: false, error: m.status || 'not approved' });

      const ok = await bcrypt.compare(String(password), m.passwordHash);
      if (!ok) return res.status(401).json({ ok: false, error: 'bad credentials' });

      const token = signJwt(m);
      res.json({ ok: true, token, member: { id: m.id, name: m.name, email: m.email } });
    } catch (e) {
      console.error('login-email error', e?.message || e);
      res.status(500).json({ ok: false, error: 'server error' });
    }
  });

  // Who am I (JWT)
  router.get('/auth/me', requireJwt, async (req, res) => {
    try {
      await store.read();
      const members = store.getMembers();
      const me = members.find(x => x.id === req.jwt.sub);
      if (!me) return res.status(404).json({ ok: false });
      res.json({ ok: true, member: { id: me.id, name: me.name, email: me.email, status: me.status } });
    } catch (e) {
      res.status(500).json({ ok: false, error: 'server error' });
    }
  });

  // ------------- CHAT (REST; JWT-protected for send, read allowed to logged-in users) -------------

  // last 100 messages
  router.get('/chat/messages', requireJwt, async (_req, res) => {
    await store.read();
    const msgs = (store.getMessages() || []).slice(-100);
    res.json(msgs);
  });

  // send message
  router.post('/chat/messages', requireJwt, async (req, res) => {
    const text = (req.body?.text || '').toString().trim();
    if (!text) return res.status(400).json({ ok: false, error: 'text required' });

    await store.read();
    const members = store.getMembers();
    const me = members.find(x => x.id === req.jwt.sub);
    if (!me || me.status !== 'approved') return res.status(403).json({ ok: false, error: 'not allowed' });

    const msgs = store.getMessages() || [];
    const msg = {
      id: nanoid(),
      memberId: me.id,
      name: me.name || me.email || 'Member',
      text,
      ts: now()
    };
    msgs.push(msg);
    store.setMessages(msgs);
    await store.write();

    // broadcast to existing Socket.IO room if provided
    try {
      if (io) io.emit('chat:new', msg);
    } catch (e) {
      console.warn('socket emit failed (non-fatal):', e?.message || e);
    }

    res.json({ ok: true, message: msg });
  });

  return router;
}

// Provide a default export so `import createAuthChat from ...` works.
export default createAuthChat;
