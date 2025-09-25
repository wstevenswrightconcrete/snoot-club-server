// server-addons-auth-chat.js — Email/password auth (+ optional /addons/chat endpoints)
// Requires: npm i bcryptjs jsonwebtoken

import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

export default function createAuthChat(opts = {}) {
  const {
    store,           // { read, write, getMembers, setMembers, getMessages, setMessages }
    adminPin,
    jwtSecret = 'dev',
    io,              // socket.io server (optional, used to broadcast /addons/chat sends)
    twilio           // { client, from } (optional – reserved for later)
  } = opts;

  const router = (await import('express')).default.Router();
  router.use((await import('body-parser')).json());

  // ---- Helpers ----
  function signToken(member) {
    return jwt.sign({ sub: member.id, email: member.email }, jwtSecret, { expiresIn: '30d' });
  }
  function isAdminReq(req) {
    const pin = (req.headers['x-admin-pin'] || req.query.pin || '').toString().trim();
    return pin && pin === adminPin;
  }

  // ---- Auth: register/login with email/password ----
  router.post('/auth/register', async (req, res) => {
    const { email = '', password = '', name = '' } = req.body || {};
    const cleanEmail = email.trim().toLowerCase();
    if (!cleanEmail || !password) return res.status(400).json({ ok:false, error:'email & password required' });

    await store.read();
    const members = store.getMembers();
    let m = members.find(u => (u.email || '').toLowerCase() === cleanEmail);
    if (m) return res.status(409).json({ ok:false, error:'email exists' });

    const hash = await bcrypt.hash(password, 10);
    m = {
      id: `m_${Date.now().toString(36)}`,
      email: cleanEmail,
      name: name || cleanEmail,
      phone: '',
      status: 'approved',          // email signups are admin-managed in real life; keep simple here
      isAdmin: false,
      sessionTokens: [],
      passwordHash: hash,
      createdAt: Date.now()
    };
    members.push(m);
    store.setMembers(members);
    await store.write();

    const token = signToken(m);
    return res.json({ ok:true, token, member: { id:m.id, name:m.name, email:m.email } });
  });

  router.post('/auth/login', async (req, res) => {
    const { email = '', password = '' } = req.body || {};
    const cleanEmail = email.trim().toLowerCase();
    if (!cleanEmail || !password) return res.status(400).json({ ok:false, error:'email & password required' });

    await store.read();
    const members = store.getMembers();
    const m = members.find(u => (u.email || '').toLowerCase() === cleanEmail);
    if (!m || !m.passwordHash) return res.status(401).json({ ok:false, error:'invalid credentials' });

    const ok = await bcrypt.compare(password, m.passwordHash);
    if (!ok || m.status !== 'approved') return res.status(401).json({ ok:false, error:'invalid credentials' });

    const token = signToken(m);
    return res.json({ ok:true, token, member: { id:m.id, name:m.name, email:m.email } });
  });

  // ---- /addons/chat (separate namespace; optional) ----
  // Admin via PIN OR member via Bearer (JWT)
  async function requireMemberOrAdmin(req, res, next) {
    if (isAdminReq(req)) return next();
    const auth = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    if (!auth || auth.split('.').length !== 3) return res.status(401).json({ ok:false, error:'auth required' });

    try {
      const dec = jwt.verify(auth, jwtSecret);
      await store.read();
      const m = store.getMembers().find(u => u.id === dec.sub || (u.email || '').toLowerCase() === (dec.email || '').toLowerCase());
      if (!m || m.status !== 'approved') return res.status(401).json({ ok:false, error:'invalid session' });
      req.member = m;
      return next();
    } catch {
      return res.status(401).json({ ok:false, error:'invalid session' });
    }
  }

  router.get('/chat', requireMemberOrAdmin, async (_req, res) => {
    await store.read();
    res.json(store.getMessages().slice(-100));
  });

  router.post('/chat', requireMemberOrAdmin, async (req, res) => {
    const text = (req.body?.text || '').toString().trim();
    if (!text) return res.status(400).json({ ok:false, error:'text required' });

    await store.read();
    const all = store.getMessages();
    const msg = {
      id: `c_${Date.now().toString(36)}`,
      memberId: req.member?.id || 'admin',
      name: req.member?.name || (isAdminReq(req) ? 'Admin' : 'Member'),
      text,
      ts: Date.now()
    };
    all.push(msg);
    store.setMessages(all);
    await store.write();
    try { io?.emit?.('chat:new', msg); } catch {}

    res.json({ ok:true, message: msg });
  });

  return router;
}
