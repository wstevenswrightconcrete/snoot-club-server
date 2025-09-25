// server/index.js — Snoot Club server (OTP auth, meetings, chat, admin-by-PIN; admin chat via REST)

import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { Low } from 'lowdb';
import { JSONFile } from 'lowdb/node';
import { Expo } from 'expo-server-sdk';
import { nanoid } from 'nanoid';
import twilio from 'twilio';
import { Server as SocketIOServer } from 'socket.io';
import createAuthChat from './server-addons-auth-chat.js';
import jwt from 'jsonwebtoken';

// ---------- Setup ----------
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(cors());
app.use(bodyParser.json());

// ---------- Data location ----------
const DATA_DIR = process.env.DATA_DIR || __dirname; // if using Render Disk, set DATA_DIR=/data
fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_PATH = path.join(DATA_DIR, 'db.json');

// ---------- DB ----------
const db = new Low(new JSONFile(DB_PATH), { members: [], meetings: [], chat: [] });
await db.read();
db.data ||= { members: [], meetings: [], chat: [] };
await db.write();

// ---------- Env ----------
const ADMIN_PIN   = process.env.ADMIN_PIN || '123456';
const CRON_SECRET = process.env.CRON_SECRET || 'changeme';
const TWILIO_FROM = process.env.TWILIO_FROM || '';
const JWT_SECRET  = process.env.JWT_SECRET || 'dev';
const expo = new Expo();
const twilioClient = (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN)
  ? twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN)
  : null;

// ---------- Static admin ----------
app.use('/admin', express.static(path.join(__dirname, 'admin')));

// ---------- Helpers ----------
const nowMs = () => Date.now();
const byStatus = (status) => db.data.members.filter(m => m.status === status);

function decodeJwtIfPresent(token) {
  if (!token || token.split('.').length !== 3) return null;
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}

function makeToken() { return crypto.randomBytes(24).toString('hex'); }
function makeCode()  { return String(Math.floor(100000 + Math.random() * 900000)); }

// Normalize phone into +1XXXXXXXXXX (US) if possible
function normalizeUS(phone) {
  const digits = (phone || '').replace(/\D/g, '');
  if (!digits) return '';
  if (digits.length === 10) return `+1${digits}`;
  if (digits.length === 11 && digits.startsWith('1')) return `+${digits}`;
  if ((phone || '').startsWith('+')) return phone;
  return `+${digits}`;
}

// OTP (in-memory)
const otpStore = new Map(); // phone -> { code, expMs }
function setOtp(phone) {
  const code = makeCode();
  otpStore.set(phone, { code, expMs: nowMs() + 10 * 60 * 1000 }); // 10 minutes
  return code;
}
function checkOtp(phone, code) {
  const v = otpStore.get(phone);
  if (!v) return false;
  const ok = v.code === code && nowMs() < v.expMs;
  if (ok) otpStore.delete(phone);
  return ok;
}

async function memberByToken(token) {
  await db.read();

  // 1) Session token from OTP flow
  const m1 = db.data.members.find(x => (x.sessionTokens || []).includes(token));
  if (m1 && m1.status === 'approved') return m1;

  // 2) JWT from email/password add-on
  const dec = decodeJwtIfPresent(token);
  if (dec) {
    const m2 = db.data.members.find(x => x.id === dec.sub || x.email === dec.email);
    if (m2 && m2.status === 'approved') return m2;
  }

  return null;
}

async function requireAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ ok:false, error:'auth required' });
  const m = await memberByToken(token);
  if (!m) return res.status(401).json({ ok:false, error:'invalid session' });
  req.member = m;
  next();
}

function isAdminReq(req) {
  const pin = (req.headers['x-admin-pin'] || req.query.pin || '').toString().trim();
  return pin && pin === ADMIN_PIN;
}
function requireAdmin(req, res, next) {
  if (!isAdminReq(req)) return res.status(401).json({ ok:false, error:'admin auth required' });
  next();
}

// Allow either a logged-in member (Bearer) OR an admin with PIN
async function requireMemberOrAdmin(req, res, next) {
  if (isAdminReq(req)) return next();
  return requireAuth(req, res, next);
}

// ---------- Health ----------
app.get('/healthz', (_req, res) => res.json({ ok: true }));

// ---------- Admin PIN check (no auto-login; UI must POST to this) ----------
app.post('/auth/admin', (req, res) => {
  const { pin } = req.body || {};
  res.json({ ok: pin === ADMIN_PIN });
});

// ---------- Member registration & OTP login ----------
app.post('/register', async (req, res) => {
  const { phone, name, email, expoToken } = req.body || {};
  const norm = normalizeUS(phone);
  if (!norm) return res.status(400).json({ ok:false, error:'phone required' });

  await db.read();
  let m = db.data.members.find(x => x.phone === norm);
  if (!m) {
    m = {
      id: nanoid(),
      phone: norm, name: name || '', email: email || '',
      status: 'pending',
      isAdmin: false,
      expoTokens: [],
      sessionTokens: [],
      createdAt: nowMs(),
    };
    db.data.members.push(m);
  } else {
    if (name && !m.name) m.name = name;
    if (email && !m.email) m.email = email;
  }
  if (expoToken && !m.expoTokens.includes(expoToken)) m.expoTokens.push(expoToken);
  await db.write();
  res.json({ ok:true, status:m.status, memberId:m.id });
});

// ---- Add-on store adapter (reuses your LowDB structure) ----
const addonStore = {
  read: async () => { await db.read(); },
  write: async () => { await db.write(); },

  // members
  getMembers: () => db.data.members || [],
  setMembers: (arr) => { db.data.members = arr; },

  // meetings
  getMeetings: () => db.data.meetings || [],
  setMeetings: (arr) => { db.data.meetings = arr; },

  // chat/messages (map add-on "messages" -> your existing db.data.chat)
  getMessages: () => (db.data.chat = db.data.chat || [], db.data.chat),
  setMessages: (arr) => { db.data.chat = arr; },
};

app.post('/auth/request-code', async (req, res) => {
  const { phone } = req.body || {};
  const norm = normalizeUS(phone);
  if (!norm) return res.status(400).json({ ok:false, error:'phone required' });

  await db.read();
  const m = db.data.members.find(x => x.phone === norm);
  if (!m) return res.status(404).json({ ok:false, error:'not registered' });
  if (m.status !== 'approved') return res.status(403).json({ ok:false, error:m.status });

  const code = setOtp(norm);

  if (twilioClient && TWILIO_FROM) {
    try {
      await twilioClient.messages.create({
        to: norm, from: TWILIO_FROM,
        body: `Snoot Club login code: ${code} (valid 10 minutes).`,
      });
      return res.json({ ok:true, sent:true });
    } catch (e) {
      console.error('SMS error', e?.message || e);
    }
  }
  // fallback for testing (no Twilio or trial)
  res.json({ ok:true, sent:false, demoCode: code });
});

app.post('/auth/verify-code', async (req, res) => {
  const { phone, code, expoToken } = req.body || {};
  const norm = normalizeUS(phone);
  if (!norm || !code) return res.status(400).json({ ok:false, error:'phone & code required' });

  await db.read();
  const m = db.data.members.find(x => x.phone === norm);
  if (!m || m.status !== 'approved') return res.status(403).json({ ok:false });

  if (!checkOtp(norm, code)) return res.status(401).json({ ok:false, error:'bad code' });

  const token = makeToken();
  m.sessionTokens = m.sessionTokens || [];
  m.sessionTokens.push(token);
  if (expoToken && !m.expoTokens.includes(expoToken)) m.expoTokens.push(expoToken);
  await db.write();

  res.json({ ok:true, token, member: { id:m.id, name:m.name, email:m.email, phone:m.phone } });
});

app.post('/auth/logout', requireAuth, async (req, res) => {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  req.member.sessionTokens = (req.member.sessionTokens || []).filter(t => t !== token);
  await db.write();
  res.json({ ok:true });
});

app.get('/me', requireAuth, (req, res) => {
  const m = req.member;
  res.json({ id:m.id, name:m.name, email:m.email, phone:m.phone, status:m.status });
});

// ---------- Admin: members ----------
app.get('/members', requireAdmin, async (req, res) => {
  const { status } = req.query;
  await db.read();
  if (status) return res.json(byStatus(status));
  res.json(db.data.members);
});
app.post('/members/:id/approve', requireAdmin, async (req, res) => {
  const m = db.data.members.find(x => x.id === req.params.id);
  if (!m) return res.status(404).json({ ok:false });
  m.status = 'approved';
  await db.write();
  res.json({ ok:true });
});
app.post('/members/:id/reject', requireAdmin, async (req, res) => {
  const m = db.data.members.find(x => x.id === req.params.id);
  if (!m) return res.status(404).json({ ok:false });
  m.status = 'rejected';
  await db.write();
  res.json({ ok:true });
});
app.post('/members/:id/make-admin', requireAdmin, async (req, res) => {
  const m = db.data.members.find(x => x.id === req.params.id);
  if (!m) return res.status(404).json({ ok:false });
  m.isAdmin = true;
  await db.write();
  res.json({ ok:true });
});
app.post('/members/:id/remove-admin', requireAdmin, async (req, res) => {
  const m = db.data.members.find(x => x.id === req.params.id);
  if (!m) return res.status(404).json({ ok:false });
  m.isAdmin = false;
  await db.write();
  res.json({ ok:true });
});
app.delete('/members/:id', requireAdmin, async (req, res) => {
  db.data.members = db.data.members.filter(x => x.id !== req.params.id);
  await db.write();
  res.json({ ok:true });
});

// ---------- Meetings ----------
app.get('/meetings', requireMemberOrAdmin, async (_req, res) => {
  await db.read();
  res.json(db.data.meetings.sort((a, b) => a.startsAt.localeCompare(b.startsAt)));
});

app.post('/meetings', requireAdmin, async (req, res) => {
  const m = req.body || {};
  const meeting = {
    id: nanoid(),
    title: m.title,
    description: m.description || '',
    location: m.location || '',
    startsAt: m.startsAt,
    reminderMinutes: m.reminderMinutes || 60,
    didNotify24h: false,
  };

  db.data.meetings.push(meeting);
  await db.write();

  const approved = byStatus('approved');

  // SMS on create
  if ((m.sendSms ?? true) && twilioClient && TWILIO_FROM) {
    const when = new Date(meeting.startsAt).toLocaleString();
    const body = `Snoot Club: ${meeting.title} at ${meeting.location || 'TBA'} on ${when}. Reply STOP to opt out.`;
    for (const mem of approved) {
      try { await twilioClient.messages.create({ to: mem.phone, from: TWILIO_FROM, body }); }
      catch (e) { console.error('SMS error', e?.message || e); }
    }
  }

  // Push on create
  if (m.sendPush ?? true) {
    const tokens = approved.flatMap(mem => mem.expoTokens || []);
    const messages = [];
    for (const t of tokens) {
      if (!Expo.isExpoPushToken(t)) continue;
      messages.push({ to: t, sound: 'default', title: 'Snoot Club Reminder', body: `${meeting.title} @ ${meeting.location || 'TBA'}` });
    }
    const chunks = expo.chunkPushNotifications(messages);
    for (const chunk of chunks) {
      try { await expo.sendPushNotificationsAsync(chunk); } catch (e) { console.error(e); }
    }
  }

  res.json(meeting);
});

// ---------- Cron: 24h reminders ----------
app.post('/tasks/notify-24h', async (req, res) => {
  try {
    if ((req.query.secret || '') !== CRON_SECRET) {
      return res.status(401).json({ ok:false, error:'unauthorized' });
    }
    await db.read();
    const now = nowMs();
    const windowStart = now + (24*60 - 10)*60*1000;
    const windowEnd   = now + (24*60 + 10)*60*1000;

    const due = db.data.meetings.filter(meet => {
      if (meet.didNotify24h) return false;
      const t = new Date(meet.startsAt).getTime();
      return t >= windowStart && t < windowEnd;
    });

    const approved = byStatus('approved');
    let smsCount = 0, pushCount = 0;

    for (const meeting of due) {
      if (twilioClient && TWILIO_FROM) {
        const when = new Date(meeting.startsAt).toLocaleString();
        const body = `Snoot Club: ${meeting.title} at ${meeting.location || 'TBA'} on ${when}. Reply STOP to opt out.`;
        for (const mem of approved) {
          try { await twilioClient.messages.create({ to: mem.phone, from: TWILIO_FROM, body }); smsCount++; }
          catch (e) { console.error('SMS error', e?.message || e); }
        }
      }
      const tokens = approved.flatMap(mem => mem.expoTokens || []);
      const messages = [];
      for (const t of tokens) {
        if (!Expo.isExpoPushToken(t)) continue;
        messages.push({ to: t, sound: 'default', title: 'Snoot Club — 24h Reminder', body: `${meeting.title} @ ${meeting.location || 'TBA'}` });
      }
      const chunks = expo.chunkPushNotifications(messages);
      for (const chunk of chunks) {
        try { await expo.sendPushNotificationsAsync(chunk); pushCount += chunk.length; }
        catch (e) { console.error(e); }
      }

      meeting.didNotify24h = true;
    }

    await db.write();
    res.json({ ok:true, meetingsNotified: due.map(d => d.id), smsCount, pushCount });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok:false, error:String(e?.message || e) });
  }
});

// ---------- Start & Socket.IO (chat) ----------
const port = process.env.PORT || 3333;
const server = app.listen(port, () => {
  console.log('Snoot Club server on ' + port + '  (DB at ' + DB_PATH + ')');
});

const io = new SocketIOServer(server, { cors: { origin: '*' } });

// Members-only sockets (PIN isn’t accepted here; admin uses REST below)
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth?.token || '';
    const m = await memberByToken(token);
    if (!m) return next(new Error('unauthorized'));
    socket.data.member = { id: m.id, name: m.name || '', phone: m.phone };
    next();
  } catch (e) { next(e); }
});

io.on('connection', async (socket) => {
  try {
    await db.read();
    const recent = (db.data.chat || []).slice(-100);
    socket.emit('chat:init', recent);
  } catch {}

  socket.on('chat:send', async (payload) => {
    const text = (payload?.text || '').toString().trim();
    if (!text) return;
    const me = socket.data.member || {};
    const msg = {
      id: nanoid(),
      memberId: me.id,
      name: me.name || me.phone || 'Member',
      text,
      ts: Date.now()
    };
    await db.read();
    db.data.chat = db.data.chat || [];
    db.data.chat.push(msg);
    await db.write();
    io.emit('chat:new', msg);
  });
});

// ----- REST chat for Admin (PIN) or Member (Bearer) -----
app.get('/chat/messages', requireMemberOrAdmin, async (_req, res) => {
  await db.read();
  res.json((db.data.chat || []).slice(-100));
});

app.post('/chat/send', requireMemberOrAdmin, async (req, res) => {
  const text = (req.body?.text || '').toString().trim();
  if (!text) return res.status(400).json({ ok:false, error:'text required' });

  const name =
    req.member?.name ||
    req.member?.phone ||
    (isAdminReq(req) ? 'Admin' : 'Member');

  const msg = {
    id: nanoid(),
    memberId: req.member?.id || 'admin',
    name,
    text,
    ts: Date.now(),
  };

  await db.read();
  db.data.chat = db.data.chat || [];
  db.data.chat.push(msg);
  await db.write();

  try { io.emit('chat:new', msg); } catch {}

  res.json({ ok:true, message: msg });
});

// ---- Mount email/password auth + (separate) REST chat under /addons ----
app.use('/addons', createAuthChat({
  store: addonStore,
  adminPin: ADMIN_PIN,
  jwtSecret: JWT_SECRET,
  io,
  twilio: { client: twilioClient, from: TWILIO_FROM }
}));
