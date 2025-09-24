// server/index.js
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

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(cors());
app.use(bodyParser.json());

// ---------- DATA LOCATION (supports persistent disk) ----------
const DATA_DIR = process.env.DATA_DIR || __dirname;
fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_PATH = path.join(DATA_DIR, 'db.json');

// ---------- DB ----------
const db = new Low(new JSONFile(DB_PATH), { members: [], meetings: [] });
await db.read();
db.data ||= { members: [], meetings: [] };
await db.write();

// ---------- ENV ----------
const ADMIN_PIN   = process.env.ADMIN_PIN || '123456';
const CRON_SECRET = process.env.CRON_SECRET || 'changeme';
const TWILIO_FROM = process.env.TWILIO_FROM || '';

const expo = new Expo();
const twilioClient = (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN)
  ? twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN)
  : null;

// ---------- STATIC / ADMIN ----------
app.use('/admin', express.static(path.join(__dirname, 'admin')));

// ---------- HELPERS ----------
const byStatus = (status) => db.data.members.filter(m => m.status === status);
const nowMs = () => Date.now();

function makeToken() { return crypto.randomBytes(24).toString('hex'); }
function makeCode()  { return String(Math.floor(100000 + Math.random() * 900000)); }

// Normalize US numbers to E.164 (+1XXXXXXXXXX)
function normalizeUS(phone) {
  const raw = (phone || '').trim();
  const digits = raw.replace(/\D/g, '');
  if (digits.length === 10) return `+1${digits}`;
  if (digits.length === 11 && digits.startsWith('1')) return `+${digits}`;
  if (raw.startsWith('+')) return raw;
  return digits ? `+${digits}` : '';
}

// In-memory OTP store (10 min)
const otpStore = new Map(); // phone -> { code, expMs }
function setOtp(phone) {
  const code = makeCode();
  otpStore.set(phone, { code, expMs: nowMs() + 10 * 60 * 1000 });
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
  const m = db.data.members.find(x => (x.sessionTokens || []).includes(token));
  return m && m.status === 'approved' ? m : null;
}

async function requireAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ ok: false, error: 'auth required' });
  const m = await memberByToken(token);
  if (!m) return res.status(401).json({ ok: false, error: 'invalid session' });
  req.member = m;
  next();
}

function isAdminReq(req) {
  const pin = (req.headers['x-admin-pin'] || req.query.pin || '').toString().trim();
  return pin && pin === ADMIN_PIN;
}
function requireAdmin(req, res, next) {
  if (!isAdminReq(req)) return res.status(401).json({ ok:false, error:'admin pin required' });
  next();
}

// ---------- HEALTH ----------
app.get('/healthz', (_req, res) => res.json({ ok: true }));

// ---------- ADMIN AUTH (web page only) ----------
app.post('/auth/admin', (req, res) => {
  const { pin } = req.body || {};
  res.json({ ok: pin === ADMIN_PIN });
});

// ---------- MEMBER REGISTRATION & LOGIN ----------
app.post('/register', async (req, res) => {
  const { name, email, expoToken } = req.body || {};
  const phone = normalizeUS(req.body?.phone);
  if (!phone) return res.status(400).json({ ok: false, error: 'phone required' });

  await db.read();
  let m = db.data.members.find(x => x.phone === phone);
  if (!m) {
    m = {
      id: nanoid(),
      phone,
      name: name || '',
      email: email || '',
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
    if (expoToken && !m.expoTokens.includes(expoToken)) m.expoTokens.push(expoToken);
  }
  if (expoToken && !m.expoTokens.includes(expoToken)) m.expoTokens.push(expoToken);

  await db.write();
  res.json({ ok:true, status:m.status, memberId:m.id });
});

// OTP: request code (approved members only)
app.post('/auth/request-code', async (req, res) => {
  const phone = normalizeUS(req.body?.phone);
  if (!phone) return res.status(400).json({ ok:false, error:'phone required' });

  await db.read();
  const m = db.data.members.find(x => x.phone === phone);
  if (!m) return res.status(404).json({ ok:false, error:'not registered' });
  if (m.status !== 'approved') return res.status(403).json({ ok:false, error:m.status });

  const code = setOtp(phone);

  if (twilioClient && TWILIO_FROM) {
    try {
      await twilioClient.messages.create({
        to: phone,
        from: TWILIO_FROM,
        body: `Snoot Club login code: ${code} (valid 10 minutes).`,
      });
      return res.json({ ok:true, sent:true });
    } catch (e) {
      console.error('SMS error', e?.message || e);
    }
  }
  // Fallback for testing without Twilio
  res.json({ ok:true, sent:false, demoCode: code });
});

// OTP: verify -> create session
app.post('/auth/verify-code', async (req, res) => {
  const phone = normalizeUS(req.body?.phone);
  const { code, expoToken } = req.body || {};
  if (!phone || !code) return res.status(400).json({ ok:false, error:'phone & code required' });

  await db.read();
  const m = db.data.members.find(x => x.phone === phone);
  if (!m || m.status !== 'approved') return res.status(403).json({ ok:false });

  if (!checkOtp(phone, code)) return res.status(401).json({ ok:false, error:'bad code' });

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

// ---------- ADMIN: moderate members ----------
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

// ---------- MEETINGS ----------
app.get('/meetings', requireAuth, async (_req, res) => {
  await db.read();
  res.json(db.data.meetings.sort((a, b) => a.startsAt.localeCompare(b.startsAt)));
});

// Admin-only create (PIN required)
app.post('/meetings', requireAdmin, async (req, res) => {
  const m = req.body || {};
  const id = nanoid();
  const meeting = {
    id,
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
      messages.push({
        to: t,
        sound: 'default',
        title: 'Snoot Club Reminder',
        body: `${meeting.title} @ ${meeting.location || 'TBA'}`
      });
    }
    const chunks = expo.chunkPushNotifications(messages);
    for (const chunk of chunks) {
      try { await expo.sendPushNotificationsAsync(chunk); }
      catch (e) { console.error(e); }
    }
  }

  res.json(meeting);
});

// ---------- CRON: 24h reminders ----------
app.post('/tasks/notify-24h', async (req, res) => {
  try {
    if ((req.query.secret || '') !== CRON_SECRET) {
      return res.status(401).json({ ok: false, error: 'unauthorized' });
    }

    await db.read();
    const now = nowMs();
    const windowStart = now + (24 * 60 - 10) * 60 * 1000; // 24h - 10m
    const windowEnd   = now + (24 * 60 + 10) * 60 * 1000; // 24h + 10m

    const due = db.data.meetings.filter(meet => {
      if (meet.didNotify24h) return false;
      const t = new Date(meet.startsAt).getTime();
      return t >= windowStart && t < windowEnd;
    });

    const approved = byStatus('approved');
    let smsCount = 0, pushCount = 0;

    for (const meeting of due) {
      // SMS
      if (twilioClient && TWILIO_FROM) {
        const when = new Date(meeting.startsAt).toLocaleString();
        const body = `Snoot Club: ${meeting.title} at ${meeting.location || 'TBA'} on ${when}. Reply STOP to opt out.`;
        for (const mem of approved) {
          try { await twilioClient.messages.create({ to: mem.phone, from: TWILIO_FROM, body }); smsCount++; }
          catch (e) { console.error('SMS error', e?.message || e); }
        }
      }
      // Push
      const tokens = approved.flatMap(mem => mem.expoTokens || []);
      const messages = [];
      for (const t of tokens) {
        if (!Expo.isExpoPushToken(t)) continue;
        messages.push({
          to: t,
          sound: 'default',
          title: 'Snoot Club — 24h Reminder',
          body: `${meeting.title} @ ${meeting.location || 'TBA'}`
        });
      }
      const chunks = expo.chunkPushNotifications(messages);
      for (const chunk of chunks) {
        try { await expo.sendPushNotificationsAsync(chunk); pushCount += chunk.length; }
        catch (e) { console.error(e); }
      }

      meeting.didNotify24h = true; // prevent duplicates
    }

    await db.write();
    res.json({ ok: true, meetingsNotified: due.map(d => d.id), smsCount, pushCount });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// ---------- START ----------
const port = process.env.PORT || 3333;
app.listen(port, () => console.log('Snoot Club server on ' + port + '  (DB at ' + DB_PATH + ')'));
