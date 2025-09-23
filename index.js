import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import { Low } from 'lowdb';
import { JSONFile } from 'lowdb/node';
import { Expo } from 'expo-server-sdk';
import { nanoid } from 'nanoid';
import twilio from 'twilio';

const app = express();
app.use(cors());
app.use(bodyParser.json());

// DB shape: members [{id, phone, name, status:'pending'|'approved'|'rejected', isAdmin:boolean, expoTokens:[], createdAt}], meetings []
const db = new Low(new JSONFile('./db.json'), { members: [], meetings: [] });
await db.read();
db.data ||= { members: [], meetings: [] };
await db.write();

const ADMIN_PIN = process.env.ADMIN_PIN || '123456';
const expo = new Expo();
const twilioClient = (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN)
  ? twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN)
  : null;
const TWILIO_FROM = process.env.TWILIO_FROM || '';

// Serve admin page and any static assets
app.use('/admin', express.static('admin'));

// Helpers
const byStatus = (status) => db.data.members.filter(m => m.status === status);

// -------- AUTH --------
// Admin login now requires: approved member with isAdmin=true AND correct PIN
app.post('/auth/admin', async (req, res) => {
  const { phone, pin } = req.body || {};
  const m = db.data.members.find(x => x.phone === phone && x.status === 'approved' && x.isAdmin === true);
  const ok = Boolean(m && pin === ADMIN_PIN);
  res.json({ ok });
});

// -------- MEMBERSHIP --------
// App calls this to request membership; ALWAYS creates/keeps role as member (no self-admin)
app.post('/register', async (req, res) => {
  const { role, phone, name, expoToken } = req.body || {};
  if (!phone) return res.status(400).json({ ok:false, error:'phone required' }); // ignore role from client
  let m = db.data.members.find(x => x.phone === phone);
  if (!m) {
    m = { id: nanoid(), phone, name: name || '', status: 'pending', isAdmin: false, expoTokens: [], createdAt: Date.now() };
    db.data.members.push(m);
  }
  if (expoToken && !m.expoTokens.includes(expoToken)) m.expoTokens.push(expoToken);
  await db.write();
  res.json({ ok:true, status: m.status, memberId: m.id, isAdmin: m.isAdmin });
});

// List / moderate
app.get('/members', async (req, res) => {
  const { status } = req.query;
  if (status) return res.json(byStatus(status));
  res.json(db.data.members);
});

app.post('/members/:id/approve', async (req, res) => {
  const m = db.data.members.find(x => x.id === req.params.id);
  if (!m) return res.status(404).json({ ok:false });
  m.status = 'approved';
  await db.write();
  res.json({ ok:true });
});

app.post('/members/:id/reject', async (req, res) => {
  const m = db.data.members.find(x => x.id === req.params.id);
  if (!m) return res.status(404).json({ ok:false });
  m.status = 'rejected';
  await db.write();
  res.json({ ok:true });
});

app.post('/members/:id/make-admin', async (req, res) => {
  const m = db.data.members.find(x => x.id === req.params.id);
  if (!m) return res.status(404).json({ ok:false });
  m.isAdmin = true;
  await db.write();
  res.json({ ok:true });
});

app.post('/members/:id/remove-admin', async (req, res) => {
  const m = db.data.members.find(x => x.id === req.params.id);
  if (!m) return res.status(404).json({ ok:false });
  m.isAdmin = false;
  await db.write();
  res.json({ ok:true });
});

app.delete('/members/:id', async (req, res) => {
  db.data.members = db.data.members.filter(x => x.id !== req.params.id);
  await db.write();
  res.json({ ok:true });
});

// -------- MEETINGS --------
app.get('/meetings', async (_req, res) => {
  res.json(db.data.meetings.sort((a, b) => a.startsAt.localeCompare(b.startsAt)));
});

app.post('/meetings', async (req, res) => {
  const m = req.body || {};
  const id = nanoid();
  const meeting = {
    id,
    title: m.title,
    description: m.description || '',
    location: m.location || '',
    startsAt: m.startsAt,
    reminderMinutes: m.reminderMinutes || 60
  };
  db.data.meetings.push(meeting);
  await db.write();

  const approved = byStatus('approved');

  // SMS to APPROVED members only
  if ((m.sendSms ?? true) && twilioClient && TWILIO_FROM) {
    const when = new Date(meeting.startsAt).toLocaleString();
    const body = `Snoot Club: ${meeting.title} at ${meeting.location || 'TBA'} on ${when}. Reply STOP to opt out.`;
    for (const mem of approved) {
      try { await twilioClient.messages.create({ to: mem.phone, from: TWILIO_FROM, body }); }
      catch (e) { console.error('SMS error', e?.message || e); }
    }
  }

  // Push to APPROVED members' devices
  if (m.sendPush ?? true) {
    const tokens = approved.flatMap(mem => mem.expoTokens || []);
    const messages = [];
    for (const t of tokens) {
      if (!Expo.isExpoPushToken(t)) continue;
      messages.push({ to: t, sound: 'default', title: 'Snoot Club Reminder', body: `${meeting.title} @ ${meeting.location || 'TBA'}` });
    }
    const chunks = expo.chunkPushNotifications(messages);
    for (const chunk of chunks) { try { await expo.sendPushNotificationsAsync(chunk); } catch (e) { console.error(e); } }
  }

  res.json(meeting);
});

const port = process.env.PORT || 3333;
app.listen(port, () => console.log('Snoot Club server on ' + port));
