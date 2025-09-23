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

// Simple file DB
const db = new Low(new JSONFile('./db.json'), { devices: [], members: [], meetings: [] });
await db.read();
db.data ||= { devices: [], members: [], meetings: [] };
await db.write();

// Config via env
const ADMIN_PIN = process.env.ADMIN_PIN || '123456';
const expo = new Expo();
const twilioClient = (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN)
  ? twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN)
  : null;
const TWILIO_FROM = process.env.TWILIO_FROM || '';

// Serve the admin page
app.use('/admin', express.static('admin'));

// Device/phone registration
app.post('/register', async (req, res) => {
  const { role, phone, expoToken, name } = req.body;
  if (expoToken) {
    const exists = db.data.devices.find(d => d.token === expoToken);
    if (!exists) db.data.devices.push({ id: nanoid(), token: expoToken, name: name || '' });
  }
  if (role === 'member' && phone) {
    const exists = db.data.members.find(m => m.phone === phone);
    if (!exists) db.data.members.push({ id: nanoid(), phone });
  }
  await db.write();
  res.json({ ok: true });
});

// Admin auth
app.post('/auth/admin', async (req, res) => {
  const { pin } = req.body;
  res.json({ ok: pin === ADMIN_PIN });
});

// Members (for admin UI)
app.get('/members', async (_req, res) => {
  res.json(db.data.members);
});
app.delete('/members/:id', async (req, res) => {
  db.data.members = db.data.members.filter(m => m.id !== req.params.id);
  await db.write();
  res.json({ ok: true });
});

// Meetings
app.get('/meetings', async (_req, res) => {
  res.json(db.data.meetings.sort((a, b) => a.startsAt.localeCompare(b.startsAt)));
});

app.post('/meetings', async (req, res) => {
  const m = req.body;
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

  // 1) SMS broadcast (if configured + requested)
  if ((m.sendSms ?? true) && twilioClient && TWILIO_FROM) {
    const when = new Date(meeting.startsAt).toLocaleString();
    const body = `Snoot Club: ${meeting.title} at ${meeting.location || 'TBA'} on ${when}. Reply STOP to opt out.`;
    for (const mem of db.data.members) {
      try {
        await twilioClient.messages.create({ to: mem.phone, from: TWILIO_FROM, body });
      } catch (e) {
        console.error('SMS error', e?.message || e);
      }
    }
  }

  // 2) Push broadcast to registered devices (if requested)
  if (m.sendPush ?? true) {
    const messages = [];
    for (const d of db.data.devices) {
      if (!Expo.isExpoPushToken(d.token)) continue;
      messages.push({
        to: d.token,
        sound: 'default',
        title: 'Snoot Club Reminder',
        body: `${meeting.title} @ ${meeting.location || 'TBA'}`
      });
    }
    const chunks = expo.chunkPushNotifications(messages);
    for (const chunk of chunks) {
      try { await expo.sendPushNotificationsAsync(chunk); } catch (e) { console.error(e); }
    }
  }

  res.json(meeting);
});

const port = process.env.PORT || 3333;
app.listen(port, () => console.log('Snoot Club server on ' + port));
