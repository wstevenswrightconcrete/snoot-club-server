// server-socket.js
// ESM module to attach Socket.IO to an existing HTTP server.
import { Server as SocketIOServer } from 'socket.io';
import { nanoid } from 'nanoid';

/**
 * Attach Socket.IO to your HTTP server.
 * @param {import('http').Server} httpServer
 * @param {{ db: any, memberByToken: (token:string)=>Promise<any> }} opts
 * @returns {SocketIOServer}
 */
export function attachSocketIO(httpServer, { db, memberByToken }) {
  const io = new SocketIOServer(httpServer, {
    cors: { origin: '*' } // For development. Lock down in production.
  });

  // Authenticate sockets with the same Bearer token your REST API uses
  io.use(async (socket, next) => {
    try {
      const token = socket.handshake.auth?.token || '';
      const m = await memberByToken(token);
      if (!m) return next(new Error('unauthorized'));
      socket.data.member = { id: m.id, name: m.name || '', phone: m.phone };
      next();
    } catch (e) {
      next(e);
    }
  });

  io.on('connection', async (socket) => {
    // Send last 100 messages on connect
    try {
      await db.read();
      db.data.chat ||= [];
      socket.emit('chat:init', db.data.chat.slice(-100));
    } catch {}

    // Receive and broadcast a new chat message
    socket.on('chat:send', async (payload) => {
      const text = (payload?.text || '').toString().trim();
      if (!text) return;
      const me = socket.data.member;
      const msg = {
        id: nanoid(),
        memberId: me.id,
        name: me.name || me.phone || 'Member',
        text,
        ts: Date.now()
      };
      await db.read();
      db.data.chat ||= [];
      db.data.chat.push(msg);
      await db.write();
      io.emit('chat:new', msg);
    });
  });

  return io;
}
