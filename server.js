// RE4MP Server — no native dependencies required
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-prod';
const DB_PATH = path.join(__dirname, 're4mp-db.json');

// ─── Simple JSON database ─────────────────────────────────────────────────────
let DB = { users: {}, rooms: {}, members: {} };

function loadDB() {
  try {
    if (fs.existsSync(DB_PATH)) {
      DB = JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));
      DB.users   = DB.users   || {};
      DB.rooms   = DB.rooms   || {};
      DB.members = DB.members || {};
    }
  } catch { DB = { users: {}, rooms: {}, members: {} }; }
}

function saveDB() {
  try { fs.writeFileSync(DB_PATH, JSON.stringify(DB, null, 2)); } catch {}
}

loadDB();

// ─── App setup ────────────────────────────────────────────────────────────────
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' }, maxHttpBufferSize: 2e6 });

app.use(cors());
app.use(express.json({ limit: '2mb' }));

const uuid = () => crypto.randomUUID();

function genRoomCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

function uniqueRoomCode() {
  let code, tries = 0;
  do { code = genRoomCode(); tries++; }
  while (Object.values(DB.rooms).some(r => r.code === code) && tries < 20);
  return code;
}

const buckets = new Map();
function rateLimit(key, max, ms) {
  const now = Date.now();
  let b = buckets.get(key);
  if (!b || now > b.reset) b = { count: 0, reset: now + ms };
  b.count++;
  buckets.set(key, b);
  return b.count > max;
}

function requireAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}

// ─── Auth ─────────────────────────────────────────────────────────────────────
app.post('/auth/signup', async (req, res) => {
  const { email, password, gamertag } = req.body || {};
  if (!email || !password || !gamertag)
    return res.status(400).json({ error: 'Email, password, and gamertag are required' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (!/^[a-zA-Z0-9_\-]{3,20}$/.test(gamertag))
    return res.status(400).json({ error: 'Gamertag: 3-20 chars, letters/numbers/_-' });
  if (rateLimit(`signup:${req.ip}`, 10, 60000))
    return res.status(429).json({ error: 'Too many attempts. Wait a minute.' });

  const emailLower = email.toLowerCase().trim();
  if (Object.values(DB.users).some(u => u.email === emailLower))
    return res.status(409).json({ error: 'Email already registered' });
  if (Object.values(DB.users).some(u => u.gamertag.toLowerCase() === gamertag.toLowerCase()))
    return res.status(409).json({ error: 'Gamertag already taken' });

  const id = uuid();
  const hash = await bcrypt.hash(password, 12);
  DB.users[id] = { id, email: emailLower, password_hash: hash, gamertag: gamertag.trim(), created_at: Date.now() };
  saveDB();
  const token = jwt.sign({ id, email: emailLower, gamertag: gamertag.trim() }, JWT_SECRET, { expiresIn: '30d' });
  res.status(201).json({ token, user: { id, email: emailLower, gamertag: gamertag.trim() } });
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  if (rateLimit(`login:${req.ip}`, 10, 60000))
    return res.status(429).json({ error: 'Too many attempts. Wait a minute.' });

  const user = Object.values(DB.users).find(u => u.email === email.toLowerCase().trim());
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });
  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) return res.status(401).json({ error: 'Invalid email or password' });

  const token = jwt.sign({ id: user.id, email: user.email, gamertag: user.gamertag }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: user.id, email: user.email, gamertag: user.gamertag } });
});

// ─── Rooms ────────────────────────────────────────────────────────────────────
app.post('/rooms', requireAuth, (req, res) => {
  const { name } = req.body || {};
  const id = uuid();
  const code = uniqueRoomCode();
  const roomName = name?.trim() || `${req.user.gamertag}'s Room`;
  DB.rooms[id] = { id, code, name: roomName, host_id: req.user.id, status: 'waiting', created_at: Date.now() };
  DB.members[`${id}:${req.user.id}`] = { room_id: id, user_id: req.user.id, role: 'A' };
  saveDB();
  res.status(201).json({ roomId: id, code, name: roomName, myRole: 'A', hostGamertag: req.user.gamertag, partnerGamertag: null });
});

app.get('/rooms', requireAuth, (req, res) => {
  const waiting = Object.values(DB.rooms)
    .filter(r => r.status === 'waiting')
    .sort((a, b) => b.created_at - a.created_at)
    .slice(0, 30)
    .map(r => ({
      id: r.id, code: r.code, name: r.name, status: r.status,
      hostGamertag: DB.users[r.host_id]?.gamertag || '?',
      memberCount: Object.values(DB.members).filter(m => m.room_id === r.id).length
    }));
  res.json(waiting);
});

app.post('/rooms/join/:code', requireAuth, (req, res) => {
  const code = req.params.code.toUpperCase().trim();
  const room = Object.values(DB.rooms).find(r => r.code === code && r.status === 'waiting');
  if (!room) return res.status(404).json({ error: 'Room not found or already full' });
  if (DB.members[`${room.id}:${req.user.id}`]) return res.status(400).json({ error: 'Already in this room' });
  const memberCount = Object.values(DB.members).filter(m => m.room_id === room.id).length;
  if (memberCount >= 2) return res.status(400).json({ error: 'Room is full' });

  DB.members[`${room.id}:${req.user.id}`] = { room_id: room.id, user_id: req.user.id, role: 'B' };
  DB.rooms[room.id].status = 'active';
  saveDB();
  const host = DB.users[room.host_id];
  res.json({ roomId: room.id, code: room.code, name: room.name, myRole: 'B', hostGamertag: host?.gamertag, partnerGamertag: host?.gamertag });
});

app.get('/health', (_, res) => res.json({ ok: true, uptime: Math.floor(process.uptime()) }));

// ─── WebSocket ────────────────────────────────────────────────────────────────
const socketMeta = new Map();

io.use((socket, next) => {
  try { socket.user = jwt.verify(socket.handshake.auth.token, JWT_SECRET); next(); }
  catch { next(new Error('Invalid token')); }
});

io.on('connection', (socket) => {
  console.log(`[+] ${socket.user.gamertag}`);

  socket.on('room:join', ({ roomId, role }) => {
    socket.join(roomId);
    socketMeta.set(socket.id, { userId: socket.user.id, gamertag: socket.user.gamertag, roomId, role });
    socket.to(roomId).emit('room:partner_joined', { gamertag: socket.user.gamertag, role });
  });

  socket.on('bridge:file', ({ filename, data }) => {
    const meta = socketMeta.get(socket.id);
    if (meta?.roomId) socket.to(meta.roomId).emit('bridge:file', { filename, data });
  });

  socket.on('room:leave', () => cleanup(socket));
  socket.on('disconnect', () => cleanup(socket));

  function cleanup(s) {
    const meta = socketMeta.get(s.id);
    if (!meta) return;
    s.to(meta.roomId).emit('room:partner_left', { gamertag: meta.gamertag });
    s.leave(meta.roomId);
    socketMeta.delete(s.id);
    const room = DB.rooms[meta.roomId];
    if (room && room.host_id === meta.userId && room.status !== 'closed') {
      DB.rooms[meta.roomId].status = 'closed';
      saveDB();
      io.to(meta.roomId).emit('room:closed', { reason: 'host_left' });
    }
    console.log(`[-] ${meta.gamertag}`);
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────
server.listen(PORT, () => {
  console.log(`\nRE4MP Server running on port ${PORT}`);
  console.log(`Users: ${Object.keys(DB.users).length}\n`);
});
