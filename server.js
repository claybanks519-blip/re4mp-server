// RE4MP Server
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-prod';
const DB_PATH = path.join(__dirname, 're4mp-db.json');

// Email config — set these in Render environment variables
const EMAIL_USER = process.env.EMAIL_USER || '';
const EMAIL_PASS = process.env.EMAIL_PASS || '';
const BASE_URL   = process.env.BASE_URL   || 'https://re4mp-server.onrender.com';

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: EMAIL_USER, pass: EMAIL_PASS }
});

async function sendVerificationEmail(email, token) {
  const link = `${BASE_URL}/auth/verify/${token}`;
  await transporter.sendMail({
    from: `"RE4MP" <${EMAIL_USER}>`,
    to: email,
    subject: 'Verify your RE4MP account',
    html: `
      <div style="background:#080c12;color:#e8e0d0;font-family:sans-serif;padding:40px;max-width:480px;margin:0 auto;">
        <div style="font-size:28px;font-weight:700;letter-spacing:4px;margin-bottom:8px;">
          <span style="color:#b01828">R</span>E4MP
        </div>
        <div style="font-size:11px;color:#7a7870;letter-spacing:3px;margin-bottom:32px;text-transform:uppercase;">
          Multiplayer Bridge
        </div>
        <div style="font-size:14px;color:#c8c4bc;line-height:1.8;margin-bottom:32px;">
          Thanks for signing up. Click the button below to verify your email address and activate your account.
        </div>
        <a href="${link}" style="display:inline-block;background:#b01828;color:#fff;padding:12px 32px;text-decoration:none;font-size:13px;letter-spacing:4px;text-transform:uppercase;font-weight:600;">
          Verify Account
        </a>
        <div style="margin-top:32px;font-size:10px;color:#504840;letter-spacing:1px;">
          This link expires in 24 hours. If you didn't create an account, ignore this email.
        </div>
      </div>
    `
  });
}

// ─── JSON Database ────────────────────────────────────────────────────────────
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

// ─── Disposable email blocklist ───────────────────────────────────────────────
const DISPOSABLE_DOMAINS = new Set([
  'mailinator.com','guerrillamail.com','guerrillamail.net','guerrillamail.org',
  'temp-mail.org','tempmail.com','tempmail.net','throwam.com','trashmail.com',
  'trashmail.net','trashmail.me','yopmail.com','yopmail.fr','dispostable.com',
  'fakeinbox.com','mailnull.com','maildrop.cc','mailnesia.com','pookmail.com',
  'tempr.email','discard.email','discardmail.com','mohmal.com','tempinbox.com',
  '10minutemail.com','10minutemail.net','minutemail.com','20minutemail.com',
  'emailondeck.com','getairmail.com','filzmail.com','sharklasers.com',
  'spam4.me','grr.la','guerrillamail.info','spamgourmet.com','spamhole.com',
  'mailtemp.net','mailtemp.info','wegwerfmail.de','wegwerfmail.net',
  'jetable.fr.nf','jetable.net','jetable.org','jetable.com','netzidiot.de'
]);

function isDisposableEmail(email) {
  const domain = email.split('@')[1]?.toLowerCase();
  if (!domain) return true;
  return DISPOSABLE_DOMAINS.has(domain);
}

// ─── Password validation ──────────────────────────────────────────────────────
function validatePassword(password) {
  if (password.length < 8)
    return 'Password must be at least 8 characters';
  if (!/[A-Z]/.test(password))
    return 'Password must contain at least one uppercase letter';
  if (!/[0-9]/.test(password))
    return 'Password must contain at least one number';
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password))
    return 'Password must contain at least one special character';
  return null;
}

// ─── Auth ─────────────────────────────────────────────────────────────────────
app.post('/auth/signup', async (req, res) => {
  const { email, password, gamertag } = req.body || {};
  if (!email || !password || !gamertag)
    return res.status(400).json({ error: 'Email, password, and gamertag are required' });

  const passError = validatePassword(password);
  if (passError) return res.status(400).json({ error: passError });

  if (!/^[a-zA-Z0-9_\-]{3,20}$/.test(gamertag))
    return res.status(400).json({ error: 'Gamertag: 3-20 chars, letters/numbers/_-' });

  if (rateLimit(`signup:${req.ip}`, 5, 60000))
    return res.status(429).json({ error: 'Too many attempts. Wait a minute.' });

  const emailLower = email.toLowerCase().trim();

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailLower))
    return res.status(400).json({ error: 'Invalid email address' });
  if (isDisposableEmail(emailLower))
    return res.status(400).json({ error: 'Disposable or temporary email addresses are not allowed' });
  if (Object.values(DB.users).some(u => u.email === emailLower))
    return res.status(409).json({ error: 'Email already registered' });
  if (Object.values(DB.users).some(u => u.gamertag.toLowerCase() === gamertag.toLowerCase()))
    return res.status(409).json({ error: 'Gamertag already taken' });

  const id = uuid();
  const hash = await bcrypt.hash(password, 12);
  const verifyToken = crypto.randomBytes(32).toString('hex');
  const verifyExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

  DB.users[id] = {
    id, email: emailLower, password_hash: hash,
    gamertag: gamertag.trim(), created_at: Date.now(),
    verified: false, verifyToken, verifyExpires
  };
  saveDB();

  // Send verification email
  try {
    await sendVerificationEmail(emailLower, verifyToken);
  } catch (err) {
    console.error('[email] Failed to send verification:', err.message);
    // Don't fail signup if email fails — just log it
  }

  res.status(201).json({ message: 'Account created. Please check your email to verify your account before logging in.' });
});

// Email verification endpoint
app.get('/auth/verify/:token', (req, res) => {
  const { token } = req.params;
  const user = Object.values(DB.users).find(u => u.verifyToken === token);

  if (!user) return res.status(400).send(verifyPage('Invalid or expired verification link.', false));
  if (Date.now() > user.verifyExpires) return res.status(400).send(verifyPage('Verification link has expired. Please sign up again.', false));

  DB.users[user.id].verified = true;
  DB.users[user.id].verifyToken = null;
  DB.users[user.id].verifyExpires = null;
  saveDB();

  res.send(verifyPage('Your account has been verified. You can now log in to RE4MP.', true));
});

function verifyPage(message, success) {
  return `<!DOCTYPE html>
<html>
<head><title>RE4MP Verification</title>
<style>
  body { background: #080c12; color: #e8e0d0; font-family: sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
  .box { text-align: center; max-width: 400px; padding: 40px; border: 1px solid ${success ? '#305030' : '#701018'}; }
  h1 { font-size: 28px; letter-spacing: 4px; margin-bottom: 8px; color: ${success ? '#90c890' : '#e08090'}; }
  p { font-size: 13px; color: #a8a49c; line-height: 1.7; }
  .brand { font-size: 22px; font-weight: 700; letter-spacing: 6px; margin-bottom: 32px; }
  .brand span { color: #b01828; }
</style>
</head>
<body>
<div class="box">
  <div class="brand"><span>R</span>E4MP</div>
  <h1>${success ? '✓ VERIFIED' : '✗ FAILED'}</h1>
  <p>${message}</p>
</div>
</body>
</html>`;
}

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  if (rateLimit(`login:${req.ip}`, 10, 60000))
    return res.status(429).json({ error: 'Too many attempts. Wait a minute.' });

  const user = Object.values(DB.users).find(u => u.email === email.toLowerCase().trim());
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) return res.status(401).json({ error: 'Invalid email or password' });

  if (!user.verified)
    return res.status(403).json({ error: 'Please verify your email before logging in. Check your inbox.' });

  const token = jwt.sign({ id: user.id, email: user.email, gamertag: user.gamertag }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: user.id, email: user.email, gamertag: user.gamertag } });
});

// ─── Rooms ────────────────────────────────────────────────────────────────────
app.post('/rooms', requireAuth, (req, res) => {
  const { name } = req.body || {};
  const existing = Object.values(DB.rooms).find(r => r.host_id === req.user.id && r.status === 'waiting');
  if (existing) return res.status(400).json({ error: 'You already have an open room. Close it first.' });
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
