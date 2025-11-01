// --- server.js (ESM) ---
import express from 'express';
import cors from 'cors';
import fs from 'fs-extra';
import path from 'node:path';
import crypto from 'node:crypto';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import validator from 'validator';
import { fileURLToPath } from 'node:url';

// If you don't use these yet, you can remove them:
// import multer from 'multer';
// import { nanoid } from 'nanoid';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(
  cors({
    origin: process.env.FRONTEND_BASE_URL || '*',
    credentials: false,
  })
);

// -------- Simple JSON "DB"
const DB_PATH = path.join(__dirname, 'db.json');
async function loadDB() {
  try {
    return await fs.readJson(DB_PATH);
  } catch {
    return { users: {}, vaults: {} };
  }
}
async function saveDB(db) {
  await fs.writeJson(DB_PATH, db, { spaces: 2 });
}

// -------- Helpers
function genToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}
function hoursFromNow(h) {
  return new Date(Date.now() + h * 3600 * 1000).toISOString();
}

// -------- Email transport
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

transporter.verify()
  .then(() => console.log('SMTP: OK'))
  .catch(e => console.error('SMTP: FAIL ->', e.message));
console.log('APP_BASE_URL:', process.env.APP_BASE_URL);
console.log('FRONTEND_BASE_URL:', process.env.FRONTEND_BASE_URL);

// -------- Rate limits
const registerLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 60 });

// ========== ROUTES ==========

// POST /register { username, email, salt, verifier, vault }
app.post('/register', registerLimiter, async (req, res) => {
  const { username, email, salt, verifier, vault } = req.body || {};
  if (!username || !email || !salt || !verifier || !vault) {
    return res.status(400).json({ error: 'Missing fields' });
  }
  if (!validator.isEmail(email)) {
    return res.status(400).json({ error: 'Invalid email' });
  }

  const db = await loadDB();

  const uname = String(username).toLowerCase();
  const existingUserByName = db.users[uname];
  const existingUserByEmail = Object.values(db.users).find(
    (u) => u.email.toLowerCase() === email.toLowerCase()
  );

  if (existingUserByName) return res.status(409).json({ error: 'Username already exists' });
  if (existingUserByEmail) return res.status(409).json({ error: 'Email already registered' });

  const activationToken = genToken(32);
  const tokenTTL = Number(process.env.TOKEN_TTL_HOURS || 24);
  const activationExpiresAt = hoursFromNow(tokenTTL);

  db.users[uname] = {
    username: uname,
    email,
    salt,
    verifier,
    isActivated: false,
    activationToken,
    activationExpiresAt,
  };
  db.vaults[uname] = vault;

  await saveDB(db);

  const activateUrl = `${process.env.APP_BASE_URL || 'http://localhost:3000'}/activate?token=${activationToken}`;
  const html = `
  <div style="font-family:system-ui,Segoe UI,Roboto,Arial">
    <h2>Activate your account</h2>
    <p>Hi ${validator.escape(username)}, thanks for registering.</p>
    <p><a href="${activateUrl}" style="display:inline-block;padding:10px 16px;border-radius:8px;text-decoration:none;border:1px solid #333">Activate Account</a></p>
    <p>If the button doesn’t work: <a href="${activateUrl}">${activateUrl}</a></p>
    <p>This link expires in ${tokenTTL} hours.</p>
  </div>`;

  try {
    await transporter.sendMail({
      from: process.env.EMAIL_FROM || 'no-reply@example.com',
      to: email,
      subject: 'Activate your account',
      html,
    });
  } catch (e) {
    // rollback if email fails
    delete db.users[uname];
    delete db.vaults[uname];
    await saveDB(db);
    return res.status(500).json({ error: 'Failed to send activation email' });
  }

  res.json({ ok: true, message: 'Registration received. Check your email to activate.' });
});

// GET /activate?token=...
app.get('/activate', async (req, res) => {
  const { token } = req.query || {};
  if (!token || typeof token !== 'string') {
    return res.status(400).send('Invalid activation link');
  }
  const db = await loadDB();
  const userEntry = Object.values(db.users).find((u) => u.activationToken === token);
  if (!userEntry) return res.status(400).send('Invalid or already used activation token');

  if (new Date(userEntry.activationExpiresAt).getTime() < Date.now()) {
    return res.status(400).send('Activation link has expired. Please re-register.');
  }

  userEntry.isActivated = true;
  userEntry.activationToken = undefined;
  userEntry.activationExpiresAt = undefined;
  await saveDB(db);

  const loginUrl = `${process.env.FRONTEND_BASE_URL || 'http://127.0.0.1:5500'}/password-manager.html#activated`;
  res.redirect(loginUrl);
});

// Debug: show DB content (do NOT leave this in production)
// Debug: show DB (remove later)
app.get('/debug-db', async (req, res) => {
  try { res.json(await loadDB()); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// Debug: send a test email (remove later)
app.get('/debug-send', async (req, res) => {
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: 'test@example.com',
      subject: 'Mailtrap test',
      text: 'Hello from debug'
    });
    res.send('OK – check Mailtrap Sandbox inbox');
  } catch (e) {
    res.status(500).send(e.message);
  }
});

// Health
app.get('/', (req, res) => res.send('PM server running'));

// POST /login { username }
app.post('/login', loginLimiter, async (req, res) => {
  const { username } = req.body || {};
  if (!username) return res.status(400).json({ error: 'Missing username' });

  const uname = String(username).toLowerCase();
  const db = await loadDB();
  const user = db.users[uname];
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (!user.isActivated) return res.status(403).json({ error: 'Account not activated. Check your email.' });

  const vault = db.vaults[uname];
  res.json({
    username: uname,
    email: user.email,
    salt: user.salt,
    verifier: user.verifier,
    vault,
  });
});

// POST /updateVault { username, vault }
app.post('/updateVault', async (req, res) => {
  const { username, vault } = req.body || {};
  if (!username || !vault) return res.status(400).json({ error: 'Missing fields' });
  const uname = String(username).toLowerCase();

  const db = await loadDB();
  const user = db.users[uname];
  if (!user || !user.isActivated) return res.status(403).json({ error: 'Not allowed' });

  db.vaults[uname] = vault;
  await saveDB(db);
  res.json({ ok: true });
});

// Health
app.get('/', (req, res) => res.send('PM server running'));

// Start
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server on http://localhost:${PORT}`));

