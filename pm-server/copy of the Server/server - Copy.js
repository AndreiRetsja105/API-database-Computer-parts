// server.mjs
import express from "express";
import cors from "cors";
import multer from "multer";
import fs from "fs-extra";
import path from "path";
import { fileURLToPath } from "url";
import { nanoid } from "nanoid";

// ---- Resolve __dirname and file paths safely
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

// ---- Constants
const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = path.join(__dirname, "secure_uploads");
const DB_FILE    = path.join(__dirname, "users.json");

// ---- App + middleware
const app = express();
app.use(cors());                           // allow your frontend
app.use(express.json({ limit: "2mb" }));   // PBKDF2 payloads etc. are tiny

// Ensure folders / files exist
await fs.ensureDir(UPLOAD_DIR);

async function initDB() {
  if (!(await fs.pathExists(DB_FILE))) {
    await fs.writeJson(DB_FILE, {}); // empty object keyed by username
  }
}
await initDB();

async function loadUsers() {
  return fs.readJson(DB_FILE);
}
async function saveUsers(users) {
  return fs.writeJson(DB_FILE, users, { spaces: 2 });
}

// ---------------- Password Manager API ----------------

/*
POST /register
Body: {
  "username": "Alice",
  "salt": "base64...",
  "verifier": "base64...",
  "vault": { "iv":"...", "ciphertext":"..." }
}
*/
app.post("/register", async (req, res) => {
  try {
    const { username, salt, verifier, vault } = req.body;
    if (!username || !salt || !verifier || !vault) {
      return res.status(400).json({ error: "Missing fields" });
    }
    const users = await loadUsers();
    if (users[username]) {
      return res.status(409).json({ error: "User exists" });
    }
    users[username] = { salt, verifier, vault };
    await saveUsers(users);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

/*
POST /login
Body: { "username": "Alice" }
Returns: { salt, verifier, vault }
*/
app.post("/login", async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: "Missing username" });
    const users = await loadUsers();
    if (!users[username]) return res.status(404).json({ error: "No such user" });
    res.json(users[username]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

/*
POST /updateVault
Body: {
  "username": "Alice",
  "vault": { "iv":"...", "ciphertext":"..." }
}
*/
app.post("/updateVault", async (req, res) => {
  try {
    const { username, vault } = req.body;
    if (!username || !vault) return res.status(400).json({ error: "Missing fields" });
    const users = await loadUsers();
    if (!users[username]) return res.status(404).json({ error: "No such user" });
    users[username].vault = vault;
    await saveUsers(users);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------------- Secure Storage API (.secure files) ----------------

// Multer storage (disk)
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${nanoid(8)}.secure`)
});

// Only accept .secure files
function fileFilter(req, file, cb) {
  const allowed = file.originalname?.toLowerCase().endsWith(".secure");
  if (!allowed) return cb(new Error("Only .secure files are allowed"));
  cb(null, true);
}

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB max; adjust if needed
});

// POST /secure/upload  (field name must be "file")
app.post("/secure/upload", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "Missing file" });
    const id = req.file.filename; // unique id used for download
    res.json({
      id,
      name: req.file.originalname || "encrypted.secure",
      size: req.file.size
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Upload failed" });
  }
});

// GET /secure/download/:id
app.get("/secure/download/:id", async (req, res) => {
  try {
    const filePath = path.join(UPLOAD_DIR, req.params.id);
    if (!(await fs.pathExists(filePath))) {
      return res.status(404).json({ error: "Not found" });
    }
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Disposition", `attachment; filename="${req.params.id}"`);
    fs.createReadStream(filePath).pipe(res);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Download failed" });
  }
});

// DELETE /secure/:id
app.delete("/secure/:id", async (req, res) => {
  try {
    const filePath = path.join(UPLOAD_DIR, req.params.id);
    if (!(await fs.pathExists(filePath))) {
      return res.status(404).json({ error: "Not found" });
    }
    await fs.remove(filePath);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Delete failed" });
  }
});

// Simple health check
app.get("/healthz", (req, res) => res.json({ ok: true }));

// ---- Start once
app.listen(PORT, () => console.log(`API listening on port ${PORT}`));
