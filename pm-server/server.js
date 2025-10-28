import express from "express";
import cors from "cors";
import fs from "fs-extra";

const app = express();
const PORT = process.env.PORT || 3000;

// allow JSON body
app.use(express.json());

// allow your frontend to talk to this backend
app.use(cors());

// path to our "database" file on disk
const DB_FILE = "./users.json";

// make sure file exists
async function initDB() {
  if (!(await fs.pathExists(DB_FILE))) {
    await fs.writeJson(DB_FILE, {}); // start with empty object {}
  }
}
await initDB();

// helper: load all users
async function loadUsers() {
  return fs.readJson(DB_FILE);
}

// helper: save all users
async function saveUsers(users) {
  return fs.writeJson(DB_FILE, users, { spaces: 2 });
}

/*
POST /register
Body: {
  "username": "Admin",
  "salt": "...",
  "verifier": "...",
  "vault": { "iv": "...", "ciphertext": "..." }
}
*/
app.post("/register", async (req, res) => {
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
});

/*
POST /login
Body: { "username": "Admin" }
Returns that user's encrypted record
(frontend will verify password and decrypt vault locally)
*/
app.post("/login", async (req, res) => {
  const { username } = req.body;

  if (!username) {
    return res.status(400).json({ error: "Missing username" });
  }

  const users = await loadUsers();
  if (!users[username]) {
    return res.status(404).json({ error: "No such user" });
  }

  res.json(users[username]);
});

/*
POST /updateVault
Body: {
  "username": "Admin",
  "vault": { "iv": "...", "ciphertext": "..." }
}
Used when user adds new password entries.
*/
app.post("/updateVault", async (req, res) => {
  const { username, vault } = req.body;

  if (!username || !vault) {
    return res.status(400).json({ error: "Missing fields" });
  }

  const users = await loadUsers();
  if (!users[username]) {
    return res.status(404).json({ error: "No such user" });
  }

  users[username].vault = vault;
  await saveUsers(users);

  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log("Password Manager backend running on port", PORT);
});
