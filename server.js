import express from "express";
import sqlite3 from "sqlite3";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import bodyParser from "body-parser";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();
const app = express();
const db = new sqlite3.Database("./db.sqlite");
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 3000;
const WALLET_ADDRESS = process.env.PI_WALLET_ADDRESS || "YOUR_WALLET_ADDRESS";
const JWT_SECRET = process.env.JWT_SECRET || "secret123";

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));

// Init database
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS deposits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    txid TEXT,
    amount REAL,
    status TEXT DEFAULT 'pending',
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// Auth middleware
function authenticateToken(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Routes
app.get("/wallet", (req, res) => {
  res.json({ address: WALLET_ADDRESS });
});

app.post("/register", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Missing fields" });
  db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, password], function (err) {
    if (err) return res.status(400).json({ error: "User exists" });
    res.json({ success: true });
  });
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ? AND password = ?`, [username, password], (err, user) => {
    if (!user) return res.status(401).json({ error: "Invalid login" });
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "1d" });
    res.json({ token });
  });
});

app.post("/deposit", authenticateToken, (req, res) => {
  const { txid, amount } = req.body;
  if (!txid || !amount) return res.status(400).json({ error: "Missing data" });
  db.run(`INSERT INTO deposits (user_id, txid, amount) VALUES (?, ?, ?)`, [req.user.id, txid, amount], function (err) {
    if (err) return res.status(500).json({ error: "Failed to save deposit" });
    res.json({ success: true });
  });
});

app.get("/deposits", authenticateToken, (req, res) => {
  db.all(`SELECT * FROM deposits WHERE user_id = ? ORDER BY timestamp DESC`, [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: "Failed to fetch" });
    res.json(rows);
  });
});

// Start server
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
