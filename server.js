
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'pi_coin_secret';

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname)));

// Database setup
const db = new sqlite3.Database('./db.sqlite', (err) => {
  if (err) console.error(err);
  console.log('Connected to SQLite database.');
});

db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT
)`);

db.run(`CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  type TEXT,
  amount REAL,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

// Middleware for token verification
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Register endpoint
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashedPassword], function(err) {
    if (err) return res.status(400).json({ error: 'Username already exists' });
    res.json({ success: true });
  });
});

// Login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  });
});

// Buy endpoint
app.post('/buy', authenticateToken, (req, res) => {
  const { amount } = req.body;
  db.run(`INSERT INTO transactions (user_id, type, amount) VALUES (?, 'buy', ?)`, [req.user.id, amount], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to record transaction' });
    res.json({ success: true });
  });
});

// Sell endpoint
app.post('/sell', authenticateToken, (req, res) => {
  const { amount } = req.body;
  db.run(`INSERT INTO transactions (user_id, type, amount) VALUES (?, 'sell', ?)`, [req.user.id, amount], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to record transaction' });
    res.json({ success: true });
  });
});

// Get transactions
app.get('/transactions', authenticateToken, (req, res) => {
  db.all(`SELECT * FROM transactions WHERE user_id = ? ORDER BY timestamp DESC`, [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch transactions' });
    res.json(rows);
  });
});

// Serve frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
