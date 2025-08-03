import express from 'express';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cors from 'cors';

const SECRET = 'TwojSekretnyKluczJWT123'; // Zmień na mocniejszy na produkcji
const PORT = process.env.PORT || 3000;

const app = express();
app.use(express.json());
app.use(cors({ origin: true, credentials: true }));

let db;
(async () => {
  db = await open({
    filename: './database.sqlite',
    driver: sqlite3.Database
  });

  // Tworzymy tabele
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      email TEXT UNIQUE,
      password TEXT,
      avatar TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS news (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT,
      content TEXT,
      author TEXT,
      time INTEGER
    );
    CREATE TABLE IF NOT EXISTS chat (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user TEXT,
      text TEXT,
      time INTEGER
    );
  `);

  // Dodaj admina, jeśli nie istnieje
  const admin = await db.get('SELECT * FROM users WHERE username = ?', 'admin');
  if (!admin) {
    const hashed = await bcrypt.hash('admin', 10);
    await db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', 'admin', 'admin@example.com', hashed);
    console.log('Admin user created with password "admin"');
  }
})();

// Middleware weryfikujący token JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Brak tokenu' });

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Nieprawidłowy token' });
    req.user = user;
    next();
  });
}

// Sprawdza czy user to admin
function requireAdmin(req, res, next) {
  if (req.user.username !== 'admin') return res.status(403).json({ error: 'Brak uprawnień' });
  next();
}

// Rejestracja
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'Brak danych' });

  const userExist = await db.get('SELECT * FROM users WHERE username = ? OR email = ?', username, email);
  if (userExist) return res.status(400).json({ error: 'Użytkownik lub email już istnieje' });

  const hashed = await bcrypt.hash(password, 10);
  await db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', username, email, hashed);
  res.json({ message: 'Zarejestrowano pomyślnie' });
});

// Logowanie
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Brak danych' });

  const user = await db.get('SELECT * FROM users WHERE username = ?', username);
  if (!user) return res.status(400).json({ error: 'Nieprawidłowy login lub hasło' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: 'Nieprawidłowy login lub hasło' });

  const token = jwt.sign({ username: user.username }, SECRET, { expiresIn: '8h' });
  res.json({ token, username: user.username, avatar: user.avatar });
});

// Pobierz dane użytkownika
app.get('/api/users/:username', authenticateToken, async (req, res) => {
  const username = req.params.username;
  const user = await db.get('SELECT username, email, avatar FROM users WHERE username = ?', username);
  if (!user) return res.status(404).json({ error: 'Nie znaleziono użytkownika' });
  res.json(user);
});

// Ustaw avatar
app.post('/api/users/avatar', authenticateToken, async (req, res) => {
  const { avatar } = req.body;
  if (!avatar) return res.status(400).json({ error: 'Brak avataru' });
  await db.run('UPDATE users SET avatar = ? WHERE username = ?', avatar, req.user.username);
  res.json({ message: 'Avatar zaktualizowany' });
});

// Pobierz newsy
app.get('/api/news', async (req, res) => {
  const news = await db.all('SELECT * FROM news ORDER BY time DESC');
  res.json(news);
});

// Dodaj news (tylko admin)
app.post('/api/news', authenticateToken, requireAdmin, async (req, res) => {
  const { title, content } = req.body;
  if (!title || !content) return res.status(400).json({ error: 'Brak danych' });
  await db.run('INSERT INTO news (title, content, author, time) VALUES (?, ?, ?, ?)', title, content, req.user.username, Date.now());
  res.json({ message: 'News dodany' });
});

// Usuń news (tylko admin)
app.delete('/api/news/:id', authenticateToken, requireAdmin, async (req, res) => {
  const id = req.params.id;
  await db.run('DELETE FROM news WHERE id = ?', id);
  res.json({ message: 'News usunięty' });
});

// Pobierz wiadomości czatu
app.get('/api/chat', authenticateToken, async (req, res) => {
  const chat = await db.all('SELECT * FROM chat ORDER BY time ASC');
  res.json(chat);
});

// Dodaj wiadomość czatu
app.post('/api/chat', authenticateToken, async (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: 'Brak tekstu' });
  await db.run('INSERT INTO chat (user, text, time) VALUES (?, ?, ?)', req.user.username, text, Date.now());
  res.json({ message: 'Wiadomość dodana' });
});

// Edytuj wiadomość (tylko admin)
app.put('/api/chat/:id', authenticateToken, requireAdmin, async (req, res) => {
  const id = req.params.id;
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: 'Brak tekstu' });
  await db.run('UPDATE chat SET text = ? WHERE id = ?', text, id);
  res.json({ message: 'Wiadomość zaktualizowana' });
});

// Usuń wiadomość (tylko admin)
app.delete('/api/chat/:id', authenticateToken, requireAdmin, async (req, res) => {
  const id = req.params.id;
  await db.run('DELETE FROM chat WHERE id = ?', id);
  res.json({ message: 'Wiadomość usunięta' });
});

app.listen(PORT, () => {
  console.log(`Serwer działa na porcie ${PORT}`);
});
