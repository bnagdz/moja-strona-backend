const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const SECRET = 'twoj_super_tajny_klucz'; // Zmień na silne hasło!

// Tworzymy bazę SQLite
const db = new sqlite3.Database('./users.db', (err) => {
  if (err) return console.error(err.message);
  console.log('Połączono z bazą danych.');
});

// Tworzymy tabelę użytkowników, jeśli nie istnieje
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT
)`);

// Rejestracja
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Brak loginu lub hasła' });

  const hashedPassword = bcrypt.hashSync(password, 10);

  db.run(
    `INSERT INTO users(username, password) VALUES (?, ?)`,
    [username, hashedPassword],
    function (err) {
      if (err) {
        return res.status(400).json({ error: 'Użytkownik już istnieje' });
      }
      res.json({ message: 'Zarejestrowano pomyślnie' });
    }
  );
});

// Logowanie
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Brak loginu lub hasła' });

  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (err) return res.status(500).json({ error: 'Błąd serwera' });
    if (!user) return res.status(400).json({ error: 'Niepoprawny login lub hasło' });

    const isPasswordValid = bcrypt.compareSync(password, user.password);
    if (!isPasswordValid)
      return res.status(400).json({ error: 'Niepoprawny login lub hasło' });

    // Tworzymy token JWT na 1 godzinę
    const token = jwt.sign({ id: user.id, username: user.username }, SECRET, {
      expiresIn: '1h',
    });
    res.json({ message: 'Zalogowano pomyślnie', token });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Serwer działa na porcie ${PORT}`));
