const express = require('express');
const path = require('path');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const session = require('express-session');
const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(session({
  secret: 'secret-key',
  resave: false,
  saveUninitialized: false, // changed from true
  cookie: {
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));



// app.get('/i', (req, res) => {
//   console.log('Route /i hit');
//   res.send('hello there');
// });

app.use(express.static(path.join(__dirname, 'public')));
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Oluwasegun&1',
  database: 'auth_app'
});

db.connect(err => {
  if (err) throw err;
  console.log('Connected to MySQL');
});

app.get('/', (req, res) => res.redirect('/signup'));



app.get('/signup', (req, res) => res.sendFile(path.join(__dirname, 'public/signup.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public/login.html')));
app.get('/dashboard', (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'public/dashboard.html'));
});

app.post('/signup', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: 'Missing fields' });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], err => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ message: 'User already exists' });
        return res.status(500).json({ message: 'DB error' });
      }
      res.json({ message: 'User registered' });
    });
  } catch {
    res.status(500).json({ message: 'Internal error' });
  }
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
    if (err || results.length === 0) return res.status(400).json({ message: 'Invalid credentials' });

    const user = results[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: 'Incorrect password' });

    req.session.userId = user.id;
    res.json({ message: 'Login successful' });
  });
});


// Place this before app.listen()
// app.post('/logout', (req, res) => {
//   console.log('Logout route hit');
//   console.log('Session:', req.session);
  
//   if (!req.session || !req.session.userId) {
//     return res.status(401).json({ message: 'Not logged in' });
//   }

//   req.session.destroy((err) => {
//     if (err) {
//       console.error('Logout error:', err);
//       return res.status(500).json({ message: 'Could not log out' });
//     }
//     res.clearCookie('connect.sid');
//     return res.status(200).json({ message: 'Logged out successfully' });
//   });
// });
// app.get('/logout', (req, res) => {
//   req.session.destroy(err => {
//     if (err) return res.redirect('/dashboard');
//     res.clearCookie('connect.sid');
//     res.redirect('/login');
//   });
// });








app.listen(5000, () => console.log('Server running on http://localhost:5000'));