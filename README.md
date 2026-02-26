# studious-tribble2

const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const fs = require('fs');

const app = express();
const db = new sqlite3.Database('./users.db');

// ===== VULNERABILITY 1: Security Misconfiguration =====
// Weak session secret, insecure cookies
app.use(session({
  secret: 'insecure-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { 
    httpOnly: false,  // XSS vulnerable
    secure: false     // No HTTPS enforcement
  }
}));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static('public'));

// Initialize DB
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT,
  password TEXT,
  email TEXT,
  role TEXT
)`);

// ===== VULNERABILITY 2: SQL Injection =====
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // VULNERABLE: No prepared statements, direct string concatenation
  const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  
  db.get(sql, (err, row) => {
    if (row) {
      req.session.userId = row.id;
      req.session.username = row.username;
      req.session.role = row.role;
      res.send('Login successful!');
    } else {
      res.status(401).send('Invalid credentials');
    }
  });
});

// ===== VULNERABILITY 3: Broken Authentication =====
app.post('/register', (req, res) => {
  const { username, password, email } = req.body;
  
  // VULNERABLE: No password validation, no salting/hashing
  const sql = `INSERT INTO users (username, password, email, role) VALUES ('${username}', '${password}', '${email}', 'user')`;
  
  db.run(sql, (err) => {
    if (err) {
      res.status(400).send('Registration failed');
    } else {
      res.send('Registration successful!');
    }
  });
});

// ===== VULNERABILITY 4: Reflected XSS =====
app.get('/search', (req, res) => {
  const query = req.query.q;
  
  // VULNERABLE: User input directly reflected without escaping
  res.send(`
    <html>
      <body>
        <h1>Search Results for: ${query}</h1>
        <p>You searched for: ${query}</p>
      </body>
    </html>
  `);
});

// ===== VULNERABILITY 5: Sensitive Data Exposure =====
app.get('/api/users', (req, res) => {
  // VULNERABLE: No authentication check, exposes all user data
  db.all('SELECT * FROM users', (err, rows) => {
    if (rows) {
      // VULNERABLE: Exposing passwords and sensitive data
      res.json(rows);
    } else {
      res.status(500).send('Error retrieving users');
    }
  });
});

// ===== VULNERABILITY 6: Broken Access Control =====
app.get('/admin', (req, res) => {
  // VULNERABLE: No role/permission checking
  res.send(`
    <html>
      <body>
        <h1>Admin Panel</h1>
        <p>User ID: ${req.session.userId}</p>
        <p>Username: ${req.session.username}</p>
        <button>Delete User</button>
        <button>Modify Settings</button>
      </body>
    </html>
  `);
});

// ===== VULNERABILITY 7: Broken Access Control - IDOR =====
app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  
  // VULNERABLE: No authorization check, anyone can access any user profile
  const sql = `SELECT * FROM users WHERE id = ${userId}`;
  
  db.get(sql, (err, row) => {
    if (row) {
      res.json({
        id: row.id,
        username: row.username,
        email: row.email,
        password: row.password  // VULNERABLE: Exposed
      });
    } else {
      res.status(404).send('User not found');
    }
  });
});

// ===== VULNERABILITY 8: Insecure File Upload =====
app.post('/upload', (req, res) => {
  // VULNERABLE: No file type validation, path traversal possible
  const filename = req.body.filename;
  const content = req.body.content;
  
  fs.writeFileSync(`./uploads/${filename}`, content);
  res.send('File uploaded successfully!');
});

// ===== VULNERABILITY 9: No Rate Limiting / Brute Force =====
app.post('/contact', (req, res) => {
  const { name, email, message } = req.body;
  
  // VULNERABLE: No rate limiting, spam/DOS possible
  // VULNERABLE: No input validation
  const contact = `Name: ${name}\nEmail: ${email}\nMessage: ${message}\n---\n`;
  fs.appendFileSync('./contacts.txt', contact);
  
  res.send('Thank you for contacting us!');
});

// ===== VULNERABILITY 10: Using Components with Known Vulnerabilities =====
// See package.json for vulnerable dependencies
// Example: express-session with known CVE

// ===== VULNERABILITY 11: Insufficient Logging & Monitoring =====
app.post('/api/sensitive-action', (req, res) => {
  // VULNERABLE: No logging of sensitive actions
  const action = req.body.action;
  
  if (action === 'delete_data') {
    db.run('DELETE FROM users', (err) => {
      res.send('Data deleted'); // No audit log
    });
  }
});

// ===== VULNERABILITY 12: XXE (if XML endpoints) =====
const xml2js = require('xml2js');
const parser = new xml2js.Parser({
  // VULNERABLE: XXE not disabled
  resolvexmlEntities: true
});

app.post('/parse-xml', (req, res) => {
  parser.parseString(req.body.xml, (err, result) => {
    res.json(result);
  });
});

// ===== VULNERABILITY 13: Hardcoded Secrets =====
const API_KEY = 'sk-12345678901234567890'; // VULNERABLE: Hardcoded
const DB_PASSWORD = 'admin123'; // VULNERABLE: Hardcoded

// ===== VULNERABILITY 14: CORS Misconfiguration =====
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*'); // VULNERABLE: Allows all origins
  res.header('Access-Control-Allow-Methods', '*');
  res.header('Access-Control-Allow-Headers', '*');
  next();
});

// Server startup
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Aikido Pentest Demo App running on http://localhost:${PORT}`);
  console.log('Ready for vulnerability scanning...');
});
