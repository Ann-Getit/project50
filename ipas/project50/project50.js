const express = require('express');
const app = express();
require('dotenv').config();
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const PORT = process.env.PORT || 3002;
const cors = require('cors');
const JWT_SECRET = process.env.JWT_SECRET;



app.use(bodyParser.json());

//CORS aanzetten voor alle frontends
app.use(cors({
    origin: '*',   // alle frontends toegestaan
  methods: ['GET','POST','PUT','DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));




app.use(express.json());//Middleware

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ success: false, message: 'Geen token meegegeven' });

  const token = authHeader.split(' ')[1]; // "Bearer TOKEN"

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, message: 'Token ongeldig' });
    req.user = user; // zet de user in req voor later gebruik
    next();
  });
}


app.use((req, res, next) => {
  console.log('Incoming request:', req.method, req.url);
  next();
});

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

db.connect(err => {
  if (err) {
  console.error('❌ MySQL connection failed:', err);
    process.exit(1); // stop app als DB niet connect

}
  console.log('✅Connected to MySQL!');
});


app.use((req, res, next) => {
  console.log('Incoming request:', req.method, req.url, req.body);
  next();
});

app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  next();
});

const bcrypt = require('bcrypt');
//schrijft (nieuwe user maken)
app.post('/api/users', async (req, res) => { //post endpoint
  const { name, email, password } = req.body;


//validatie data
 if (!name.trim() || !email.trim() || !password.trim()) {
    return res.status(400).json({ success: false, message: 'Name,  email en pw zijn verplicht' });
  }
  // Eenvoudige e-mail check
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ success: false, message: 'Ongeldig e-mailadres' });
  }

  try {
    // 2️⃣ Password hashen
    const hashedPassword = await bcrypt.hash(password, 10);

  db.query(
    'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
    [name, email, hashedPassword],
    (err, result) => {
      if (err) {
        console.error('MySQL error:', err);

        // Check duplicate email
          if (err.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ success: false, message: 'Email bestaat al' });
          }
        return res.status(500).json({ success: false, message: 'Kon user niet aanmaken' });
    }


        res.json({
          success: true,
          id: result.insertId,
          name,
          email
        });
      }
    );
    } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Er is iets misgegaan' });
    }
});



// LOGIN endpoint-------------------------
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  if (!email.trim() || !password.trim()) {
    return res.status(400).json({ success: false, message: 'Email en password zijn verplicht' });
  }

  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) {
      console.error('MySQL error:', err);
      return res.status(500).json({ success: false, message: 'Database fout' });
    }

    if (results.length === 0) {
      return res.status(401).json({ success: false, message: 'Ongeldig email of wachtwoord' });
    }

    const user = results[0];

    // bcrypt compare check
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({ success: false, message: 'Ongeldig email of wachtwoord' });
    }


       // ✅ Maak JWT token
    const token = jwt.sign(
      { id: user.id, name: user.name, email: user.email },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    // ✅ Stuur token mee terug 
    console.log('Generated JWT token:', token);
res.json({
      success: true,
      message: 'Login succesvol',
      token,
      user: { id: user.id, name: user.name, email: user.email }
    });
  });
});

app.post('/api/logout', (req, res) => {
const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(400).json({ success: false, message: 'Geen token meegegeven' });
  

  const token = authHeader.split(' ')[1]; // "Bearer TOKEN"
if (!token) return res.status(400).json({ success: false, message: 'Ongeldige token' });

  try {
  // token verifiëren 
  const user = jwt.verify(token, JWT_SECRET); 
  console.log(`User heeft uitgelogd: ${user.name} (${user.email})`);

res.json({ 
    success: true, 
    message: 'Logout geregistreerd', user });
  } catch (err) {
    return res.status(400).json({ success: false, message: 'Ongeldige token' });
  }
});





app.get('/api/users/:id', authenticateToken, (req, res) => {
  const userId = req.params.id;

  // Je kan nu req.user gebruiken (uit de token)
  console.log('Ingelogde user:', req.user);

  db.query('SELECT * FROM users WHERE id = ?', [userId], (err, results) => {
    if (err) return res.status(500).send('Database error');
    if (results.length === 0) return res.status(404).json({ message: 'User niet gevonden' });
    res.json(results[0]);
});
});

app.get('/api/users/', (req, res) => { //eadonly (alle users ophalen)
  console.log('GET /api/users hit');  // check of request binnenkomt
  db.query('SELECT * FROM users', (err, results) => {
    if (err) return res.status(500).send('Database error');
     // console.error('DB query error:', err);
    res.json(results);
  });
});


// UPDATE (user aanpassen)
app.put('/api/users/:id', (req, res) => {
  console.log('PUT /api/users/:id hit', req.params, req.body);
  const userId = req.params.id;
  const { name, email } = req.body;
  

// Validatie
  if (!name.trim() || !email.trim()) {
    return res.status(400).json({ message: 'Name en email zijn verplicht' });
  }
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: 'Ongeldig e-mailadres' });
  }


  db.query(
    'UPDATE users SET name = ?, email = ? WHERE id = ?',
    [name, email, userId],
    (err, result) => {
      if (err) return res.status(500).send('Database error');
       // console.error('MySQL error:', err);
        
      if (result.affectedRows === 0)  return res.status(404).json({ message: 'User niet gevonden' });
      
      res.json({ id: userId, name, email });
    });
});

// DELETE (user verwijderen)
app.delete('/api/users/:id', (req, res) => {
  const userId = req.params.id;

  db.query('DELETE FROM users WHERE id = ?', [userId], (err, result) => {
    if (err) {
      console.error('MySQL error:', err);
      return res.status(500).send('Database error');
    }
      
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'User niet gevonden' });
    }
    res.json({ message: `User met id=${userId} verwijderd` });
  });
});

//Test POST endpoint


app.get('/ping', (req, res) => {
  console.log('got GET /ping');
  res.send('pong');
});

app.use(express.static('public'));

app.listen(PORT, () => {
console.log(`🚀 listening :${PORT} ✅`);
});









// mysql volledige pad /usr/local/mysql/bin/mysql --version
// datadir=/usr/local/mysql/data → hier staan de databases

//inloggen on mysql:  /usr/local/mysql/bin/mysql -u root -p

//-----------------------------------------------

/*curl -v -X POST http://127.0.0.1:3001/api \
>   -H "Content-Type: application/json" \
>   -d '{"name":"Anna","email":"anna@example.com"}'*/

//API testen  ||   curl http://127.0.0.1:3001/api/users

//mijn API URL ||  http://127.0.0.1:3001/api/users
