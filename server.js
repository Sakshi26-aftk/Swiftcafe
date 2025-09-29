require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'secret123',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 3600000 } // 1 hour
}));

// MySQL connection
let db;
(async () => {
  db = await mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
  });
  console.log('✅ Connected to MySQL');
})();

// ====================
// Register endpoint
// ====================
app.post('/register', async (req,res)=>{
  const { name, email, username, role, password } = req.body;
  try {
    const hashed = await bcrypt.hash(password, 10);
    await db.execute(
      'INSERT INTO users (name,email,username,role,password) VALUES (?,?,?,?,?)',
      [name,email,username,role,hashed]
    );
    res.json({ message:'Registration successful' });
  } catch(err){
    console.error(err);
    res.status(500).json({ error:'Registration failed' });
  }
});

// ====================
// Login endpoint
// ====================
app.post('/login', async (req,res)=>{
  const { username,password } = req.body;
  try {
    const [rows] = await db.execute('SELECT * FROM users WHERE username=?', [username]);
    if(!rows.length) return res.status(401).json({ error:'Invalid credentials' });

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);
    if(!match) return res.status(401).json({ error:'Invalid credentials' });

    // Store session info
    req.session.userId = user.id;
    req.session.role = user.role;

    // Return user data
    res.json({
      id: user.id,
      username: user.username,
      name: user.name,
      email: user.email,
      dob: user.dob || '',
      points: user.points || 0,
      role: user.role
    });

  } catch(err){
    console.error(err);
    res.status(500).json({ error:'Login failed' });
  }
});

// ====================
// Profile endpoint
// ====================
app.get('/profile', async (req, res) => {
  if(!req.session.userId) return res.status(401).json({ error: 'Not logged in' });

  try {
    const [rows] = await db.execute(
      'SELECT id, username, name, email, dob, points, role FROM users WHERE id=?',
      [req.session.userId]
    );
    if(rows.length === 0) return res.status(404).json({ error: 'User not found' });

    res.json(rows[0]);
  } catch(err){
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// ====================
// Logout endpoint
// ====================
app.post('/logout', (req,res)=>{
  req.session.destroy(err => {
    if(err) return res.status(500).json({ error:'Logout failed' });
    res.json({ message:'Logged out' });
  });
});

// ====================
// Save Orders
// ====================
app.post('/save-order', async (req, res) => {
  const orders = req.body.orders;

  if (!orders || !orders.length) {
    return res.status(400).json({ error: 'No orders received' });
  }

  try {
    const values = orders.map(o => [o.item, o.price, o.qty]);
    await db.query(
      'INSERT INTO orders (item_name, price, qty) VALUES ?',
      [values]
    );
    res.json({ message: '✅ Orders saved successfully', inserted: orders.length });
  } catch (err) {
    console.error('❌ Error saving orders:', err);
    res.status(500).json({ error: 'Failed to save orders' });
  }
});

// ====================
// Fetch all orders
// ====================
app.get('/orders', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM orders ORDER BY created_at DESC');
    res.json(rows);
  } catch (err) {
    console.error('❌ Error fetching orders:', err);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// Start server
app.listen(PORT, ()=>console.log(`Server running on port ${PORT}`));
