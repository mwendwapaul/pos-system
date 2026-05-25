const express = require('express');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.static('public'));

// Create data directory
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

// Create database connection
const dbPath = path.join(dataDir, 'pos.db');
const db = new Database(dbPath);
console.log('✅ Database connected');

// Create all tables
db.exec(`
  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    sku TEXT,
    barcode TEXT,
    price REAL NOT NULL,
    cost REAL DEFAULT 0,
    quantity INTEGER DEFAULT 0,
    min_stock INTEGER DEFAULT 5,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS sales (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sale_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    total REAL NOT NULL,
    tax REAL DEFAULT 0,
    payment_method TEXT,
    cashier_name TEXT
  );

  CREATE TABLE IF NOT EXISTS sale_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sale_id INTEGER,
    product_id INTEGER,
    quantity INTEGER,
    price_at_sale REAL,
    FOREIGN KEY(sale_id) REFERENCES sales(id),
    FOREIGN KEY(product_id) REFERENCES products(id)
  );

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'cashier',
    full_name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Create default admin user
const adminPassword = bcrypt.hashSync('admin123', 10);
const existingAdmin = db.prepare('SELECT * FROM users WHERE username = ?').get('admin');
if (!existingAdmin) {
  db.prepare('INSERT INTO users (username, password, role, full_name) VALUES (?, ?, ?, ?)')
    .run('admin', adminPassword, 'admin', 'Store Owner');
  console.log('✅ Admin user created (admin/admin123)');
}

console.log('✅ Database tables ready');

// ============ AUTHENTICATION ============
const SECRET_KEY = process.env.JWT_SECRET || 'your-secret-key-change-this';

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    SECRET_KEY,
    { expiresIn: '24h' }
  );
  
  res.json({ 
    token, 
    user: { id: user.id, username: user.username, role: user.role, full_name: user.full_name }
  });
});

function verifyToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ============ USER ROUTES ============
// Get all users (admin only)
app.get('/api/users', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  const users = db.prepare('SELECT id, username, role, full_name FROM users').all();
  res.json(users);
});

// Create new user (admin only)
app.post('/api/users', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  const { username, password, role, full_name } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);
  
  try {
    const result = db.prepare('INSERT INTO users (username, password, role, full_name) VALUES (?, ?, ?, ?)')
      .run(username, hashedPassword, role, full_name);
    res.json({ id: result.lastInsertRowid, message: 'User created' });
  } catch (err) {
    res.status(500).json({ error: 'Username already exists' });
  }
});

// Delete user (admin only)
app.delete('/api/users/:username', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  
  const { username } = req.params;
  
  // Prevent deleting the default admin
  if (username === 'admin') {
    return res.status(400).json({ error: 'Cannot delete default admin user' });
  }
  
  const result = db.prepare('DELETE FROM users WHERE username = ?').run(username);
  if (result.changes === 0) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json({ message: 'User deleted successfully' });
});

// ============ PRODUCT ROUTES ============
app.get('/api/products', verifyToken, (req, res) => {
  const products = db.prepare('SELECT * FROM products ORDER BY name').all();
  res.json(products);
});

app.get('/api/products/search', verifyToken, (req, res) => {
  const { q } = req.query;
  const products = db.prepare(
    `SELECT * FROM products 
     WHERE barcode = ? OR sku = ? OR name LIKE ? 
     LIMIT 10`
  ).all(q, q, `%${q}%`);
  res.json(products);
});

app.get('/api/products/low-stock', verifyToken, (req, res) => {
  const products = db.prepare('SELECT * FROM products WHERE quantity <= min_stock ORDER BY quantity ASC').all();
  res.json(products);
});

app.post('/api/products', verifyToken, (req, res) => {
  const { name, sku, barcode, price, cost, quantity, min_stock } = req.body;
  
  const result = db.prepare(
    `INSERT INTO products (name, sku, barcode, price, cost, quantity, min_stock)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(name, sku || null, barcode || null, price, cost || 0, quantity || 0, min_stock || 5);
  
  res.json({ id: result.lastInsertRowid, message: 'Product added successfully' });
});

app.put('/api/products/:id', verifyToken, (req, res) => {
  const { name, sku, barcode, price, cost, quantity, min_stock } = req.body;
  db.prepare(
    `UPDATE products SET name=?, sku=?, barcode=?, price=?, cost=?, quantity=?, min_stock=?
     WHERE id=?`
  ).run(name, sku, barcode, price, cost, quantity, min_stock, req.params.id);
  res.json({ message: 'Product updated' });
});

app.delete('/api/products/:id', verifyToken, (req, res) => {
  db.prepare('DELETE FROM products WHERE id=?').run(req.params.id);
  res.json({ message: 'Product deleted' });
});

// ============ SALES ROUTES ============
app.post('/api/sales', verifyToken, (req, res) => {
  const { items, total, tax, payment_method, cashier_name } = req.body;
  
  const insertSale = db.prepare(
    `INSERT INTO sales (total, tax, payment_method, cashier_name)
     VALUES (?, ?, ?, ?)`
  );
  
  const insertSaleItem = db.prepare(
    `INSERT INTO sale_items (sale_id, product_id, quantity, price_at_sale)
     VALUES (?, ?, ?, ?)`
  );
  
  const updateStock = db.prepare('UPDATE products SET quantity = quantity - ? WHERE id = ?');
  
  const saleId = db.transaction(() => {
    const saleResult = insertSale.run(total, tax, payment_method, cashier_name);
    const id = saleResult.lastInsertRowid;
    
    for (const item of items) {
      insertSaleItem.run(id, item.id, item.quantity, item.price);
      updateStock.run(item.quantity, item.id);
    }
    
    return id;
  })();
  
  res.json({ 
    sale_id: saleId, 
    message: 'Sale completed',
    receipt: {
      id: saleId,
      date: new Date(),
      items,
      total,
      tax,
      payment_method
    }
  });
});

app.get('/api/sales/today', verifyToken, (req, res) => {
  const row = db.prepare(
    `SELECT COALESCE(SUM(total), 0) as total_today, COUNT(*) as sale_count
     FROM sales WHERE DATE(sale_date) = DATE('now')`
  ).get();
  res.json(row);
});

app.get('/api/sales/history', verifyToken, (req, res) => {
  const { limit = 50 } = req.query;
  const rows = db.prepare(
    `SELECT s.*, 
      (SELECT COUNT(*) FROM sale_items WHERE sale_id = s.id) as item_count
     FROM sales s 
     ORDER BY s.sale_date DESC 
     LIMIT ?`
  ).all(limit);
  res.json(rows);
});

// ============ REPORTS ROUTES ============
app.get('/api/reports/sales', verifyToken, (req, res) => {
  const { start, end } = req.query;
  
  const summary = db.prepare(
    `SELECT 
       COALESCE(SUM(total), 0) as total_sales,
       COUNT(*) as transaction_count,
       COALESCE(AVG(total), 0) as average_order
     FROM sales 
     WHERE DATE(sale_date) BETWEEN DATE(?) AND DATE(?)`
  ).get(start, end);
  
  const topProducts = db.prepare(
    `SELECT 
       p.name,
       SUM(si.quantity) as total_quantity,
       SUM(si.quantity * si.price_at_sale) as revenue
     FROM sale_items si
     JOIN products p ON si.product_id = p.id
     JOIN sales s ON si.sale_id = s.id
     WHERE DATE(s.sale_date) BETWEEN DATE(?) AND DATE(?)
     GROUP BY si.product_id
     ORDER BY revenue DESC
     LIMIT 5`
  ).all(start, end);
  
  res.json({ ...summary, top_products: topProducts });
});

// ============ DEFAULT ROUTE ============
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// ============ START SERVER ============
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 POS System running on port ${PORT}`);
  console.log(`📋 Login: admin / admin123`);
  console.log(`📍 Open: http://localhost:${PORT}/login.html`);
});