const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.static('public'));

// Create data directory if it doesn't exist (Render fix)
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

// Create database connection with persistent path
const dbPath = process.env.DATABASE_PATH || path.join(dataDir, 'pos.db');
const db = new sqlite3.Database(dbPath);

// Create all tables
db.serialize(() => {
  // Products table
  db.run(`
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
    )
  `);

  // Sales table
  db.run(`
    CREATE TABLE IF NOT EXISTS sales (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sale_date DATETIME DEFAULT CURRENT_TIMESTAMP,
      total REAL NOT NULL,
      tax REAL DEFAULT 0,
      payment_method TEXT,
      cashier_name TEXT
    )
  `);

  // Sale items table
  db.run(`
    CREATE TABLE IF NOT EXISTS sale_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sale_id INTEGER,
      product_id INTEGER,
      quantity INTEGER,
      price_at_sale REAL,
      FOREIGN KEY(sale_id) REFERENCES sales(id),
      FOREIGN KEY(product_id) REFERENCES products(id)
    )
  `);

  // Users table
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'cashier',
      full_name TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Create default admin user (if not exists)
  const adminPassword = bcrypt.hashSync('admin123', 10);
  db.run(`INSERT OR IGNORE INTO users (username, password, role, full_name) 
          VALUES (?, ?, ?, ?)`, 
          ['admin', adminPassword, 'admin', 'Store Owner']);
  
  console.log('✅ Database tables created successfully');
});

// ============ AUTHENTICATION ============
const SECRET_KEY = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err || !user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    if (bcrypt.compareSync(password, user.password)) {
      const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        SECRET_KEY,
        { expiresIn: '24h' }
      );
      res.json({ 
        token, 
        user: { id: user.id, username: user.username, role: user.role, full_name: user.full_name }
      });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  });
});

// Verify token middleware
function verifyToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.user = decoded;
    next();
  });
}

// ============ PRODUCT ROUTES ============
app.get('/api/products', verifyToken, (req, res) => {
  db.all('SELECT * FROM products ORDER BY name', (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/api/products/search', verifyToken, (req, res) => {
  const { q } = req.query;
  db.all(
    `SELECT * FROM products 
     WHERE barcode = ? OR sku = ? OR name LIKE ? 
     LIMIT 10`,
    [q, q, `%${q}%`],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

app.get('/api/products/low-stock', verifyToken, (req, res) => {
  db.all(
    'SELECT * FROM products WHERE quantity <= min_stock ORDER BY quantity ASC',
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

app.post('/api/products', verifyToken, (req, res) => {
  const { name, sku, barcode, price, cost, quantity, min_stock } = req.body;
  
  db.run(
    `INSERT INTO products (name, sku, barcode, price, cost, quantity, min_stock)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [name, sku || null, barcode || null, price, cost || 0, quantity || 0, min_stock || 5],
    function(err) {
      if (err) {
        console.error('Database error:', err.message);
        return res.status(500).json({ error: err.message });
      }
      res.json({ id: this.lastID, message: 'Product added successfully' });
    }
  );
});

app.put('/api/products/:id', verifyToken, (req, res) => {
  const { name, sku, barcode, price, cost, quantity, min_stock } = req.body;
  db.run(
    `UPDATE products SET name=?, sku=?, barcode=?, price=?, cost=?, quantity=?, min_stock=?
     WHERE id=?`,
    [name, sku, barcode, price, cost, quantity, min_stock, req.params.id],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: 'Product updated' });
    }
  );
});

app.delete('/api/products/:id', verifyToken, (req, res) => {
  db.run('DELETE FROM products WHERE id=?', [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Product deleted' });
  });
});

// ============ SALES ROUTES ============
app.post('/api/sales', verifyToken, (req, res) => {
  const { items, total, tax, payment_method, cashier_name } = req.body;
  
  db.serialize(() => {
    db.run('BEGIN TRANSACTION');
    
    db.run(
      `INSERT INTO sales (total, tax, payment_method, cashier_name)
       VALUES (?, ?, ?, ?)`,
      [total, tax, payment_method, cashier_name],
      function(err) {
        if (err) {
          db.run('ROLLBACK');
          return res.status(500).json({ error: err.message });
        }
        
        const saleId = this.lastID;
        let completed = 0;
        let hasError = false;
        
        items.forEach(item => {
          db.run(
            `INSERT INTO sale_items (sale_id, product_id, quantity, price_at_sale)
             VALUES (?, ?, ?, ?)`,
            [saleId, item.id, item.quantity, item.price],
            (err) => { if (err) hasError = true; }
          );
          
          db.run(
            'UPDATE products SET quantity = quantity - ? WHERE id = ?',
            [item.quantity, item.id],
            (err) => { if (err) hasError = true; }
          );
          
          completed++;
          if (completed === items.length) {
            if (hasError) {
              db.run('ROLLBACK');
              return res.status(500).json({ error: 'Transaction failed' });
            }
            db.run('COMMIT');
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
          }
        });
      }
    );
  });
});

app.get('/api/sales/today', verifyToken, (req, res) => {
  db.get(
    `SELECT COALESCE(SUM(total), 0) as total_today, COUNT(*) as sale_count
     FROM sales WHERE DATE(sale_date) = DATE('now')`,
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(row);
    }
  );
});

// ============ REPORTS ROUTES ============
app.get('/api/reports/sales', verifyToken, (req, res) => {
  const { start, end } = req.query;
  
  db.get(
    `SELECT 
       COALESCE(SUM(total), 0) as total_sales,
       COUNT(*) as transaction_count,
       COALESCE(AVG(total), 0) as average_order
     FROM sales 
     WHERE DATE(sale_date) BETWEEN DATE(?) AND DATE(?)`,
    [start, end],
    (err, summary) => {
      if (err) return res.status(500).json({ error: err.message });
      
      db.all(
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
         LIMIT 5`,
        [start, end],
        (err, topProducts) => {
          res.json({
            ...summary,
            top_products: topProducts || []
          });
        }
      );
    }
  );
});

// ============ USER ROUTES ============
app.get('/api/users', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  db.all('SELECT id, username, role, full_name FROM users', (err, rows) => {
    res.json(rows);
  });
});

app.post('/api/users', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  const { username, password, role, full_name } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);
  
  db.run('INSERT INTO users (username, password, role, full_name) VALUES (?, ?, ?, ?)',
    [username, hashedPassword, role, full_name],
    function(err) {
      if (err) return res.status(500).json({ error: 'Username already exists' });
      res.json({ id: this.lastID, message: 'User created' });
    });
});

// ============ DEFAULT ROUTE ============
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// ============ START SERVER ============
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Database initialized at: ${dbPath}`);
  console.log(`🚀 POS System running on port ${PORT}`);
  console.log(`📋 Login with: admin / admin123`);
  console.log(`📍 Open http://localhost:${PORT}/login.html locally`);
});