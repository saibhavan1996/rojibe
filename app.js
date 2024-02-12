// server.js
const express = require("express");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 5000;

const dbPath = `C:Users\bhava\OneDrive\Desktop\database\roziroti`;

// Initialize SQLite database
const db = new sqlite3.Database(dbPath); // Path to my SQLite database file

// Create tables
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      username TEXT NOT NULL,
      password TEXT NOT NULL
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY,
      userId INTEGER NOT NULL,
      category TEXT NOT NULL,
      amount REAL NOT NULL,
      date TEXT NOT NULL,
      FOREIGN KEY (userId) REFERENCES users(id)
    )
  `);
});

app.use(bodyParser.json());

// User Authentication
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;

  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (err) {
      res.status(500).json({ error: "Internal server error" });
    } else if (!user) {
      res.status(401).json({ error: "Invalid username or password" });
    } else {
      bcrypt.compare(password, user.password, (err, result) => {
        if (err) {
          res.status(500).json({ error: "Internal server error" });
        } else if (!result) {
          res.status(401).json({ error: "Invalid username or password" });
        } else {
          const token = jwt.sign(
            { id: user.id, username: user.username },
            "secret",
            { expiresIn: "1h" }
          );
          res.status(200).json({ token });
        }
      });
    }
  });
});

app.get("/", (req, res) => {
  res.send("Hello, World!");
});

app.post("/api/register", (req, res) => {
  const { username, password } = req.body;

  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      res.status(500).json({ error: "Internal server error" });
    } else {
      db.run(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [username, hash],
        (err) => {
          if (err) {
            res.status(500).json({ error: "Internal server error" });
          } else {
            res.status(201).json({ message: "User registered successfully" });
          }
        }
      );
    }
  });
});

// Middleware to verify token
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(403).json({ error: "Token is required" });
  }

  jwt.verify(token, "secret", (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: "Invalid token" });
    }

    req.user = decoded;
    next();
  });
};

// Transaction Management
app.post("/api/transactions", verifyToken, (req, res) => {
  const { category, amount, date } = req.body;
  const userId = req.user.id;

  db.run(
    `INSERT INTO transactions (userId, category, amount, date) VALUES (?, ?, ?, ?)`,
    [userId, category, amount, date],
    (err) => {
      if (err) {
        res.status(500).json({ error: "Internal server error" });
      } else {
        res.status(201).json({ message: "Transaction added successfully" });
      }
    }
  );
});

app.get("/api/transactions", verifyToken, (req, res) => {
  const userId = req.user.id;

  db.all(
    `SELECT * FROM transactions WHERE userId = ?`,
    [userId],
    (err, transactions) => {
      if (err) {
        res.status(500).json({ error: "Internal server error" });
      } else {
        res.status(200).json(transactions);
      }
    }
  );
});

app.delete("/api/transactions/:id", verifyToken, (req, res) => {
  const id = req.params.id;

  db.run(`DELETE FROM transactions WHERE id = ?`, [id], (err) => {
    if (err) {
      res.status(500).json({ error: "Internal server error" });
    } else {
      res.status(200).json({ message: "Transaction deleted successfully" });
    }
  });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
