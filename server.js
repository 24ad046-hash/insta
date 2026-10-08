import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import db from './db.js';
import { hashPassword, comparePassword, generateToken } from './auth.js';
import {
  validateEmail,
  validatePassword,
  validateUsername,
  sanitizeInput,
} from './validation.js';

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'Server is running' });
});

// Sign up endpoint
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { username, email, password, fullName } = req.body;

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const usernameError = validateUsername(sanitizeInput(username));
    if (usernameError) return res.status(400).json({ error: usernameError });

    const emailError = validateEmail(sanitizeInput(email));
    if (!emailError) return res.status(400).json({ error: 'Invalid email format' });

    const passwordError = validatePassword(password);
    if (passwordError) return res.status(400).json({ error: passwordError });

    // Check if user exists
    db.get(
      'SELECT id FROM users WHERE username = ? OR email = ?',
      [sanitizeInput(username), sanitizeInput(email)],
      async (err, row) => {
        if (err) return res.status(500).json({ error: 'Database error' });

        if (row) {
          return res.status(409).json({ error: 'Username or email already exists' });
        }

        // Hash password
        const hashedPassword = await hashPassword(password);

        // Insert user
        db.run(
          'INSERT INTO users (username, email, password, full_name) VALUES (?, ?, ?, ?)',
          [sanitizeInput(username), sanitizeInput(email), hashedPassword, sanitizeInput(fullName || '')],
          function (err) {
            if (err) return res.status(500).json({ error: 'Failed to create user' });

            const token = generateToken(this.lastID);
            res.status(201).json({
              message: 'User created successfully',
              token,
              user: {
                id: this.lastID,
                username,
                email,
              },
            });
          }
        );
      }
    );
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    db.get(
      'SELECT * FROM users WHERE username = ? OR email = ?',
      [sanitizeInput(username), sanitizeInput(username)],
      async (err, user) => {
        if (err) return res.status(500).json({ error: 'Database error' });

        if (!user) {
          return res.status(401).json({ error: 'Invalid username or password' });
        }

        const passwordMatch = await comparePassword(password, user.password);

        if (!passwordMatch) {
          return res.status(401).json({ error: 'Invalid username or password' });
        }

        const token = generateToken(user.id);
        res.json({
          message: 'Login successful',
          token,
          user: {
            id: user.id,
            username: user.username,
            email: user.email,
            full_name: user.full_name,
          },
        });
      }
    );
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user info endpoint (requires token)
app.get('/api/auth/me', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  // Verify token (simplified - in production use proper middleware)
  try {
    const { userId } = JSON.parse(Buffer.from(token.split('.')[1], 'base64'));
    db.get('SELECT id, username, email, full_name FROM users WHERE id = ?', [userId], (err, user) => {
      if (err || !user) return res.status(401).json({ error: 'Invalid token' });
      res.json({ user });
    });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
  console.log(`API available at http://localhost:${PORT}/api`);
});
