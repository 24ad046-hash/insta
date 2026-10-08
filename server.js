import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import path from 'path';
import { fileURLToPath } from 'url';

import db from './db.js';
import {
  hashPassword,
  comparePassword,
  generateToken
} from './auth.js';

import {
  validateEmail,
  validatePassword,
  validateUsername,
  sanitizeInput
} from './validation.js';

const app = express();

// ===============================
// VERCEL / ES MODULE PATH SETUP
// ===============================

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ===============================
// PORT
// ===============================

const PORT = process.env.PORT || 5000;

// ===============================
// MIDDLEWARE
// ===============================

app.use(cors());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files
app.use(express.static(__dirname));

// ===============================
// HOME PAGE
// ===============================

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ===============================
// HEALTH CHECK
// ===============================

app.get('/api/health', (req, res) => {
  res.json({
    status: 'Server is running',
    message: 'Instagram API is working'
  });
});

// ===============================
// SIGNUP
// ===============================

app.post('/api/auth/signup', async (req, res) => {
  try {
    const {
      username,
      email,
      password,
      fullName
    } = req.body;

    // Required fields
    if (!username || !email || !password) {
      return res.status(400).json({
        error: 'Missing required fields'
      });
    }

    // Sanitize
    const cleanUsername = sanitizeInput(username);
    const cleanEmail = sanitizeInput(email);
    const cleanFullName = sanitizeInput(fullName || '');

    // Username validation
    const usernameError = validateUsername(cleanUsername);

    if (usernameError) {
      return res.status(400).json({
        error: usernameError
      });
    }

    // Email validation
    const emailError = validateEmail(cleanEmail);

    if (emailError) {
      return res.status(400).json({
        error: emailError
      });
    }

    // Password validation
    const passwordError = validatePassword(password);

    if (passwordError) {
      return res.status(400).json({
        error: passwordError
      });
    }

    // Check existing user
    db.get(
      'SELECT id FROM users WHERE username = ? OR email = ?',
      [cleanUsername, cleanEmail],
      async (err, row) => {

        if (err) {
          console.error(err);

          return res.status(500).json({
            error: 'Database error'
          });
        }

        if (row) {
          return res.status(409).json({
            error: 'Username or email already exists'
          });
        }

        try {

          // Hash password
          const hashedPassword = await hashPassword(password);

          // Insert user
          db.run(
            `INSERT INTO users
             (username, email, password, full_name)
             VALUES (?, ?, ?, ?)`,
            [
              cleanUsername,
              cleanEmail,
              hashedPassword,
              cleanFullName
            ],
            function (err) {

              if (err) {
                console.error(err);

                return res.status(500).json({
                  error: 'Failed to create user'
                });
              }

              const userId = this.lastID;

              const token = generateToken(userId);

              return res.status(201).json({
                message: 'User created successfully',

                token,

                user: {
                  id: userId,
                  username: cleanUsername,
                  email: cleanEmail,
                  full_name: cleanFullName
                }
              });
            }
          );

        } catch (error) {

          console.error(error);

          return res.status(500).json({
            error: 'Failed to create user'
          });
        }
      }
    );

  } catch (error) {

    console.error(error);

    return res.status(500).json({
      error: 'Internal server error'
    });
  }
});

// ===============================
// LOGIN
// ===============================

app.post('/api/auth/login', async (req, res) => {

  try {

    const {
      username,
      password
    } = req.body;

    // Required fields
    if (!username || !password) {
      return res.status(400).json({
        error: 'Username and password required'
      });
    }

    const cleanUsername = sanitizeInput(username);

    // Find user
    db.get(
      `SELECT *
       FROM users
       WHERE username = ? OR email = ?`,
      [cleanUsername, cleanUsername],
      async (err, user) => {

        if (err) {

          console.error(err);

          return res.status(500).json({
            error: 'Database error'
          });
        }

        if (!user) {
          return res.status(401).json({
            error: 'Invalid username or password'
          });
        }

        try {

          const passwordMatch =
            await comparePassword(
              password,
              user.password
            );

          if (!passwordMatch) {
            return res.status(401).json({
              error: 'Invalid username or password'
            });
          }

          const token = generateToken(user.id);

          return res.json({

            message: 'Login successful',

            token,

            user: {
              id: user.id,
              username: user.username,
              email: user.email,
              full_name: user.full_name
            }

          });

        } catch (error) {

          console.error(error);

          return res.status(500).json({
            error: 'Login failed'
          });
        }
      }
    );

  } catch (error) {

    console.error(error);

    return res.status(500).json({
      error: 'Internal server error'
    });
  }
});

// ===============================
// GET CURRENT USER
// ===============================

app.get('/api/auth/me', (req, res) => {

  try {

    const authorization =
      req.headers.authorization;

    if (!authorization) {
      return res.status(401).json({
        error: 'No token provided'
      });
    }

    const token =
      authorization.split(' ')[1];

    if (!token) {
      return res.status(401).json({
        error: 'Invalid authorization header'
      });
    }

    /*
      This section assumes your generateToken()
      creates a token containing the user ID.

      If auth.js uses JWT, replace this with
      proper JWT verification.
    */

    try {

      const parts = token.split('.');

      if (parts.length < 2) {
        return res.status(401).json({
          error: 'Invalid token'
        });
      }

      const payload =
        JSON.parse(
          Buffer.from(
            parts[1],
            'base64'
          ).toString()
        );

      const userId = payload.userId;

      if (!userId) {
        return res.status(401).json({
          error: 'Invalid token'
        });
      }

      db.get(
        `SELECT
          id,
          username,
          email,
          full_name
         FROM users
         WHERE id = ?`,
        [userId],
        (err, user) => {

          if (err) {

            console.error(err);

            return res.status(500).json({
              error: 'Database error'
            });
          }

          if (!user) {
            return res.status(401).json({
              error: 'User not found'
            });
          }

          return res.json({
            user
          });

        }
      );

    } catch (error) {

      return res.status(401).json({
        error: 'Invalid token'
      });
    }

  } catch (error) {

    console.error(error);

    return res.status(500).json({
      error: 'Internal server error'
    });
  }
});

// ===============================
// API 404
// ===============================

app.use('/api', (req, res) => {
  res.status(404).json({
    error: 'API endpoint not found'
  });
});

// ===============================
// GENERAL 404
// ===============================

app.use((req, res) => {
  res.status(404).send('Page not found');
});

// ===============================
// LOCAL SERVER
// ===============================

// Vercel handles the server automatically.
// Only listen when running locally.

if (process.env.VERCEL !== '1') {

  app.listen(PORT, () => {

    console.log(
      `Server running at http://localhost:${PORT}`
    );

    console.log(
      `API available at http://localhost:${PORT}/api`
    );

  });

}

// ===============================
// EXPORT FOR VERCEL
// ===============================

export default app;