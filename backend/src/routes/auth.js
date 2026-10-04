// backend/src/routes/auth.js
import { Router } from 'express';
import { getUserByUsername, getUserById, updateLastLogin } from '../services/userService.js';
import { verifyPassword } from '../auth/passwords.js';
import { signToken } from '../auth/jwt.js';
import { authenticate, loginLimiter } from '../middleware/auth.js';

const router = Router();

// POST /api/auth/login
// Authenticates credentials and returns signed JWT with user profile.
router.post('/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body || {};

    if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const user = await getUserByUsername(username, true);

    if (!user || !user.isActive) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const passwordMatches = await verifyPassword(password, user.passwordHash, user.salt);
    if (!passwordMatches) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const token = signToken(user);
    updateLastLogin(user.id).catch(() => {});

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        isActive: user.isActive,
      },
    });
  } catch (err) {
    console.error('[auth] login error:', err.message);
    res.status(500).json({ error: 'Authentication service error' });
  }
});

// GET /api/auth/me
// Returns current authenticated profile.
router.get('/me', authenticate, async (req, res) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user || !user.isActive) {
      return res.status(401).json({ error: 'Account not found or inactive' });
    }

    res.json({
      id: user.id,
      username: user.username,
      role: user.role,
      isActive: user.isActive,
    });
  } catch (err) {
    console.error('[auth] /me error:', err.message);
    res.status(500).json({ error: 'Failed to retrieve profile' });
  }
});

// POST /api/auth/logout
// Terminates client session.
router.post('/logout', authenticate, (req, res) => {
  res.json({ success: true, message: 'Logged out successfully' });
});

export default router;
