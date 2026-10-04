// backend/src/routes/users.js
import { Router } from 'express';
import {
  listUsers,
  createUser,
  updateUser,
  deleteUser,
} from '../services/userService.js';
import { authenticate, requireRole } from '../middleware/auth.js';

const router = Router();

// Protect all /api/users routes: ADMIN role required
router.use(authenticate, requireRole('admin'));

// GET /api/users — List all user accounts
router.get('/', async (req, res) => {
  try {
    const users = await listUsers();
    res.json({ users });
  } catch (err) {
    console.error('[users] list error:', err.message);
    res.status(500).json({ error: 'Failed to retrieve user list' });
  }
});

// POST /api/users — Create a new user account
router.post('/', async (req, res) => {
  try {
    const { username, password, role } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const newUser = await createUser({ username, password, role });
    res.status(201).json({ user: newUser });
  } catch (err) {
    const status = err.statusCode || 500;
    if (status !== 500) {
      return res.status(status).json({ error: err.message });
    }
    console.error('[users] create error:', err.message);
    res.status(500).json({ error: 'Failed to create user' });
  }
});

// PATCH /api/users/:id — Update user role, password, or active status
router.patch('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { role, password, isActive } = req.body || {};

    const updated = await updateUser(id, { role, password, isActive });
    res.json({ user: updated });
  } catch (err) {
    const status = err.statusCode || 500;
    if (status !== 500) {
      return res.status(status).json({ error: err.message });
    }
    console.error('[users] update error:', err.message);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// DELETE /api/users/:id — Delete user with last active admin guard
router.delete('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await deleteUser(id);
    res.json({ success: true, message: `User "${id}" deleted successfully` });
  } catch (err) {
    const status = err.statusCode || 500;
    if (status !== 500) {
      return res.status(status).json({ error: err.message });
    }
    console.error('[users] delete error:', err.message);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

export default router;
