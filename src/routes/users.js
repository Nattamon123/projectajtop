import { Router } from 'express';
import User from '../models/User.js';
import { requireAuth, requireAdmin } from '../middleware/auth.js';

const router = Router();

// All user routes require auth + admin
router.use(requireAuth, requireAdmin);

// ── GET /api/users ────────────────────────────────────────────────────────────
router.get('/', async (req, res) => {
  try {
    const users = await User.find({}).select('-password').sort({ createdAt: -1 });
    return res.json(users);
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// ── POST /api/users ───────────────────────────────────────────────────────────
router.post('/', async (req, res) => {
  try {
    const { username, password, role = 'user' } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    const exists = await User.findOne({ username });
    if (exists) return res.status(409).json({ error: 'Username already taken' });

    const user = new User({ username, password, role });
    await user.save();
    return res.status(201).json(user.toSafeObject());
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// ── PUT /api/users/:id ────────────────────────────────────────────────────────
router.put('/:id', async (req, res) => {
  try {
    const { role, active, password } = req.body;
    const update = {};
    if (role !== undefined)   update.role   = role;
    if (active !== undefined) update.active = active;

    const user = await User.findByIdAndUpdate(req.params.id, update, { new: true }).select('-password');
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Handle password change separately (to trigger pre-save hash)
    if (password) {
      const u = await User.findById(req.params.id);
      u.password = password;
      await u.save();
    }

    return res.json(user);
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// ── DELETE /api/users/:id ─────────────────────────────────────────────────────
router.delete('/:id', async (req, res) => {
  try {
    // Prevent deleting self
    if (req.params.id === req.user.id) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }
    await User.findByIdAndDelete(req.params.id);
    return res.json({ message: 'User deleted' });
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

export default router;
