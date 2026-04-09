import { Router } from 'express';
import Alert from '../models/Alert.js';
import { requireAuth } from '../middleware/auth.js';

const router = Router();
router.use(requireAuth);

// ── GET /api/alerts ──────────────────────────────────────────────────────────
// Query params: limit, page, severity
router.get('/', async (req, res) => {
  try {
    const {
      limit = 50,
      page = 1,
      severity,
    } = req.query;

    const filter = {};
    if (severity) filter.severity = severity;

    const safeLimit = Math.min(Math.max(parseInt(limit) || 50, 1), 1000);
    const skip = (parseInt(page) - 1) * safeLimit;

    const [alerts, total] = await Promise.all([
      Alert.find(filter)
        .sort({ timestamp: -1 })
        .skip(skip)
        .limit(safeLimit)
        .lean(),
      Alert.countDocuments(filter),
    ]);

    return res.json({ alerts, total, page: parseInt(page), limit: safeLimit });
  } catch (err) {
    console.error('Alerts Route Error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

export default router;
