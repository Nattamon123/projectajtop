import { Router } from 'express';
import Packet from '../models/Packet.js';
import { requireAuth } from '../middleware/auth.js';

const router = Router();
router.use(requireAuth);

// ── GET /api/packets/history ──────────────────────────────────────────────────
// Query params: limit, page, protocol, appProtocol, encrypted
router.get('/history', async (req, res) => {
  try {
    const {
      limit = 100,
      page = 1,
      protocol,
      appProtocol,
      encrypted,
    } = req.query;

    const filter = {};
    if (protocol)    filter.protocol    = protocol;
    if (appProtocol) filter.appProtocol = appProtocol;
    if (encrypted !== undefined) filter.encrypted = encrypted === 'true';

    // Prevent excessive memory usage by capping the limit at 500
    const safeLimit = Math.min(Math.max(parseInt(limit) || 100, 1), 500);
    const skip = (parseInt(page) - 1) * safeLimit;

    const [packets, total] = await Promise.all([
      Packet.find(filter)
        .sort({ timestamp: -1 })
        .skip(skip)
        .limit(safeLimit)
        .lean(),
      Packet.countDocuments(filter),
    ]);

    return res.json({ packets, total, page: parseInt(page), limit: safeLimit });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// ── GET /api/packets/stats ────────────────────────────────────────────────────
// Aggregated stats from stored packets (last 1 hour)
router.get('/stats', async (req, res) => {
  try {
    const since = new Date(Date.now() - 3600_000); // last 1 hour

    const [total, encCount, protocolAgg, tlsAgg, topIpAgg] = await Promise.all([
      Packet.countDocuments({ timestamp: { $gte: since } }),
      Packet.countDocuments({ timestamp: { $gte: since }, encrypted: true }),
      Packet.aggregate([
        { $match: { timestamp: { $gte: since } } },
        { $group: { _id: '$appProtocol', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
      ]),
      Packet.aggregate([
        { $match: { timestamp: { $gte: since }, tlsVersion: { $ne: null } } },
        { $group: { _id: '$tlsVersion', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
      ]),
      Packet.aggregate([
        { $match: { timestamp: { $gte: since } } },
        { $group: { _id: '$srcIp', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 },
      ]),
    ]);

    return res.json({
      total,
      encryptedPct: total ? Math.round((encCount / total) * 100) : 0,
      protocols: Object.fromEntries(protocolAgg.map((x) => [x._id, x.count])),
      tlsVersions: Object.fromEntries(tlsAgg.map((x) => [x._id, x.count])),
      topSrcIps: topIpAgg.map((x) => ({ ip: x._id, count: x.count })),
    });
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

export default router;
