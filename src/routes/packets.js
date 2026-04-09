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
      srcIp,       // รับค่า Source IP จาก query
      dstIp,       // รับค่า Destination IP จาก query
      dstPort,     // รับค่า Destination Port จาก query
    } = req.query;

    const filter = {};
    
    // กรองตามโปรโตคอล (เช่น TCP, UDP)
    if (protocol)    filter.protocol    = protocol;
    // กรองตามโปรโตคอลของแอปพลิเคชัน (เช่น HTTP, HTTPS)
    if (appProtocol) filter.appProtocol = appProtocol;
    // กรองดูเฉพาะตัวที่เข้ารหัส หรือไม่เข้ารหัส
    if (encrypted !== undefined) filter.encrypted = encrypted === 'true';

    // ── ส่วน กรองขั้นสูง (Advanced Search) ──
    // ใช้ RegExp เพื่อให้ค้นหา IP แค่บางส่วน (Partial Match) ได้ เช่น พิมพ์แค่ 192.168
    if (srcIp) filter.srcIp = new RegExp(srcIp, 'i');
    if (dstIp) filter.dstIp = new RegExp(dstIp, 'i');
    
    // แปลงพอร์ตเป็นตัวเลขก่อนค้นหา เพราะในฐานข้อมูลเก็บเป็น Number
    if (dstPort) filter.dstPort = Number(dstPort);

    // ป้องกันคนดึงข้อมูลทีละเยอะๆ มากเกินไปจนเซิร์ฟเวอร์ค้าง (ยึดเพดานไว้ที่ 500)
    const safeLimit = Math.min(Math.max(parseInt(limit) || 100, 1), 5000); // ยืดเป็น 5000 เผื่อตอน export

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
