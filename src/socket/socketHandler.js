import jwt from 'jsonwebtoken';
import { captureEngine } from '../capture/captureEngine.js';
import Packet from '../models/Packet.js';
import Alert from '../models/Alert.js';

// ── In-memory Stats ──────────────────────────────────────────────────────────
function freshStats() {
  return {
    totalPackets:      0,
    encryptedPackets:  0,
    unencryptedPackets: 0,
    protocols:         {},   // { HTTP: n, HTTPS: n, … }
    tlsVersions:       {},   // { 'TLS 1.3': n, … }
    topSrcIps:         {},   // { '192.168.1.x': n }
    sizeBuckets: { '0-64': 0, '65-256': 0, '257-512': 0, '513-1024': 0, '1025+': 0 },
    ppsWindow:         [],   // [{ t, pps }] last 60 seconds
    _lastWindowCount:  0,
    _lastWindowTs:     Date.now(),
  };
}
let stats = freshStats();

// ── DB Write Buffer ───────────────────────────────────────────────────────────
let dbBuf = [];
const DB_FLUSH_MS   = 1000;
const DB_BATCH_MAX  = 500;

// ── Security Alert Detection ──────────────────────────────────────────────────
const portScanTracker = new Map();
const ALERT_COOLDOWN = 30000; // 30 seconds cooldown per type per IP
const cooldowns = new Map();

function detectAlerts(packets) {
  const alerts = [];
  const now = Date.now();

  for (const p of packets) {
    const ipStr = p.srcIp;
    let type = null;
    let severity = 'LOW';
    let message = '';

    // Rule 1: SSL 3.0 or TLS 1.0/1.1 usage
    if (p.encrypted && (p.tlsVersion === 'SSL 3.0' || p.tlsVersion === 'TLS 1.0' || p.tlsVersion === 'TLS 1.1')) {
      type = 'DEPRECATED_TLS';
      severity = 'MEDIUM';
      message = `Insecure protocol (${p.tlsVersion}) from ${ipStr}`;
    }
    // Rule 2: Unencrypted Traffic
    else if (!p.encrypted && (p.dstPort === 21 || p.dstPort === 23)) {
      type = 'UNENCRYPTED_AUTH';
      severity = 'HIGH';
      message = `Cleartext ${p.appProtocol || 'traffic'} to port ${p.dstPort} from ${ipStr}`;
    }

    // Rule 3: Port Scan
    if (!portScanTracker.has(ipStr)) {
      portScanTracker.set(ipStr, new Set());
    }
    const ports = portScanTracker.get(ipStr);
    ports.add(p.dstPort);
    if (ports.size > 15) {
       type = 'PORT_SCAN';
       severity = 'CRITICAL';
       message = `Potential Port Scan from ${ipStr} (${ports.size} ports)`;
    }

    if (type) {
      const cdKey = `${ipStr}_${type}`;
      const lastTrigger = cooldowns.get(cdKey) || 0;
      if (now - lastTrigger > ALERT_COOLDOWN) {
         alerts.push({
           type,
           severity,
           message,
           metadata: { srcIp: ipStr, dstIp: p.dstIp, protocol: p.appProtocol, dstPort: p.dstPort }
         });
         cooldowns.set(cdKey, now);
      }
    }
  }

  // Basic memory leak prevention
  if (portScanTracker.size > 2000) portScanTracker.clear();
  if (cooldowns.size > 2000) cooldowns.clear();

  return alerts;
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function clamp(val, min, max) { return Math.min(Math.max(val, min), max); }

function updateStats(packets) {
  const now = Date.now();
  const elapsed = (now - stats._lastWindowTs) / 1000;

  // Per-second PPS sliding window
  stats._lastWindowCount += packets.length;
  if (elapsed >= 1) {
    const pps = Math.round(stats._lastWindowCount / elapsed);
    stats.ppsWindow.push({ t: new Date().toISOString(), pps });
    if (stats.ppsWindow.length > 60) stats.ppsWindow.shift();
    stats._lastWindowCount = 0;
    stats._lastWindowTs    = now;
  }

  for (const p of packets) {
    stats.totalPackets++;
    if (p.encrypted) stats.encryptedPackets++;
    else             stats.unencryptedPackets++;

    stats.protocols[p.appProtocol] = (stats.protocols[p.appProtocol] || 0) + 1;

    if (p.tlsVersion) {
      stats.tlsVersions[p.tlsVersion] = (stats.tlsVersions[p.tlsVersion] || 0) + 1;
    }

    stats.topSrcIps[p.srcIp] = (stats.topSrcIps[p.srcIp] || 0) + 1;

    if      (p.size <=   64) stats.sizeBuckets['0-64']++;
    else if (p.size <=  256) stats.sizeBuckets['65-256']++;
    else if (p.size <=  512) stats.sizeBuckets['257-512']++;
    else if (p.size <= 1024) stats.sizeBuckets['513-1024']++;
    else                     stats.sizeBuckets['1025+']++;
  }
}

function buildPayload() {
  const total = stats.totalPackets || 1;
  const currentPps = stats.ppsWindow.length
    ? stats.ppsWindow[stats.ppsWindow.length - 1].pps : 0;

  // Top 10 IPs sorted by count
  const topSrcIps = Object.entries(stats.topSrcIps)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 10)
    .map(([ip, count]) => ({ ip, count }));

  return {
    totalPackets:      stats.totalPackets,
    currentPps,
    encryptedPct:      Math.round((stats.encryptedPackets  / total) * 100),
    encryptedPackets:  stats.encryptedPackets,
    unencryptedPackets: stats.unencryptedPackets,
    protocols:         stats.protocols,
    tlsVersions:       stats.tlsVersions,
    topSrcIps,
    sizeBuckets:       stats.sizeBuckets,
    ppsHistory:        stats.ppsWindow.slice(-60),
  };
}

export async function flushDbBuffer() {
  if (!dbBuf.length) return;
  const batch = dbBuf.splice(0, dbBuf.length);
  try {
    await Packet.insertMany(batch, { ordered: false, lean: true });
    console.log(`💾 Flushed remaining ${batch.length} packets to DB gracefully.`);
  } catch (err) {
    console.error('❌ Failed to flush payload buffer:', err.message);
  }
}

// ── Socket Handler ────────────────────────────────────────────────────────────
export function setupSocketHandler(io) {

  // ── JWT Auth Middleware ───────────────────────────────────────────────────
  io.use((socket, next) => {
    const token = socket.handshake.auth?.token;
    if (!token) return next(new Error('Authentication required'));
    try {
      socket.data.user = jwt.verify(token, process.env.JWT_SECRET);
      next();
    } catch {
      next(new Error('Invalid token'));
    }
  });

  // ── DB Write Flush ────────────────────────────────────────────────────────
  setInterval(async () => {
    if (!dbBuf.length) return;
    const batch = dbBuf.splice(0, DB_BATCH_MAX);
    try {
      await Packet.insertMany(batch, { ordered: false, lean: true });
    } catch {
      // Non-critical: drop batch if DB unavailable
    }
  }, DB_FLUSH_MS);

  // ── Capture Engine → Socket Fan-out ──────────────────────────────────────
  captureEngine.on('batch', (packets) => {
    updateStats(packets);
    dbBuf.push(...packets);

    const alerts = detectAlerts(packets);
    alerts.forEach(alertData => {
      io.to('dashboard').emit('security_alert', alertData);
      Alert.create(alertData).catch(err => console.error('Alert DB Error:', err.message));
    });

    // Live feed: last 20 packets (not full batch — saves bandwidth)
    const feed = packets.slice(-20);
    io.to('dashboard').emit('packet:batch', feed);
    io.to('dashboard').emit('stats:update', buildPayload());
  });

  captureEngine.on('status', (status) => {
    io.to('dashboard').emit('capture:status', status);
  });

  // ── Connection ────────────────────────────────────────────────────────────
  io.on('connection', (socket) => {
    const { username, role } = socket.data.user;
    console.log(`🔌 [socket] ${username} (${role}) connected [${socket.id}]`);

    socket.join('dashboard');
    if (role === 'admin') socket.join('admin');

    // Send current state on connect
    socket.emit('capture:status', {
      running:   captureEngine.running,
      mode:      captureEngine.mode,
      interface: captureEngine.iface,
      pps:       captureEngine.pps,
    });
    socket.emit('stats:update', buildPayload());

    // ── Admin Controls ──────────────────────────────────────────────────
    function adminOnly(fn) {
      if (role !== 'admin') {
        socket.emit('error:auth', { message: 'Admin access required' });
        return;
      }
      fn();
    }

    socket.on('capture:getInterfaces', (cb) => {
      adminOnly(() => {
        const interfaces = captureEngine.getInterfaces();
        if (typeof cb === 'function') cb({ interfaces });
      });
    });

    socket.on('capture:start', ({ iface, pps }) => {
      adminOnly(() => captureEngine.start(iface, pps));
    });

    socket.on('capture:stop', () => {
      adminOnly(() => captureEngine.stop());
    });

    socket.on('capture:setPps', ({ pps }) => {
      adminOnly(() => captureEngine.setPps(clamp(pps, 100, 10000)));
    });

    socket.on('stats:reset', () => {
      adminOnly(() => {
        stats = freshStats();
        io.to('dashboard').emit('stats:reset');
        io.to('dashboard').emit('stats:update', buildPayload());
      });
    });

    socket.on('disconnect', () => {
      console.log(`🔌 [socket] ${username} disconnected`);
    });
  });
}
