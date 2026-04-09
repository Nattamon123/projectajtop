import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import helmet from 'helmet';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

import { connectDB, disconnectDB } from './src/db/database.js';
import { setupSocketHandler, flushDbBuffer } from './src/socket/socketHandler.js';
import { captureEngine } from './src/capture/captureEngine.js';
import authRoutes from './src/routes/auth.js';
import userRoutes from './src/routes/users.js';
import packetRoutes from './src/routes/packets.js';
import alertsRoutes from './src/routes/alerts.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
  pingTimeout: 20000,
  pingInterval: 25000,
});

// ── Middleware ──────────────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── REST Routes ─────────────────────────────────────────────────────────────
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/packets', packetRoutes);
app.use('/api/alerts', alertsRoutes);

// ── Global Error Handler ────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('❌ Express App Error:', err.stack || err);
  res.status(500).json({ error: 'Internal Server Error' });
});

// ── Health check ────────────────────────────────────────────────────────────
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', mode: 'simulation', ts: new Date().toISOString() });
});

// ── Catch-all → Return index.html for SPA-like routing ─────────────────────
app.get('*', (req, res) => {
  // Only for non-API routes
  if (!req.path.startsWith('/api/')) {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }
});

// ── Socket.IO ───────────────────────────────────────────────────────────────
setupSocketHandler(io);

// ── Start ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;

async function start() {
  await connectDB();
  httpServer.listen(PORT, () => {
    console.log('');
    console.log('╔══════════════════════════════════════════════╗');
    console.log('║        NetWatch — Packet Analyzer v1.0       ║');
    console.log('╠══════════════════════════════════════════════╣');
    console.log(`║  🌐 Dashboard  →  http://localhost:${PORT}       ║`);
    console.log('║  📡 Mode       →  SIMULATION                 ║');
    console.log('║  🔑 Admin      →  admin / admin123           ║');
    console.log('╚══════════════════════════════════════════════╝');
    console.log('');
  });
}

start().catch((err) => {
  console.error('Fatal startup error:', err);
  process.exit(1);
});

async function gracefulShutdown(signal) {
  console.log(`\n🛑 Received ${signal}, starting graceful shutdown...`);
  
  // 1. Stop capture
  captureEngine.stop();
  
  // 2. Stop accepting connections
  httpServer.close(() => {
    console.log('🚪 HTTP server closed.');
  });
  
  // 3. Flush packets
  await flushDbBuffer();
  
  // 4. Disconnect DB
  await disconnectDB();
  
  console.log('✅ Graceful shutdown completed. Exiting process.');
  process.exit(0);
}

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
