import { EventEmitter } from 'events';
import os from 'os';
import { analyzePacket } from '../analysis/protocolAnalyzer.js';

let Cap = null;
let decoders = null;
let PROTOCOL = null;

// Dynamically load cap if available
try {
  const capModule = await import('cap');
  const capExports = capModule.default || capModule;
  Cap = capExports.Cap;
  decoders = capExports.decoders;
  PROTOCOL = decoders.PROTOCOL;
} catch (e) {
  console.warn('⚠️  [Capture] "cap" library not found or failed to load. Details:', e.message);
}

// ── Simulation Scenarios (weighted pool) ────────────────────────────────────
const SCENARIOS = [
  { w: 28, protocol: 'TCP', dstPort: 443, appProtocol: 'HTTPS', encrypted: true, tlsVersion: 'TLS 1.3' },
  { w: 16, protocol: 'TCP', dstPort: 443, appProtocol: 'HTTPS', encrypted: true, tlsVersion: 'TLS 1.2' },
  { w: 10, protocol: 'TCP', dstPort: 22, appProtocol: 'SSH', encrypted: true, tlsVersion: 'SSH-2.0' },
  { w: 4, protocol: 'TCP', dstPort: 993, appProtocol: 'IMAPS', encrypted: true, tlsVersion: 'TLS 1.2' },
  { w: 3, protocol: 'TCP', dstPort: 465, appProtocol: 'SMTPS', encrypted: true, tlsVersion: 'TLS 1.2' },
  { w: 2, protocol: 'TCP', dstPort: 995, appProtocol: 'POP3S', encrypted: true, tlsVersion: 'TLS 1.2' },
  { w: 2, protocol: 'TCP', dstPort: 8443, appProtocol: 'HTTPS', encrypted: true, tlsVersion: 'TLS 1.3' },
  { w: 14, protocol: 'UDP', dstPort: 53, appProtocol: 'DNS', encrypted: false, tlsVersion: null },
  { w: 9, protocol: 'TCP', dstPort: 80, appProtocol: 'HTTP', encrypted: false, tlsVersion: null },
  { w: 4, protocol: 'TCP', dstPort: 25, appProtocol: 'SMTP', encrypted: false, tlsVersion: null },
  { w: 3, protocol: 'ICMP', dstPort: 0, appProtocol: 'ICMP', encrypted: false, tlsVersion: null },
  { w: 2, protocol: 'TCP', dstPort: 3306, appProtocol: 'MySQL', encrypted: false, tlsVersion: null },
  { w: 2, protocol: 'UDP', dstPort: 123, appProtocol: 'NTP', encrypted: false, tlsVersion: null },
  { w: 2, protocol: 'TCP', dstPort: 8080, appProtocol: 'HTTP', encrypted: false, tlsVersion: null },
  { w: 1, protocol: 'TCP', dstPort: 443, appProtocol: 'HTTPS', encrypted: true, tlsVersion: 'SSL 3.0' },
  { w: 1, protocol: 'TCP', dstPort: 443, appProtocol: 'HTTPS', encrypted: true, tlsVersion: 'TLS 1.0' },
  { w: 1, protocol: 'TCP', dstPort: 443, appProtocol: 'HTTPS', encrypted: true, tlsVersion: 'TLS 1.1' },
];

const POOL = [];
SCENARIOS.forEach((s) => {
  for (let i = 0; i < s.w; i++) POOL.push(s);
});

const PRIVATE = ['192.168.1', '192.168.0', '10.0.0', '172.16.0'];
const PUBLIC = ['8.8.8', '1.1.1', '104.16', '142.250'];

function rand(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function pick(arr) { return arr[rand(0, arr.length - 1)]; }
function randomIP(isPrivate) { return `${isPrivate ? pick(PRIVATE) : pick(PUBLIC)}.${rand(1, 254)}`; }

function sizeForScenario(s) {
  switch (s.appProtocol) {
    case 'DNS': return rand(28, 512);
    case 'ICMP': return rand(28, 84);
    default: return rand(40, 1500);
  }
}

function generatePacket(iface) {
  const s = pick(POOL);
  const local = Math.random() > 0.35;
  return {
    timestamp: new Date(),
    srcIp: randomIP(local),
    dstIp: randomIP(!local),
    srcPort: s.protocol === 'ICMP' ? 0 : rand(1024, 65535),
    dstPort: s.dstPort,
    protocol: s.protocol,
    appProtocol: s.appProtocol,
    encrypted: s.encrypted,
    tlsVersion: s.tlsVersion,
    size: sizeForScenario(s),
    interface: iface,
  };
}

// ── Capture Engine ──────────────────────────────────────────────────────────
export class CaptureEngine extends EventEmitter {
  constructor() {
    super();
    this.running = false;
    this.mode = 'simulation';
    this.iface = null;
    this.pps = 1000;
    this._timer = null;

    // Live mode variables
    this._capSession = null;
    this._liveBatch = [];
    this._cachedLive = {}; // Cache Cap instances to avoid Windows close() crash
    this._livePacketCount = 0;
    this._livePacketTimestamp = 0;
  }

  getInterfaces() {
    const interfaces = [];
    if (Cap && Cap.deviceList) {
      try {
        const devs = Cap.deviceList();
        devs.forEach(d => {
          const addrs = d.addresses.map(a => a.addr).join(', ');
          interfaces.push({
            name: d.name,
            desc: d.description ? `${d.description} [${addrs}]` : `Real Dev [${addrs}]`,
            type: 'real'
          });
        });
      } catch (err) {
        console.error('Error fetching real devices:', err.message);
      }
    }

    const simulated = [
      { name: 'eth0-sim', desc: 'Simulated Ethernet (1 Gbps)', type: 'simulation' },
      { name: 'wlan0-sim', desc: 'Simulated Wi-Fi 802.11ac', type: 'simulation' },
      { name: 'lo-sim', desc: 'Simulated Loopback (127.0.0.1)', type: 'simulation' },
    ];
    return [...interfaces, ...simulated];
  }

  start(iface = 'eth0-sim', pps = 1000) {
    if (this.running) this.stop();

    this.iface = iface;
    this.pps = Math.min(Math.max(parseInt(pps) || 1000, 100), 10000);
    this.running = true;

    const isSim = iface.endsWith('-sim') || iface === 'simulation';
    this.mode = isSim ? 'simulation' : 'live';

    if (this.mode === 'live') {
      if (!Cap) {
        console.error('❌ "cap" library not available. Falling back to simulation.');
        this.mode = 'simulation';
        this.iface = 'eth0-sim';
        return this.start(this.iface, this.pps);
      }
      this._startLive();
    } else {
      this._startSim();
    }

    this.emit('status', {
      running: true, mode: this.mode,
      interface: this.iface, pps: this.pps,
    });
    console.log(`📡 Capture STARTED: interface=${this.iface} pps=${this.pps} mode=${this.mode}`);
  }
  //เริ่มทำงานการจำลองถ้าไม่มีcap
  _startSim() {
    const BATCH_MS = 100;
    const packetsPerBatch = Math.ceil(this.pps * BATCH_MS / 1000);

    this._timer = setInterval(() => {
      if (!this.running) return;
      const batch = [];
      for (let i = 0; i < packetsPerBatch; i++) {
        batch.push(generatePacket(this.iface));
      }
      this.emit('batch', batch);
    }, BATCH_MS);
  }
  //ทำงานจริง 
  _startLive() {
    try {
      let liveData = this._cachedLive[this.iface];
      if (!liveData) {
        liveData = {
          session: new Cap(),
          buffer: Buffer.alloc(65535)
        };
        const linkType = liveData.session.open(this.iface, 'ip or udp or tcp or icmp', 10 * 1024 * 1024, liveData.buffer);
        liveData.linkType = linkType;
        if (typeof liveData.session.setMinBytes === 'function') {
          liveData.session.setMinBytes(0);
        }
        this._cachedLive[this.iface] = liveData;
      }

      this._capSession = liveData.session;
      const buffer = liveData.buffer;
      const linkType = liveData.linkType;

      // Flush batch every 100ms
      this._timer = setInterval(() => {
        if (!this.running) return;
        if (this._liveBatch.length > 0) {
          this.emit('batch', this._liveBatch);
          this._liveBatch = [];
        }
      }, 100);

      this._capSession.on('packet', (nbytes, trunc) => {
        const now = Date.now();
        if (now - this._livePacketTimestamp >= 1000) {
          this._livePacketCount = 0;
          this._livePacketTimestamp = now;
        }
        if (this._livePacketCount >= this.pps) return; // Drop packet if over limit
        this._livePacketCount++;

        try {
          if (linkType === 'ETHERNET') {
            const ret = decoders.Ethernet(buffer);
            let ipProtocol, srcIp, dstIp, srcPort = 0, dstPort = 0, payloadOffset = 0, protocolName = 'Unknown';

            if (ret.info.type === PROTOCOL.ETHERNET.IPV4) {
              const ip = decoders.IPV4(buffer, ret.offset);
              ipProtocol = ip.info.protocol;
              srcIp = ip.info.srcaddr;
              dstIp = ip.info.dstaddr;

              if (ipProtocol === PROTOCOL.IP.TCP) {
                const tcp = decoders.TCP(buffer, ip.offset);
                protocolName = 'TCP';
                srcPort = tcp.info.srcport;
                dstPort = tcp.info.dstport;
                payloadOffset = tcp.offset;
              } else if (ipProtocol === PROTOCOL.IP.UDP) {
                const udp = decoders.UDP(buffer, ip.offset);
                protocolName = 'UDP';
                srcPort = udp.info.srcport;
                dstPort = udp.info.dstport;
                payloadOffset = udp.offset;
              } else if (ipProtocol === PROTOCOL.IP.ICMP) {
                protocolName = 'ICMP';
              }
            } else if (ret.info.type === PROTOCOL.ETHERNET.IPV6) {
              const ip = decoders.IPV6(buffer, ret.offset);
              ipProtocol = ip.info.next_header;
              srcIp = ip.info.srcaddr;
              dstIp = ip.info.dstaddr;

              // Simplistic IPv6 handling (assuming no extension headers for simplicity here)
              if (ipProtocol === PROTOCOL.IP.TCP) {
                const tcp = decoders.TCP(buffer, ip.offset);
                protocolName = 'TCP'; srcPort = tcp.info.srcport; dstPort = tcp.info.dstport; payloadOffset = tcp.offset;
              } else if (ipProtocol === PROTOCOL.IP.UDP) {
                const udp = decoders.UDP(buffer, ip.offset);
                protocolName = 'UDP'; srcPort = udp.info.srcport; dstPort = udp.info.dstport; payloadOffset = udp.offset;
              }
            }

            if (protocolName !== 'Unknown') {
              const sliceLength = Math.min(nbytes, buffer.length) - payloadOffset;
              let payloadBuf = null;
              if (sliceLength > 0 && payloadOffset > 0) {
                // subarray provides a reference. safe since analyzePacket is synchronous.
                payloadBuf = buffer.subarray(payloadOffset, payloadOffset + sliceLength);
              }

              const rawPacket = {
                timestamp: new Date(),
                srcIp, dstIp, srcPort, dstPort,
                protocol: protocolName,
                size: nbytes,
                interface: this.iface,
                payload: payloadBuf
              };

              // Hand over to the analyzer to identify application protocol and encryption!
              const analyzed = analyzePacket(rawPacket);

              // remove raw buffer from memory before batching
              delete analyzed.payload;

              this._liveBatch.push(analyzed);
            }
          }
        } catch (perr) { }
      });
    } catch (err) {
      console.error(`❌ Failed to start live capture on ${this.iface}:`, err.message);
      this.mode = 'simulation';
      this.iface = 'eth0-sim';
      this._startSim();
    }
  }

  stop() {
    if (this._timer) { clearInterval(this._timer); this._timer = null; }
    if (this._capSession) {
      // Workaround: Calling close() on 'cap' throws a fatal UV_HANDLE_CLOSING assertion on Windows.
      // We instead detach handlers, allowing the instance to stay ready in cache without crashing Node.
      this._capSession.removeAllListeners('packet');
      this._capSession = null;
    }
    this.running = false;
    this.emit('status', { running: false, mode: this.mode });
    console.log('⏹️  Capture STOPPED');
  }

  setPps(pps) {
    this.pps = Math.min(Math.max(parseInt(pps) || 1000, 100), 10000);
    if (this.running && this.mode === 'simulation') {
      this.stop();
      this.start(this.iface, this.pps);
    }
  }
}

export const captureEngine = new CaptureEngine();
