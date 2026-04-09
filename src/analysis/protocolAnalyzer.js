/**
 * Protocol & Encryption Analyzer
 *
 * Analyzes parsed packet metadata to determine:
 *  - Application-layer protocol (HTTP, HTTPS, DNS, SSH, …)
 *  - Whether the traffic is encrypted
 *  - TLS/SSL version (from payload inspection or port heuristics)
 */

// ── Port → Protocol map ──────────────────────────────────────────────────────
const PORT_MAP = {
  20: { app: 'FTP-Data', encrypted: false },
  21: { app: 'FTP', encrypted: false },
  22: { app: 'SSH', encrypted: true, tls: 'SSH-2.0' },
  23: { app: 'Telnet', encrypted: false },
  25: { app: 'SMTP', encrypted: false },
  53: { app: 'DNS', encrypted: false },
  67: { app: 'DHCP', encrypted: false },
  68: { app: 'DHCP', encrypted: false },
  80: { app: 'HTTP', encrypted: false },
  110: { app: 'POP3', encrypted: false },
  143: { app: 'IMAP', encrypted: false },
  443: { app: 'HTTPS', encrypted: true, tls: 'TLS 1.3' },
  465: { app: 'SMTPS', encrypted: true, tls: 'TLS 1.2' },
  587: { app: 'SMTP', encrypted: false },
  993: { app: 'IMAPS', encrypted: true, tls: 'TLS 1.2' },
  995: { app: 'POP3S', encrypted: true, tls: 'TLS 1.2' },
  1194: { app: 'OpenVPN', encrypted: true, tls: 'TLS 1.2' },
  1433: { app: 'MSSQL', encrypted: false },
  3306: { app: 'MySQL', encrypted: false },
  3389: { app: 'RDP', encrypted: true, tls: 'TLS 1.2' },
  5432: { app: 'PostgreSQL', encrypted: false },
  5601: { app: 'Kibana', encrypted: false },
  6379: { app: 'Redis', encrypted: false },
  8080: { app: 'HTTP-Alt', encrypted: false },
  8443: { app: 'HTTPS-Alt', encrypted: true, tls: 'TLS 1.2' },
  9200: { app: 'Elastic', encrypted: false },
  27017: { app: 'MongoDB', encrypted: false },
  123: { app: 'NTP', encrypted: false },
};

// ── Payload Inspection Helpers ───────────────────────────────────────────────

/**
 * Detect TLS handshake record and extract version
 * TLS record: byte[0]=0x16, byte[1]=major, byte[2]=minor
 */

//ส่องดู byte ใน memory ที่ 0-2 ถ้าเป็น 0x16, 0x03 แสดงว่าเป็น TLS
function detectTLSVersion(buf) {
  if (!buf || buf.length < 5) return null;
  if (buf[0] !== 0x16 || buf[1] !== 0x03) return null;

  switch (buf[2]) {
    case 0x00: return 'SSL 3.0';
    case 0x01: return 'TLS 1.0';
    case 0x02: return 'TLS 1.1';
    case 0x03: {
      // Distinguish TLS 1.2 vs TLS 1.3 via supported_versions extension
      // TLS 1.3 advertises version 0x0304 in extensions
      const limit = Math.min(buf.length - 1, 200);
      for (let i = 5; i < limit; i++) {
        if (buf[i] === 0x03 && buf[i + 1] === 0x04) return 'TLS 1.3';
      }
      return 'TLS 1.2';
    }
    default: return null;
  }
}

function detectSSH(buf) {
  if (!buf || buf.length < 4) return false;
  return buf.slice(0, 4).toString('ascii') === 'SSH-';
}

// เช็ค http ว่ามี GET, POST, PUT, DELETE, HEAD, HTTP/ หรือไม่ ถ้ามีมันคือ HTTP เพราะมันไม่เข้ารหัส
function detectHTTP(buf) {
  if (!buf || buf.length < 4) return false;
  const h = buf.slice(0, 8).toString('ascii');
  return (
    h.startsWith('GET ') ||
    h.startsWith('POST ') ||
    h.startsWith('PUT ') ||
    h.startsWith('DELETE ') ||
    h.startsWith('HEAD ') ||
    h.startsWith('HTTP/')
  );
}

// ── Main Analyzer ────────────────────────────────────────────────────────────

/**
 * Analyze a parsed packet and return enriched metadata.
 * @param {object} packet
 * @returns {object} packet with appProtocol, encrypted, tlsVersion added
 */
export function analyzePacket(packet) {
  const { protocol, srcPort, dstPort, payload } = packet;

  // 1. Port-based heuristic (fast path)
  const portInfo = PORT_MAP[dstPort] || PORT_MAP[srcPort] || null;

  let appProtocol = portInfo?.app ?? 'Unknown';
  let encrypted = portInfo?.encrypted ?? false;
  let tlsVersion = portInfo?.tls ?? null;

  // 2. Protocol overrides
  if (protocol === 'ICMP') {
    appProtocol = 'ICMP'; encrypted = false; tlsVersion = null;
  }

  if (protocol === 'UDP' && (dstPort === 53 || srcPort === 53)) {
    appProtocol = 'DNS'; encrypted = false;
  }

  // 3. Deep payload inspection (when raw buffer provided)
  if (payload instanceof Buffer && payload.length > 0) {
    if (detectSSH(payload)) {
      appProtocol = 'SSH'; encrypted = true; tlsVersion = 'SSH-2.0';
    } else if (payload[0] === 0x16) {
      const ver = detectTLSVersion(payload);
      if (ver) {
        encrypted = true;
        tlsVersion = ver;
        if (!appProtocol || appProtocol === 'Unknown')
          appProtocol = 'HTTPS';
      }
    } else if (detectHTTP(payload)) {
      appProtocol = 'HTTP'; encrypted = false; tlsVersion = null;
    }
  }

  // 4. Attach encryption simulation metadata if encrypted
  let simEncryption = null;
  if (encrypted) {
    simEncryption = generateMockEncryptionData(tlsVersion, appProtocol);
  }

  return { ...packet, appProtocol, encrypted, tlsVersion, simEncryption };
}

/**
 * Generate mock encryption simulation metadata for demonstration purposes.
 */
export function generateMockEncryptionData(tlsVersion, appProtocol) {
  const isSSH = appProtocol === 'SSH';
  const isOldTLS = tlsVersion === 'SSL 3.0' || tlsVersion === 'TLS 1.0' || tlsVersion === 'TLS 1.1';
  
  if (isSSH) {
    return {
      algorithm: Math.random() > 0.5 ? 'aes256-ctr' : 'chacha20-poly1305@openssh.com',
      keyExchange: 'curve25519-sha256',
      process: [
        '1. Client & Server: Version Exchange (SSH-2.0)',
        '2. Client & Server: KEXINIT (Algorithm negotiation)',
        '3. Client: KEXDH_INIT (Send public key)',
        '4. Server: KEXDH_REPLY (Send public key & signature)',
        '5. Derive Shared Secret (Diffie-Hellman)',
        '6. NEWKEYS: Switch to Encrypted Transport',
        '7. Secure Payload Transmission'
      ]
    };
  }
  
  if (isOldTLS) {
    return {
      algorithm: 'RSA_WITH_AES_128_CBC_SHA',
      keyExchange: 'RSA (Static - Vulnerable to Forward Secrecy loss)',
      process: [
        '1. ClientHello: Propose Cipher Suites',
        '2. ServerHello: Agree on RSA_WITH_AES_128_CBC_SHA',
        '3. Client: Send Encrypted Pre-Master Secret (using Server RSA PubKey)',
        '4. Server: Decrypt Pre-Master Secret',
        '5. Derive Symmetric Keys',
        '6. ChangeCipherSpec: Switch to encrypted mode'
      ]
    };
  }

  // Modern TLS
  const cipher = Math.random() > 0.4 ? 'TLS_AES_256_GCM_SHA384' : 'TLS_CHACHA20_POLY1305_SHA256';
  const kex = Math.random() > 0.5 ? 'X25519 (Elliptic Curve)' : 'ECDHE-RSA';
  return {
    algorithm: cipher,
    keyExchange: kex,
    process: [
      '1. ClientHello: Support for TLS 1.2/1.3 + Cipher suites',
      '2. ServerHello: Select ' + cipher,
      '3. Server: Send Certificate & ' + kex + ' Params',
      '4. Client: Verify Certificate & Send ' + kex + ' Params',
      '5. Derive Master Secret (Perfect Forward Secrecy)',
      '6. Application Data Encrypted/Decrypted'
    ]
  };
}

/**
 * Lightweight encryption check used by simulation (no payload)
 */
export function encryptionLabel(encrypted, tlsVersion) {
  if (!encrypted) return 'Unencrypted';
  if (!tlsVersion) return 'Encrypted';
  if (tlsVersion === 'SSL 3.0' || tlsVersion === 'TLS 1.0' || tlsVersion === 'TLS 1.1') {
    return `⚠ ${tlsVersion}`;
  }
  return tlsVersion;
}
