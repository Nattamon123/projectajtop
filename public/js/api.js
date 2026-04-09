/**
 * NetWatch API Client
 * Centralized outbound Request handlers for the NetWatch frontend.
 */

const nwToken = () => sessionStorage.getItem('nw_token');

export const nwApi = {
  // ── Authentication ────────────────────────────────────────────────────────
  async login(username, password) {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Login failed');
    return data;
  },

  // ── Packets & History ─────────────────────────────────────────────────────
  // ดึงประวัติแพ็กเก็ต (รองรับการกรองทั้งแบบพื้นฐานและขั้นสูง)
  async getHistory({ page = 1, limit = 100, protocol, appProtocol, encrypted, srcIp, dstIp, dstPort }) {
    const q = new URLSearchParams();
    q.set('page', page);
    q.set('limit', limit);
    if (protocol) q.set('protocol', protocol);
    if (appProtocol) q.set('appProtocol', appProtocol);
    if (encrypted !== undefined && encrypted !== "") q.set('encrypted', encrypted);

    // ── แนบค่าตัวกรองขั้นสูงเข้าไปกับ URL ถ้ามีการกรอกเข้ามา ──
    if (srcIp) q.set('srcIp', srcIp);
    if (dstIp) q.set('dstIp', dstIp);
    if (dstPort) q.set('dstPort', dstPort);

    const res = await fetch(`/api/packets/history?${q.toString()}`, {
      headers: { 'Authorization': `Bearer ${nwToken()}` }
    });
    if (!res.ok) throw new Error('Failed to fetch history');
    return res.json();
  },

  // ── Users Management (Admin) ──────────────────────────────────────────────
  async getUsers() {
    const res = await fetch('/api/users', {
      headers: { 'Authorization': `Bearer ${nwToken()}` }
    });
    if (!res.ok) throw new Error('Failed to fetch users');
    return res.json();
  },

  async createUser(userData) {
    const res = await fetch('/api/users', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${nwToken()}` 
      },
      body: JSON.stringify(userData),
    });
    if (!res.ok) {
        const d = await res.json();
        throw new Error(d.error || 'Failed to create user');
    }
    return res.json();
  },

  async updateUser(id, updateData) {
    const res = await fetch(`/api/users/${id}`, {
      method: 'PUT',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${nwToken()}` 
      },
      body: JSON.stringify(updateData),
    });
    if (!res.ok) throw new Error('Failed to update user');
    return res.json();
  },

  async deleteUser(id) {
    const res = await fetch(`/api/users/${id}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${nwToken()}` }
    });
    if (!res.ok) throw new Error('Failed to delete user');
    return res.json();
  },
};

/**
 * Socket.IO Request Wrappers for Dashboard
 */
export const nwSocket = {
  getInterfaces(socket) {
    return new Promise((resolve) => {
      socket.emit('capture:getInterfaces', resolve);
    });
  },
  startCapture(socket, iface, pps) {
    socket.emit('capture:start', { iface, pps });
  },
  stopCapture(socket) {
    socket.emit('capture:stop');
  },
  resetStats(socket) {
    socket.emit('stats:reset');
  },
  setPps(socket, pps) {
    socket.emit('capture:setPps', { pps });
  },
  lookupIp(socket, ip, callback) {
    socket.emit('capture:lookupIp', ip, callback);
  }
};
