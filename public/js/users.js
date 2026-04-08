import { nwApi } from './api.js';

/**
 * NetWatch — User Management Page
 * Admin-only CRUD for user accounts
 */

// ── Auth Guard ────────────────────────────────────────────────────────────────
const token = sessionStorage.getItem('nw_token');
const me    = JSON.parse(sessionStorage.getItem('nw_user') || 'null');
if (!token || !me || me.role !== 'admin') {
  window.location.href = me ? '/dashboard.html' : '/';
}

// ── Nav ───────────────────────────────────────────────────────────────────────
document.getElementById('userNameDisplay').textContent = me.username;
document.getElementById('userAvatar').textContent      = me.username[0].toUpperCase();
document.getElementById('logoutBtn').addEventListener('click', () => {
  sessionStorage.clear(); window.location.href = '/';
});

// ── Toast ─────────────────────────────────────────────────────────────────────
function toast(msg, type = 'info', ms = 3500) {
  const tc = document.getElementById('toastContainer');
  const el = document.createElement('div');
  
  const baseClasses = "px-4 py-3 text-sm font-semibold border bg-sys-surface shadow-xl flex items-center gap-3 animate-[slideIn_0.3s_ease-out]";
  let typeClasses = "";
  if (type === 'success') typeClasses = "border-sys-green text-sys-green";
  else if (type === 'error') typeClasses = "border-sys-red text-sys-red";
  else typeClasses = "border-sys-cyan text-sys-cyan";
  
  el.className = `${baseClasses} ${typeClasses}`;
  el.innerHTML = `<span class="w-1.5 h-1.5 inline-block ${type === 'error' ? 'bg-sys-red' : (type === 'success' ? 'bg-sys-green' : 'bg-sys-cyan')}"></span> ${msg}`;

  tc.appendChild(el);
  setTimeout(() => el.remove(), ms);
}

// ── State ─────────────────────────────────────────────────────────────────────
let users       = [];
let deleteTarget = null;

// ── Render ────────────────────────────────────────────────────────────────────
function formatDate(d) {
  if (!d) return '<span class="text-sys-text-muted">Never</span>';
  return new Date(d).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' });
}

function renderRow(u, idx) {
  const isSelf = u._id === me.id;
  const adminBadge = '<span class="px-2 py-0.5 border border-sys-purple text-sys-purple bg-sys-purple-faint text-[0.65rem] tracking-wider uppercase font-bold inline-flex items-center gap-1"><span class="w-1 h-1 bg-sys-purple block"></span> Admin</span>';
  const userBadge = '<span class="px-2 py-0.5 border border-sys-cyan text-sys-cyan bg-sys-cyan-faint text-[0.65rem] tracking-wider uppercase font-bold inline-flex items-center gap-1"><span class="w-1 h-1 bg-sys-cyan block"></span> User</span>';
  
  const activeBadge = '<span class="px-2 py-0.5 border border-sys-green text-sys-green bg-sys-green-faint text-[0.65rem] tracking-wider uppercase font-bold inline-flex items-center gap-1"><span class="w-1 h-1 bg-sys-green block"></span> Active</span>';
  const inactiveBadge = '<span class="px-2 py-0.5 border border-sys-border text-sys-text-muted bg-sys-base text-[0.65rem] tracking-wider uppercase font-bold inline-flex items-center gap-1"><span class="w-1 h-1 bg-sys-text-muted block"></span> Inactive</span>';

  return `
    <tr class="hover:bg-sys-border/20 transition-colors">
      <td class="px-5 py-3 text-sys-text-muted w-16">${idx + 1}</td>
      <td class="px-5 py-3">
        <span class="font-bold text-sys-text">${u.username}</span>
        ${isSelf ? '<span class="text-[0.65rem] text-sys-cyan ml-2 tracking-widest uppercase">(you)</span>' : ''}
      </td>
      <td class="px-5 py-3">${u.role === 'admin' ? adminBadge : userBadge}</td>
      <td class="px-5 py-3">${u.active ? activeBadge : inactiveBadge}</td>
      <td class="px-5 py-3 text-sys-text-muted">${formatDate(u.lastSeen)}</td>
      <td class="px-5 py-3 text-sys-text-muted">${formatDate(u.createdAt)}</td>
      <td class="px-5 py-3 text-right">
        <div class="flex items-center gap-2 justify-end">
          <button
            class="btn-ghost text-[0.65rem] px-2 py-1 uppercase tracking-wider"
            onclick="openEditModal('${u._id}')"
            aria-label="Edit ${u.username}"
          >Edit</button>
          <button
            class="btn-danger text-[0.65rem] px-2 py-1 uppercase tracking-wider"
            onclick="openDeleteModal('${u._id}', '${u.username}')"
            ${isSelf ? 'disabled title="Cannot delete yourself" class="btn-danger text-[0.65rem] px-2 py-1 uppercase tracking-wider opacity-50 cursor-not-allowed"' : ''}
            aria-label="Delete ${u.username}"
          >Revoke</button>
        </div>
      </td>
    </tr>`;
}

function renderTable() {
  const tbody = document.getElementById('usersTbody');
  if (!users.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center text-sys-text-muted p-12">No identities found in registry.</td></tr>`;
    return;
  }
  tbody.innerHTML = users.map((u, i) => renderRow(u, i)).join('');

  // Stats
  document.getElementById('statTotal').textContent  = users.length;
  document.getElementById('statAdmins').textContent = users.filter((u) => u.role === 'admin').length;
  document.getElementById('statActive').textContent = users.filter((u) => u.active).length;
}

// ── Fetch users ───────────────────────────────────────────────────────────────
async function loadUsers() {
  try {
    users = await nwApi.getUsers();
    renderTable();
  } catch (err) {
    toast('Failed to load users: ' + err.message, 'error');
  }
}

document.getElementById('btnRefresh').addEventListener('click', loadUsers);

// ── Add/Edit Modal ────────────────────────────────────────────────────────────
const userModal    = document.getElementById('userModal');
const modalTitle   = document.getElementById('modalTitle');
const modalError   = document.getElementById('modalError');
const pwHint       = document.getElementById('pwHint');
const editUserId   = document.getElementById('editUserId');
const modalUsername = document.getElementById('modalUsername');
const modalPassword = document.getElementById('modalPassword');
const modalRole    = document.getElementById('modalRole');

function openAddModal() {
  editUserId.value    = '';
  modalTitle.innerHTML = '<span class="w-1.5 h-1.5 bg-sys-cyan inline-block"></span> Provision New User';
  modalUsername.value = '';
  modalPassword.value = '';
  modalRole.value     = 'user';
  modalUsername.disabled = false;
  pwHint.classList.add('hidden');
  modalError.classList.add('hidden');
  openModal(userModal);
}

function openEditModal(id) {
  const u = users.find((x) => x._id === id);
  if (!u) return;
  editUserId.value       = u._id;
  modalTitle.innerHTML   = `<span class="w-1.5 h-1.5 bg-sys-cyan inline-block"></span> Modify — <span class="text-sys-cyan">${u.username}</span>`;
  modalUsername.value    = u.username;
  modalUsername.disabled = true; // username is immutable after creation
  modalPassword.value    = '';
  modalRole.value        = u.role;
  pwHint.classList.remove('hidden');
  modalError.classList.add('hidden');
  openModal(userModal);
}
// Expose to inline onclick
window.openEditModal = openEditModal;

document.getElementById('btnAddUser').addEventListener('click', openAddModal);

document.getElementById('modalSave').addEventListener('click', async () => {
  const id       = editUserId.value;
  const username = modalUsername.value.trim();
  const password = modalPassword.value;
  const role     = modalRole.value;

  modalError.classList.remove('show');

  if (!id && !username) { showModalError('Username is required.'); return; }
  if (!id && !password) { showModalError('Password is required for new users.'); return; }
  if (password && password.length < 6) { showModalError('Password must be at least 6 characters.'); return; }

  try {
    if (id) {
      const updateData = { role };
      if (password) updateData.password = password;
      await nwApi.updateUser(id, updateData);
      toast(`User updated`, 'success');
    } else {
      await nwApi.createUser({ username, password, role });
      toast(`User "${username}" created`, 'success');
    }
    closeModal(userModal);
    await loadUsers();
  } catch (err) {
    showModalError(err.message);
  }
});

function showModalError(msg) {
  modalError.textContent = msg;
  modalError.classList.remove('hidden');
}

// ── Delete Modal ──────────────────────────────────────────────────────────────
const deleteModal   = document.getElementById('deleteModal');
const deleteUsername = document.getElementById('deleteUsername');

function openDeleteModal(id, username) {
  deleteTarget             = id;
  deleteUsername.textContent = username;
  openModal(deleteModal);
}
window.openDeleteModal = openDeleteModal;

document.getElementById('deleteConfirmBtn').addEventListener('click', async () => {
  if (!deleteTarget) return;
  try {
    await nwApi.deleteUser(deleteTarget);
    toast('Access permanently revoked', 'success');
    closeModal(deleteModal);
    await loadUsers();
  } catch (err) {
    toast('Delete failed: ' + err.message, 'error');
  } finally {
    deleteTarget = null;
  }
});

// ── Modal Helpers ─────────────────────────────────────────────────────────────
function openModal(el)  { 
  el.classList.remove('hidden');
  el.classList.add('flex');
}
function closeModal(el) { 
  el.classList.add('hidden');
  el.classList.remove('flex');
}

document.getElementById('modalClose').addEventListener('click',  () => closeModal(userModal));
document.getElementById('modalCancel').addEventListener('click', () => closeModal(userModal));
document.getElementById('deleteClose').addEventListener('click', () => closeModal(deleteModal));
document.getElementById('deleteCancelBtn').addEventListener('click', () => closeModal(deleteModal));

// Close on overlay click
[userModal, deleteModal].forEach((m) => {
  m.addEventListener('click', (e) => { if (e.target === m) closeModal(m); });
});

// ── Init ──────────────────────────────────────────────────────────────────────
loadUsers();
