import { nwApi } from './api.js';

// ── Login Form Handler ───────────────────────────────────────────────────────
const form    = document.getElementById('loginForm');
const errEl   = document.getElementById('loginError');
const btnText = document.getElementById('btnText');
const spinner = document.getElementById('btnSpinner');
const loginBtn = document.getElementById('loginBtn');

// Redirect if already logged in
if (sessionStorage.getItem('nw_token')) {
  window.location.href = '/dashboard.html';
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();

  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;

  if (!username || !password) {
    showError('Please enter username and password.');
    return;
  }

  setLoading(true);
  hideError();

  try {
    const data = await nwApi.login(username, password);

    // Store token and user info
    sessionStorage.setItem('nw_token', data.token);
    sessionStorage.setItem('nw_user', JSON.stringify(data.user));

    // Redirect to dashboard
    window.location.href = '/dashboard.html';
  } catch (err) {
    showError(err.message || 'Cannot connect to server. Please try again.');
  } finally {
    setLoading(false);
  }
});

function setLoading(on) {
  loginBtn.disabled = on;
  btnText.textContent = on ? 'AUTHENTICATING...' : 'AUTHENTICATE';
  if (on) {
    spinner.classList.remove('hidden');
    loginBtn.classList.add('opacity-70', 'cursor-not-allowed');
  } else {
    spinner.classList.add('hidden');
    loginBtn.classList.remove('opacity-70', 'cursor-not-allowed');
  }
}

function showError(msg) {
  errEl.textContent = msg;
  errEl.classList.remove('hidden');
}

function hideError() {
  errEl.classList.add('hidden');
}
