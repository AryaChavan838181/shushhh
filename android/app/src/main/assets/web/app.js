// ============================================================
// app.js — Shushhh Android WebView Application Logic
// ============================================================
// Bridges the HTML UI to the native C++ crypto core via
// window.ShushhhBridge (injected by MainActivity.java).

'use strict';

// ── State ──
let currentScreen = 'screen-boot';
let myUsername = '';
let peerUsername = '';
let lastMessageCount = 0;

// ── Bridge helper ──
// ShushhhBridge is injected by Android WebView's JavascriptInterface.
// For testing in a browser, we provide a mock.
const Bridge = window.ShushhhBridge || {
    isTorRunning: () => false,
    register: (u, p) => '{"error":"No native bridge"}',
    login: (u, p) => '{"error":"No native bridge"}',
    connect: (p) => '{"error":"No native bridge"}',
    sendMessage: (m) => false,
    getMessages: () => '[]',
    getState: () => '{}',
    setServerUrls: (k, m) => {},
    selfDestruct: () => {}
};

// ============================================================
// Screen Navigation
// ============================================================

function showScreen(screenId) {
    // Hide current
    const current = document.querySelector('.screen.active');
    if (current) {
        current.classList.remove('active');
        current.classList.remove('fade-in');
    }

    // Show target
    const target = document.getElementById(screenId);
    if (target) {
        target.classList.add('active');
        // Trigger reflow for animation
        void target.offsetWidth;
        target.classList.add('fade-in');
        currentScreen = screenId;
    }

    // Focus first input on form screens
    setTimeout(() => {
        const input = target?.querySelector('input');
        if (input) input.focus();
    }, 400);
}

// ============================================================
// Boot Sequence
// ============================================================

// Called from native when crypto + Tor init complete
function onNativeReady(cryptoOk, torRunning) {
    const progress = document.getElementById('boot-progress');
    const statusText = document.getElementById('boot-status-text');

    // Animate progress
    setTimeout(() => {
        progress.style.width = '40%';
        statusText.textContent = cryptoOk
            ? '✓ Crypto engine initialized'
            : '✗ Crypto init failed!';
    }, 300);

    setTimeout(() => {
        progress.style.width = '75%';
        statusText.textContent = torRunning
            ? '✓ Tor circuit established'
            : '○ Tor bootstrapping...';
        updateTorIndicator(torRunning);
    }, 1200);

    setTimeout(() => {
        progress.style.width = '100%';
        statusText.textContent = '✓ Ready';
    }, 2000);

    setTimeout(() => {
        showScreen('screen-menu');
    }, 2800);
}

// Fallback: if native doesn't call onNativeReady within 8 seconds, show menu anyway
setTimeout(() => {
    if (currentScreen === 'screen-boot') {
        const progress = document.getElementById('boot-progress');
        const statusText = document.getElementById('boot-status-text');
        progress.style.width = '100%';
        statusText.textContent = 'Ready (native init pending)';
        setTimeout(() => showScreen('screen-menu'), 500);
    }
}, 8000);

// ============================================================
// Tor Status
// ============================================================

let currentTorIp = null;

function updateTorIndicator(running, ip = null) {
    if (ip) currentTorIp = ip;
    if (!running) currentTorIp = null;

    const indicator = document.getElementById('tor-indicator');
    const dot = indicator?.querySelector('.dot');
    const txt = indicator?.querySelector('span:nth-child(2)');
    if (dot) {
        dot.className = running ? 'dot dot-green' : 'dot dot-red';
        if (txt) {
            txt.textContent = (running && currentTorIp) ? 'Tor (' + currentTorIp + ')' : (running ? 'Tor (Connected)' : 'Tor');
        }
    }
    // Update chat header dot too
    const chatDot = document.getElementById('chat-tor-dot');
    if (chatDot) {
        chatDot.className = running
            ? 'dot dot-small dot-green'
            : 'dot dot-small dot-red';
    }
}

// Periodically check Tor status
setInterval(() => {
    try {
        updateTorIndicator(Bridge.isTorRunning());
    } catch (e) {}
}, 5000);

// ============================================================
// Authentication
// ============================================================

function doLogin() {
    const user = document.getElementById('login-user').value.trim();
    const pass = document.getElementById('login-pass').value;
    const error = document.getElementById('login-error');
    const loading = document.getElementById('login-loading');

    if (!user || !pass) {
        error.textContent = 'Username and password are required';
        return;
    }

    error.textContent = '';
    loading.classList.add('active');

    // Run on next tick to allow UI update
    setTimeout(() => {
        try {
            const result = JSON.parse(Bridge.login(user, pass));
            loading.classList.remove('active');

            if (result.status === 'ok') {
                myUsername = user;
                showScreen('screen-connect');
            } else {
                error.textContent = result.error || 'Authentication failed';
                vibrate();
            }
        } catch (e) {
            loading.classList.remove('active');
            error.textContent = 'Connection error: ' + e.message;
            vibrate();
        }
    }, 100);
}

function doRegister() {
    const user = document.getElementById('reg-user').value.trim();
    const pass = document.getElementById('reg-pass').value;
    const pass2 = document.getElementById('reg-pass2').value;
    const error = document.getElementById('reg-error');
    const loading = document.getElementById('reg-loading');

    if (!user || !pass) {
        error.textContent = 'All fields are required';
        return;
    }
    if (pass !== pass2) {
        error.textContent = 'Passwords do not match';
        vibrate();
        return;
    }
    if (pass.length < 4) {
        error.textContent = 'Password too short (minimum 4 characters)';
        return;
    }

    error.textContent = '';
    loading.classList.add('active');

    setTimeout(() => {
        try {
            const result = JSON.parse(Bridge.register(user, pass));
            loading.classList.remove('active');

            if (result.status === 'ok') {
                // Auto-login after registration
                const loginResult = JSON.parse(Bridge.login(user, pass));
                if (loginResult.status === 'ok') {
                    myUsername = user;
                    showScreen('screen-connect');
                } else {
                    error.textContent = 'Registered but auto-login failed';
                }
            } else {
                error.textContent = result.error || 'Registration failed';
                vibrate();
            }
        } catch (e) {
            loading.classList.remove('active');
            error.textContent = 'Connection error: ' + e.message;
            vibrate();
        }
    }, 100);
}

// ============================================================
// Configuration
// ============================================================

function saveConfig() {
    const ks = document.getElementById('cfg-ks').value.trim();
    const ms = document.getElementById('cfg-ms').value.trim();

    if (ks && ms) {
        Bridge.setServerUrls(ks, ms);
    }

    showScreen('screen-menu');
}

// ============================================================
// Session Management
// ============================================================

function doConnect() {
    const peer = document.getElementById('peer-user').value.trim();
    const error = document.getElementById('connect-error');
    const loading = document.getElementById('connect-loading');

    if (!peer) {
        error.textContent = 'Enter a peer username';
        return;
    }

    error.textContent = '';
    loading.classList.add('active');

    setTimeout(() => {
        try {
            const result = JSON.parse(Bridge.connect(peer));
            loading.classList.remove('active');

            if (result.status === 'ok') {
                peerUsername = peer;
                enterChat();
            } else {
                error.textContent = result.error || 'Connection failed';
                vibrate();
            }
        } catch (e) {
            loading.classList.remove('active');
            error.textContent = 'Error: ' + e.message;
            vibrate();
        }
    }, 100);
}

function doWait() {
    peerUsername = 'waiting...';
    enterChat();
}

function enterChat() {
    document.getElementById('chat-my-name').textContent = myUsername;
    document.getElementById('chat-peer-name').textContent = peerUsername;
    showScreen('screen-chat');
}

// ============================================================
// Messaging
// ============================================================

function sendMessage() {
    const input = document.getElementById('chat-input');
    const text = input.value.trim();
    if (!text) return;

    const sent = Bridge.sendMessage(text);
    if (sent) {
        input.value = '';
        refreshMessages();
        vibrate(30);
    }
}

// Called periodically by MainActivity's refresh handler
function refreshMessages() {
    try {
        const messagesJson = Bridge.getMessages();
        const messages = JSON.parse(messagesJson);

        // Only update if message count changed
        if (messages.length === lastMessageCount) return;
        lastMessageCount = messages.length;

        // Update peer name from state
        try {
            const state = JSON.parse(Bridge.getState());
            if (state.peer && state.peer !== peerUsername) {
                peerUsername = state.peer;
                document.getElementById('chat-peer-name').textContent = peerUsername;
            }
        } catch (e) {}

        renderMessages(messages);
    } catch (e) {
        console.error('Message refresh error:', e);
    }
}

function renderMessages(messages) {
    const container = document.getElementById('chat-messages');

    if (messages.length === 0) {
        container.innerHTML = `
            <div class="chat-empty">
                <p>🔐 End-to-end encrypted</p>
                <p class="hint">Messages are routed through Tor</p>
            </div>`;
        return;
    }

    let html = '';
    for (const msg of messages) {
        if (msg.startsWith('[SYSTEM]')) {
            html += `<div class="msg msg-system">${escapeHtml(msg.replace('[SYSTEM] ', ''))}</div>`;
        } else if (msg.startsWith(myUsername + '>')) {
            const text = msg.substring(myUsername.length + 2);
            html += `<div class="msg msg-sent">${escapeHtml(text)}</div>`;
        } else {
            // Find the > separator to extract the message
            const sepIdx = msg.indexOf('> ');
            const text = sepIdx >= 0 ? msg.substring(sepIdx + 2) : msg;
            html += `<div class="msg msg-received">${escapeHtml(text)}</div>`;
        }
    }

    container.innerHTML = html;

    // Auto-scroll to bottom
    requestAnimationFrame(() => {
        container.scrollTop = container.scrollHeight;
    });
}

// ============================================================
// Utilities
// ============================================================

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function vibrate(ms) {
    if ('vibrate' in navigator) {
        navigator.vibrate(ms || 50);
    }
}

// ============================================================
// Boot Animation
// ============================================================

// Animate boot progress on load
document.addEventListener('DOMContentLoaded', () => {
    const progress = document.getElementById('boot-progress');
    const statusText = document.getElementById('boot-status-text');

    setTimeout(() => {
        progress.style.width = '15%';
        statusText.textContent = 'Loading native libraries...';
    }, 200);

    setTimeout(() => {
        progress.style.width = '25%';
        statusText.textContent = 'Initializing crypto engine...';
    }, 800);
});
