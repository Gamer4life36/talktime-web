// Whisper front-end — vanilla JS SPA talking to the Node/SQLite backend.

// ---- anonymous device identity (persists in localStorage, no login) ------- //
function deviceId() {
  let id = localStorage.getItem('whisper_device');
  if (!id) {
    id = (crypto.randomUUID ? crypto.randomUUID() : String(Math.random()).slice(2) + Date.now());
    localStorage.setItem('whisper_device', id);
  }
  return id;
}

// Backend base URL: localStorage override, else config.js value, else same-origin.
const API_BASE = (localStorage.getItem('whisper_api') || window.WHISPER_API_BASE || '').replace(/\/$/, '');

// ---- content encryption (AES-256-GCM, shared key with the server) --------- //
// Header that skips localtunnel's browser "reminder" interstitial (harmless elsewhere).
const TUNNEL_HDR = { 'bypass-tunnel-reminder': '1', 'ngrok-skip-browser-warning': 'true' };

// ---- ECDH session key exchange (no secret ships in the app) ---------------- //
// The app pins only the server's PUBLIC signing key. On first use it runs a
// handshake to derive an ephemeral AES key that never leaves memory. Verifying
// the server's signature stops a man-in-the-middle (e.g. the tunnel) from posing
// as the server.
const SERVER_SIGN_PUB = Uint8Array.from(atob(window.WHISPER_SERVER_PUB || ''), (c) => c.charCodeAt(0));
const b64e = (u8) => { let s = ''; for (const b of u8) s += String.fromCharCode(b); return btoa(s); };
const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

let session = null;              // { id, key: CryptoKey }
let handshaking = null;

async function doHandshake() {
  const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const clientPub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
  const res = await fetch(API_BASE + '/api/handshake', {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...TUNNEL_HDR },
    body: JSON.stringify({ clientPub: b64e(clientPub) }),
  });
  if (!res.ok) throw new Error('handshake failed (' + res.status + ')');
  const { sessionId, serverPub, sig } = await res.json();
  const serverPubRaw = b64d(serverPub);
  const vKey = await crypto.subtle.importKey('raw', SERVER_SIGN_PUB, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, vKey, b64d(sig), serverPubRaw);
  if (!ok) throw new Error('server identity check failed');       // wrong server / MITM
  const serverKey = await crypto.subtle.importKey('raw', serverPubRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const bits = await crypto.subtle.deriveBits({ name: 'ECDH', public: serverKey }, kp.privateKey, 256);
  const key = await crypto.subtle.importKey('raw', bits, 'AES-GCM', false, ['encrypt', 'decrypt']);
  session = { id: sessionId, key };
}
function ensureSession() {
  if (session) return Promise.resolve();
  if (!handshaking) handshaking = doHandshake().finally(() => { handshaking = null; });
  return handshaking;
}

async function encPayload(obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, session.key, new TextEncoder().encode(JSON.stringify(obj))));
  const out = new Uint8Array(iv.length + ct.length); out.set(iv); out.set(ct, iv.length);
  return b64e(out);
}
async function decPayload(b64) {
  const buf = b64d(b64);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12) }, session.key, buf.slice(12));
  return JSON.parse(new TextDecoder().decode(pt));
}

async function api(path, opts = {}, _retry = false) {
  await ensureSession();
  const init = { ...opts, headers: { 'Content-Type': 'application/json', 'x-device-id': deviceId(), 'x-session-id': session.id, ...TUNNEL_HDR, ...(opts.headers || {}) } };
  if (opts.body) init.body = JSON.stringify({ e: await encPayload(JSON.parse(opts.body)) });
  const res = await fetch(API_BASE + '/api' + path, init);
  if (res.status === 401 && !_retry) { session = null; await ensureSession(); return api(path, opts, true); }
  if (res.status === 204) return null;
  const raw = await res.json().catch(() => null);
  const data = raw && typeof raw.e === 'string' ? await decPayload(raw.e) : raw;
  if (!res.ok) { const e = new Error((data && data.error) || res.statusText); e.status = res.status; e.data = data; throw e; }
  return data;
}

async function uploadFile(file, _retry = false) {
  await ensureSession();
  const fd = new FormData();
  fd.append('file', file);
  const res = await fetch(API_BASE + '/api/upload', { method: 'POST', headers: { 'x-device-id': deviceId(), 'x-session-id': session.id, ...TUNNEL_HDR }, body: fd });
  if (res.status === 401 && !_retry) { session = null; await ensureSession(); return uploadFile(file, true); }
  const raw = await res.json().catch(() => null);
  const data = raw && typeof raw.e === 'string' ? await decPayload(raw.e) : raw;
  if (!res.ok) throw new Error((data && data.error) || 'upload failed');
  return data.url;
}

// ---- backgrounds ---------------------------------------------------------- //
const GRADIENTS = [
  'linear-gradient(135deg,#667eea,#764ba2)', 'linear-gradient(135deg,#f093fb,#f5576c)',
  'linear-gradient(135deg,#4facfe,#00f2fe)', 'linear-gradient(135deg,#43e97b,#38f9d7)',
  'linear-gradient(135deg,#fa709a,#fee140)', 'linear-gradient(135deg,#30cfd0,#330867)',
  'linear-gradient(135deg,#a8edea,#fed6e3)', 'linear-gradient(135deg,#ff9a9e,#fecfef)',
  'linear-gradient(135deg,#2b5876,#4e4376)', 'linear-gradient(135deg,#141e30,#243b55)',
];
function hashSeed(s) { let h = 0; for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0; return h; }
function meshBg(seed) {
  const h = hashSeed(seed);
  const a = h % 360, b = (h >> 3) % 360, c = (h >> 6) % 360, d = (h >> 9) % 360;
  return `background-color:hsl(${a},55%,42%);background-image:` +
    `radial-gradient(at 18% 22%, hsl(${a},72%,58%) 0, transparent 55%),` +
    `radial-gradient(at 82% 18%, hsl(${b},70%,52%) 0, transparent 52%),` +
    `radial-gradient(at 25% 82%, hsl(${c},72%,55%) 0, transparent 55%),` +
    `radial-gradient(at 78% 80%, hsl(${d},68%,48%) 0, transparent 52%)`;
}
// bg string: "grad:N" | "photo:SEED" | "img:URL" (uploaded image/GIF)
function bgStyle(bg) {
  if (bg && bg.startsWith('img:')) return meshBg(bg);   // placeholder until the blob loads
  if (bg && bg.startsWith('photo:')) return meshBg(bg.slice(6));
  const n = bg && bg.startsWith('grad:') ? (parseInt(bg.slice(5), 10) || 0) : 0;
  return `background-image:${GRADIENTS[n % GRADIENTS.length]}`;
}

// Uploaded images must be fetched (not loaded via CSS) so we can send the
// tunnel-bypass header; the decrypted bytes become an object URL. Cached by path.
const _blobCache = new Map();
async function imageBlobUrl(imgPath) {
  if (_blobCache.has(imgPath)) return _blobCache.get(imgPath);
  const res = await fetch(API_BASE + imgPath, { headers: TUNNEL_HDR });
  if (!res.ok) throw new Error('img ' + res.status);
  const url = URL.createObjectURL(await res.blob());
  _blobCache.set(imgPath, url);
  return url;
}
// Any element carrying data-img gets its real background loaded asynchronously.
function hydrateImages(root) {
  (root || document).querySelectorAll('[data-img]').forEach(async (el) => {
    const p = el.getAttribute('data-img');
    el.removeAttribute('data-img');
    try { el.style.backgroundImage = `url('${await imageBlobUrl(p)}')`; } catch (e) { /* keep placeholder */ }
  });
}
// data-img attribute for uploaded-image cards (empty otherwise)
function imgAttr(bg) {
  return (bg && bg.startsWith('img:')) ? ` data-img="${esc(bg.slice(4).replace(/["']/g, ''))}"` : '';
}

// ---- helpers -------------------------------------------------------------- //
const $ = (s) => document.querySelector(s);
const esc = (s) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function timeAgo(ts) {
  const d = Math.floor((Date.now() - ts) / 1000);
  if (d < 60) return 'now';
  if (d < 3600) return Math.floor(d / 60) + 'm';
  if (d < 86400) return Math.floor(d / 3600) + 'h';
  return Math.floor(d / 86400) + 'd';
}
const HEART = '<svg viewBox="0 0 24 24"><path d="M20.8 4.6a5.5 5.5 0 00-7.8 0L12 5.6l-1-1a5.5 5.5 0 00-7.8 7.8l1 1L12 21l7.8-7.6 1-1a5.5 5.5 0 000-7.8z"/></svg>';
const CHAT = '<svg viewBox="0 0 24 24"><path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/></svg>';

function distLabel(w) {
  if (w.distKm == null) return '';
  return w.distKm < 1 ? ' · nearby' : ` · ${w.distKm} km`;
}
function cardHtml(w) {
  return `
    <div class="card" style="${bgStyle(w.bg)}"${imgAttr(w.bg)} data-id="${w.id}">
      <div class="card-text">${esc(w.text)}</div>
      <div class="card-meta">
        <span class="loc">${esc(w.nickname)} · ${timeAgo(w.created_at)}${distLabel(w)}</span>
        <button class="heart-btn ${w.hearted ? 'on' : ''}" data-heart="${w.id}">${HEART}<span>${w.hearts}</span></button>
        <span class="chip">${CHAT}<span>${w.replies}</span></span>
      </div>
    </div>`;
}

// ---- geolocation (best-effort; unavailable over plain-http LAN) ----------- //
let geoCache = null;
function getGeo() {
  return new Promise((resolve) => {
    if (geoCache) return resolve(geoCache);
    if (!navigator.geolocation || !window.isSecureContext) return resolve(null);
    navigator.geolocation.getCurrentPosition(
      (p) => { geoCache = { lat: p.coords.latitude, lng: p.coords.longitude }; resolve(geoCache); },
      () => resolve(null),
      { enableHighAccuracy: false, timeout: 6000, maximumAge: 300000 });
  });
}

// ---- view routing --------------------------------------------------------- //
const views = {
  feed: $('#feedView'), search: $('#searchView'), activity: $('#activityView'),
  me: $('#meView'), detail: $('#detailView'),
  conversations: $('#conversationsView'), chat: $('#chatView'), nearby: $('#nearbyView'),
  rooms: $('#roomsView'), room: $('#roomView'),
};
const SUBVIEWS = new Set(['detail', 'conversations', 'chat', 'nearby', 'rooms', 'room']);
let backTo = 'feed';
let currentView = 'feed';
let feedScrollY = 0;        // remembers your place on the home feed
let popping = false;        // true while handling a hardware/browser back
function showView(name) {
  if (currentView === 'feed' && name !== 'feed') feedScrollY = window.scrollY;   // save home scroll on leave
  for (const [k, el] of Object.entries(views)) el.hidden = k !== name;
  $('#backBtn').hidden = !SUBVIEWS.has(name);
  $('#inboxBtn').hidden = SUBVIEWS.has(name);
  document.querySelectorAll('.nav-btn[data-nav]').forEach((b) =>
    b.classList.toggle('is-active', b.dataset.nav === name));
  // one history entry per sub-view level → the phone's Back button walks back
  // through the app instead of exiting (skipped while we're handling a Back)
  if (!popping && SUBVIEWS.has(name)) history.pushState({ view: name }, '');
  currentView = name;
  if (name === 'feed') window.scrollTo(0, feedScrollY);   // restore home scroll
  else window.scrollTo(0, 0);
}
// go back one level, keeping the home feed exactly where the user left it
function goBack() {
  if (currentView === 'search' || currentView === 'activity' || currentView === 'me') {
    showView('feed'); return;                         // a main tab → home
  }
  if (backTo === 'conversations') { openConversations(); return; }
  if (backTo === 'nearby') { openNearby(); return; }
  if (backTo === 'rooms') { openRooms(); return; }
  showView('feed');   // subview → home; no reload, preserves scroll + loaded posts
}
// browser/PWA back button + gesture
window.addEventListener('popstate', () => {
  if (currentView !== 'feed') { popping = true; goBack(); popping = false; }
});
// Android hardware Back button (Capacitor): go to the previous screen instead of
// closing the app; only exit when already on the home feed.
const CapApp = window.Capacitor && window.Capacitor.Plugins && window.Capacitor.Plugins.App;
if (CapApp) {
  CapApp.addListener('backButton', () => {
    if (currentView === 'feed') CapApp.exitApp();
    else { popping = true; goBack(); popping = false; }
  });
}

// ---- feed (Latest / Local / Tag) ------------------------------------------ //
let currentTab = 'latest';
let currentTag = null;
// home-feed pagination (newest first, endless scroll)
let feedOldest = null, feedLoading = false, feedHasMore = false;
const FEED_PAGE = 30;

function renderFeedList(list) {
  $('#feedEmpty').hidden = list.length > 0;
  $('#feed').innerHTML = list.map(cardHtml).join('');
  hydrateImages($('#feed'));
}
function appendFeedList(list) {
  $('#feed').insertAdjacentHTML('beforeend', list.map(cardHtml).join(''));
  hydrateImages($('#feed'));   // only the newly-added cards still carry data-img
}

// load the next (older) page of the home feed as the user scrolls down
async function loadMoreFeed() {
  if (feedLoading || !feedHasMore || currentTab !== 'latest' || feedOldest == null) return;
  feedLoading = true;
  $('#feedMore').hidden = false;
  try {
    const list = await api(`/whispers?sort=latest&limit=${FEED_PAGE}&before=${feedOldest}`);
    if (list.length) { appendFeedList(list); feedOldest = list[list.length - 1].created_at; }
    feedHasMore = list.length === FEED_PAGE;
  } catch (e) { /* keep what we have */ }
  finally { feedLoading = false; $('#feedMore').hidden = true; }
}

// live refresh: merge in any NEW posts at the top without resetting the user's
// scroll position or the pages they've already loaded (used by the sync poll).
async function refreshFeedTop() {
  if (currentTab !== 'latest') return loadFeed();     // local/tag: plain reload
  if (window.scrollY > 400) return;                   // don't yank a scrolled reader
  const list = await api(`/whispers?sort=latest&limit=${FEED_PAGE}`);
  const feed = $('#feed');
  const have = new Set([...feed.querySelectorAll('.card')].map((c) => c.dataset.id));
  const fresh = list.filter((w) => !have.has(w.id));
  if (!fresh.length) return;
  feed.insertAdjacentHTML('afterbegin', fresh.map(cardHtml).join(''));   // newest on top
  hydrateImages(feed);
  $('#feedEmpty').hidden = feed.children.length > 0;
}

async function loadFeed() {
  const tab = currentTab;
  $('#tagBar').hidden = tab !== 'tag';
  $('#tagSearch').hidden = tab !== 'tag';
  $('#feedNote').hidden = true;
  feedHasMore = false; feedOldest = null;   // reset paging on any (re)load
  if (tab === 'latest') {
    const list = await api(`/whispers?sort=latest&limit=${FEED_PAGE}`);
    renderFeedList(list);
    if (list.length) feedOldest = list[list.length - 1].created_at;
    feedHasMore = list.length === FEED_PAGE;
  } else if (tab === 'local') {
    const geo = await getGeo();
    let url = '/whispers?sort=local';
    if (geo) url += `&lat=${geo.lat}&lng=${geo.lng}`;
    else {
      $('#feedNote').hidden = false;
      $('#feedNote').textContent = 'Showing all located posts. Enable location (needs HTTPS) to sort by distance.';
    }
    renderFeedList(await api(url));
  } else if (tab === 'tag') {
    const q = $('#tagSearch').value.trim();
    const tags = await loadTagBar(q);
    if (currentTag && tags.some((t) => t.tag === currentTag)) {
      renderFeedList(await api('/whispers?tag=' + encodeURIComponent(currentTag)));
    } else { $('#feed').innerHTML = ''; $('#feedEmpty').hidden = true; }
  }
}

// infinite scroll — load older posts as you near the bottom of the home feed
window.addEventListener('scroll', () => {
  if (views.feed.hidden) return;
  const nearBottom = window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 700;
  if (nearBottom) loadMoreFeed();
}, { passive: true });

// pull-to-refresh — drag down at the top of the feed to reload
(() => {
  const THRESHOLD = 70, MAX = 110;
  let startY = null, pulling = false;
  const ptr = () => $('#ptr');
  views.feed.addEventListener('touchstart', (e) => {
    if (window.scrollY <= 0 && !feedLoading) { startY = e.touches[0].clientY; pulling = true; }
  }, { passive: true });
  views.feed.addEventListener('touchmove', (e) => {
    if (!pulling || startY == null) return;
    const dy = e.touches[0].clientY - startY;
    if (dy > 0 && window.scrollY <= 0) {
      const pull = Math.min(dy * 0.5, MAX);
      ptr().style.transition = 'none';
      ptr().style.height = pull + 'px';
      ptr().classList.toggle('ready', pull >= THRESHOLD);
    } else { pulling = false; }
  }, { passive: true });
  views.feed.addEventListener('touchend', async () => {
    if (!pulling) return;
    pulling = false;
    const el = ptr();
    const h = parseInt(el.style.height, 10) || 0;
    el.style.transition = 'height .2s';
    el.classList.remove('ready');
    if (h >= THRESHOLD) {
      el.classList.add('refreshing');
      el.style.height = '44px';
      try { await loadFeed(); } catch (e) { /* ignore */ }
      el.classList.remove('refreshing');
    }
    el.style.height = '0px';
    startY = null;
  }, { passive: true });
})();

async function loadTagBar(q) {
  const tags = await api('/tags' + (q ? '?q=' + encodeURIComponent(q) : ''));
  const bar = $('#tagBar');
  if (!tags.length) {
    bar.innerHTML = `<span class="feed-note">${q ? 'No tags match “' + esc(q) + '”.' : 'No tags yet. Add tags when you post.'}</span>`;
    currentTag = null;
    return [];
  }
  if (!currentTag || !tags.some((t) => t.tag === currentTag)) currentTag = tags[0].tag;
  bar.innerHTML = tags.map((t) =>
    `<button class="tag-chip ${t.tag === currentTag ? 'sel' : ''}" data-tag="${esc(t.tag)}">#${esc(t.tag)}<span class="cnt">${t.n}</span></button>`).join('');
  return tags;
}

// debounced tag search
let tagSearchTimer;
$('#tagSearch').addEventListener('input', () => {
  clearTimeout(tagSearchTimer);
  tagSearchTimer = setTimeout(() => { currentTag = null; if (currentTab === 'tag') loadFeed(); }, 250);
});

// ---- search --------------------------------------------------------------- //
let allForSearch = [];
async function loadSearch() {
  allForSearch = await api('/whispers?sort=latest');
  renderSearch($('#searchInput').value);
}
function renderSearch(q) {
  q = (q || '').trim().toLowerCase();
  const box = $('#searchResults');
  if (!q) { box.innerHTML = ''; $('#searchHint').hidden = false; return; }
  $('#searchHint').hidden = true;
  const hits = allForSearch.filter((w) => w.text.toLowerCase().includes(q));
  box.innerHTML = hits.length ? hits.map(cardHtml).join('') : '<div class="empty">No matches.</div>';
  hydrateImages(box);
}

// ---- activity / me -------------------------------------------------------- //
async function loadActivity() {
  const list = await api('/hearted');
  $('#activityEmpty').hidden = list.length > 0;
  $('#activityFeed').innerHTML = list.map(cardHtml).join('');
  hydrateImages($('#activityFeed'));
}
async function loadMe() {
  const list = await api('/mine');
  $('#meEmpty').hidden = list.length > 0;
  $('#meFeed').innerHTML = list.map(cardHtml).join('');
  hydrateImages($('#meFeed'));
}

// ---- post detail ---------------------------------------------------------- //
let currentWhisperId = null;
let currentDetail = null;
async function openDetail(id, from) {
  currentWhisperId = id;
  const w = await api('/whispers/' + id);
  currentDetail = w;
  $('#detailAuthor').textContent = w.nickname;
  $('#detailLoc').textContent = 'Somewhere';
  $('#detailTime').textContent = timeAgo(w.created_at);
  $('#detailCard').innerHTML = `<div class="card" style="${bgStyle(w.bg)}"${imgAttr(w.bg)}><div class="card-text">${esc(w.text)}</div></div>`;
  hydrateImages($('#detailCard'));
  $('#paLike').classList.toggle('on', !!w.hearted);
  $('#paLikeN').textContent = w.hearts;
  $('#paChat').hidden = w.isMine || !w.user_id;   // can't DM yourself
  $('#paDelete').hidden = !w.isMine;              // only you can delete your post
  renderReplies(w.replyList);
  backTo = from || 'feed';
  showView('detail');
}
function renderReplies(list) {
  const box = $('#replyList');
  if (!list.length) { box.innerHTML = '<div class="empty">NO REPLIES, BE THE FIRST!</div>'; return; }
  box.innerHTML = list.map((r) => `
    <div class="reply"><div class="nick">${esc(r.nickname)}</div>
      <div class="rtext">${esc(r.text)}</div><div class="time">${timeAgo(r.created_at)}</div></div>`).join('');
}

// ---- media gate: image/video upload unlocks after 10 messages sent -------- //
const MEDIA_MIN = 10;
let sentCount = 0, mediaUnlocked = false;
function applyMediaLock() {   // silently hide upload controls until unlocked (no warning)
  $('#uploadBtn').hidden = !mediaUnlocked;   // image-in-post
  $('#attachBtn').hidden = !mediaUnlocked;   // chat media
}
function bumpSent() {         // count a sent post/reply/DM; reveal media at the threshold
  sentCount += 1;
  if (!mediaUnlocked && sentCount >= MEDIA_MIN) { mediaUnlocked = true; applyMediaLock(); }
}

// ---- private messages ----------------------------------------------------- //
let myUserId = null;
let currentChatUser = null;      // { userId, nickname }

async function openConversations() {
  backTo = 'feed';
  showView('conversations');
  await loadConversations();
}

async function loadConversations() {
  const list = await api('/conversations');
  $('#convEmpty').hidden = list.length > 0;
  $('#convList').innerHTML = list.map((c) => `
    <div class="conv" data-uid="${c.userId}" data-nick="${esc(c.nickname)}">
      <div class="conv-avatar">${esc((c.nickname || '?')[0])}</div>
      <div class="conv-body">
        <div class="conv-top"><span class="conv-name">${esc(c.nickname)}</span><span class="conv-time">${timeAgo(c.lastAt)}</span></div>
        <div class="conv-last ${c.unread ? 'unread' : ''}">${c.lastMine ? 'You: ' : ''}${esc(c.lastText)}</div>
      </div>
      ${c.unread ? '<span class="conv-dot"></span>' : ''}
    </div>`).join('');
}

async function openChat(userId, nickname, from) {
  currentChatUser = { userId, nickname, blocked: false };
  backTo = (from === 'conversations' || from === 'nearby') ? from : 'feed';
  $('#chatHead').textContent = nickname;
  $('#chatInput').placeholder = 'Reply to ' + nickname + '…';
  $('#chatThread').innerHTML = '';
  $('#chatMenu').hidden = true;
  showView('chat');
  await loadThread();
  refreshUnread();
  setTimeout(() => $('#chatInput').focus(), 50);
}

function bubbleHtml(m, blocked) {
  let inner = '';
  if (m.media) {
    if (m.mediaType === 'video') {
      inner += `<video controls playsinline preload="metadata" data-media="${esc(m.media)}"></video>`;
    } else if (blocked) {
      inner += `<span class="img-blocked">📷 Image hidden — tap the camera icon to allow images</span>`;
    } else {
      inner += `<img data-media="${esc(m.media)}" alt="photo">`;
    }
  }
  if (m.text) inner += esc(m.text);
  return `<div class="bubble ${m.mine ? 'me' : 'them'}">${inner}<div class="bubble-time">${timeAgo(m.created_at)}</div></div>`;
}
function hydrateChatMedia(box) {
  box.querySelectorAll('[data-media]').forEach(async (el) => {
    const p = el.getAttribute('data-media'); el.removeAttribute('data-media');
    try { el.src = await imageBlobUrl(p); } catch (e) { /* ignore */ }
  });
}

async function loadThread() {
  if (!currentChatUser) return;
  const t = await api('/messages/' + encodeURIComponent(currentChatUser.userId));
  currentChatUser.blocked = !!t.blocked;
  $('#chatHead').textContent = t.partner.nickname;
  $('#chatInput').placeholder = 'Reply to ' + t.partner.nickname + '…';
  $('#blockAct').textContent = t.blocked ? 'Unblock' : 'Block';
  updateCameraIcon();
  const imgOff = imgBlocked(currentChatUser.userId);
  const box = $('#chatThread');
  const lastMine = [...t.messages].reverse().find((m) => m.mine);
  const readRow = (lastMine && lastMine.read) ? '<div class="bubble-read">Read</div>' : '';
  const banner = t.blocked ? '<div class="empty">You blocked this user. Unblock from the ⋮ menu to message again.</div>' : '';
  box.innerHTML = (t.messages.map((m) => bubbleHtml(m, imgOff)).join('') + readRow) || '<div class="empty">Say hi 👋</div>';
  box.insertAdjacentHTML('afterbegin', banner);
  hydrateChatMedia(box);
  box.scrollTop = box.scrollHeight;
  window.scrollTo(0, document.body.scrollHeight);
}

// ---- people nearby -------------------------------------------------------- //
async function openNearby() {
  backTo = 'conversations';
  showView('nearby');
  $('#nearbyList').innerHTML = ''; $('#nearbyEmpty').hidden = true;
  $('#nearbyNote').textContent = 'Getting your location…';
  const geo = await getGeo();
  if (!geo) { $('#nearbyNote').textContent = 'Location unavailable — enable location (needs HTTPS) to find people nearby.'; return; }
  try { await api('/location', { method: 'POST', body: JSON.stringify(geo) }); } catch (e) { /* ignore */ }
  const list = await api('/nearby?lat=' + geo.lat + '&lng=' + geo.lng);
  $('#nearbyNote').textContent = list.length ? `${list.length} nearby` : '';
  $('#nearbyEmpty').hidden = list.length > 0;
  $('#nearbyList').innerHTML = list.map((u) => `
    <div class="conv" data-uid="${u.userId}" data-nick="${esc(u.nickname)}">
      <div class="conv-avatar">${esc((u.nickname || '?')[0])}</div>
      <div class="conv-body">
        <div class="conv-name">${esc(u.nickname)}</div>
        <div class="km">${u.distKm < 1 ? 'very close' : u.distKm + ' km away'}</div>
      </div>
    </div>`).join('');
}

async function refreshUnread() {
  try {
    const { count } = await api('/unread');
    for (const id of ['#inboxBadge', '#navInboxBadge']) {
      const b = $(id); if (!b) continue;
      if (count > 0) { b.hidden = false; b.textContent = count > 99 ? '99+' : count; }
      else b.hidden = true;
    }
  } catch (e) { /* ignore */ }
}

// ---- chat rooms ----------------------------------------------------------- //
let currentRoom = null;   // { id, name }

async function openRooms() {
  backTo = 'feed';
  showView('rooms');
  $('#newRoomName').value = '';
  await loadRooms();
}
async function loadRooms() {
  const rooms = await api('/rooms');
  $('#roomsList').innerHTML = rooms.map((r) => `
    <div class="conv" data-room="${r.id}" data-name="${esc(r.name)}" data-nsfw="${r.nsfw ? 1 : 0}">
      <div class="room-icon ${r.nsfw ? 'nsfw' : ''}"${r.cover ? ` data-img="${esc(r.cover)}"` : ''}>${r.cover ? '' : esc((r.name || '?')[0])}</div>
      <div class="conv-body">
        <div class="conv-name">${esc(r.name)}${r.nsfw ? '<span class="nsfw-tag">18+</span>' : ''}</div>
        <div class="room-sub">${r.members} member${r.members === 1 ? '' : 's'} · ${r.posts} post${r.posts === 1 ? '' : 's'}</div>
      </div>
    </div>`).join('');
  hydrateImages($('#roomsList'));
}

const roomCoverBg = (name) => meshBg('room-' + name);   // stable gradient cover per room
async function openRoom(id, name, nsfw) {
  if (nsfw && !sessionStorage.getItem('nsfw_ok_' + id)) {
    if (!confirm('“' + name + '” may contain adult (18+) content. Enter only if you’re comfortable with that.')) return;
    sessionStorage.setItem('nsfw_ok_' + id, '1');
  }
  currentRoom = { id, name };
  backTo = 'rooms';
  showView('room');
  await loadRoom();
}
async function loadRoom() {
  if (!currentRoom) return;
  const r = await api('/rooms/' + encodeURIComponent(currentRoom.id));
  currentRoom.name = r.room.name;
  $('#roomHead').textContent = r.room.name + (r.room.nsfw ? '  ·  18+' : '');
  $('#roomCover').style.cssText = roomCoverBg(r.room.name);   // gradient placeholder
  if (r.room.cover) {
    imageBlobUrl(r.room.cover).then((url) => { $('#roomCover').style.cssText = `background-image:url('${url}')`; }).catch(() => {});
  }
  $('#changeCoverBtn').hidden = !r.room.isMine || !mediaUnlocked;   // creator only, and media unlocked
  $('#roomDesc').textContent = r.room.description || 'A place to post and connect.';
  $('#roomMembers').textContent = `👥 ${r.room.members} member${r.room.members === 1 ? '' : 's'}`;
  $('#roomEmpty').hidden = r.posts.length > 0;
  $('#roomFeed').innerHTML = r.posts.map(cardHtml).join('');
  hydrateImages($('#roomFeed'));
}

// ---- compose -------------------------------------------------------------- //
let selectedBg = 'grad:0';
function buildBgPicker() {
  const picker = $('#bgPicker');
  picker.innerHTML = GRADIENTS.map((g, i) =>
    `<div class="bg-swatch ${i === 0 ? 'sel' : ''}" data-bg="grad:${i}" style="background-image:${g}"></div>`).join('');
  picker.querySelectorAll('.bg-swatch').forEach((el) => el.addEventListener('click', () => selectBg(el.dataset.bg, el)));
}
function selectBg(bg, el) {
  selectedBg = bg;
  $('#composeStage').style.cssText = bgStyle(bg);
  if (bg && bg.startsWith('img:')) {
    imageBlobUrl(bg.slice(4)).then((url) => { $('#composeStage').style.backgroundImage = `url('${url}')`; }).catch(() => {});
  }
  document.querySelectorAll('.bg-swatch').forEach((s) => s.classList.remove('sel'));
  if (el) el.classList.add('sel');
}
let composeRoomId = null;
function openCompose(roomId) {
  composeRoomId = roomId || null;
  $('#composeText').value = '';
  $('#composeTags').value = '';
  $('.compose-title').textContent = composeRoomId ? 'Post to ' + (currentRoom ? currentRoom.name : 'room') : 'New Post';
  selectBg('grad:0', document.querySelector('.bg-swatch'));
  $('#composeView').hidden = false;
  setTimeout(() => $('#composeText').focus(), 50);
}
function closeCompose() { $('#composeView').hidden = true; }

// ---- events --------------------------------------------------------------- //
document.addEventListener('click', async (e) => {
  const heart = e.target.closest('[data-heart]');
  if (heart) {
    e.stopPropagation();
    try {
      const r = await api('/whispers/' + heart.dataset.heart + '/heart', { method: 'POST' });
      heart.classList.toggle('on', r.hearted);
      heart.innerHTML = `${HEART}<span>${r.hearts}</span>`;
    } catch (err) { /* ignore */ }
    return;
  }
  const roomEl = e.target.closest('.conv[data-room]');
  if (roomEl) { openRoom(roomEl.dataset.room, roomEl.dataset.name, roomEl.dataset.nsfw === '1'); return; }
  const conv = e.target.closest('.conv[data-uid]');
  if (conv) { openChat(conv.dataset.uid, conv.dataset.nick, conv.closest('#nearbyList') ? 'nearby' : 'conversations'); return; }
  const card = e.target.closest('.card[data-id]');
  if (card) openDetail(card.dataset.id, card.closest('#roomFeed') ? 'room' : 'feed');
});

// post detail actions: Like · Reply · Chat
$('#paLike').addEventListener('click', async () => {
  if (!currentDetail) return;
  try {
    const r = await api('/whispers/' + currentDetail.id + '/heart', { method: 'POST' });
    currentDetail.hearted = r.hearted; currentDetail.hearts = r.hearts;
    $('#paLike').classList.toggle('on', r.hearted);
    $('#paLikeN').textContent = r.hearts;
  } catch (e) { /* ignore */ }
});
$('#paReply').addEventListener('click', () => { $('#replyInput').focus(); $('#replyInput').scrollIntoView({ block: 'center' }); });
$('#paChat').addEventListener('click', () => { if (currentDetail && currentDetail.user_id) openChat(currentDetail.user_id, currentDetail.nickname, 'feed'); });
$('#paDelete').addEventListener('click', async () => {
  if (!currentDetail || !confirm('Delete this post? This can’t be undone.')) return;
  try {
    await api('/whispers/' + currentDetail.id + '/delete', { method: 'POST' });
    showView(backTo || 'feed');
    if (backTo === 'me') loadMe(); else if (backTo === 'room' && currentRoom) loadRoom(); else loadFeed();
  } catch (err) { alert('Could not delete: ' + err.message); }
});

// inbox + rooms + nearby + back
$('#inboxBtn').addEventListener('click', openConversations);
$('#roomsBtn').addEventListener('click', openRooms);
$('#nearbyBtn').addEventListener('click', openNearby);

// create a room
$('#createRoomBtn').addEventListener('click', async () => {
  const name = $('#newRoomName').value.trim();
  if (name.length < 2) { $('#newRoomName').focus(); return; }
  try {
    const r = await api('/rooms', { method: 'POST', body: JSON.stringify({ name }) });
    $('#newRoomName').value = '';
    await loadRooms();
    openRoom(r.id, name, false);
  } catch (err) { alert(err.message); }
});

// post into the current room
$('#roomPostBtn').addEventListener('click', () => { if (currentRoom) openCompose(currentRoom.id); });

// change the room's cover image (creator only)
$('#changeCoverBtn').addEventListener('click', () => $('#coverFile').click());
$('#coverFile').addEventListener('change', async (e) => {
  const file = e.target.files[0]; e.target.value = '';
  if (!file || !currentRoom) return;
  const btn = $('#changeCoverBtn'); const label = btn.textContent; btn.textContent = 'Uploading…'; btn.disabled = true;
  try {
    const url = await uploadFile(file);
    await api('/rooms/' + currentRoom.id + '/cover', { method: 'POST', body: JSON.stringify({ cover: url }) });
    await loadRoom();
  } catch (err) { alert('Could not set cover: ' + err.message); }
  finally { btn.textContent = label; btn.disabled = false; }
});
$('#chatForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const input = $('#chatInput');
  const text = input.value.trim();
  if (!text || !currentChatUser) return;
  input.value = '';
  try {
    await api('/messages', { method: 'POST', body: JSON.stringify({ to: currentChatUser.userId, text }) });
    bumpSent();
    await loadThread();
  } catch (err) { alert('Could not send: ' + err.message); input.value = text; }
});

// chat: media attach (image or video ≤ 5s)
$('#attachBtn').addEventListener('click', () => $('#chatFile').click());
function videoDuration(file) {
  return new Promise((resolve) => {
    const v = document.createElement('video'); v.preload = 'metadata';
    v.onloadedmetadata = () => { const d = v.duration; URL.revokeObjectURL(v.src); resolve(d); };
    v.onerror = () => resolve(Infinity);
    v.src = URL.createObjectURL(file);
  });
}
$('#chatFile').addEventListener('change', async (e) => {
  const file = e.target.files[0]; e.target.value = '';
  if (!file || !currentChatUser) return;
  const isVideo = file.type.startsWith('video/');
  if (isVideo) {
    const dur = await videoDuration(file);
    if (dur > 10.5) { alert('Video must be 10 seconds or less.'); return; }
  }
  const btn = $('#attachBtn'); btn.textContent = '…'; btn.disabled = true;
  try {
    const url = await uploadFile(file);
    await api('/messages', { method: 'POST', body: JSON.stringify({ to: currentChatUser.userId, media: url, mediaType: isVideo ? 'video' : 'image' }) });
    await loadThread();
  } catch (err) { alert('Could not send: ' + err.message); }
  finally { btn.textContent = '＋'; btn.disabled = false; }
});

// chat: camera icon toggles whether images are received in this chat.
// A diagonal slash on the icon = images OFF (incoming photos are hidden).
function imgBlocked(uid) { return !!localStorage.getItem('imgblock_' + uid); }
function updateCameraIcon() {
  $('#cameraBtn').classList.toggle('blocked', !!(currentChatUser && imgBlocked(currentChatUser.userId)));
}
$('#cameraBtn').addEventListener('click', async () => {
  if (!currentChatUser) return;
  const key = 'imgblock_' + currentChatUser.userId;
  if (localStorage.getItem(key)) localStorage.removeItem(key); else localStorage.setItem(key, '1');
  updateCameraIcon();
  await loadThread();
});

// tap a received/sent photo to view it full-screen
$('#chatThread').addEventListener('click', (e) => {
  const img = e.target.closest('.bubble img');
  if (img && img.src) { $('#lightboxImg').src = img.src; $('#lightbox').hidden = false; }
});
$('#lightbox').addEventListener('click', () => { $('#lightbox').hidden = true; $('#lightboxImg').src = ''; });

// chat: ⋮ menu (block / report / delete)
$('#chatMenuBtn').addEventListener('click', (e) => { e.stopPropagation(); $('#chatMenu').hidden = !$('#chatMenu').hidden; });
document.addEventListener('click', (e) => { if (!e.target.closest('#chatMenu,#chatMenuBtn')) $('#chatMenu').hidden = true; });
$('#chatMenu').addEventListener('click', async (e) => {
  const btn = e.target.closest('button[data-act]'); if (!btn || !currentChatUser) return;
  const act = btn.dataset.act; $('#chatMenu').hidden = true;
  const u = currentChatUser.userId;
  try {
    if (act === 'block') {
      const path = currentChatUser.blocked ? '/unblock' : '/block';
      await api(path, { method: 'POST', body: JSON.stringify({ user: u }) });
      await loadThread();
    } else if (act === 'report') {
      const reason = prompt('Report this user — what’s wrong? (optional)') ?? '';
      await api('/report', { method: 'POST', body: JSON.stringify({ user: u, reason }) });
      alert('Reported. Thanks — we’ve received your report.');
    } else if (act === 'delete') {
      if (!confirm('Delete this chat? It disappears for you (the other person still has it).')) return;
      await api('/chat/' + encodeURIComponent(u) + '/delete', { method: 'POST' });
      openConversations();
    }
  } catch (err) { alert('Action failed: ' + err.message); }
});

// bottom nav
document.querySelectorAll('.nav-btn[data-nav]').forEach((b) => b.addEventListener('click', () => {
  const nav = b.dataset.nav;
  if (nav === 'compose') { openCompose(); return; }
  if (nav === 'conversations') { openConversations(); return; }   // Messages
  showView(nav);
  if (nav === 'feed') loadFeed();
  else if (nav === 'search') loadSearch();
  else if (nav === 'activity') loadActivity();
  else if (nav === 'me') loadMe();
}));

// the top-left back arrow uses the same history path as the phone's Back button
$('#backBtn').addEventListener('click', () => { history.back(); });

document.querySelectorAll('.ftab').forEach((t) => t.addEventListener('click', () => {
  document.querySelectorAll('.ftab').forEach((x) => x.classList.remove('is-active'));
  t.classList.add('is-active');
  currentTab = t.dataset.tab;
  loadFeed();
}));

// tag chip selection
$('#tagBar').addEventListener('click', async (e) => {
  const chip = e.target.closest('.tag-chip');
  if (!chip) return;
  currentTag = chip.dataset.tag;
  document.querySelectorAll('.tag-chip').forEach((c) => c.classList.toggle('sel', c === chip));
  renderFeedList(await api('/whispers?tag=' + encodeURIComponent(currentTag)));
});

$('#searchInput').addEventListener('input', (e) => renderSearch(e.target.value));

// compose actions
$('#composeCancel').addEventListener('click', closeCompose);
$('#shufflePhoto').addEventListener('click', () => selectBg('photo:w' + Math.floor(Math.random() * 100000), null));
$('#uploadBtn').addEventListener('click', () => $('#fileInput').click());
$('#fileInput').addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const btn = $('#uploadBtn');
  const label = btn.textContent;
  btn.textContent = 'Uploading…'; btn.disabled = true;
  try {
    const url = await uploadFile(file);
    selectBg('img:' + url, null);
  } catch (err) { alert('Upload failed: ' + err.message); }
  finally { btn.textContent = label; btn.disabled = false; e.target.value = ''; }
});

$('#postBtn').addEventListener('click', async () => {
  const text = $('#composeText').value.trim();
  if (!text) { $('#composeText').focus(); return; }
  $('#postBtn').disabled = true;
  try {
    const geo = await getGeo();                       // best-effort location
    const tags = [...new Set($('#composeTags').value.split(/[\s,#]+/)
      .map((t) => t.toLowerCase().replace(/[^a-z0-9_]/g, '')).filter(Boolean))].slice(0, 10);
    const body = { text, bg: selectedBg, tags, ...(geo || {}) };
    if (composeRoomId) body.room_id = composeRoomId;
    await api('/whispers', { method: 'POST', body: JSON.stringify(body) });
    bumpSent();
    closeCompose();
    if (composeRoomId) {                       // posted into a room -> back to that room
      showView('room');
      await loadRoom();
    } else {
      currentTab = 'latest';
      document.querySelectorAll('.ftab').forEach((x) => x.classList.toggle('is-active', x.dataset.tab === 'latest'));
      showView('feed');
      await loadFeed();
    }
  } catch (err) {
    if (err.status === 429 && err.data && err.data.retryMs) {
      const mins = Math.ceil(err.data.retryMs / 60000);
      alert(`You can post again in about ${mins} minute${mins > 1 ? 's' : ''}. (One post every 10 minutes.)`);
    } else { alert('Could not post: ' + err.message); }
  }
  finally { $('#postBtn').disabled = false; }
});

$('#replyForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const input = $('#replyInput');
  const text = input.value.trim();
  if (!text || !currentWhisperId) return;
  input.value = '';
  try {
    await api('/whispers/' + currentWhisperId + '/replies', { method: 'POST', body: JSON.stringify({ text }) });
    bumpSent();
    const w = await api('/whispers/' + currentWhisperId);
    renderReplies(w.replyList);
  } catch (err) { alert('Could not reply: ' + err.message); }
});

// username (app-chosen by default; user can change it)
$('#saveUsernameBtn').addEventListener('click', async () => {
  const name = $('#usernameInput').value.trim();
  try {
    const r = await api('/username', { method: 'POST', body: JSON.stringify({ username: name }) });
    $('#meName').textContent = r.nickname;
    $('#meTag').textContent = r.nickname;
    $('#meAvatar').textContent = (r.nickname || '?')[0];
    alert('Username updated to ' + r.nickname);
  } catch (err) { alert(err.message); }
});

// server address setting (lets the user repoint the app without rebuilding)
$('#serverUrl').value = API_BASE;
$('#saveServer').addEventListener('click', () => {
  const v = $('#serverUrl').value.trim().replace(/\/$/, '');
  if (v) localStorage.setItem('whisper_api', v);
  else localStorage.removeItem('whisper_api');
  location.reload();
});

// ---- optional app lock (PIN) ---------------------------------------------- //
// Device-local lock: a salted SHA-256 of the PIN is stored (never the PIN). It
// gates opening the app on this phone; it is NOT server auth or data encryption.
async function hashPin(pin, saltB64) {
  const salt = saltB64 ? b64d(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const data = new Uint8Array([...salt, ...new TextEncoder().encode(pin)]);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
  return { salt: b64e(salt), hash: b64e(digest) };
}
function storedPin() { try { return JSON.parse(localStorage.getItem('whisper_pin') || 'null'); } catch (e) { return null; } }
function lockNow() {
  if (!storedPin()) return;
  $('#lockInput').value = ''; $('#lockError').hidden = true; $('#lockView').hidden = false;
  setTimeout(() => $('#lockInput').focus(), 60);
}
async function tryUnlock() {
  const sp = storedPin(); if (!sp) { $('#lockView').hidden = true; return; }
  const { hash } = await hashPin($('#lockInput').value, sp.salt);
  if (hash === sp.hash) { $('#lockView').hidden = true; $('#lockInput').value = ''; }
  else { $('#lockError').hidden = false; $('#lockInput').value = ''; $('#lockInput').focus(); }
}
function updatePinStatus() {
  const on = !!storedPin();
  $('#pinStatus').textContent = on ? 'On — the app asks for your PIN to open.' : 'Off — the app opens without a PIN.';
  $('#removePinBtn').hidden = !on;
  $('#setPinBtn').textContent = on ? 'Change' : 'Set';
}
$('#unlockBtn').addEventListener('click', tryUnlock);
$('#lockInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') tryUnlock(); });
$('#setPinBtn').addEventListener('click', async () => {
  const pin = $('#pinInput').value.trim();
  if (!/^\d{4,12}$/.test(pin)) { alert('PIN must be 4–12 digits.'); return; }
  localStorage.setItem('whisper_pin', JSON.stringify(await hashPin(pin)));
  $('#pinInput').value = '';
  updatePinStatus();
  alert('PIN set. TalkTime will ask for it when it opens or returns from the background.');
});
$('#removePinBtn').addEventListener('click', () => { localStorage.removeItem('whisper_pin'); updatePinStatus(); });
// re-lock whenever the app is backgrounded
document.addEventListener('visibilitychange', () => { if (document.hidden) lockNow(); });

// ---- legal disclaimer (shown once, on first use) -------------------------- //
function showDisclaimer() { if (!localStorage.getItem('tt_agreed')) $('#disclaimerView').hidden = false; }
$('#agreeBtn').addEventListener('click', () => {
  localStorage.setItem('tt_agreed', '1');
  $('#disclaimerView').hidden = true;
});

// ---- boot ----------------------------------------------------------------- //
(async function init() {
  showDisclaimer();                // legal disclaimer sits above everything else
  updatePinStatus();
  lockNow();                       // show the lock immediately if a PIN is set
  buildBgPicker();
  try {
    const me = await api('/me');
    myUserId = me.userId;
    sentCount = me.sent || 0;
    mediaUnlocked = !!me.mediaUnlocked;
    $('#meTag').textContent = me.nickname;
    $('#meName').textContent = me.nickname;
    $('#meAvatar').textContent = (me.nickname || '?')[0];
    $('#usernameInput').value = me.nickname;
  } catch (err) { $('#meTag').textContent = ''; }
  applyMediaLock();   // hide upload controls until the 10-message threshold
  await loadFeed();
  refreshUnread();
  startSync();
})();

// ---- live sync / auto-reconnect ------------------------------------------- //
// Keeps the current view + unread badge fresh. If the server goes away (restart,
// tunnel blip) requests throw; we flag "reconnecting" and keep trying. The moment
// it answers again, api() re-does the ECDH handshake automatically and we pull a
// FULL refresh of whatever is on screen so every post/message catches up.
let online = true;
let syncing = false;

function refreshCurrentView(full) {
  if (!views.feed.hidden) return full ? loadFeed() : refreshFeedTop();
  if (!views.chat.hidden) return loadThread();
  if (!views.room.hidden) return loadRoom();
  if (!views.rooms.hidden) return loadRooms();
  if (!views.conversations.hidden) return loadConversations();
  if (!views.activity.hidden) return loadActivity();
  return Promise.resolve();
}

async function syncTick() {
  if (syncing) return;
  syncing = true;
  const wasOffline = !online;
  try {
    await refreshCurrentView(wasOffline);   // full reload right after a reconnect
    await refreshUnread();
    if (wasOffline) { online = true; $('#reconnecting').hidden = true; }
  } catch (e) {
    if (online) { online = false; $('#reconnecting').hidden = false; }
  } finally { syncing = false; }
}

function startSync() {
  setInterval(syncTick, 20000);   // 20s poll — light on the tunnel's data budget
  // reconnect/refresh the instant the app regains focus or the network returns
  document.addEventListener('visibilitychange', () => { if (!document.hidden) syncTick(); });
  window.addEventListener('online', syncTick);
  window.addEventListener('focus', syncTick);
}
