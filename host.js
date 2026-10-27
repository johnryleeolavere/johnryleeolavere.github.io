'use strict';
const http = require('http'), crypto = require('crypto'), fs = require('fs'), path = require('path');
const E = process.env;
const PORT = +E.PORT || 3000, ADMIN = E.ADMIN_TOKEN, DB_FILE = path.resolve(__dirname, E.DB_FILE || 'scripts.json');
const DATABASE_URL = E.DATABASE_URL;
const TAMPER_CHECK = E.TAMPER_CHECK !== '0', UA_CHECK = E.UA_CHECK !== '0';
const LOADER_UA = new RegExp(E.LOADER_UA || '^Roblox/', 'i');
const GAMESENSE_UA = /^Valve\/Steam HTTP Client 1\.0 \(730\)$/i;
const KEY_HOURS = +E.KEY_HOURS || 24;
const KEY_WAIT = +E.KEY_WAIT || 15;
const WK = E.WORKINK_BASE || 'https://work.ink';
const wkLink = v => { v = String(v || '').trim(); return /^https:\/\/work\.ink\/[\w\-\/]+$/i.test(v) ? v : ''; };
const TRUST_PROXY = E.TRUST_PROXY === '1';

if (!ADMIN || ADMIN.length < 16 || new Set(ADMIN).size < 6) {
  console.error('Set ADMIN_TOKEN: 16+ characters, not repetitive.');
  process.exit(1);
}

const SECRET = (() => {
  if (E.SESSION_SECRET) {
    if (!/^[a-f0-9]{64}$/i.test(E.SESSION_SECRET)) {
      throw new Error('SESSION_SECRET must be exactly 64 hexadecimal characters (32 random bytes).');
    }
    return Buffer.from(E.SESSION_SECRET, 'hex');
  }
  const secretFile = path.join(__dirname, '.session_secret');
  try {
    if (fs.existsSync(secretFile)) {
      const secret = fs.readFileSync(secretFile);
      if (secret.length !== 32) throw new Error('Existing secret file must contain exactly 32 bytes.');
      return secret;
    }
    const s = crypto.randomBytes(32);
    fs.writeFileSync(secretFile, s, { mode: 0o600 });
    return s;
  } catch (err) {
    throw new Error(`Could not read or create ${secretFile}: ${err.message} Configure a stable SESSION_SECRET instead.`);
  }
})();

let db = { scripts: {}, keys: {}, logs: [], users: {} };
let pool = null, dirty = false, revision = 0, flushing = null;

function parseDatabase(raw, label) {
  const d = JSON.parse(raw);
  if (!d || typeof d !== 'object' || Array.isArray(d) ||
      (d.scripts !== undefined && (!d.scripts || typeof d.scripts !== 'object' || Array.isArray(d.scripts))) ||
      (d.keys !== undefined && (!d.keys || typeof d.keys !== 'object' || Array.isArray(d.keys))) ||
      (d.logs !== undefined && !Array.isArray(d.logs))) {
    throw new Error(`Database at ${label} must contain scripts and keys objects and a logs array.`);
  }
  if (d.users !== undefined && (!d.users || typeof d.users !== 'object' || Array.isArray(d.users))) {
    throw new Error(`Database at ${label} must contain a users object.`);
  }
  return { scripts: d.scripts || {}, keys: d.keys || {}, logs: d.logs || [], users: d.users || {} };
}

function readLocalDatabase({ allowEmpty = false } = {}) {
  let raw;
  try {
    raw = fs.readFileSync(DB_FILE, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw new Error(`Could not read script database at ${DB_FILE}: ${err.message}`);
  }
  if (!raw.trim()) {
    if (allowEmpty) return null;
    throw new Error(`Script database at ${DB_FILE} is empty. Restore a backup or initialize it with valid JSON before restarting.`);
  }
  try {
    return parseDatabase(raw, DB_FILE);
  } catch (err) {
    throw new Error(`Could not parse script database at ${DB_FILE}: ${err.message}`);
  }
}

async function initializeDatabase() {
  if (!DATABASE_URL) {
    db = readLocalDatabase() || db;
    return;
  }

  const { Pool } = require('pg');
  pool = new Pool({ connectionString: DATABASE_URL, max: 3, idleTimeoutMillis: 30000, connectionTimeoutMillis: 10000 });
  await pool.query(`
    CREATE TABLE IF NOT EXISTS scripthost_state (
      id SMALLINT PRIMARY KEY CHECK (id = 1),
      payload JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  const result = await pool.query('SELECT payload FROM scripthost_state WHERE id = 1');
  if (result.rowCount) {
    db = parseDatabase(JSON.stringify(result.rows[0].payload), 'Neon Postgres');
    return;
  }

  db = readLocalDatabase({ allowEmpty: true }) || db;
  await pool.query(
    'INSERT INTO scripthost_state (id, payload) VALUES (1, $1::jsonb) ON CONFLICT (id) DO NOTHING',
    [JSON.stringify(db)]
  );
}

const save = () => { dirty = true; revision++; };
const flush = () => {
  if (!dirty || !db || !db.scripts) return Promise.resolve();
  if (flushing) return flushing;
  const savedRevision = revision, snapshot = JSON.stringify(db);
  flushing = (async () => {
    try {
      if (pool) {
        await pool.query(
          `INSERT INTO scripthost_state (id, payload, updated_at) VALUES (1, $1::jsonb, NOW())
           ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload, updated_at = NOW()`,
          [snapshot]
        );
      } else {
        fs.writeFileSync(DB_FILE + '.tmp', snapshot);
        fs.renameSync(DB_FILE + '.tmp', DB_FILE);
      }
      if (revision === savedRevision) dirty = false;
    } catch (err) {
      console.error(`Could not save script database at ${pool ? 'Neon Postgres' : DB_FILE}:`, err);
    } finally {
      flushing = null;
    }
  })();
  return flushing;
};
setInterval(flush, 2000).unref();

const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const scriptPlatform = s => s.platform == null || s.platform === 'roblox' ? 'roblox' : s.platform === 'gamesense' ? 'gamesense' : 'unsupported';
const getScript = id => has(db.scripts, id) ? db.scripts[id] : null;
const getUser = id => has(db.users, id) ? db.users[id] : null;
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const validUsername = value => typeof value === 'string' && /^[A-Za-z0-9_.-]{3,32}$/.test(value);
const validPassword = value => typeof value === 'string' && value.length >= 12 && value.length <= 1024;
const same = (a, b) => {
  if (!a || !b) return false;
  const ba = Buffer.from(sha(String(a))), bb = Buffer.from(sha(String(b)));
  return crypto.timingSafeEqual(ba, bb);
};
const log = (ip, event, id, ua) => {
  db.logs.push({ t: Date.now(), ip, event, id: id || null, ua: String(ua || '').slice(0, 60) });
  if (db.logs.length > 500) db.logs.shift();
  save();
};

const clientIp = req => {
  if (TRUST_PROXY) {
    const cf = req.headers['cf-connecting-ip'];
    if (cf) return String(cf).trim();
    const xff = req.headers['x-forwarded-for'];
    if (xff) return String(xff).split(',')[0].trim();
  }
  return String(req.socket.remoteAddress || '').replace(/^::ffff:/, '');
};

const hits = new Map();
const limited = (ip, max) => {
  const n = Date.now(), a = (hits.get(ip) || []).filter(t => n - t < 60000);
  a.push(n);
  hits.set(ip, a);
  return a.length > max;
};

const usedTickets = new Set();
const sessions = new Map();
const accountSessions = new Map();
const mac = s => crypto.createHmac('sha256', SECRET).update(s).digest('hex');
const accountSessionMs = 12 * 60 * 60 * 1000;
const apiKeyEncryptionKey = crypto.createHash('sha256').update(SECRET).digest();

function hashPassword(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, key) => err ? reject(err) : resolve(key.toString('hex')));
  });
}

function encryptSecret(value) {
  const iv = crypto.randomBytes(12), cipher = crypto.createCipheriv('aes-256-gcm', apiKeyEncryptionKey, iv);
  const data = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return [iv.toString('hex'), cipher.getAuthTag().toString('hex'), data.toString('hex')].join('.');
}

function decryptSecret(value) {
  const [iv, tag, data] = String(value || '').split('.');
  if (!/^[a-f0-9]{24}$/i.test(iv || '') || !/^[a-f0-9]{32}$/i.test(tag || '') || !/^(?:[a-f0-9]{2})+$/i.test(data || '')) {
    throw new Error('Stored Work.ink API key has an invalid encrypted format.');
  }
  const decipher = crypto.createDecipheriv('aes-256-gcm', apiKeyEncryptionKey, Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(tag, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(data, 'hex')), decipher.final()]).toString('utf8');
}

function accountFromRequest(req) {
  const cookie = String(req.headers.cookie || '').split(';').map(v => v.trim()).find(v => v.startsWith('scripthost_session='));
  if (!cookie) return null;
  const token = cookie.slice('scripthost_session='.length);
  const key = sha(token), session = accountSessions.get(key);
  if (!session || session.expires <= Date.now()) {
    accountSessions.delete(key);
    return null;
  }
  const user = getUser(session.userId);
  if (!user) {
    accountSessions.delete(key);
    return null;
  }
  return { user, key };
}

function revokeAccountSessions(userId) {
  for (const [key, session] of accountSessions) if (session.userId === userId) accountSessions.delete(key);
}

function workinkApiKeyForScript(script) {
  if (!script.ownerId) return E.WORKINK_API_KEY || '';
  const user = getUser(script.ownerId);
  return user && user.workinkApiKey ? decryptSecret(user.workinkApiKey) : '';
}

setInterval(() => {
  const n = Date.now();
  for (const [k, v] of hits) if (!v.some(t => n - t < 60000)) hits.delete(k);
  for (const [h, k] of Object.entries(db.keys)) if (k.expires && k.expires < n - 2 * 864e5) delete db.keys[h];
  for (const [sid, sess] of sessions) if (sess.expires < n || (sess.consumed && sess.expires < n - 60000)) sessions.delete(sid);
  for (const [sid, sess] of accountSessions) if (sess.expires < n) accountSessions.delete(sid);
}, 60000).unref();

function derivePayloadKey(secretKey, sessionId, hwid) {
  return crypto.createHmac('sha256', Buffer.from(secretKey, 'utf8'))
    .update(sessionId + ':' + hwid)
    .digest();
}

function aes256gcmEncrypt(key, data) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let enc = cipher.update(Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8'));
  enc = Buffer.concat([enc, cipher.final()]);
  return {
    iv: iv.toString('hex'),
    tag: cipher.getAuthTag().toString('hex'),
    ct: enc.toString('hex')
  };
}

function mint(hours, note, ip, src, script) {
  const key = crypto.randomUUID(), h = sha(key);
  db.keys[h] = {
    id: h.slice(0, 8),
    created: Date.now(),
    expires: hours ? Date.now() + hours * 36e5 : null,
    hwid: null,
    lastReset: 0,
    revoked: false,
    uses: 0,
    note: note || '',
    src,
    script: script || null,
    ip: ip ? sha(ip) : null
  };
  save();
  return key;
}

const findKey = k => { const h = sha(k); return has(db.keys, h) ? db.keys[h] : null; };
const byId = id => Object.values(db.keys).find(k => k.id === id);
const activeFor = (ip, sid) => Object.values(db.keys).find(k => k.src === 'user' && k.script === sid && k.ip === sha(ip) && !k.revoked && k.expires > Date.now());

function checkKey(s, sid, k, hwid, origin, commit = true) {
  const link = origin + '/getkey/' + sid;
  if (s.keyHash && same(k, s.keyHash)) return null;
  const rec = findKey(k);
  if (!rec) return 'Invalid key. Get a key for this script at ' + link;
  if (rec.script ? rec.script !== sid : rec.src === 'user') return 'This key belongs to a different script. Get the right one at ' + link;
  if (rec.revoked) return 'This key was revoked.';
  if (rec.expires && rec.expires < Date.now()) return 'This key expired. Get a new one at ' + link;
  if (!hwid) return 'No device fingerprint received.';
  const hh = sha(hwid);
  if (rec.hwid && rec.hwid !== hh) return 'This key is locked to another device.';
  if (commit) {
    if (!rec.hwid) rec.hwid = hh;
    rec.uses++;
    save();
  }
  return null;
}

const isBrowser = h =>
  !!(h['sec-fetch-mode'] || h['sec-fetch-dest'] || h['sec-fetch-site'] || h['upgrade-insecure-requests']) ||
  (h.accept || '').includes('text/html') ||
  (UA_CHECK && /^Mozilla\/5\.0.*(Chrome|Safari|Firefox|Edg|OPR)/i.test(h['user-agent'] || ''));

const readText = (req, max) => new Promise((ok, no) => {
  let s = '';
  req.on('data', c => { s += c; if (s.length > max) { no(new Error('Payload too large')); req.destroy(); } });
  req.on('end', () => ok(s));
  req.on('error', no);
});
const readJson = async (req, max) => { const t = await readText(req, max); return t ? JSON.parse(t) : {}; };
const readRequestObject = async (req, max) => {
  const text = await readText(req, max);
  if (!text) return {};
  try {
    const value = JSON.parse(text);
    if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  } catch {}
  return Object.fromEntries(new URLSearchParams(text));
};

function obfuscateLua(code) {
  const sensitiveStrings = [
    'RbxAnalyticsService', 'GetClientId', 'Players', 'LocalPlayer', 'UserId',
    'identifyexecutor', 'getexecutorname', 'gethwid', 'DEV_FALLBACK'
  ];
  let out = code;
  for (const s of sensitiveStrings) {
    const bytes = Array.from(Buffer.from(s, 'utf8')).join(',');
    out = out.split('"' + s + '"').join('string.char(' + bytes + ')');
  }
  return out;
}

const gameSenseStub = (origin, id, sessionToken, requireKey) => `local http = require("gamesense/http")
local json = json
local url = "${origin}/gs/d/${id}"
local requiresKey = ${requireKey}
local keyLink = "${origin}/getkey/${id}"
local validateUrl = "${origin}/gs/validate/${id}"
local keyStore = "scripthost_key_${id}"
local installKey = "scripthost_install_${id}"
local fingerprint = database.read(installKey)
local errorLines = nil
local errorUntil = 0
local keyLabel = nil
local keyInput = nil
local importButton = nil
local validateButton = nil
local busy = false

print("This key system is provided by Scripthost")

local function reportError(message)
  local consoleMessage = "[Scripthost] " .. tostring(message)
  if client and type(client.color_log) == "function" then
    client.color_log(255, 80, 80, consoleMessage)
  else
    print(consoleMessage)
  end
  errorLines = {}
  local line = ""
  for word in ("[Scripthost] " .. tostring(message)):gmatch("%S+") do
    if #line > 0 and #line + #word + 1 > 58 then
      errorLines[#errorLines + 1] = line
      line = word
    else
      line = #line > 0 and (line .. " " .. word) or word
    end
    if #errorLines == 2 then
      line = line:sub(1, 55) .. "..."
      break
    end
  end
  if line ~= "" then errorLines[#errorLines + 1] = line end
  errorUntil = globals.realtime() + 6
end

local function setKeyControlsVisible(visible)
  for _, control in ipairs({ keyLabel, keyInput, importButton, validateButton }) do
    if control then ui.set_visible(control, visible) end
  end
end

client.set_event_callback("paint_ui", function()
  if not errorLines then return end
  if globals.realtime() >= errorUntil then errorLines = nil; return end

  local screenWidth, screenHeight = client.screen_size()
  local width = math.min(540, screenWidth - 32)
  local height = 58 + #errorLines * 18
  local x, y = (screenWidth - width) / 2, screenHeight * 0.42 - height / 2
  renderer.rectangle(x, y, width, height, 24, 27, 34, 235)
  renderer.rectangle(x, y, width, 3, 255, 76, 76, 255)
  renderer.text(screenWidth / 2, y + 13, 255, 105, 105, 255, "bc", width - 24, "Scripthost")
  for i, text in ipairs(errorLines) do
    renderer.text(screenWidth / 2, y + 34 + (i - 1) * 18, 245, 245, 245, 255, "c", width - 24, text)
  end
end)

if type(fingerprint) ~= "string" or fingerprint == "" then
  fingerprint = tostring({}) .. ":" .. tostring(math.random()) .. ":" .. tostring(math.random())
  database.write(installKey, fingerprint)
  database.flush()
end

local function deliver(key, sessionToken)
  local body = json.stringify({
    key = key,
    hwid = fingerprint,
    session = sessionToken
  })

  http.post(url, {
    body = body,
    headers = { ["Content-Type"] = "application/json" }
  }, function(success, response)
    if not success or not response then
      busy = false
      reportError("Could not reach the script server.")
      return
    end
    if response.status ~= 200 then
      busy = false
      local detail = type(response.body) == "string" and response.body or tostring(response.status)
      if response.status == 403 then
        if requiresKey then
          database.write(keyStore, "")
          database.flush()
          if keyInput then ui.set(keyInput, "") end
          setKeyControlsVisible(true)
        end
        local keyHint = requiresKey and not detail:find(keyLink, 1, true) and (" Get a key: " .. keyLink) or ""
        reportError("Key/access rejected: " .. detail .. keyHint)
      else
        if requiresKey then setKeyControlsVisible(true) end
        reportError("Delivery failed (" .. tostring(response.status) .. "): " .. detail)
      end
      return
    end

    local chunk, err = loadstring(response.body, "@Scripthost")
    if not chunk then
      busy = false
      if requiresKey then setKeyControlsVisible(true) end
      reportError("Could not compile script: " .. tostring(err))
      return
    end
    busy = false
    local ok, runErr = pcall(chunk)
    if not ok then reportError("Script error: " .. tostring(runErr)) end
  end)
end

local function validateAndLoad(candidate, wasSaved)
  if busy then return end
  local key = type(candidate) == "string" and candidate:match("^%s*(.-)%s*$") or ""
  if key == "" then
    reportError("Enter your key in the Scripthost key field. Get a key: " .. keyLink)
    return
  end

  busy = true
  http.post(validateUrl, {
    body = json.stringify({ key = key, hwid = fingerprint }),
    headers = { ["Content-Type"] = "application/json" }
  }, function(success, response)
    if not success or not response then
      busy = false
      reportError("Could not check your key. Try again.")
      return
    end
    if response.status ~= 200 then
      busy = false
      local detail = type(response.body) == "string" and response.body or tostring(response.status)
      if wasSaved then
        database.write(keyStore, "")
        database.flush()
        if keyInput then ui.set(keyInput, "") end
        detail = "Saved key is no longer valid. Enter a valid key. " .. detail
      end
      setKeyControlsVisible(true)
      local keyHint = not detail:find(keyLink, 1, true) and (" Get a key: " .. keyLink) or ""
      reportError("Key check failed: " .. detail .. keyHint)
      return
    end

    database.write(keyStore, key)
    database.flush()
    if keyInput then ui.set(keyInput, key) end
    setKeyControlsVisible(false)
    deliver(key, response.body)
  end)
end

if requiresKey then
  local savedKey = database.read(keyStore)
  if type(savedKey) ~= "string" then savedKey = "" end
  keyLabel = ui.new_label("LUA", "A", "Scripthost: enter a key below and validate it to load.")
  keyInput =   ui.new_textbox("LUA", "A", "Scripthost key " .. "${id}")
  ui.set(keyInput, savedKey)
  importButton = ui.new_button("LUA", "A", "Import key from clipboard " .. "${id}", function()
    local ok, imported = pcall(function() return require("gamesense/clipboard").get() end)
    if not ok or type(imported) ~= "string" or imported:match("^%s*$") then
      reportError("Could not read a key from the clipboard. Copy the key first, then try again.")
      return
    end
    imported = imported:match("^%s*(.-)%s*$")
    ui.set(keyInput, imported)
    validateAndLoad(imported, false)
  end)
  validateButton = ui.new_button("LUA", "A", "Validate & load " .. "${id}", function()
    validateAndLoad(ui.get(keyInput), false)
  end)
  if savedKey ~= "" then
    validateAndLoad(savedKey, true)
  else
    reportError("Enter your key in the Scripthost key field. Get a key: " .. keyLink)
  end
else
  deliver("", "${sessionToken}")
end
`;

const stub = (origin, id, sessionToken, requireKey) => `local _ID = "${id}"
local _S = "${sessionToken}"
local _U = "${origin}/d/${id}"
local _SESS_URL = "${origin}/session/${id}"
local _KEYLINK = "${origin}/getkey/${id}"
local _raw_load = loadstring

local function _get_fp()
  local parts = {}
  pcall(function() table.insert(parts, "C:"..tostring(game:GetService("RbxAnalyticsService"):GetClientId())) end)
  pcall(function()
    local lp = game:GetService("Players").LocalPlayer
    if lp and lp.UserId then table.insert(parts, "U:"..tostring(lp.UserId)) end
  end)
  pcall(function()
    local ex = (identifyexecutor and identifyexecutor()) or (getexecutorname and getexecutorname())
    if ex then table.insert(parts, "E:"..tostring(ex)) end
  end)
  pcall(function()
    if type(gethwid) == "function" then table.insert(parts, "H:"..tostring(gethwid())) end
  end)
  if #parts == 0 then table.insert(parts, "DEV_FALLBACK") end
  return table.concat(parts, "|")
end
local _fp = _get_fp()
local _r = (type(syn) == "table" and syn.request) or request or http_request

-- Pure Lua Bit operations
local _bxor, _band, _bor, _bshl, _bshr
if bit32 then
  _bxor, _band, _bor, _bshl, _bshr = bit32.bxor, bit32.band, bit32.bor, bit32.lshift, bit32.rshift
elseif bit then
  _bxor, _band, _bor, _bshl, _bshr = bit.bxor, bit.band, bit.bor, bit.lshift, bit.rshift
else
  local _M = 4294967296
  _bxor = function(a, b) a, b = a % _M, b % _M; local res, bv = 0, 1; for i = 1, 32 do local ra, rb = a % 2, b % 2; if ra ~= rb then res = res + bv end; a, b = math.floor(a / 2), math.floor(b / 2); bv = bv * 2 end return res end
  _band = function(a, b) a, b = a % _M, b % _M; local res, bv = 0, 1; for i = 1, 32 do local ra, rb = a % 2, b % 2; if ra == 1 and rb == 1 then res = res + bv end; a, b = math.floor(a / 2), math.floor(b / 2); bv = bv * 2 end return res end
  _bor  = function(a, b) return _bxor(a, _bxor(b, _band(a, b))) end
  _bshl = function(a, n) return (a * (2 ^ n)) % _M end
  _bshr = function(a, n) return math.floor((a % _M) / (2 ^ n)) end
end

-- Lightweight SHA-256 & HMAC for in-client key derivation
local _K = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
}

local function _rrot(x, n) return _bor(_bshr(x, n), _bshl(x, 32 - n)) end

local function _sha256(msg)
  local bytes = {string.byte(msg, 1, #msg)}
  local len = #bytes * 8
  table.insert(bytes, 0x80)
  while (#bytes % 64) ~= 56 do table.insert(bytes, 0) end
  for i = 7, 0, -1 do table.insert(bytes, _band(_bshr(len, i * 8), 0xff)) end

  local H = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}
  local W = {}
  for chunk = 0, (#bytes / 64) - 1 do
    for t = 0, 15 do
      local idx = chunk * 64 + t * 4 + 1
      W[t] = _bor(_bshl(bytes[idx], 24), _bor(_bshl(bytes[idx+1], 16), _bor(_bshl(bytes[idx+2], 8), bytes[idx+3])))
    end
    for t = 16, 63 do
      local s0 = _bxor(_rrot(W[t-15], 7), _bxor(_rrot(W[t-15], 18), _bshr(W[t-15], 3)))
      local s1 = _bxor(_rrot(W[t-2], 17), _bxor(_rrot(W[t-2], 19), _bshr(W[t-2], 10)))
      W[t] = (W[t-16] + s0 + W[t-7] + s1) % 4294967296
    end
    local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
    for t = 0, 63 do
      local S1 = _bxor(_rrot(e, 6), _bxor(_rrot(e, 11), _rrot(e, 25)))
      local ch = _bxor(_band(e, f), _band(_bxor(e, 0xffffffff), g))
      local t1 = (h + S1 + ch + _K[t+1] + W[t]) % 4294967296
      local S0 = _bxor(_rrot(a, 2), _bxor(_rrot(a, 13), _rrot(a, 22)))
      local maj = _bxor(_band(a, b), _bxor(_band(a, c), _band(b, c)))
      local t2 = (S0 + maj) % 4294967296
      h, g, f, e, d, c, b, a = g, f, e, (d + t1) % 4294967296, c, b, a, (t1 + t2) % 4294967296
    end
    H[1]=(H[1]+a)%4294967296; H[2]=(H[2]+b)%4294967296; H[3]=(H[3]+c)%4294967296; H[4]=(H[4]+d)%4294967296;
    H[5]=(H[5]+e)%4294967296; H[6]=(H[6]+f)%4294967296; H[7]=(H[7]+g)%4294967296; H[8]=(H[8]+h)%4294967296;
  end
  local out = {}
  for i = 1, 8 do
    for j = 3, 0, -1 do table.insert(out, _band(_bshr(H[i], j * 8), 0xff)) end
  end
  return out
end

local function _hmac_sha256(key, data)
  local k = {string.byte(key, 1, #key)}
  if #k > 64 then k = _sha256(key) end
  while #k < 64 do table.insert(k, 0) end
  local o_key_pad, i_key_pad = {}, {}
  for i = 1, 64 do
    o_key_pad[i] = string.char(_bxor(k[i], 0x5c))
    i_key_pad[i] = string.char(_bxor(k[i], 0x36))
  end
  local inner = _sha256(table.concat(i_key_pad) .. data)
  local inner_str = ""
  for i = 1, #inner do inner_str = inner_str .. string.char(inner[i]) end
  return _sha256(table.concat(o_key_pad) .. inner_str)
end

-- AES-256 SBOX and Expansion
local _SBOX = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
}
local _RCON = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36}

local function _sub_word(w)
  return _bor(_bshl(_SBOX[_band(_bshr(w,24),0xff)+1],24), _bor(_bshl(_SBOX[_band(_bshr(w,16),0xff)+1],16), _bor(_bshl(_SBOX[_band(_bshr(w,8),0xff)+1],8), _SBOX[_band(w,0xff)+1])))
end
local function _rot_word(w) return _bor(_bshl(_band(w,0x00ffffff),8), _band(_bshr(w,24),0xff)) end

local function _key_exp(kb)
  local w = {}
  for i = 0, 7 do w[i] = _bor(_bshl(kb[i*4+1],24), _bor(_bshl(kb[i*4+2],16), _bor(_bshl(kb[i*4+3],8), kb[i*4+4]))) end
  for i = 8, 59 do
    local t = w[i-1]
    if i % 8 == 0 then t = _bxor(_sub_word(_rot_word(t)), _bshl(_RCON[math.floor(i/8)], 24))
    elseif i % 8 == 4 then t = _sub_word(t) end
    w[i] = _bxor(w[i-8], t)
  end
  return w
end

local function _xtime(b)
  local s = _bshl(b, 1)
  if _band(b, 0x80) ~= 0 then s = _bxor(s, 0x11b) end
  return _band(s, 0xff)
end

local function _aes_enc_blk(w, in_b)
  local s = {}
  for i = 1, 16 do s[i] = in_b[i] end
  for col = 0, 3 do
    local kw = w[col]
    s[col*4+1] = _bxor(s[col*4+1], _band(_bshr(kw, 24), 0xff))
    s[col*4+2] = _bxor(s[col*4+2], _band(_bshr(kw, 16), 0xff))
    s[col*4+3] = _bxor(s[col*4+3], _band(_bshr(kw, 8), 0xff))
    s[col*4+4] = _bxor(s[col*4+4], _band(kw, 0xff))
  end
  for round = 1, 14 do
    for i = 1, 16 do s[i] = _SBOX[s[i] + 1] end
    local r1_0, r2_0, r2_1, r3_0, r3_1, r3_2 = s[2], s[3], s[7], s[4], s[8], s[12]
    s[2], s[6], s[10], s[14] = s[6], s[10], s[14], r1_0
    s[3], s[7], s[11], s[15] = s[11], s[15], r2_0, r2_1
    s[4], s[8], s[12], s[16] = s[16], r3_0, r3_1, r3_2
    if round < 14 then
      for c = 0, 3 do
        local i = c * 4
        local a0, a1, a2, a3 = s[i+1], s[i+2], s[i+3], s[i+4]
        local t = _bxor(_bxor(a0, a1), _bxor(a2, a3))
        s[i+1] = _bxor(_bxor(a0, t), _xtime(_bxor(a0, a1)))
        s[i+2] = _bxor(_bxor(a1, t), _xtime(_bxor(a1, a2)))
        s[i+3] = _bxor(_bxor(a2, t), _xtime(_bxor(a2, a3)))
        s[i+4] = _bxor(_bxor(a3, t), _xtime(_bxor(a3, a0)))
      end
    end
    for col = 0, 3 do
      local kw = w[round * 4 + col]
      s[col*4+1] = _bxor(s[col*4+1], _band(_bshr(kw, 24), 0xff))
      s[col*4+2] = _bxor(s[col*4+2], _band(_bshr(kw, 16), 0xff))
      s[col*4+3] = _bxor(s[col*4+3], _band(_bshr(kw, 8), 0xff))
      s[col*4+4] = _bxor(s[col*4+4], _band(kw, 0xff))
    end
  end
  return s
end

local function _ghash_mult(X, Y)
  local Z = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0}
  local V = {}
  for i = 1, 16 do V[i] = Y[i] end
  for i = 1, 16 do
    local b = X[i]
    for bit_idx = 7, 0, -1 do
      if _band(_bshr(b, bit_idx), 1) == 1 then
        for k = 1, 16 do Z[k] = _bxor(Z[k], V[k]) end
      end
      local lsb = _band(V[16], 1)
      for k = 16, 2, -1 do V[k] = _bor(_bshr(V[k], 1), _band(_bshl(V[k-1], 7), 0x80)) end
      V[1] = _bshr(V[1], 1)
      if lsb == 1 then V[1] = _bxor(V[1], 0xe1) end
    end
  end
  return Z
end

local function _hex_to_bytes(h)
  local b = {}
  for i = 1, #h, 2 do b[#b + 1] = tonumber(h:sub(i, i+1), 16) end
  return b
end

local function _bytes_to_str(b)
  local chunks, t = {}, {}
  for i = 1, #b do
    t[#t + 1] = string.char(b[i])
    if #t > 2048 then
      chunks[#chunks + 1] = table.concat(t)
      t = {}
    end
  end
  if #t > 0 then chunks[#chunks + 1] = table.concat(t) end
  return table.concat(chunks)
end

local function _aes_gcm_dec(kb, ivb, ctb, tagb)
  local w = _key_exp(kb)
  local H = _aes_enc_blk(w, {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0})
  local J0 = {ivb[1], ivb[2], ivb[3], ivb[4], ivb[5], ivb[6], ivb[7], ivb[8], ivb[9], ivb[10], ivb[11], ivb[12], 0, 0, 0, 1}
  local S = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0}
  local ct_len = #ctb
  local num_blks = math.ceil(ct_len / 16)

  for b = 0, num_blks - 1 do
    local blk = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0}
    for i = 1, 16 do
      local idx = b * 16 + i
      if idx <= ct_len then blk[i] = ctb[idx] end
    end
    for i = 1, 16 do S[i] = _bxor(S[i], blk[i]) end
    S = _ghash_mult(S, H)
  end

  local len_blk = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0}
  local ct_bits = ct_len * 8
  len_blk[13] = _band(_bshr(ct_bits, 24), 0xff)
  len_blk[14] = _band(_bshr(ct_bits, 16), 0xff)
  len_blk[15] = _band(_bshr(ct_bits, 8), 0xff)
  len_blk[16] = _band(ct_bits, 0xff)
  for i = 1, 16 do S[i] = _bxor(S[i], len_blk[i]) end
  S = _ghash_mult(S, H)

  local EJ0 = _aes_enc_blk(w, J0)
  for i = 1, 16 do
    if _bxor(EJ0[i], S[i]) ~= tagb[i] then
      return nil, "Auth tag verification failed."
    end
  end

  local pt = {}
  local counter = 1
  local J_cur = {}
  for i = 1, 16 do J_cur[i] = J0[i] end

  for b = 0, num_blks - 1 do
    counter = counter + 1
    J_cur[13] = _band(_bshr(counter, 24), 0xff)
    J_cur[14] = _band(_bshr(counter, 16), 0xff)
    J_cur[15] = _band(_bshr(counter, 8), 0xff)
    J_cur[16] = _band(counter, 0xff)
    local ks = _aes_enc_blk(w, J_cur)
    for i = 1, 16 do
      local idx = b * 16 + i
      if idx <= ct_len then pt[idx] = _bxor(ctb[idx], ks[i]) end
    end
  end
  return _bytes_to_str(pt)
end

-- Delivery handshake: Derives key client-side and validates response
local function _deliver(key, session)
  local body = '{"key":'..string.format("%q", key)..',"hwid":'..string.format("%q", _fp)..',"session":'..string.format("%q", session)..'}'
  local ok, res = pcall(_r, {
    Url = _U,
    Method = "POST",
    Headers = {
      ["Content-Type"] = "application/json",
      ["Accept"] = "application/json",
      ["User-Agent"] = "Roblox/WinInet"
    },
    Body = body
  })
  if not ok or type(res) ~= "table" then
    return false, "Could not reach the script server."
  end
  if res.StatusCode ~= 200 then
    return false, tostring(res.Body or "Delivery failed.")
  end

  local resp = res.Body or ""
  local iv_hex = resp:match('"iv"%s*:%s*"([^"]+)"')
  local tag_hex = resp:match('"tag"%s*:%s*"([^"]+)"')
  local ct_hex = resp:match('"ct"%s*:%s*"([^"]+)"')
  if not iv_hex or not tag_hex or not ct_hex then
    return false, "Empty payload received."
  end

  -- Derive the 256-bit AES key locally using SCRIPT_KEY + Session + HWID
  local sessionId = session:match("^([^%.]+)%.")
  if not sessionId then
    return false, "Invalid session token."
  end
  local derivedKeyBytes = _hmac_sha256(key, sessionId .. ":" .. _fp)

  local code, err = _aes_gcm_dec(derivedKeyBytes, _hex_to_bytes(iv_hex), _hex_to_bytes(ct_hex), _hex_to_bytes(tag_hex))
  if not code then
    return false, "Security violation: integrity check failed: " .. tostring(err)
  end

  local fn, cerr = _raw_load(code)
  if not fn then
    return false, "Compilation failed: " .. tostring(cerr)
  end
  return true, fn
end

local function _newSession()
  local ok, res = pcall(_r, {
    Url = _SESS_URL,
    Method = "POST",
    Headers = { ["Content-Type"] = "application/json", ["Accept"] = "application/json", ["User-Agent"] = "Roblox/WinInet" },
    Body = "{}"
  })
  if ok and type(res) == "table" and res.StatusCode == 200 then
    return (res.Body or ""):match('"session"%s*:%s*"([^"]+)"')
  end
  return nil
end

${requireKey ? `
-- ---- FULL IN-GAME GUI (Preserved with TweenService & Draggable Frame) ----
local TS = game:GetService("TweenService")
local function _tween(obj, time, props, style, dir)
  local t = TS:Create(obj, TweenInfo.new(time, style or Enum.EasingStyle.Quad, dir or Enum.EasingDirection.Out), props)
  t:Play()
  return t
end

local _copyFn = setclipboard or toclipboard or (type(Clipboard) == "table" and Clipboard.set)
local function _copyKeyLink()
  if type(_copyFn) ~= "function" then return false end
  local ok = pcall(_copyFn, _KEYLINK)
  return ok
end

local _C_BG       = Color3.fromRGB(19, 28, 35)
local _C_BAR      = Color3.fromRGB(13, 19, 24)
local _C_LINE     = Color3.fromRGB(40, 54, 64)
local _C_TEXT     = Color3.fromRGB(228, 236, 241)
local _C_MUTED    = Color3.fromRGB(141, 157, 169)
local _C_TEAL     = Color3.fromRGB(76, 195, 184)
local _C_TEAL_DK  = Color3.fromRGB(14, 111, 104)
local _C_BAD      = Color3.fromRGB(240, 138, 116)
local _C_FIELD    = Color3.fromRGB(14, 21, 26)

local _gui, _frame, _shadow, _stateIcon, _titleLbl, _msgLbl, _box, _boxStroke, _submitBtn, _submitGrad, _getBtn, _dots
local _busy = false
local _onSubmit

local function _buildUI()
  if _gui then return end
  local parent
  pcall(function() parent = (gethui and gethui()) or game:GetService("CoreGui") end)
  if not parent then pcall(function() parent = game:GetService("Players").LocalPlayer:WaitForChild("PlayerGui") end) end

  _gui = Instance.new("ScreenGui")
  _gui.Name = "ScripthostKeyPrompt"
  _gui.ResetOnSpawn = false
  _gui.IgnoreGuiInset = true
  _gui.DisplayOrder = 999
  pcall(function() _gui.Parent = parent end)

  _shadow = Instance.new("Frame")
  _shadow.Size = UDim2.new(0, 356, 0, 300)
  _shadow.Position = UDim2.new(0.5, -178, 0.5, -146)
  _shadow.BackgroundColor3 = Color3.fromRGB(0, 0, 0)
  _shadow.BackgroundTransparency = 0.6
  _shadow.BorderSizePixel = 0
  _shadow.ZIndex = 0
  _shadow.Parent = _gui
  Instance.new("UICorner", _shadow).CornerRadius = UDim.new(0, 16)
  -- Soft shadow falloff so the box doesn't look like a hard translucent rectangle.
  local shadowGrad = Instance.new("UIGradient")
  shadowGrad.Transparency = NumberSequence.new({
    NumberSequenceKeypoint.new(0, 0.55),
    NumberSequenceKeypoint.new(0.75, 0.55),
    NumberSequenceKeypoint.new(1, 1)
  })
  shadowGrad.Rotation = 90
  shadowGrad.Parent = _shadow

  _frame = Instance.new("Frame")
  _frame.Size = UDim2.new(0, 344, 0, 0)
  _frame.AutomaticSize = Enum.AutomaticSize.Y
  _frame.Position = UDim2.new(0.5, -172, 0.5, -130)
  _frame.BackgroundColor3 = _C_BG
  _frame.BorderSizePixel = 0
  _frame.ZIndex = 1
  _frame.ClipsDescendants = true
  _frame.BackgroundTransparency = 1
  _frame.Parent = _gui
  Instance.new("UICorner", _frame).CornerRadius = UDim.new(0, 14)

  local frameStroke = Instance.new("UIStroke")
  frameStroke.Color = _C_LINE
  frameStroke.Thickness = 1
  frameStroke.Parent = _frame

  local listLayout = Instance.new("UIListLayout")
  listLayout.SortOrder = Enum.SortOrder.LayoutOrder
  listLayout.Parent = _frame

  local bar = Instance.new("Frame")
  bar.LayoutOrder = 1
  bar.Size = UDim2.new(1, 0, 0, 44)
  bar.BackgroundColor3 = _C_BAR
  bar.BorderSizePixel = 0
  bar.Parent = _frame
  Instance.new("UICorner", bar).CornerRadius = UDim.new(0, 14)

  local barFix = Instance.new("Frame")
  barFix.Size = UDim2.new(1, 0, 0, 14)
  barFix.Position = UDim2.new(0, 0, 1, -14)
  barFix.BackgroundColor3 = _C_BAR
  barFix.BorderSizePixel = 0
  barFix.ZIndex = 0
  barFix.Parent = bar

  local logoDot = Instance.new("Frame")
  logoDot.Size = UDim2.new(0, 8, 0, 8)
  logoDot.Position = UDim2.new(0, 14, 0.5, -4)
  logoDot.BackgroundColor3 = _C_TEAL
  logoDot.BorderSizePixel = 0
  logoDot.Parent = bar
  Instance.new("UICorner", logoDot).CornerRadius = UDim.new(1, 0)

  local brand = Instance.new("TextLabel")
  brand.BackgroundTransparency = 1
  brand.Size = UDim2.new(1, -90, 1, 0)
  brand.Position = UDim2.new(0, 30, 0, 0)
  brand.Text = "Scripthost"
  brand.TextColor3 = _C_TEXT
  brand.Font = Enum.Font.GothamBold
  brand.TextSize = 14
  brand.TextXAlignment = Enum.TextXAlignment.Left
  brand.Parent = bar

  local tag = Instance.new("TextLabel")
  tag.BackgroundColor3 = _C_LINE
  tag.Size = UDim2.new(0, 56, 0, 18)
  tag.Position = UDim2.new(1, -92, 0.5, -9)
  tag.Text = "KEY"
  tag.TextColor3 = _C_MUTED
  tag.Font = Enum.Font.GothamBold
  tag.TextSize = 10
  tag.Parent = bar
  Instance.new("UICorner", tag).CornerRadius = UDim.new(1, 0)

  local closeBtn = Instance.new("TextButton")
  closeBtn.Size = UDim2.new(0, 28, 0, 28)
  closeBtn.Position = UDim2.new(1, -32, 0.5, -14)
  closeBtn.BackgroundTransparency = 1
  closeBtn.Text = "X"
  closeBtn.TextColor3 = _C_MUTED
  closeBtn.Font = Enum.Font.GothamBold
  closeBtn.TextSize = 14
  closeBtn.Parent = bar
  closeBtn.MouseEnter:Connect(function() _tween(closeBtn, 0.12, {TextColor3 = _C_TEXT}) end)
  closeBtn.MouseLeave:Connect(function() _tween(closeBtn, 0.12, {TextColor3 = _C_MUTED}) end)
  closeBtn.MouseButton1Click:Connect(function()
    _tween(_frame, 0.15, {BackgroundTransparency = 1})
    _tween(_shadow, 0.15, {BackgroundTransparency = 1})
    task.delay(0.16, function() pcall(function() _gui:Destroy() end) end)
  end)

  local body = Instance.new("Frame")
  body.LayoutOrder = 2
  body.Size = UDim2.new(1, 0, 0, 0)
  body.AutomaticSize = Enum.AutomaticSize.Y
  body.BackgroundTransparency = 1
  body.Parent = _frame

  local bodyPad = Instance.new("UIPadding")
  bodyPad.PaddingTop = UDim.new(0, 16)
  bodyPad.PaddingBottom = UDim.new(0, 16)
  bodyPad.PaddingLeft = UDim.new(0, 16)
  bodyPad.PaddingRight = UDim.new(0, 16)
  bodyPad.Parent = body

  local bodyList = Instance.new("UIListLayout")
  bodyList.SortOrder = Enum.SortOrder.LayoutOrder
  bodyList.Padding = UDim.new(0, 10)
  bodyList.Parent = body

  local statusRow = Instance.new("Frame")
  statusRow.LayoutOrder = 1
  statusRow.Size = UDim2.new(1, 0, 0, 20)
  statusRow.BackgroundTransparency = 1
  statusRow.Parent = body

  _stateIcon = Instance.new("TextLabel")
  _stateIcon.BackgroundTransparency = 1
  _stateIcon.Size = UDim2.new(0, 20, 0, 20)
  _stateIcon.Text = "!"
  _stateIcon.TextColor3 = _C_BAD
  _stateIcon.TextSize = 14
  _stateIcon.Font = Enum.Font.GothamBold
  _stateIcon.Parent = statusRow

  _titleLbl = Instance.new("TextLabel")
  _titleLbl.BackgroundTransparency = 1
  _titleLbl.Size = UDim2.new(1, -24, 1, 0)
  _titleLbl.Position = UDim2.new(0, 24, 0, 0)
  _titleLbl.Text = "Wrong key provided."
  _titleLbl.TextColor3 = _C_TEXT
  _titleLbl.Font = Enum.Font.GothamBold
  _titleLbl.TextSize = 15
  _titleLbl.TextXAlignment = Enum.TextXAlignment.Left
  _titleLbl.TextYAlignment = Enum.TextYAlignment.Center
  _titleLbl.Parent = statusRow

  local msgCard = Instance.new("Frame")
  msgCard.LayoutOrder = 2
  msgCard.Size = UDim2.new(1, 0, 0, 0)
  msgCard.AutomaticSize = Enum.AutomaticSize.Y
  msgCard.BackgroundColor3 = _C_FIELD
  msgCard.BorderSizePixel = 0
  msgCard.Parent = body
  Instance.new("UICorner", msgCard).CornerRadius = UDim.new(0, 8)

  local msgPad = Instance.new("UIPadding")
  msgPad.PaddingTop = UDim.new(0, 10)
  msgPad.PaddingBottom = UDim.new(0, 10)
  msgPad.PaddingLeft = UDim.new(0, 12)
  msgPad.PaddingRight = UDim.new(0, 12)
  msgPad.Parent = msgCard

  _msgLbl = Instance.new("TextLabel")
  _msgLbl.BackgroundTransparency = 1
  _msgLbl.Size = UDim2.new(1, 0, 0, 0)
  _msgLbl.AutomaticSize = Enum.AutomaticSize.Y
  _msgLbl.Text = ""
  _msgLbl.TextWrapped = true
  _msgLbl.TextColor3 = _C_MUTED
  _msgLbl.Font = Enum.Font.Gotham
  _msgLbl.TextSize = 12.5
  _msgLbl.TextXAlignment = Enum.TextXAlignment.Left
  _msgLbl.TextYAlignment = Enum.TextYAlignment.Top
  _msgLbl.Parent = msgCard

  _getBtn = Instance.new("TextButton")
  _getBtn.LayoutOrder = 3
  _getBtn.Size = UDim2.new(1, 0, 0, 28)
  _getBtn.BackgroundColor3 = _C_BG
  _getBtn.AutoButtonColor = false
  _getBtn.Text = "Get Key"
  _getBtn.TextColor3 = _C_TEAL
  _getBtn.Font = Enum.Font.GothamBold
  _getBtn.TextSize = 12
  _getBtn.Parent = body
  Instance.new("UICorner", _getBtn).CornerRadius = UDim.new(0, 8)
  local getStroke = Instance.new("UIStroke")
  getStroke.Color = _C_TEAL_DK
  getStroke.Thickness = 1.2
  getStroke.Parent = _getBtn
  _getBtn.MouseEnter:Connect(function() _tween(_getBtn, 0.12, {BackgroundColor3 = Color3.fromRGB(26, 40, 46)}) end)
  _getBtn.MouseLeave:Connect(function() _tween(_getBtn, 0.12, {BackgroundColor3 = _C_BG}) end)

  local divider = Instance.new("Frame")
  divider.LayoutOrder = 4
  divider.Size = UDim2.new(1, 0, 0, 14)
  divider.BackgroundTransparency = 1
  divider.Parent = body

  local dLeft = Instance.new("Frame")
  dLeft.Size = UDim2.new(0.5, -22, 0, 1)
  dLeft.Position = UDim2.new(0, 0, 0.5, 0)
  dLeft.BackgroundColor3 = _C_LINE
  dLeft.BorderSizePixel = 0
  dLeft.Parent = divider

  local dRight = dLeft:Clone()
  dRight.Position = UDim2.new(0.5, 22, 0.5, 0)
  dRight.Parent = divider

  local dLabel = Instance.new("TextLabel")
  dLabel.BackgroundTransparency = 1
  dLabel.Size = UDim2.new(0, 44, 1, 0)
  dLabel.Position = UDim2.new(0.5, -22, 0, 0)
  dLabel.Text = "paste it"
  dLabel.TextColor3 = _C_MUTED
  dLabel.Font = Enum.Font.Gotham
  dLabel.TextSize = 11
  dLabel.Parent = divider

  _box = Instance.new("TextBox")
  _box.LayoutOrder = 5
  _box.Size = UDim2.new(1, 0, 0, 36)
  _box.BackgroundColor3 = _C_FIELD
  _box.PlaceholderText = "Paste your key here"
  _box.Text = ""
  _box.ClearTextOnFocus = false
  _box.TextColor3 = _C_TEXT
  _box.PlaceholderColor3 = Color3.fromRGB(88, 103, 116)
  _box.Font = Enum.Font.Code
  _box.TextSize = 13
  _box.TextXAlignment = Enum.TextXAlignment.Left
  _box.TextYAlignment = Enum.TextYAlignment.Center
  _box.TextTruncate = Enum.TextTruncate.AtEnd
  _box.Parent = body
  Instance.new("UICorner", _box).CornerRadius = UDim.new(0, 8)

  local boxPad = Instance.new("UIPadding")
  boxPad.PaddingLeft = UDim.new(0, 10)
  boxPad.PaddingRight = UDim.new(0, 10)
  boxPad.Parent = _box

  _boxStroke = Instance.new("UIStroke")
  _boxStroke.Color = _C_LINE
  _boxStroke.Thickness = 1.2
  _boxStroke.Parent = _box
  _box.Focused:Connect(function() _tween(_boxStroke, 0.15, {Color = _C_TEAL}) end)
  _box.FocusLost:Connect(function(enterPressed)
    _tween(_boxStroke, 0.15, {Color = _C_LINE})
    if enterPressed then _onSubmit() end
  end)

  _submitBtn = Instance.new("TextButton")
  _submitBtn.LayoutOrder = 6
  _submitBtn.Size = UDim2.new(1, 0, 0, 38)
  _submitBtn.BackgroundColor3 = _C_TEAL
  _submitBtn.AutoButtonColor = false
  _submitBtn.Text = "Submit"
  _submitBtn.TextColor3 = Color3.fromRGB(11, 26, 24)
  _submitBtn.Font = Enum.Font.GothamBold
  _submitBtn.TextSize = 14.5
  _submitBtn.Parent = body
  Instance.new("UICorner", _submitBtn).CornerRadius = UDim.new(0, 8)

  _submitGrad = Instance.new("UIGradient")
  _submitGrad.Color = ColorSequence.new(Color3.fromRGB(92, 214, 202), Color3.fromRGB(62, 171, 161))
  _submitGrad.Rotation = 90
  _submitGrad.Parent = _submitBtn

  -- Use UIScale for hover so the button visually grows WITHOUT pushing the layout below.
  local _submitScale = Instance.new("UIScale")
  _submitScale.Scale = 1
  _submitScale.Parent = _submitBtn
  _submitBtn.MouseEnter:Connect(function()
    if not _busy then _tween(_submitScale, 0.12, {Scale = 1.025}) end
  end)
  _submitBtn.MouseLeave:Connect(function()
    _tween(_submitScale, 0.12, {Scale = 1})
  end)

  local footnote = Instance.new("TextLabel")
  footnote.LayoutOrder = 7
  footnote.BackgroundTransparency = 1
  footnote.Size = UDim2.new(1, 0, 0, 14)
  footnote.Text = "One key per device - expires automatically"
  footnote.TextColor3 = Color3.fromRGB(96, 110, 121)
  footnote.Font = Enum.Font.Gotham
  footnote.TextSize = 10.5
  footnote.Parent = body

  -- Start slightly higher than final position so we can tween BOTH transparency and position.
  _frame.Position = UDim2.new(0.5, -172, 0.5, -138)
  _shadow.Position = UDim2.new(0.5, -178, 0.5, -144)
  _tween(_frame, 0.22, {BackgroundTransparency = 0, Position = UDim2.new(0.5, -172, 0.5, -118)})
  _tween(_shadow, 0.22, {BackgroundTransparency = 0.6, Position = UDim2.new(0.5, -178, 0.5, -124)})

  -- Keep the shadow size synced with the frame's AutomaticSize height.
  _frame:GetPropertyChangedSignal("AbsoluteSize"):Connect(function()
    local h = _frame.AbsoluteSize.Y
    _shadow.Size = UDim2.new(0, 356, 0, h + 12)
  end)

  -- ESC closes the prompt (in addition to the X button).
  local UIS = game:GetService("UserInputService")
  local _escConn
  _escConn = UIS.InputBegan:Connect(function(input, gp)
    if gp then return end
    if input.KeyCode == Enum.KeyCode.Escape and _gui and _gui.Parent then
      _tween(_frame, 0.15, {BackgroundTransparency = 1})
      _tween(_shadow, 0.15, {BackgroundTransparency = 1})
      task.delay(0.16, function()
        pcall(function() _gui:Destroy() end)
        if _escConn then pcall(function() _escConn:Disconnect() end) end
      end)
    end
  end)

  local _dragging, _dragStart, _startPos
  bar.InputBegan:Connect(function(input)
    if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
      _dragging = true
      _dragStart = input.Position
      _startPos = _frame.Position
      input.Changed:Connect(function()
        if input.UserInputState == Enum.UserInputState.End then _dragging = false end
      end)
    end
  end)
  bar.InputChanged:Connect(function(input)
    if _dragging and (input.UserInputType == Enum.UserInputType.MouseMovement or input.UserInputType == Enum.UserInputType.Touch) then
      local delta = input.Position - _dragStart
      local newPos = UDim2.new(_startPos.X.Scale, _startPos.X.Offset + delta.X, _startPos.Y.Scale, _startPos.Y.Offset + delta.Y)
      _frame.Position = newPos
      _shadow.Position = UDim2.new(newPos.X.Scale, newPos.X.Offset - 6, newPos.Y.Scale, newPos.Y.Offset - 6)
    end
  end)
end

local function _setState(kind, title, detail)
  _buildUI()
  local accent = (kind == "error") and _C_BAD or _C_TEAL
  _stateIcon.Text = (kind == "error") and "!" or "i"
  _stateIcon.TextColor3 = accent
  _titleLbl.Text = title
  _msgLbl.Text = detail
end

local _dotsRunning = false
local function _animateDots(prefix)
  _dotsRunning = true
  task.spawn(function()
    local n = 0
    while _dotsRunning and _submitBtn do
      n = (n % 3) + 1
      pcall(function() _submitBtn.Text = prefix .. string.rep(".", n) end)
      task.wait(0.35)
    end
  end)
end

_onSubmit = function()
  if _busy then return end
  local key = _box.Text
  if type(key) ~= "string" or key:gsub("%s", "") == "" then
    _setState("error", "Wrong key provided.", "Enter a key first, or press Get Key to copy the key link.")
    return
  end
  _busy = true
  _animateDots("Checking")
  -- Dim the button so the user sees the busy state, not just the text dots.
  _tween(_submitBtn, 0.15, {BackgroundColor3 = _C_TEAL_DK})
  _submitGrad.Transparency = NumberSequence.new(0.35)
  local session = _newSession()
  if not session then
    _dotsRunning = false
    _busy = false
    _submitBtn.Text = "Submit"
    _tween(_submitBtn, 0.15, {BackgroundColor3 = _C_TEAL})
    _submitGrad.Transparency = NumberSequence.new(0)
    _setState("error", "Couldn't reach the server.", "Check your internet connection and try again.")
    return
  end

  local ok, result = _deliver(key, session)
  _dotsRunning = false
  _busy = false
  _submitBtn.Text = "Submit"
  _tween(_submitBtn, 0.15, {BackgroundColor3 = _C_TEAL})
  _submitGrad.Transparency = NumberSequence.new(0)
  if ok then
    _setState("info", "Key accepted!", "Running the script now.")
    task.delay(0.35, function() pcall(function() _gui:Destroy() end) end)
    result()
  else
    _setState("error", "Wrong key provided.", tostring(result))
  end
end

local function _bindButtons()
  _getBtn.MouseButton1Click:Connect(function()
    local copied = _copyKeyLink()
    _getBtn.Text = copied and "Copied! Open in browser" or "Copied link to console"
    if not copied then print("[Scripthost] Key link: " .. _KEYLINK) end
    task.delay(2.5, function()
      if _getBtn then pcall(function() _getBtn.Text = "Get Key" end) end
    end)
  end)
  _submitBtn.MouseButton1Click:Connect(_onSubmit)
end

local _k0 = getgenv and getgenv().SCRIPT_KEY or _G.SCRIPT_KEY
if type(_k0) == "string" and _k0 ~= "" then
  local ok, result = _deliver(_k0, _S)
  if ok then
    result()
  else
    _buildUI()
    _bindButtons()
    _setState("error", "Wrong key provided.", tostring(result))
  end
else
  _buildUI()
  _bindButtons()
  _setState("info", "No key set.", "Press Get Key, finish the steps, paste your key below, then press Submit.")
end
` : `
local ok, result = _deliver("open", _S)
if ok then
  result()
else
  warn("[Scripthost] Delivery failed: " .. tostring(result))
end
`}`;

const BLOCK_PAGE = `<!doctype html><meta charset=utf-8><title>Access denied</title><p>This endpoint serves authorized executors only.</p>`;
const HOME_PAGE = fs.readFileSync(path.join(__dirname, 'home.html'), 'utf8');
const ADMIN_PAGE = fs.readFileSync(path.join(__dirname, 'admin.html'), 'utf8');
const LOGIN_PAGE = fs.readFileSync(path.join(__dirname, 'login.html'), 'utf8');
const DASHBOARD_PAGE = fs.readFileSync(path.join(__dirname, 'dashboard.html'), 'utf8');
const KEY_PAGE = fs.readFileSync(path.join(__dirname, 'getkey.html'), 'utf8');
const ANTI_ADBLOCK_PAGE = fs.readFileSync(path.join(__dirname, 'anti-adblock.js'), 'utf8');
const ADS_TXT = fs.readFileSync(path.join(__dirname, 'ads.txt'), 'utf8');
const CSP = "default-src 'self'; script-src 'self' 'unsafe-inline' https://pagead2.googlesyndication.com https://ep2.adtrafficquality.google https://*.googlesyndication.com https://*.doubleclick.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https://*.google.com https://ep1.adtrafficquality.google https://*.googlesyndication.com https://*.doubleclick.net; frame-src 'self' about: https://*.google.com https://*.googlesyndication.com https://*.doubleclick.net; frame-ancestors 'none'";

const server = http.createServer(async (req, res) => {
  const ip = clientIp(req), url = new URL(req.url, 'http://x'), p = url.pathname.replace(/\/+/g, '/'), ua = req.headers['user-agent'] || '';
  const hostHdr = String(req.headers['x-forwarded-host'] || req.headers.host || '').trim();
  const rawProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
  const proto = rawProto || (hostHdr.includes('localhost') || hostHdr.includes('127.0.0.1') ? 'http' : 'https');
  const origin = (E.PUBLIC_URL || (proto + '://' + (hostHdr || 'localhost:' + PORT))).trim().replace(/\/+$/, '');

  const send = (code, body, type = 'application/json') => {
    const h = { 'content-type': type, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer' };
    if (type.startsWith('text/html')) { h['content-security-policy'] = CSP; h['x-frame-options'] = 'DENY'; }
    res.writeHead(code, h);
    res.end(typeof body === 'string' ? body : JSON.stringify(body));
  };

  try {
    if (req.method === 'GET' && p === '/') return send(200, HOME_PAGE, 'text/html; charset=utf-8');
    if (req.method === 'GET' && p === '/admin') return send(200, ADMIN_PAGE, 'text/html; charset=utf-8');
    if (req.method === 'GET' && p === '/login') return send(200, LOGIN_PAGE, 'text/html; charset=utf-8');
    if (req.method === 'GET' && p === '/dashboard') return send(200, DASHBOARD_PAGE, 'text/html; charset=utf-8');
    if (req.method === 'GET' && (p === '/getkey' || p.startsWith('/getkey/'))) return send(200, KEY_PAGE, 'text/html; charset=utf-8');
    if (req.method === 'GET' && p === '/anti-adblock.js') return send(200, ANTI_ADBLOCK_PAGE, 'application/javascript; charset=utf-8');
    if (req.method === 'GET' && p === '/ads.txt') return send(200, ADS_TXT, 'text/plain; charset=utf-8');

    if (p === '/auth/login' && req.method === 'POST') {
      if (req.headers.origin !== origin) return send(403, { error: 'Invalid request origin.' });
      if (limited(ip + ':login', 10)) return send(429, { error: 'Too many login attempts. Try again in a minute.' });
      const b = await readJson(req, 4096);
      const username = typeof b.username === 'string' ? b.username.trim().toLowerCase() : '';
      const password = typeof b.password === 'string' ? b.password : '';
      if (password.length > 1024) return send(401, { error: 'Invalid username or password.' });
      const user = Object.values(db.users).find(u => u.username.toLowerCase() === username);
      const salt = user ? user.passwordSalt : '00000000000000000000000000000000';
      const candidate = await hashPassword(password, salt);
      if (!user || !same(candidate, user.passwordHash)) {
        log(ip, 'user_login_failed', username.slice(0, 32), ua);
        return send(401, { error: 'Invalid username or password.' });
      }
      const token = crypto.randomBytes(32).toString('hex'), sessionKey = sha(token);
      accountSessions.set(sessionKey, { userId: user.id, expires: Date.now() + accountSessionMs });
      res.setHeader('set-cookie', `scripthost_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${accountSessionMs / 1000}${proto === 'https' ? '; Secure' : ''}`);
      log(ip, 'user_login', user.username, ua);
      return send(200, { ok: true, username: user.username });
    }

    if (p === '/auth/logout' && req.method === 'POST') {
      if (req.headers.origin !== origin) return send(403, { error: 'Invalid request origin.' });
      const account = accountFromRequest(req);
      if (account) accountSessions.delete(account.key);
      res.setHeader('set-cookie', `scripthost_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${proto === 'https' ? '; Secure' : ''}`);
      return send(200, { ok: true });
    }

    if (p.startsWith('/user/')) {
      const account = accountFromRequest(req);
      if (!account) return send(401, { error: 'Please log in again.' });
      if (req.method === 'POST' && req.headers.origin !== origin) return send(403, { error: 'Invalid request origin.' });
      const user = account.user;
      if (p === '/user/me' && req.method === 'GET') {
        return send(200, { username: user.username, hasWorkinkApiKey: !!user.workinkApiKey });
      }
      if (p === '/user/workink' && req.method === 'POST') {
        const b = await readJson(req, 4096), key = typeof b.apiKey === 'string' ? b.apiKey.trim() : '';
        if (key.length > 512) return send(400, { error: 'Work.ink API key is too long.' });
        if (key) user.workinkApiKey = encryptSecret(key);
        else if (b.clear === true) delete user.workinkApiKey;
        else return send(400, { error: 'Enter an API key or choose to clear the saved key.' });
        save();
        return send(200, { ok: true, hasWorkinkApiKey: !!user.workinkApiKey });
      }
      if (p === '/user/data' && req.method === 'GET') {
        const scripts = Object.entries(db.scripts).filter(([, s]) => s.ownerId === user.id).map(([id, s]) => ({
          id, name: s.name, platform: scriptPlatform(s), size: s.content.length, served: s.served,
          workink: s.workink || '', requireKey: !!(s.keyed || s.keyHash)
        }));
        return send(200, { scripts });
      }
      if (p === '/user/script-content' && req.method === 'GET') {
        const s = getScript(url.searchParams.get('id'));
        return s && s.ownerId === user.id
          ? send(200, { content: s.content, workink: s.workink || '', platform: scriptPlatform(s) })
          : send(404, { error: 'Script not found.' });
      }
      if (p === '/user/script' && req.method === 'POST') {
        const b = await readJson(req, 2 << 20);
        if (typeof b.content !== 'string' || !b.content.trim()) return send(400, { error: 'Paste some code first.' });
        if (b.platform !== undefined && !['roblox', 'gamesense'].includes(b.platform)) return send(400, { error: 'Invalid script platform.' });
        if (b.requireKey && !String(b.workink || '').trim()) return send(400, { error: 'A Work.ink link is required when key protection is enabled.' });
        if (String(b.workink || '').trim() && !wkLink(b.workink)) return send(400, { error: 'Invalid Work.ink link format.' });
        const id = crypto.randomBytes(12).toString('hex'), platform = b.platform === 'gamesense' ? 'gamesense' : 'roblox';
        db.scripts[id] = {
          name: String(b.name || 'untitled').trim().slice(0, 60) || 'untitled',
          content: b.content, platform, keyed: !!b.requireKey, workink: wkLink(b.workink), served: 0, ownerId: user.id
        };
        log(ip, 'user_script_created', id, ua);
        save();
        return send(200, { id, keyed: !!b.requireKey, platform });
      }
      if (p === '/user/update' && req.method === 'POST') {
        const b = await readJson(req, 2 << 20), s = getScript(String(b.id || ''));
        if (!s || s.ownerId !== user.id) return send(404, { error: 'Script not found.' });
        if (typeof b.content !== 'string' || !b.content.trim()) return send(400, { error: 'Paste some code first.' });
        if ((s.keyed || s.keyHash) && !String(b.workink || '').trim()) return send(400, { error: 'A Work.ink link is required when key protection is enabled.' });
        if (String(b.workink || '').trim() && !wkLink(b.workink)) return send(400, { error: 'Invalid Work.ink link format.' });
        if (b.platform !== undefined && !['roblox', 'gamesense'].includes(b.platform)) return send(400, { error: 'Invalid script platform.' });
        s.name = String(b.name || 'untitled').trim().slice(0, 60) || 'untitled';
        s.workink = wkLink(b.workink);
        s.content = b.content;
        if (['roblox', 'gamesense'].includes(b.platform)) s.platform = b.platform;
        save();
        log(ip, 'user_script_edited', b.id, ua);
        return send(200, { ok: true });
      }
      if (p === '/user/delete' && req.method === 'POST') {
        const b = await readJson(req, 4096), id = String(b.id || ''), s = getScript(id);
        if (!s || s.ownerId !== user.id) return send(404, { error: 'Script not found.' });
        delete db.scripts[id];
        for (const hash of Object.keys(db.keys)) if (db.keys[hash].script === id) delete db.keys[hash];
        log(ip, 'user_script_deleted', id, ua);
        save();
        return send(200, { ok: true });
      }
      return send(404, { error: 'Not found.' });
    }

    // Self-Serve HWID Reset Endpoint (Cooldown protected)
    if (p === '/key/reset-hwid' && req.method === 'POST') {
      if (limited(ip + ':reset', 5)) return send(429, { error: 'Too many reset attempts.' });
      const b = await readJson(req, 1024), k = typeof b.key === 'string' && findKey(b.key);
      if (!k) return send(404, { error: 'Key not found.' });
      if (k.revoked) return send(403, { error: 'Key is revoked.' });
      const COOLDOWN = 24 * 36e5;
      if (k.lastReset && Date.now() - k.lastReset < COOLDOWN) {
        const remaining = Math.ceil((COOLDOWN - (Date.now() - k.lastReset)) / 36e5);
        return send(429, { error: `Device reset is on cooldown. Try again in ${remaining} hour(s).` });
      }
      k.hwid = null;
      k.lastReset = Date.now();
      save();
      log(ip, 'admin_key_reset', k.script, ua);
      return send(200, { ok: true, message: 'Device reset successfully. Run your script on the new device.' });
    }

    // Key claim flows
    if (p.startsWith('/key/') && req.method === 'POST') {
      if (limited(ip + ':key', 12)) return send(429, { error: 'Too many requests. Try again in a minute.' });
      const b = await readJson(req, 2048), sid = String(b.script || ''), sc = getScript(sid);
      if (!sc || scriptPlatform(sc) === 'unsupported' || !(sc.keyed || sc.keyHash)) return send(404, { error: 'This key link is not valid.' });
      if (p === '/key/info') return send(200, { name: sc.name, platform: scriptPlatform(sc) });

      const wl = sc.workink || wkLink(E.WORKINK_LINK);

      if (p === '/key/start') {
        const a = activeFor(ip, sid);
        if (a) return send(409, { error: 'You already have an active key for this script.' });
        if (wl) {
          let apiKey;
          try { apiKey = workinkApiKeyForScript(sc); }
          catch (err) { console.error('Could not decrypt Work.ink API key:', err); return send(500, { error: 'Could not read the Work.ink API key for this script owner.' }); }
          if (!apiKey) return send(500, { error: 'Work.ink API key is not configured for this script owner.' });
          const r0 = Date.now() + '.' + crypto.randomBytes(8).toString('hex'), ref = r0 + '.' + mac('wk' + r0 + sid);
          const dest = origin + '/getkey/' + sid + '?token={TOKEN}&ref=' + encodeURIComponent(ref);
          try {
            const j = await (await fetch(WK + '/_api/v2/override?destination=' + encodeURIComponent(dest), {
              headers: { 'X-Api-Key': apiKey },
              signal: AbortSignal.timeout(8000)
            })).json();
            if (!j.sr) throw new Error('no sr');
            return send(200, { redirect: wl + (wl.includes('?') ? '&' : '?') + 'sr=' + encodeURIComponent(j.sr) });
          } catch {
            return send(502, { error: 'Could not reach Work.ink. Try again in a moment.' });
          }
        }
        const t = Date.now() + '.' + crypto.randomBytes(8).toString('hex');
        return send(200, { ticket: t + '.' + mac(t + ip + sid), wait: KEY_WAIT });
      }

      // Work.ink Claim Flow (Atomic TOCTOU Defense)
      if (p === '/key/claim' && wl) {
        const token = String(b.token || ''), ref = String(b.ref || ''), i = ref.lastIndexOf('.'), body = ref.slice(0, i), ts = +body.split('.')[0];
        if (!/^[A-Za-z0-9-]{8,80}$/.test(token) || i < 0 || !same(mac('wk' + body + sid), ref.slice(i + 1))) {
          return send(400, { error: 'Invalid link signature.' });
        }
        let apiKey;
        try { apiKey = workinkApiKeyForScript(sc); }
        catch (err) { console.error('Could not decrypt Work.ink API key:', err); return send(500, { error: 'Could not read the Work.ink API key for this script owner.' }); }
        if (!apiKey) return send(500, { error: 'Work.ink API key is not configured for this script owner.' });
        if (usedTickets.has(body)) {
          return send(400, { error: 'This ticket is already being processed or was used.' });
        }
        usedTickets.add(body);

        if (Date.now() - ts > 3600000) return send(400, { error: 'Session expired. Start again.' });
        if (activeFor(ip, sid)) return send(409, { error: 'You already have an active key.' });

        let j;
        try {
          const r = await fetch(WK + '/_api/v2/token/verify/' + encodeURIComponent(token) + '?deleteToken=1', {
            headers: { 'X-Api-Key': apiKey },
            signal: AbortSignal.timeout(8000)
          });
          if (r.status === 401 || r.status === 403) {
            usedTickets.delete(body);
            log(ip, 'provider_error', sid, 'HTTP ' + r.status);
            return send(502, { error: 'Key provider is misconfigured.' });
          }
          j = await r.json();
        } catch {
          usedTickets.delete(body);
          return send(502, { error: 'Could not reach Work.ink. Try again in a moment.' });
        }

        if (!j.valid) return send(403, { error: 'The verification token is invalid or expired.' });
        setTimeout(() => usedTickets.delete(body), 3700000).unref();
        const key = mint(KEY_HOURS, '', ip, 'user', sid);
        log(ip, 'key_issued', sid, ua);
        return send(200, { key, hours: KEY_HOURS });
      }

      // Standard Countdown Claim Flow (Atomic)
      if (p === '/key/claim') {
        const t = String(b.ticket || ''), i = t.lastIndexOf('.'), body = t.slice(0, i), ts = +body.split('.')[0];
        if (i < 0 || !same(mac(body + ip + sid), t.slice(i + 1))) {
          return send(400, { error: 'Invalid ticket signature.' });
        }
        if (usedTickets.has(body)) {
          return send(400, { error: 'Ticket is already used or processing.' });
        }
        usedTickets.add(body);

        const age = Date.now() - ts;
        if (age < KEY_WAIT * 1000 - 500) {
          usedTickets.delete(body);
          return send(425, { error: 'Please wait for the countdown to complete.' });
        }
        if (age > 600000) return send(400, { error: 'Ticket expired.' });
        if (activeFor(ip, sid)) return send(409, { error: 'You already have an active key.' });

        setTimeout(() => usedTickets.delete(body), 700000).unref();
        const key = mint(KEY_HOURS, '', ip, 'user', sid);
        log(ip, 'key_issued', sid, ua);
        return send(200, { key, hours: KEY_HOURS });
      }

      if (p === '/key/status') {
        const k = typeof b.key === 'string' && findKey(b.key);
        return send(200, k && k.script === sid && !k.revoked ? { valid: !(k.expires && k.expires < Date.now()), expires: k.expires } : { valid: false });
      }
    }

    const mintSession = id => {
      const sessionId = crypto.randomBytes(16).toString('hex');
      const sessionToken = sessionId + '.' + mac('session:' + sessionId + ':' + id);
      sessions.set(sessionId, { scriptId: id, ip: sha(ip), created: Date.now(), expires: Date.now() + 90000, consumed: false });
      return sessionToken;
    };

    if (p.startsWith('/s/') && req.method === 'GET') {
      const id = p.slice(3).replace(/\.(lua|txt)$/i, '').replace(/\/+$/, ''), s = getScript(id);
      if (!s || scriptPlatform(s) !== 'roblox') return send(404, '', 'text/plain');
      if (isBrowser(req.headers)) {
        if (!limited(ip + ':b', 20)) log(ip, 'browser_blocked', id, ua);
        return send(403, BLOCK_PAGE, 'text/html; charset=utf-8');
      }
      if (limited(ip, 30)) { log(ip, 'rate_limited', id, ua); return send(429, 'Rate limited', 'text/plain'); }
      if (TAMPER_CHECK && !LOADER_UA.test(ua)) { log(ip, 'tamper_attempt', id, ua); return send(403, 'Tamper attempt detected.', 'text/plain'); }
      const isKeyed = !!(s.keyed || s.keyHash);
      log(ip, 'stub', id, ua);
      return send(200, obfuscateLua(stub(origin, id, mintSession(id), isKeyed)), 'text/plain; charset=utf-8');
    }

    if (p.startsWith('/gs/s/') && req.method === 'GET') {
      const id = p.slice(6).replace(/\.(lua|txt)$/i, '').replace(/\/+$/, ''), s = getScript(id);
      if (!s || scriptPlatform(s) !== 'gamesense') return send(404, '', 'text/plain');
      if (isBrowser(req.headers) && !GAMESENSE_UA.test(ua)) {
        if (!limited(ip + ':gs-browser', 20)) log(ip, 'browser_blocked', id, ua);
        return send(403, BLOCK_PAGE, 'text/html; charset=utf-8');
      }
      if (limited(ip + ':gs-loader', 30)) return send(429, 'Rate limited', 'text/plain');
      log(ip, 'gamesense_stub', id, ua);
      return send(200, obfuscateLua(gameSenseStub(origin, id, mintSession(id), !!(s.keyed || s.keyHash))), 'text/plain; charset=utf-8');
    }

    if (p.startsWith('/gs/validate/') && req.method === 'POST') {
      const id = p.slice(13).replace(/\/+$/, ''), s = getScript(id);
      if (limited(ip + ':gs-validate', 30)) return send(429, 'Rate limited', 'text/plain');
      if (!s || scriptPlatform(s) !== 'gamesense') return send(404, 'Script not found', 'text/plain');
      if (!(s.keyed || s.keyHash)) return send(400, 'This script does not require a key.', 'text/plain');

      let b;
      try { b = await readJson(req, 4096); } catch { return send(400, 'Invalid request body', 'text/plain'); }
      const k = String(b.key || '').trim(), hwid = String(b.hwid || '').trim().slice(0, 256);
      const err = k ? checkKey(s, id, k, hwid, origin, false) : 'No key provided. Get a key at ' + origin + '/getkey/' + id;
      if (err) {
        log(ip, /another device/.test(err) ? 'hwid_mismatch' : /expired/.test(err) ? 'key_expired' : 'bad_key', id, ua);
        return send(403, err, 'text/plain');
      }
      return send(200, mintSession(id), 'text/plain; charset=utf-8');
    }

    if (p.startsWith('/session/') && req.method === 'POST') {
      const id = p.slice(9).replace(/\/+$/, ''), s = getScript(id);
      if (isBrowser(req.headers)) return send(403, BLOCK_PAGE, 'text/html; charset=utf-8');
      if (limited(ip + ':sess', 30)) { log(ip, 'rate_limited', id, ua); return send(429, { error: 'Rate limited' }); }
      if (TAMPER_CHECK && !LOADER_UA.test(ua)) { log(ip, 'tamper_attempt', id, ua); return send(403, { error: 'Tamper attempt detected.' }); }
      if (!s || scriptPlatform(s) !== 'roblox') return send(404, { error: 'Script not found' });
      return send(200, { session: mintSession(id) });
    }

    // Hardened Delivery: AES-256-GCM via Locally Derived Key
    if (p.startsWith('/d/') && req.method === 'POST') {
      const id = p.slice(3).replace(/\/+$/, ''), s = getScript(id);
      if (limited(ip + ':d', 30)) return send(429, 'Rate limited', 'text/plain');
      if (!s || scriptPlatform(s) !== 'roblox') return send(404, 'Script not found', 'text/plain');

      let b;
      try { b = await readJson(req, 4096); } catch { return send(400, 'Invalid request body', 'text/plain'); }
      const k = String(b.key || '').trim(), hwid = String(b.hwid || '').trim().slice(0, 256), sessionToken = String(b.session || '').trim();
      const sp = sessionToken.split('.');
      if (sp.length !== 2) return send(403, 'Invalid session token format.', 'text/plain');

      const sessionId = sp[0], sig = sp[1];
      if (!same(mac('session:' + sessionId + ':' + id), sig)) {
        log(ip, 'tamper_attempt', id, ua);
        return send(403, 'Invalid session signature.', 'text/plain');
      }

      const sess = sessions.get(sessionId);
      if (!sess || sess.scriptId !== id) return send(403, 'Session not found. Re-run loader.', 'text/plain');
      if (sess.consumed) { log(ip, 'replayed_session', id, ua); return send(403, 'Session already consumed.', 'text/plain'); }
      if (Date.now() > sess.expires) return send(403, 'Session expired.', 'text/plain');
      sess.consumed = true;

      const isKeyed = !!(s.keyed || s.keyHash);
      if (isKeyed) {
        const err = k ? checkKey(s, id, k, hwid, origin) : 'No key provided. Get one at ' + origin + '/getkey/' + id;
        if (err) {
          log(ip, /another device/.test(err) ? 'hwid_mismatch' : /expired/.test(err) ? 'key_expired' : 'bad_key', id, ua);
          return send(403, err, 'text/plain');
        }
      }

      // Encrypt with locally-derived AES key (matching the client's derived key)
      const derivedKey = derivePayloadKey(isKeyed ? k : 'open', sessionId, hwid);
      const payload = aes256gcmEncrypt(derivedKey, s.content);

      s.served++;
      log(ip, 'served', id, ua);

      // Return IV, tag, and ciphertext (NO key in response body)
      return send(200, JSON.stringify(payload), 'application/json; charset=utf-8');
    }

    if (p.startsWith('/gs/d/') && req.method === 'POST') {
      const id = p.slice(6).replace(/\/+$/, ''), s = getScript(id);
      if (limited(ip + ':gs-delivery', 30)) return send(429, 'Rate limited', 'text/plain');
      if (!s || scriptPlatform(s) !== 'gamesense') return send(404, 'Script not found', 'text/plain');

      let b;
      try { b = await readJson(req, 4096); } catch { return send(400, 'Invalid request body', 'text/plain'); }
      const k = String(b.key || '').trim(), hwid = String(b.hwid || '').trim().slice(0, 256), sessionToken = String(b.session || '').trim();
      const sp = sessionToken.split('.');
      if (sp.length !== 2) return send(403, 'Invalid session token format.', 'text/plain');

      const sessionId = sp[0], sig = sp[1];
      if (!same(mac('session:' + sessionId + ':' + id), sig)) {
        log(ip, 'tamper_attempt', id, ua);
        return send(403, 'Invalid session signature.', 'text/plain');
      }

      const sess = sessions.get(sessionId);
      if (!sess || sess.scriptId !== id) return send(403, 'Session not found. Re-run loader.', 'text/plain');
      if (sess.consumed) { log(ip, 'replayed_session', id, ua); return send(403, 'Session already consumed.', 'text/plain'); }
      if (Date.now() > sess.expires) return send(403, 'Session expired.', 'text/plain');
      sess.consumed = true;

      const isKeyed = !!(s.keyed || s.keyHash);
      if (isKeyed) {
        const err = k ? checkKey(s, id, k, hwid, origin) : 'No key provided. Get a key at ' + origin + '/getkey/' + id;
        if (err) {
          log(ip, /another device/.test(err) ? 'hwid_mismatch' : /expired/.test(err) ? 'key_expired' : 'bad_key', id, ua);
          return send(403, err, 'text/plain');
        }
      }

      s.served++;
      log(ip, 'gamesense_served', id, ua);
      return send(200, s.content, 'text/plain; charset=utf-8');
    }

    if (p.startsWith('/admin/')) {
      if (limited(ip + ':admin', 30)) return send(429, { error: 'RATE_LIMITED' });
      const t = (req.headers.authorization || '').replace(/^Bearer /, '');
      if (!same(t, ADMIN)) { log(ip, 'admin_denied'); return send(401, { error: 'UNAUTHORIZED' }); }

      if (req.method === 'GET' && p === '/admin/data') {
        return send(200, {
          logs: db.logs.slice(-100).reverse(),
          scripts: Object.entries(db.scripts).map(([id, s]) => ({ id, name: s.name, platform: scriptPlatform(s), size: s.content.length, served: s.served, workink: s.workink || '', requireKey: !!(s.keyed || s.keyHash) })),
          users: Object.values(db.users).map(u => ({
            id: u.id,
            username: u.username,
            hasWorkinkApiKey: !!u.workinkApiKey,
            scripts: Object.values(db.scripts).filter(s => s.ownerId === u.id).length
          })),
          keys: Object.values(db.keys).sort((a, b) => b.created - a.created).slice(0, 200).map(k => ({
            script: k.script,
            scriptName: k.script && has(db.scripts, k.script) ? db.scripts[k.script].name : null,
            id: k.id,
            note: k.note,
            src: k.src,
            created: k.created,
            expires: k.expires,
            bound: !!k.hwid,
            uses: k.uses,
            revoked: k.revoked
          }))
        });
      }

      if (req.method === 'GET' && p === '/admin/script-content') {
        const s = getScript(url.searchParams.get('id'));
        return s ? send(200, { content: s.content, workink: s.workink || '', platform: scriptPlatform(s) }) : send(404, { error: 'Script not found' });
      }

      const b = await readJson(req, 2 << 20), s = getScript(String(b.id || '')), k = byId(String(b.id || ''));
      const audit = what => log(ip, 'admin_' + what, b.id);

      if (p === '/admin/user-create') {
        const username = typeof b.username === 'string' ? b.username.trim() : '';
        const password = typeof b.password === 'string' ? b.password : '';
        if (!validUsername(username)) return send(400, { error: 'Username must be 3-32 letters, numbers, dots, underscores, or hyphens.' });
        if (!validPassword(password)) return send(400, { error: 'Password must be 12-1024 characters.' });
        if (Object.values(db.users).some(u => u.username.toLowerCase() === username.toLowerCase())) {
          return send(409, { error: 'That username already exists.' });
        }
        const id = crypto.randomUUID(), passwordSalt = crypto.randomBytes(16).toString('hex');
        db.users[id] = { id, username, passwordSalt, passwordHash: await hashPassword(password, passwordSalt) };
        audit('user_created');
        save();
        return send(200, { id, username });
      }
      if (p === '/admin/user-password') {
        const user = getUser(String(b.id || '')), password = typeof b.password === 'string' ? b.password : '';
        if (!user) return send(404, { error: 'User not found.' });
        if (!validPassword(password)) return send(400, { error: 'Password must be 12-1024 characters.' });
        user.passwordSalt = crypto.randomBytes(16).toString('hex');
        user.passwordHash = await hashPassword(password, user.passwordSalt);
        revokeAccountSessions(user.id);
        audit('user_password_reset');
        save();
        return send(200, { ok: true });
      }
      if (p === '/admin/user-delete') {
        const user = getUser(String(b.id || ''));
        if (!user) return send(404, { error: 'User not found.' });
        const ownedScripts = Object.entries(db.scripts).filter(([, script]) => script.ownerId === user.id).map(([id]) => id);
        for (const id of ownedScripts) {
          delete db.scripts[id];
          for (const hash of Object.keys(db.keys)) if (db.keys[hash].script === id) delete db.keys[hash];
        }
        delete db.users[user.id];
        revokeAccountSessions(user.id);
        audit('user_deleted');
        save();
        return send(200, { ok: true });
      }

      if (p === '/admin/script') {
        if (typeof b.content !== 'string' || !b.content) return send(400, { error: 'Paste some code first' });
        if (b.platform !== undefined && !['roblox', 'gamesense'].includes(b.platform)) return send(400, { error: 'Invalid script platform' });
        const id = crypto.randomBytes(12).toString('hex');
        if (b.requireKey && !String(b.workink || '').trim()) return send(400, { error: 'A Work.ink link is required when key protection is enabled.' });
        if (String(b.workink || '').trim() && !wkLink(b.workink)) return send(400, { error: 'Invalid Work.ink link format' });
        const platform = b.platform === 'gamesense' ? 'gamesense' : 'roblox';
        db.scripts[id] = { name: String(b.name || 'untitled').slice(0, 60), content: b.content, platform, keyed: !!b.requireKey, workink: wkLink(b.workink), served: 0 };
        audit('script_created');
        save();
        return send(200, { id, keyed: !!b.requireKey, platform });
      }
      if (p === '/admin/update' && s && typeof b.content === 'string') {
        if ((s.keyed || s.keyHash) && !String(b.workink || '').trim()) return send(400, { error: 'A Work.ink link is required when key protection is enabled.' });
        if (String(b.workink || '').trim() && !wkLink(b.workink)) return send(400, { error: 'Invalid Work.ink link' });
        if (b.platform !== undefined && !['roblox', 'gamesense'].includes(b.platform)) return send(400, { error: 'Invalid script platform' });
        s.workink = wkLink(b.workink);
        s.content = b.content;
        if (['roblox', 'gamesense'].includes(b.platform)) s.platform = b.platform;
        if (typeof b.name === 'string' && b.name.trim()) s.name = b.name.trim().slice(0, 60);
        audit('script_edited');
        save();
        return send(200, { ok: 1 });
      }
      if (p === '/admin/delete' && s) { delete db.scripts[b.id]; audit('script_deleted'); save(); return send(200, { ok: 1 }); }
      if (p === '/admin/key-create') {
        const sc = String(b.script || '');
        if (sc && (!getScript(sc) || scriptPlatform(getScript(sc)) === 'unsupported')) return send(400, { error: 'Script not found or platform is no longer supported' });
        const key = mint(Math.max(0, +b.hours || 0), String(b.note || '').slice(0, 60), null, 'admin', sc || null);
        audit('key_created');
        return send(200, { key });
      }
      if (p === '/admin/key-revoke' && k) { k.revoked = !!b.revoked; audit('key_revoked'); save(); return send(200, { ok: 1 }); }
      if (p === '/admin/key-reset' && k) { k.hwid = null; k.lastReset = 0; audit('key_reset'); save(); return send(200, { ok: 1 }); }
      if (p === '/admin/key-delete' && k) { for (const h in db.keys) if (db.keys[h] === k) delete db.keys[h]; audit('key_deleted'); save(); return send(200, { ok: 1 }); }
    }

    send(404, '', 'text/plain');
  } catch {
    send(400, { error: 'BAD_REQUEST' });
  }
});

async function startServer() {
  try {
    await initializeDatabase();
    server.listen(PORT, () => console.log(`Scripthost on :${PORT}${pool ? ' (Neon Postgres)' : ''}`));
  } catch (err) {
    console.error(`Could not initialize script database${DATABASE_URL ? ' in Neon Postgres' : ` at ${DB_FILE}`}:`, err);
    process.exitCode = 1;
    if (pool) await pool.end();
  }
}

let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`Received ${signal}; saving script database.`);
  server.close(async () => {
    await flush();
    if (pool) await pool.end();
    process.exit(0);
  });
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
startServer();
