#!/usr/bin/env node
'use strict';
/* MuxAI v2 — interface web auto-hébergée pour agents IA (Claude Code, Codex, Ollama, API compatibles OpenAI).
   Zéro dépendance : Node.js >= 20 suffit. */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');

const PORT = Number(process.env.PORT) || 8787;
const HOST = process.env.HOST || '127.0.0.1';
const DATA = path.resolve(process.env.MUXAI_DATA || path.join(__dirname, 'data'));
const TRUST_PROXY = !!String(process.env.MUXAI_TRUST_PROXY || '').trim();
// Noms d'hôte acceptés en plus (séparés par des virgules). Sur la machine elle-même, seuls localhost et 127.0.0.1 le sont.
const HOSTS = String(process.env.MUXAI_HOSTS || '').split(',').map(x => x.trim().toLowerCase()).filter(Boolean);
const LOOPBACK = ['127.0.0.1', '::1', 'localhost'].includes(HOST);
const INDEX = path.join(__dirname, 'public', 'index.html');
const AGENT_JS = path.join(__dirname, 'agent', 'muxai-agent.js');
const CONV_DIR = path.join(DATA, 'conversations');
const WORKDIR = path.join(DATA, 'workspace');
const DB_FILE = path.join(DATA, 'db.json');
const MASK = '••••••';

const LOGO_DIR = path.join(DATA, 'logos');
for (const d of [CONV_DIR, WORKDIR, LOGO_DIR]) fs.mkdirSync(d, { recursive: true, mode: 0o700 });

/* ───────────── Stockage (fichiers JSON, écriture atomique) ───────────── */
/* Chiffrement au repos (facultatif) : avec MUXAI_KEY, la base et les conversations sont scellées en AES-256-GCM.
   La clé ne vit que dans l'environnement, jamais sur le volume : une copie du dossier de données ne livre rien. */
const KEY = process.env.MUXAI_KEY ? crypto.createHash('sha256').update('muxai-donnees-v1\0' + process.env.MUXAI_KEY).digest() : null;
const SEALED = 'MUXAI1.';
function seal(text) {
  if (!KEY) return text;
  const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', KEY, iv), body = Buffer.concat([c.update(text, 'utf8'), c.final()]);
  return SEALED + Buffer.concat([iv, c.getAuthTag(), body]).toString('base64');
}
function unseal(text) {
  if (!text.startsWith(SEALED)) return text; // fichier en clair d'avant l'activation : relu tel quel, scellé à la prochaine écriture
  if (!KEY) throw new Error('Les données sont chiffrées : la variable MUXAI_KEY est requise pour démarrer.');
  const raw = Buffer.from(text.slice(SEALED.length), 'base64'), d = crypto.createDecipheriv('aes-256-gcm', KEY, raw.subarray(0, 12));
  d.setAuthTag(raw.subarray(12, 28));
  try { return Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString('utf8'); }
  catch { throw new Error('Déchiffrement impossible : MUXAI_KEY ne correspond pas aux données, ou le fichier a été modifié.'); }
}
let db = { users: [], sessions: {}, providers: [], agents: [], projects: [], convs: [], devices: [], mcps: [], settings: { openSignup: false } };
if (fs.existsSync(DB_FILE)) {
  try { db = Object.assign(db, JSON.parse(unseal(fs.readFileSync(DB_FILE, 'utf8')))); }
  catch (e) { console.error('MuxAI ne peut pas lire sa base : ' + e.message); process.exit(1); }
}
/* Journal de sécurité : une ligne JSON par événement, sur la sortie standard (gardée par Docker, hors du volume). */
const audit = (ev, d = {}) => console.log(JSON.stringify({ secu: ev, t: new Date().toISOString(), ...d }));

function writeAtomic(file, data) {
  const tmp = file + '.' + process.pid + '.tmp';
  fs.writeFileSync(tmp, data, { mode: 0o600 });
  fs.renameSync(tmp, file);
}
let saveTimer = null;
function flush() { if (saveTimer) { clearTimeout(saveTimer); saveTimer = null; } writeAtomic(DB_FILE, seal(JSON.stringify(db))); }
function save() { if (!saveTimer) saveTimer = setTimeout(flush, 150); }
const convPath = id => path.join(CONV_DIR, id + '.json');
function loadMsgs(id) { try { return JSON.parse(unseal(fs.readFileSync(convPath(id), 'utf8'))); } catch { return []; } }
function saveMsgs(id, msgs) { writeAtomic(convPath(id), seal(JSON.stringify(msgs))); }
const newId = () => crypto.randomBytes(8).toString('hex');

/* ───────────── Utilitaires ───────────── */
class HttpError extends Error { constructor(code, msg) { super(msg); this.code = code; } }
const bad = (msg, code = 400) => { throw new HttpError(code, msg); };
const str = (v, max) => String(v ?? '').trim().slice(0, max);
const RAW = Symbol('raw');
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const cap = s => s.charAt(0).toUpperCase() + s.slice(1).toLowerCase();

/* Mots de passe : Argon2id quand Node le fournit (24.7 et plus), sinon scrypt renforcé. Jamais de calcul bloquant.
   Format : argon2id$m,t,p$sel$empreinte ou scrypt$N,r,p$sel$empreinte. L'ancien format « sel:empreinte » reste lu, puis remplacé. */
const ARGON = { memory: 65536, passes: 3, parallelism: 4 }, SCRYPT = { N: 131072, r: 8, p: 1 };
let argonOk = typeof crypto.argon2 === 'function';
/* Deux calculs à la fois, vingt en attente au plus : une rafale de connexions ne peut ni saturer la mémoire ni figer le serveur. */
let hashing = 0; const hashQueue = [];
async function gate(fn) {
  if (hashing >= 2) { if (hashQueue.length >= 20) bad('Serveur occupé, réessaie dans un instant', 429); await new Promise(r => hashQueue.push(r)); }
  hashing++;
  try { return await fn(); } finally { hashing--; const next = hashQueue.shift(); if (next) next(); }
}
const argon = (pw, salt, o) => gate(() => new Promise((ok, ko) => crypto.argon2('argon2id', { message: Buffer.from(pw), nonce: salt, parallelism: o.parallelism, tagLength: 32, memory: o.memory, passes: o.passes }, (e, k) => (e ? ko(e) : ok(Buffer.from(k))))));
const scrypt = (pw, salt, o, len = 64) => gate(() => new Promise((ok, ko) => crypto.scrypt(pw, salt, len, { N: o.N, r: o.r, p: o.p, maxmem: 256 * 1024 * 1024 }, (e, k) => (e ? ko(e) : ok(k)))));
async function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  if (argonOk) { try { return `argon2id$${ARGON.memory},${ARGON.passes},${ARGON.parallelism}$${salt.toString('hex')}$${(await argon(pw, salt, ARGON)).toString('hex')}`; } catch (e) { argonOk = false; console.error('Argon2id indisponible, repli sur scrypt :', e.message); } }
  return `scrypt$${SCRYPT.N},${SCRYPT.r},${SCRYPT.p}$${salt.toString('hex')}$${(await scrypt(pw, salt, SCRYPT)).toString('hex')}`;
}
async function checkPw(pw, stored) {
  try {
    const f = String(stored).split('$'); let a, b;
    if (f.length === 4) {
      const n = f[1].split(',').map(Number), salt = Buffer.from(f[2], 'hex'); b = Buffer.from(f[3], 'hex');
      if (n.some(x => !Number.isInteger(x) || x < 1) || n[0] > 1048576) return false;
      a = f[0] === 'argon2id' ? await argon(pw, salt, { memory: n[0], passes: n[1], parallelism: n[2] }) : f[0] === 'scrypt' ? await scrypt(pw, salt, { N: n[0], r: n[1], p: n[2] }, b.length) : null;
    } else { const [s, h] = String(stored).split(':'); b = Buffer.from(h, 'hex'); a = await scrypt(pw, Buffer.from(s, 'hex'), { N: 16384, r: 8, p: 1 }, 64); }
    return !!a && a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch { return false; }
}
const pwCurrent = stored => String(stored).startsWith(argonOk ? `argon2id$${ARGON.memory},${ARGON.passes},${ARGON.parallelism}$` : `scrypt$${SCRYPT.N},${SCRYPT.r},${SCRYPT.p}$`);
let leurre = null; // même coût de calcul pour un nom inconnu que pour un mauvais mot de passe
const checkDecoy = async pw => { leurre = leurre || await hashPw(crypto.randomBytes(16).toString('hex')); await checkPw(pw, leurre); };

/* Adresse du client. Sans relais de confiance, c'est celle de la connexion. Avec MUXAI_TRUST_PROXY, on remonte
   X-Forwarded-For de droite à gauche en sautant les relais de confiance : la première adresse qui n'en est pas un
   est celle du client. Ce qu'un client écrit lui-même à gauche de l'en-tête n'est jamais cru.
   MUXAI_TRUST_PROXY=1 : seul le relais directement connecté. Sinon une liste de plages : 172.16.0.0/12,10.0.0.0/8 */
const v4 = ip => { const m = /^(?:::ffff:)?(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/i.exec(String(ip).trim()); return m && m.slice(1).every(x => x < 256) ? ((+m[1] << 24) | (+m[2] << 16) | (+m[3] << 8) | +m[4]) >>> 0 : null; };
const PROXY_SPEC = String(process.env.MUXAI_TRUST_PROXY || '').trim();
const PROXIES = PROXY_SPEC && PROXY_SPEC !== '1' ? PROXY_SPEC.split(',').map(s => s.trim()).filter(Boolean).map(s => { const [a, b] = s.split('/'), n = v4(a), bits = b === undefined ? 32 : Number(b); return n === null || !(bits >= 0 && bits <= 32) ? { exact: a.toLowerCase() } : { n, mask: bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0 }; }) : [];
function trustedHop(ip, direct) {
  if (PROXY_SPEC === '1') return direct;
  const n = v4(ip);
  return PROXIES.some(p => (p.exact ? p.exact === String(ip).toLowerCase() : n !== null && ((n & p.mask) >>> 0) === ((p.n & p.mask) >>> 0)));
}
const peer = req => req.socket.remoteAddress || '?';
const viaProxy = req => TRUST_PROXY && trustedHop(peer(req), true);
function clientIp(req) {
  let ip = peer(req);
  if (!viaProxy(req) || !req.headers['x-forwarded-for']) return ip;
  const chain = String(req.headers['x-forwarded-for']).split(',').map(s => s.trim()).filter(Boolean).slice(-8);
  let direct = true;
  while (chain.length && trustedHop(ip, direct)) { ip = chain.pop(); direct = false; }
  return ip.slice(0, 64);
}
function isHttps(req) { return process.env.MUXAI_SECURE === '1' || !!req.socket.encrypted || (viaProxy(req) && req.headers['x-forwarded-proto'] === 'https'); }
/* Sessions : jeton de 256 bits dont seule l'empreinte est gardée, durée bornée et fermeture après inactivité. */
const SESSION_TTL = (Number(process.env.MUXAI_SESSION_HOURS) || 12) * 3600 * 1000, SESSION_IDLE = (Number(process.env.MUXAI_IDLE_MINUTES) || 60) * 60 * 1000;
function setSession(req, res, user) {
  const token = crypto.randomBytes(32).toString('base64url'), https = isHttps(req);
  db.sessions[sha(token)] = { u: user.id, exp: Date.now() + SESSION_TTL, seen: Date.now() };
  save();
  // En HTTPS, le préfixe __Host- interdit à un sous-domaine voisin d'écraser le cookie.
  res.setHeader('Set-Cookie', [`${https ? '__Host-' : ''}muxai_sid=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL / 1000}${https ? '; Secure' : ''}`, ...(https ? ['muxai_sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'] : [])]);
}
const clearCookies = res => res.setHeader('Set-Cookie', ['muxai_sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0', '__Host-muxai_sid=; HttpOnly; SameSite=Strict; Secure; Path=/; Max-Age=0']);
// En HTTPS, seul le cookie préfixé compte : un sous-domaine voisin ne peut pas en poser un (pas de session imposée).
function getToken(req) { const c = req.headers.cookie || ''; return ((isHttps(req) ? null : /(?:^|;\s*)muxai_sid=([\w-]{20,})/.exec(c)) || /(?:^|;\s*)__Host-muxai_sid=([\w-]{20,})/.exec(c) || [])[1]; }
function currentUser(req) {
  const t = getToken(req); if (!t) return null;
  const k = sha(t), s = db.sessions[k]; if (!s) return null;
  const now = Date.now();
  if (s.exp < now || now - (s.seen || now) > SESSION_IDLE) { delete db.sessions[k]; save(); return null; }
  if (now - (s.seen || 0) > 60000) { s.seen = now; save(); }
  return db.users.find(u => u.id === s.u) || null;
}
/* Ralentisseur : dix échecs en dix minutes verrouillent la clé (une adresse, ou un compte quelle que soit l'adresse). */
const fails = new Map();
function throttle(...keys) {
  const now = Date.now();
  for (const k of keys) { const f = fails.get(k); if (f && f.until <= now) fails.delete(k); else if (f && f.n >= 10) bad('Trop de tentatives, réessaie dans quelques minutes', 429); }
}
function failed(...keys) {
  if (fails.size > 20000) { const now = Date.now(); for (const [k, f] of fails) if (f.until <= now) fails.delete(k); if (fails.size > 20000) fails.clear(); }
  for (const k of keys) { const f = fails.get(k) || { n: 0, until: Date.now() + 600000 }; f.n++; fails.set(k, f); }
}

/* Variables secrètes : jamais renvoyées au navigateur, seulement leurs noms. */
function parseEnv(text, old = {}) {
  const out = {};
  for (const line of String(text || '').split('\n')) {
    const m = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$/.exec(line); if (!m) continue;
    const v = m[2].trim();
    out[m[1]] = v === MASK && old[m[1]] != null ? old[m[1]] : v;
  }
  return out;
}
const envText = env => Object.keys(env || {}).map(k => `${k}=${MASK}`).join('\n');
/* En-têtes HTTP d'un serveur MCP distant (ex. Authorization) : même principe, « Nom: valeur ». */
function parseHeaders(text, old = {}) {
  const out = {};
  for (const line of String(text || '').split('\n')) {
    const m = /^\s*([A-Za-z][A-Za-z0-9-]*)\s*[:=]\s*(.*)$/.exec(line); if (!m) continue;
    const v = m[2].trim();
    out[m[1]] = v === MASK && old[m[1]] != null ? old[m[1]] : v;
  }
  return out;
}
const headersText = hd => Object.keys(hd || {}).map(k => `${k}: ${MASK}`).join('\n');

const userView = u => ({ id: u.id, name: u.name, role: u.role });
const isAdmin = u => u.role === 'admin';
const canUse = (u, p) => !!p && (isAdmin(u) || !p.adminOnly);
const CLI = new Set(['claude-code', 'codex']);
function providerView(p, user) {
  if (!isAdmin(user)) return { id: p.id, type: p.type, name: p.name, slash: p.slash || [] };
  const { apiKey, env, seen, ...rest } = p;
  return { ...rest, hasKey: !!apiKey, env: envText(env) };
}
const convView = c => ({ id: c.id, title: c.title, projectId: c.projectId, agentId: c.agentId || null, providerId: c.providerId || null, model: c.model || '', modelLabel: c.modelLabel || '', archived: !!c.archived, updatedAt: c.updatedAt, running: runs.has(c.id) });
const visibleAgents = user => db.agents.filter(a => a.userId === user.id || a.shared).map(a => ({ ...a, mine: a.userId === user.id }));
const deviceView = d => ({ id: d.id, name: d.name, info: d.info || {}, online: online(d), createdAt: d.createdAt });
const mcpView = m => ({ ...m, env: envText(m.env), headers: headersText(m.headers) });
function bootData(user) {
  const base = { setup: db.users.length === 0, setupToken: db.users.length === 0 && !!SETUP_TOKEN, openSignup: !!db.settings.openSignup, me: user ? userView(user) : null, gui: process.platform !== 'linux' || !!process.env.DISPLAY };
  if (!user) return base;
  return {
    ...base,
    providers: db.providers.filter(p => canUse(user, p)).map(p => providerView(p, user)),
    agents: visibleAgents(user),
    projects: db.projects.filter(p => p.userId === user.id),
    convs: db.convs.filter(c => c.userId === user.id).sort((a, b) => b.updatedAt - a.updatedAt).map(convView),
    devices: isAdmin(user) ? db.devices.map(deviceView) : [],
    mcps: isAdmin(user) ? db.mcps.map(mcpView) : [],
    github: isAdmin(user) ? ghView() : null,
  };
}

/* ───────────── Appareils distants ─────────────
   L'agent installé sur un autre poste interroge le serveur en continu (connexion sortante, passe les NAT).
   Le serveur lui confie des commandes CLI à lancer et reçoit leur sortie au fil de l'eau. */
const live = new Map();
function dev(d) { let s = live.get(d.id); if (!s) live.set(d.id, s = { seen: 0, waiter: null, queue: [], cancels: [], jobs: new Map() }); return s; }
const online = d => Date.now() - dev(d).seen < 45000;
const wake = s => { if (s.waiter) s.waiter(); };
function runRemote(device, spec, signal, onChunk) {
  return new Promise((resolve, reject) => {
    if (!online(device)) return reject(new Error(`L’appareil « ${device.name} » est hors ligne`));
    const s = dev(device), id = newId();
    const end = fn => v => { clearTimeout(ackTimer); s.jobs.delete(id); signal && signal.removeEventListener('abort', cancel); fn(v); };
    const cancel = () => { s.cancels.push(id); wake(s); };
    const job = { acked: false, out: data => { job.acked = true; clearTimeout(ackTimer); if (data) onChunk(data); }, done: end(resolve), fail: end(msg => reject(new Error(msg))) };
    const ackTimer = setTimeout(() => job.fail(`L’appareil « ${device.name} » n’a pas pris la tâche`), 30000);
    s.jobs.set(id, job);
    s.queue.push({ id, ...spec });
    if (signal) signal.addEventListener('abort', cancel, { once: true });
    wake(s);
  });
}
setInterval(() => {
  for (const d of db.devices) { const s = dev(d); if (s.jobs.size && !online(d)) for (const j of [...s.jobs.values()]) j.fail(`L’appareil « ${d.name} » s’est déconnecté`); }
}, 15000).unref();

/* ───────────── Exécution des CLI (sur ce serveur ou sur un appareil) ───────────── */
function runLocal(spec, signal, onChunk) {
  return new Promise((resolve, reject) => {
    if (spec.cwd && !fs.existsSync(spec.cwd)) return reject(new Error(`Dossier de travail introuvable sur le serveur : ${spec.cwd}`));
    let child;
    try { child = spawn(spec.cmd, spec.args, { cwd: spec.cwd || WORKDIR, env: { ...process.env, ...gitEnv(), ...spec.env }, stdio: ['pipe', 'pipe', 'pipe'] }); }
    catch (e) { return reject(e); }
    let err = '';
    child.stdout.setEncoding('utf8'); child.stdout.on('data', onChunk);
    child.stderr.on('data', d => { err = (err + d).slice(-2000); });
    child.on('error', e => reject(new Error(e.code === 'ENOENT' ? `Commande introuvable sur le serveur : ${spec.cmd}` : e.message)));
    const kill = () => child.kill('SIGTERM');
    if (signal) signal.addEventListener('abort', kill, { once: true });
    child.stdin.on('error', () => {});
    child.stdin.end(spec.input || '');
    child.on('close', code => { if (signal) signal.removeEventListener('abort', kill); resolve({ code, err: err.trim() }); });
  });
}
function exec(provider, spec, signal, onChunk) {
  spec = { ...spec, env: provider.env || {} };
  if (!provider.deviceId) return runLocal(spec, signal, onChunk);
  const device = db.devices.find(d => d.id === provider.deviceId);
  if (!device) return Promise.reject(new Error('L’appareil de ce connecteur n’existe plus'));
  return runRemote(device, spec, signal, onChunk);
}
const cliCmd = p => p.command || (p.type === 'codex' ? 'codex' : 'claude');
async function runCli(job, args, input, onLine) {
  let buf = '', thrown = null;
  const feed = l => { if (!l.trim() || thrown) return; let j; try { j = JSON.parse(l); } catch { return; } try { onLine(j); } catch (e) { thrown = e; } };
  const res = await exec(job.provider, { cmd: cliCmd(job.provider), args, input, cwd: job.cwd }, job.signal, chunk => {
    buf += chunk; let i;
    while ((i = buf.indexOf('\n')) >= 0) { feed(buf.slice(0, i)); buf = buf.slice(i + 1); }
  });
  feed(buf);
  if (thrown) throw thrown;
  return res;
}
async function cliVersion(p) {
  let out = '';
  const signal = AbortSignal.timeout(12000);
  const { code, err } = await exec(p, { cmd: cliCmd(p), args: ['--version'] }, signal, c => { out += c; });
  if (code !== 0 && !out) throw new Error(err || 'La commande a échoué');
  return out.trim().split('\n')[0].slice(0, 80);
}

/* Serveurs MCP rattachés à un connecteur CLI */
const mcpsOf = p => (p.mcpIds || []).map(id => db.mcps.find(m => m.id === id)).filter(Boolean);
function claudeMcpArgs(p) {
  const list = mcpsOf(p); if (!list.length) return [];
  const mcpServers = {};
  for (const m of list) mcpServers[m.name] = m.transport === 'stdio' ? { command: m.command, args: m.args || [], env: m.env || {} } : { type: m.transport, url: m.url, ...(m.headers && Object.keys(m.headers).length ? { headers: m.headers } : {}) };
  return ['--mcp-config', JSON.stringify({ mcpServers }), '--allowedTools', list.map(m => 'mcp__' + m.name).join(',')];
}
function codexMcpArgs(p) {
  const out = [];
  for (const m of mcpsOf(p)) {
    const k = `mcp_servers.${m.name}`;
    if (m.transport !== 'stdio') { out.push('-c', `${k}.url=${JSON.stringify(m.url)}`); continue; }
    out.push('-c', `${k}.command=${JSON.stringify(m.command)}`, '-c', `${k}.args=${JSON.stringify(m.args || [])}`);
    const env = Object.entries(m.env || {});
    if (env.length) out.push('-c', `${k}.env={${env.map(([a, b]) => `${a}=${JSON.stringify(b)}`).join(',')}}`);
  }
  return out;
}

/* ───────────── Connecteurs ───────────── */
async function* lines(stream) {
  const dec = new TextDecoder(); let buf = '';
  for await (const chunk of stream) {
    buf += dec.decode(chunk, { stream: true });
    let i;
    while ((i = buf.indexOf('\n')) >= 0) { const l = buf.slice(0, i).replace(/\r$/, ''); buf = buf.slice(i + 1); if (l) yield l; }
  }
  if (buf.trim()) yield buf;
}
const baseUrl = p => String(p.baseUrl || '').replace(/\/+$/, '');
const authHeaders = p => (p.apiKey ? { Authorization: 'Bearer ' + p.apiKey } : {});
function chatMessages(job) {
  const out = job.system ? [{ role: 'system', content: job.system }] : [];
  for (const m of job.msgs) if (m.content) out.push({ role: m.role, content: m.content });
  return out;
}
async function failText(r, label) { return new Error(`${label} a répondu ${r.status} : ${(await r.text().catch(() => '')).slice(0, 300)}`); }
/* Sans session CLI à reprendre, on rejoue l'historique dans le prompt. */
function cliPrompt(job, resuming) {
  const last = job.msgs.at(-1).content, prior = job.msgs.slice(0, -1).filter(m => m.content);
  if (resuming || !prior.length) return last;
  const hist = prior.map(m => `[${m.role === 'user' ? 'Utilisateur' : 'Assistant'}]\n${m.content}`).join('\n\n');
  return `<historique_de_la_conversation>\n${hist}\n</historique_de_la_conversation>\n\n${last}`;
}
function toolDetail(input) {
  if (!input || typeof input !== 'object') return '';
  return String(input.command || input.file_path || input.path || input.pattern || input.url || input.query || input.description || input.code || JSON.stringify(input)).replace(/^\{\}$/, '');
}
function resumeId(job) {
  const c = job.conv.cli;
  return !job.regenerate && c && c.providerId === job.provider.id ? c.session : null;
}
async function withResume(job, attempt) {
  const resume = resumeId(job);
  try { return await attempt(resume); }
  catch (e) { if (resume && e.noOutput && !job.signal.aborted) return attempt(null); throw e; }
}

const drivers = {
  async ollama(job) {
    if (!job.model) throw new Error('Choisis un modèle pour ce connecteur');
    const r = await fetch(baseUrl(job.provider) + '/api/chat', { method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeaders(job.provider) }, body: JSON.stringify({ model: job.model, messages: chatMessages(job), stream: true }), signal: job.signal });
    if (!r.ok) throw await failText(r, 'Ollama');
    for await (const l of lines(r.body)) {
      let j; try { j = JSON.parse(l); } catch { continue; }
      if (j.error) throw new Error(j.error);
      if (j.message && j.message.content) job.onText(j.message.content);
    }
  },

  async openai(job) {
    if (!job.model) throw new Error('Choisis un modèle pour ce connecteur');
    const r = await fetch(baseUrl(job.provider) + '/chat/completions', { method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeaders(job.provider) }, body: JSON.stringify({ model: job.model, messages: chatMessages(job), stream: true }), signal: job.signal });
    if (!r.ok) throw await failText(r, job.provider.name);
    for await (const l of lines(r.body)) {
      if (!l.startsWith('data:')) continue;
      const d = l.slice(5).trim();
      if (d === '[DONE]') break;
      let j; try { j = JSON.parse(d); } catch { continue; }
      if (j.error) throw new Error(j.error.message || JSON.stringify(j.error));
      const t = j.choices && j.choices[0] && j.choices[0].delta && j.choices[0].delta.content;
      if (t) job.onText(t);
    }
  },

  'claude-code'(job) {
    const p = job.provider;
    return withResume(job, async resume => {
      const args = ['-p', '--output-format', 'stream-json', '--verbose', '--include-partial-messages'];
      if (job.model) args.push('--model', job.model);
      if (job.system) args.push('--append-system-prompt', job.system);
      if (p.permissionMode && p.permissionMode !== 'default') args.push('--permission-mode', p.permissionMode);
      if (resume) args.push('--resume', resume);
      args.push(...claudeMcpArgs(p), ...(p.extraArgs || []));
      let session = null, result = null, sawDelta = false, any = false;
      const { code, err } = await runCli(job, args, cliPrompt(job, !!resume), j => {
        if (j.session_id) session = j.session_id;
        if (j.type === 'system' && j.model && job.onModel) job.onModel(String(j.model));
        if (j.type === 'system' && Array.isArray(j.slash_commands) && job.onCommands) job.onCommands(j.slash_commands);
        if (j.type === 'result') { result = j; return; }
        if (j.parent_tool_use_id) return; // sous-agents : on n'affiche que le fil principal
        if (j.type === 'stream_event') {
          const e = j.event || {};
          if (e.type === 'content_block_start' && e.content_block && e.content_block.type === 'text' && any) job.onText('\n\n');
          else if (e.type === 'content_block_delta' && e.delta && e.delta.type === 'text_delta') { sawDelta = any = true; job.onText(e.delta.text); }
        } else if (j.type === 'assistant') {
          for (const b of (j.message && j.message.content) || []) {
            if (b.type === 'tool_use') job.onTool(b.name, toolDetail(b.input));
            else if (b.type === 'text' && !sawDelta && b.text) { job.onText((any ? '\n\n' : '') + b.text); any = true; }
          }
        }
      });
      if (result && result.is_error) throw Object.assign(new Error(String(result.result || result.subtype || 'Erreur Claude Code')), { noOutput: !any });
      if (!result && code !== 0) throw Object.assign(new Error(err || `claude s'est arrêté avec le code ${code}`), { noOutput: !any });
      return { session };
    });
  },

  codex(job) {
    const p = job.provider;
    return withResume(job, async resume => {
      const args = resume ? ['exec', 'resume', resume] : ['exec'];
      args.push('--json', '--skip-git-repo-check');
      if (job.model) args.push('-m', job.model);
      if (p.sandbox && !resume) args.push('--sandbox', p.sandbox);
      args.push(...codexMcpArgs(p), ...(p.extraArgs || []), '-');
      let prompt = cliPrompt(job, !!resume);
      if (job.system && !resume) prompt = `${job.system}\n\n---\n\n${prompt}`;
      let session = null, fail = null, any = false;
      const { code, err } = await runCli(job, args, prompt, j => {
        if (j.type === 'thread.started') session = j.thread_id;
        else if (j.type === 'turn.failed') fail = (j.error && j.error.message) || 'Le tour a échoué';
        else if (j.type === 'error') fail = j.message || 'Erreur Codex';
        else if (j.type === 'item.completed' && j.item) {
          const it = j.item;
          if (it.type === 'agent_message' && it.text) { job.onText((any ? '\n\n' : '') + it.text); any = true; }
          else if (it.type === 'command_execution') job.onTool('shell', String(it.command || ''));
          else if (it.type === 'file_change') job.onTool('fichiers', (it.changes || []).map(c => c.path).join(', '));
          else if (it.type === 'mcp_tool_call') job.onTool(`${it.server || 'mcp'}.${it.tool || ''}`, '');
          else if (it.type === 'web_search') job.onTool('recherche web', String(it.query || ''));
        }
      });
      if (fail) throw Object.assign(new Error(fail), { noOutput: !any });
      if (code !== 0) throw Object.assign(new Error(err || `codex s'est arrêté avec le code ${code}`), { noOutput: !any });
      return { session: session || resume };
    });
  },
};

/* ───────────── Modèles : liste, noms courts, familles ───────────── */
function claudeLabel(id) {
  if (/^(fable|mythos|opus|sonnet|haiku)$/i.test(id)) return cap(id) + ' — dernière version';
  const m = /^claude-(?:(\d+)-(\d+)-)?([a-z]+)(?:-(\d{1,2})(?=-|$))?(?:-(\d{1,2})(?=-|$))?/.exec(id);
  if (!m) return id;
  const ver = m[1] ? `${m[1]}.${m[2]}` : [m[4], m[5]].filter(Boolean).join('.');
  return `${cap(m[3])}${ver ? ' ' + ver : ''}`;
}
function manualModels(p) {
  const text = p.models || (p.type === 'claude-code' ? 'opus\nsonnet\nhaiku\nclaude-sonnet-4-5-20250929\nclaude-haiku-4-5-20251001' : '');
  return text.split('\n').map(l => l.trim()).filter(Boolean).map(l => { const i = l.indexOf('='); return i > 0 ? { id: l.slice(0, i).trim(), label: l.slice(i + 1).trim() } : { id: l }; });
}
async function apiModels(p, signal) {
  if (p.type === 'claude-code') {
    // Avec une clé API, ou à défaut avec le jeton du compte obtenu lors de la connexion guidée.
    const oauth = p.env && p.env.CLAUDE_CODE_OAUTH_TOKEN;
    const auth = p.apiKey ? { 'x-api-key': p.apiKey } : { Authorization: 'Bearer ' + oauth, 'anthropic-beta': 'oauth-2025-04-20' };
    const r = await fetch('https://api.anthropic.com/v1/models?limit=1000', { headers: { ...auth, 'anthropic-version': '2023-06-01' }, signal });
    if (!r.ok) throw await failText(r, 'L’API Anthropic');
    return ((await r.json()).data || []).map(m => ({ id: m.id, label: String(m.display_name || '').replace(/^Claude\s+/i, '') || undefined }));
  }
  const r = await fetch('https://api.openai.com/v1/models', { headers: authHeaders(p), signal });
  if (!r.ok) throw await failText(r, 'L’API OpenAI');
  return ((await r.json()).data || []).map(m => m.id).filter(id => /^(gpt-|o\d|codex)/.test(id)).sort().map(id => ({ id }));
}
function decorate(p, list) {
  const claude = p.type === 'claude-code';
  for (const m of list) {
    if (!m.label) m.label = claude ? claudeLabel(m.id) : m.id;
    const seen = claude && p.seen && p.seen[m.id || 'default'];
    if (seen) m.label = m.id ? `${seen} — dernière version` : `Modèle par défaut (${seen})`;
    if (claude && m.id) { const f = /(fable|mythos|opus|sonnet|haiku)/i.exec(m.label + ' ' + m.id); m.family = f ? cap(f[1]) : 'Autres'; }
  }
  if (!claude && list.length > 12) for (const m of list) m.family = m.id.includes('/') ? m.id.split('/')[0] : m.id.split(/[-:.]/)[0];
  return list;
}
const modelCache = new Map();
async function probe(p) {
  const hit = modelCache.get(p.id);
  if (hit && Date.now() - hit.at < 300000) return hit.data;
  const signal = AbortSignal.timeout(10000);
  let models, info;
  if (p.type === 'ollama') {
    const r = await fetch(baseUrl(p) + '/api/tags', { headers: authHeaders(p), signal });
    if (!r.ok) throw await failText(r, 'Ollama');
    models = ((await r.json()).models || []).map(m => ({ id: m.name }));
    info = `${models.length} modèle(s) installé(s)`;
  } else if (p.type === 'openai') {
    const r = await fetch(baseUrl(p) + '/models', { headers: authHeaders(p), signal });
    if (!r.ok) throw await failText(r, p.name);
    models = ((await r.json()).data || []).map(m => ({ id: m.id })).sort((a, b) => a.id.localeCompare(b.id));
    info = `${models.length} modèle(s) disponible(s)`;
  } else {
    info = (await cliVersion(p)) || 'Commande trouvée';
    models = manualModels(p);
    const viaAccount = !p.apiKey && p.type === 'claude-code' && p.env && p.env.CLAUDE_CODE_OAUTH_TOKEN;
    if (p.apiKey || viaAccount) {
      try { const list = await apiModels(p, signal); if (list.length) models = list; }
      catch (e) { console.log(`[modèles] ${p.name} : ${e.message.slice(0, 200)}`); if (p.apiKey) info += ' — liste des modèles non chargée : ' + e.message.slice(0, 120); }
    }
    models.unshift({ id: '', label: 'Modèle par défaut' });
  }
  const data = { models: decorate(p, models), info };
  modelCache.set(p.id, { at: Date.now(), data });
  return data;
}
function modelLabel(p, id) {
  if (!id) return 'Modèle par défaut';
  const hit = modelCache.get(p.id), m = hit && hit.data.models.find(x => x.id === id);
  return m ? m.label : p.type === 'claude-code' ? claudeLabel(id) : id;
}

/* ───────────── Exécutions : la génération continue même si le navigateur se ferme ───────────── */
const runs = new Map();
function attach(run, res) {
  res.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-cache, no-transform', 'X-Accel-Buffering': 'no' });
  const sub = { send: ev => res.write('data: ' + JSON.stringify(ev) + '\n\n'), end: () => { clearInterval(hb); res.end(); } };
  const hb = setInterval(() => res.write(': hb\n\n'), 20000);
  sub.send({ t: 'snapshot', text: run.text, tools: run.tools, head: run.head });
  run.subs.add(sub);
  res.on('close', () => { clearInterval(hb); run.subs.delete(sub); });
}
function startRun(conv, msgs, agent, provider, model, regenerate) {
  const ac = new AbortController();
  const head = { agentName: agent ? agent.name : '', providerType: provider.type, providerName: provider.name, model, modelLabel: modelLabel(provider, model) };
  const run = { msgId: newId(), text: '', tools: [], subs: new Set(), ac, head };
  runs.set(conv.id, run);
  const emit = ev => { for (const s of run.subs) s.send(ev); };
  const project = db.projects.find(p => p.id === conv.projectId);
  const system = [
    agent && agent.system,
    project && project.instructions && `# Instructions du projet « ${project.name} »\n${project.instructions}`,
    project && project.context && `# Contexte du projet « ${project.name} »\n${project.context}`,
  ].filter(Boolean).join('\n\n');
  const job = {
    provider, conv, msgs, regenerate, system, model, cwd: (project && project.cwd) || null, signal: ac.signal,
    onModel: real => {
      const label = claudeLabel(real.replace(/\[.*$/, ''));
      if (!label || label === head.modelLabel) return;
      if (/^(|fable|mythos|opus|sonnet|haiku)$/i.test(model)) { provider.seen = { ...(provider.seen || {}), [model || 'default']: label }; modelCache.delete(provider.id); save(); }
      head.modelLabel = label; if (conv.model === model) conv.modelLabel = label;
      emit({ t: 'head', head });
    },
    onCommands: list => {
      const slash = cleanSlash(list);
      if (JSON.stringify(slash) !== JSON.stringify(provider.slash || [])) { provider.slash = slash; save(); }
      emit({ t: 'commands', providerId: provider.id, list: slash });
    },
    onText: t => { run.text += t; emit({ t: 'delta', text: t }); },
    onTool: (name, detail) => { const tool = { name: String(name).slice(0, 80), detail: String(detail || '').slice(0, 300) }; run.tools.push(tool); emit({ t: 'tool', tool }); },
  };
  (async () => {
    let error = null, meta = null;
    try { meta = await drivers[provider.type](job); }
    catch (e) { if (!ac.signal.aborted) error = e.name === 'TimeoutError' ? 'Délai dépassé' : (e.cause && e.cause.code ? `Connecteur injoignable (${e.cause.code})` : e.message || String(e)); }
    // Le CLI écrit parfois son erreur comme une réponse : on ne l'affiche qu'une fois, en erreur.
    if (error && run.text.trim() && error.trim().includes(run.text.trim())) run.text = '';
    const message = { id: run.msgId, role: 'assistant', content: run.text, ...head, ts: Date.now() };
    if (run.tools.length) message.tools = run.tools;
    if (error) message.error = error;
    if (ac.signal.aborted) message.stopped = true;
    if (db.convs.includes(conv)) {
      const cur = loadMsgs(conv.id); cur.push(message); saveMsgs(conv.id, cur);
      conv.updatedAt = Date.now();
      if (meta && meta.session) conv.cli = { providerId: provider.id, session: meta.session };
      save();
    }
    runs.delete(conv.id);
    for (const s of run.subs) { s.send({ t: 'done', message }); s.end(); }
  })();
  return run;
}

/* Le premier compte créé est administrateur. Dès que le serveur écoute ailleurs que sur la machine elle-même,
   sa création exige un jeton : celui de MUXAI_SETUP_TOKEN, sinon un jeton tiré au démarrage et écrit dans le journal. */
const SETUP_TOKEN = process.env.MUXAI_SETUP_TOKEN || (!LOOPBACK && !db.users.length ? crypto.randomBytes(9).toString('base64url') : '');

/* ───────────── Routes ───────────── */
const routes = [];
function R(method, pattern, fn, o = {}) {
  const keys = [];
  const re = new RegExp('^' + pattern.replace(/:(\w+)/g, (_, k) => { keys.push(k); return '([a-f0-9]{16})'; }) + '$');
  routes.push({ method, re, keys, fn, ...o });
}
const own = (list, c) => list.find(x => x.id === c.p.id && x.userId === c.user.id) || bad('Introuvable', 404);
const any = (list, c) => list.find(x => x.id === c.p.id) || bad('Introuvable', 404);
const checkPassword = pw => { if (typeof pw !== 'string' || pw.length < 12 || pw.length > 1024) bad('Mot de passe : 12 caractères minimum'); return pw; };
function checkName(name) {
  name = str(name, 40);
  if (name.length < 2) bad('Nom : 2 caractères minimum');
  if (db.users.some(u => u.name.toLowerCase() === name.toLowerCase())) bad('Ce nom est déjà pris');
  return name;
}
const slug = v => str(v, 40).toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '');

R('GET', '/healthz', () => ({ ok: true }), { pub: true });
R('GET', '/api/boot', c => bootData(c.user), { pub: true });

R('POST', '/api/auth/register', async c => {
  if (db.users.length && !db.settings.openSignup) bad('Les inscriptions sont fermées', 403);
  const ip = 'ip:' + clientIp(c.req); throttle(ip);
  const first = !db.users.length;
  if (first && SETUP_TOKEN && !crypto.timingSafeEqual(Buffer.from(sha(String(c.body.setupToken || ''))), Buffer.from(sha(SETUP_TOKEN)))) { failed(ip); audit('installation.refusee', { ip: ip.slice(3) }); bad('Jeton d’installation incorrect', 403); }
  const name = checkName(c.body.name), pw = await hashPw(checkPassword(c.body.password));
  // Le calcul du mot de passe rend la main : on revérifie qu'aucun compte n'a été créé entre-temps.
  if (first !== !db.users.length) bad('Un compte vient d’être créé : recharge la page', 409);
  const user = { id: newId(), name: checkName(name), pw, role: first ? 'admin' : 'user', createdAt: Date.now() };
  audit('compte.cree', { ip: ip.slice(3), compte: user.name, role: user.role });
  if (!first) failed(ip); // inscriptions ouvertes : dix comptes par adresse et par dix minutes
  db.users.push(user); setSession(c.req, c.res, user);
  return bootData(user);
}, { pub: true });
R('POST', '/api/auth/login', async c => {
  const name = str(c.body.name, 40).toLowerCase(), pw = String(c.body.password || '').slice(0, 1024), ip = 'ip:' + clientIp(c.req), acct = 'u:' + name;
  throttle(ip, acct);
  const user = db.users.find(u => u.name.toLowerCase() === name);
  const ok = user ? await checkPw(pw, user.pw) : (await checkDecoy(pw), false);
  if (!ok) { failed(ip, acct); audit('connexion.refusee', { ip: ip.slice(3), compte: name.slice(0, 40), connu: !!user }); bad('Nom ou mot de passe incorrect', 401); }
  audit('connexion', { ip: ip.slice(3), compte: user.name });
  if (!pwCurrent(user.pw)) { try { user.pw = await hashPw(pw); } catch {} }
  const old = getToken(c.req); if (old) delete db.sessions[sha(old)];
  setSession(c.req, c.res, user);
  return bootData(user);
}, { pub: true });
R('POST', '/api/auth/logout', c => {
  const t = getToken(c.req); if (t) { delete db.sessions[sha(t)]; save(); }
  clearCookies(c.res);
  return { ok: true };
}, { pub: true });
R('POST', '/api/auth/password', async c => {
  const key = 'pw:' + c.user.id; throttle(key);
  if (!(await checkPw(String(c.body.current || '').slice(0, 1024), c.user.pw))) { failed(key); bad('Mot de passe actuel incorrect', 403); }
  c.user.pw = await hashPw(checkPassword(c.body.next));
  audit('mot-de-passe.change', { compte: c.user.name });
  const keep = sha(getToken(c.req));
  for (const k of Object.keys(db.sessions)) if (db.sessions[k].u === c.user.id && k !== keep) delete db.sessions[k];
  save(); return { ok: true };
});

/* Comptes (admin) */
R('GET', '/api/users', () => db.users.map(userView), { admin: true });
R('POST', '/api/users', async c => {
  checkName(c.body.name);
  const pw = await hashPw(checkPassword(c.body.password));
  const user = { id: newId(), name: checkName(c.body.name), pw, role: c.body.role === 'admin' ? 'admin' : 'user', createdAt: Date.now() };
  db.users.push(user); save(); audit('compte.cree', { par: c.user.name, compte: user.name, role: user.role }); return userView(user);
}, { admin: true });
R('DELETE', '/api/users/:id', c => {
  if (c.p.id === c.user.id) bad('Impossible de supprimer ton propre compte');
  any(db.users, c);
  for (const conv of db.convs.filter(x => x.userId === c.p.id)) { runs.get(conv.id)?.ac.abort(); fs.rmSync(convPath(conv.id), { force: true }); }
  for (const k of ['convs', 'agents', 'projects']) db[k] = db[k].filter(x => x.userId !== c.p.id);
  for (const k of Object.keys(db.sessions)) if (db.sessions[k].u === c.p.id) delete db.sessions[k];
  audit('compte.supprime', { par: c.user.name, id: c.p.id });
  db.users = db.users.filter(u => u.id !== c.p.id);
  save(); return { ok: true };
}, { admin: true });
R('PATCH', '/api/settings', c => { db.settings.openSignup = !!c.body.openSignup; save(); return db.settings; }, { admin: true });

/* Connecteurs (admin) */
const PERMS = ['default', 'acceptEdits', 'plan', 'bypassPermissions'];
const SANDBOX = ['', 'read-only', 'workspace-write', 'danger-full-access'];
function providerFields(b, p) {
  if ('name' in b) p.name = str(b.name, 60) || bad('Nom requis');
  if ('brand' in b) p.brand = BRANDS[b.brand] ? b.brand : '';
  if (b.loginId) { const l = logins.get(String(b.loginId)); if (l && l.token) p.env = { ...(p.env || {}), CLAUDE_CODE_OAUTH_TOKEN: l.token }; logins.delete(String(b.loginId)); }
  if (CLI.has(p.type)) {
    if ('command' in b) p.command = str(b.command, 300);
    if ('extraArgs' in b) p.extraArgs = str(b.extraArgs, 1000).split(/\s+/).filter(Boolean);
    if ('permissionMode' in b) p.permissionMode = PERMS.includes(b.permissionMode) ? b.permissionMode : 'default';
    if ('sandbox' in b) p.sandbox = SANDBOX.includes(b.sandbox) ? b.sandbox : '';
    if ('deviceId' in b) p.deviceId = db.devices.some(d => d.id === b.deviceId) ? b.deviceId : '';
    if ('mcpIds' in b) p.mcpIds = (Array.isArray(b.mcpIds) ? b.mcpIds : []).filter(id => db.mcps.some(m => m.id === id));
    if ('env' in b) p.env = parseEnv(b.env, p.env);
    if ('models' in b) p.models = str(b.models, 4000);
  } else if ('baseUrl' in b) {
    p.baseUrl = str(b.baseUrl, 300);
    let u; try { u = new URL(p.baseUrl); } catch { bad('URL invalide'); }
    if (!/^https?:$/.test(u.protocol)) bad('URL invalide (http ou https)');
  }
  if (b.apiKey) p.apiKey = str(b.apiKey, 500);
  if (b.clearKey) delete p.apiKey;
  if ('adminOnly' in b) p.adminOnly = !!b.adminOnly;
  modelCache.delete(p.id);
  return p;
}
R('POST', '/api/providers', c => {
  const type = ['claude-code', 'codex', 'ollama', 'openai'].includes(c.body.type) ? c.body.type : bad('Type inconnu');
  const p = providerFields(c.body, { id: newId(), type, name: '', adminOnly: CLI.has(type) });
  if (!p.name) bad('Nom requis');
  if (!CLI.has(type) && !p.baseUrl) bad('URL requise');
  db.providers.push(p); save(); audit('connecteur.cree', { par: c.user.name, type: p.type, nom: p.name }); return providerView(p, c.user);
}, { admin: true });
R('PATCH', '/api/providers/:id', c => { const p = providerFields(c.body, any(db.providers, c)); save(); audit('connecteur.modifie', { par: c.user.name, nom: p.name, champs: Object.keys(c.body).slice(0, 20) }); return providerView(p, c.user); }, { admin: true });
R('DELETE', '/api/providers/:id', c => {
  any(db.providers, c); stopRemote(c.p.id);
  db.providers = db.providers.filter(p => p.id !== c.p.id);
  for (const a of db.agents) if (a.providerId === c.p.id) { a.providerId = ''; a.model = ''; }
  save(); return { ok: true };
}, { admin: true });
R('GET', '/api/providers/:id/models', async c => {
  const p = any(db.providers, c);
  if (!canUse(c.user, p)) bad('Introuvable', 404);
  if (c.query.get('fresh')) modelCache.delete(p.id);
  try { return { ok: true, ...(await probe(p)) }; }
  catch (e) {
    const fallback = CLI.has(p.type) ? decorate(p, [{ id: '', label: 'Modèle par défaut' }, ...manualModels(p)]) : [];
    return { ok: false, models: fallback, info: e.name === 'TimeoutError' ? 'Pas de réponse (délai dépassé)' : (e.cause && e.cause.code ? `Injoignable (${e.cause.code})` : e.message) };
  }
});

/* Appareils (admin) + points d'entrée de l'agent distant */
/* Liaison en une commande : un code court, valable 30 minutes, donne accès à un script d'installation
   qui contient le jeton de l'appareil. Le jeton lui-même n'est jamais stocké en clair côté serveur. */
const pairs = new Map();
function newPair(d) {
  const token = crypto.randomBytes(24).toString('base64url'), code = crypto.randomBytes(8).toString('hex');
  d.tokenHash = sha(token);
  for (const [k, v] of pairs) if (v.id === d.id || v.exp < Date.now()) pairs.delete(k);
  pairs.set(code, { id: d.id, token, exp: Date.now() + 1800000 });
  return { token, code };
}
R('POST', '/api/devices', c => {
  const d = { id: newId(), name: str(c.body.name, 60) || bad('Nom requis'), tokenHash: '', info: {}, createdAt: Date.now() };
  const pair = newPair(d);
  db.devices.push(d); save(); audit('appareil.cree', { par: c.user.name, nom: d.name });
  return { ...deviceView(d), ...pair };
}, { admin: true });
R('POST', '/api/devices/:id/link', c => {
  const d = any(db.devices, c), pair = newPair(d);   // l'ancien jeton cesse de fonctionner
  save(); wake(dev(d));
  return { ...deviceView(d), ...pair };
}, { admin: true });
const origin = req => `${isHttps(req) ? 'https' : 'http'}://${hostOf(req)}`;
const shq1 = v => "'" + String(v).replace(/'/g, "'\\''") + "'";
function installSh(S, T) {
  return `#!/bin/sh
# MuxAI — relie cet appareil au serveur ${S}
set -e
S=${shq1(S)}; T=${shq1(T)}; D="$HOME/.muxai"
command -v node >/dev/null 2>&1 || { echo "Node.js 20 ou plus est requis (macOS : brew install node — sinon https://nodejs.org)."; exit 1; }
[ "$(node -p 'process.versions.node.split(".")[0]')" -ge 20 ] || { echo "Node.js 20 ou plus est requis (version actuelle : $(node -v))."; exit 1; }
mkdir -p "$D"; chmod 700 "$D"
curl -fsSL "$S/agent.js" -o "$D/muxai-agent.js"
printf '{"server":"%s","token":"%s"}\\n' "$S" "$T" > "$D/config.json"; chmod 600 "$D/config.json"
NODE="$(command -v node)"
cat > "$D/muxai" <<'CLI'
#!/bin/sh
# MuxAI — pilote l'agent de cet appareil : muxai stop | start | status | remove
D="$HOME/.muxai"; P="$HOME/Library/LaunchAgents/io.muxai.agent.plist"; U=muxai-agent.service
sd() { command -v systemctl >/dev/null 2>&1 && [ -f "$HOME/.config/systemd/user/$U" ]; }
running() { if [ -f "$P" ]; then launchctl list 2>/dev/null | grep -q io.muxai.agent; elif sd; then systemctl --user is-active -q $U; else [ -f "$D/agent.pid" ] && kill -0 "$(cat "$D/agent.pid")" 2>/dev/null; fi; }
stop() { if [ -f "$P" ]; then launchctl unload -w "$P" 2>/dev/null; elif sd; then systemctl --user disable --now $U >/dev/null 2>&1; elif [ -f "$D/agent.pid" ]; then kill "$(cat "$D/agent.pid")" 2>/dev/null; rm -f "$D/agent.pid"; fi; }
case "$1" in
  stop) stop; echo "MuxAI : agent coupé. Il ne redémarrera pas tout seul. Pour le relancer : muxai start" ;;
  start)
    [ -f "$D/config.json" ] || { echo "MuxAI : cet appareil n'est pas relié."; exit 1; }
    if [ -f "$P" ]; then launchctl load -w "$P"; elif sd; then systemctl --user enable --now $U >/dev/null 2>&1
    elif ! running; then nohup "$(cat "$D/node.path" 2>/dev/null || echo node)" "$D/muxai-agent.js" >> "$D/agent.log" 2>&1 & echo $! > "$D/agent.pid"; fi
    echo "MuxAI : agent lancé." ;;
  status)
    if running; then echo "MuxAI : agent en marche."; else echo "MuxAI : agent coupé."; fi
    [ -f "$D/config.json" ] && echo "Serveur : $(grep -o '"server":"[^"]*"' "$D/config.json" | cut -d'"' -f4)" ;;
  remove)
    stop; rm -f "$P" "$HOME/.config/systemd/user/$U" "$D/muxai-agent.js" "$D/config.json" "$D/agent.pid" "$D/node.path"
    for b in "$HOME/.local/bin" /opt/homebrew/bin /usr/local/bin; do [ -L "$b/muxai" ] && rm -f "$b/muxai"; done
    rm -f "$D/muxai"; echo "MuxAI : agent arrêté et retiré de cet appareil." ;;
  *) echo "Usage : muxai stop | start | status | remove" ;;
esac
CLI
chmod 755 "$D/muxai"; printf '%s\n' "$NODE" > "$D/node.path"; M="$D/muxai"
for b in "$HOME/.local/bin" /opt/homebrew/bin /usr/local/bin; do case ":$PATH:" in *":$b:"*) if [ -d "$b" ] && [ -w "$b" ]; then ln -sf "$D/muxai" "$b/muxai"; M=muxai; break; fi ;; esac; done
case "$(uname -s)" in
  Darwin)
    P="$HOME/Library/LaunchAgents/io.muxai.agent.plist"; mkdir -p "$HOME/Library/LaunchAgents"
    cat > "$P" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>io.muxai.agent</string>
<key>ProgramArguments</key><array><string>$NODE</string><string>$D/muxai-agent.js</string></array>
<key>EnvironmentVariables</key><dict><key>PATH</key><string>$PATH</string></dict>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>StandardOutPath</key><string>$D/agent.log</string><key>StandardErrorPath</key><string>$D/agent.log</string>
</dict></plist>
PLIST
    O="$HOME/Library/LaunchAgents/fr.muxai.agent.plist"; [ -f "$O" ] && { launchctl unload "$O" 2>/dev/null; rm -f "$O"; }   # ancien nom de l'agent
    launchctl unload "$P" 2>/dev/null || true; launchctl load -w "$P"
    ;;
  *)
    if command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
      U="$HOME/.config/systemd/user"; mkdir -p "$U"
      printf '[Unit]\\nDescription=MuxAI agent\\n\\n[Service]\\nExecStart=%s %s\\nEnvironment=PATH=%s\\nRestart=always\\nRestartSec=5\\n\\n[Install]\\nWantedBy=default.target\\n' "$NODE" "$D/muxai-agent.js" "$PATH" > "$U/muxai-agent.service"
      systemctl --user daemon-reload; systemctl --user enable --now muxai-agent.service >/dev/null 2>&1; systemctl --user restart muxai-agent.service
      loginctl enable-linger "$(id -un)" >/dev/null 2>&1 || true   # démarre au boot, sans attendre l'ouverture de session
    else
      [ -f "$D/agent.pid" ] && kill "$(cat "$D/agent.pid")" 2>/dev/null || true
      nohup "$NODE" "$D/muxai-agent.js" >> "$D/agent.log" 2>&1 & echo $! > "$D/agent.pid"
      BOOT=0
    fi
    ;;
esac
echo "MuxAI : cet appareil est relié à $S. Journal : $D/agent.log"
if [ -n "$BOOT" ]; then echo "Il tourne en arrière-plan, terminal fermé. Sans systemd sur cette machine, il ne repart pas au redémarrage : lance « $M start »."; else echo "Il tourne en arrière-plan, terminal fermé, et repart au redémarrage."; fi
echo "Le couper : $M stop    Le relancer : $M start    Le retirer : $M remove"
`;
}
const UNINSTALL_SH = `#!/bin/sh
D="$HOME/.muxai"
P="$HOME/Library/LaunchAgents/io.muxai.agent.plist"; [ -f "$P" ] && { launchctl unload "$P" 2>/dev/null; rm -f "$P"; }
command -v systemctl >/dev/null 2>&1 && systemctl --user disable --now muxai-agent.service >/dev/null 2>&1; rm -f "$HOME/.config/systemd/user/muxai-agent.service"
[ -f "$D/agent.pid" ] && kill "$(cat "$D/agent.pid")" 2>/dev/null
rm -f "$D/muxai-agent.js" "$D/config.json" "$D/agent.pid" "$D/node.path" "$D/muxai"
for b in "$HOME/.local/bin" /opt/homebrew/bin /usr/local/bin; do [ -L "$b/muxai" ] && rm -f "$b/muxai"; done
echo "MuxAI : agent arrêté et retiré de cet appareil."
`;
function installPs1(S, T) {
  const q = v => "'" + String(v).replace(/'/g, "''") + "'";
  return `# MuxAI — relie cet appareil au serveur ${S}
$ErrorActionPreference = 'Stop'
$S = ${q(S)}; $T = ${q(T)}; $D = Join-Path $env:USERPROFILE '.muxai'
$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) { Write-Host 'Node.js 20 ou plus est requis : winget install OpenJS.NodeJS.LTS'; return }
if ([int](& node -p 'process.versions.node.split(\".\")[0]') -lt 20) { Write-Host 'Node.js 20 ou plus est requis.'; return }
New-Item -ItemType Directory -Force $D | Out-Null
Invoke-WebRequest "$S/agent.js" -OutFile (Join-Path $D 'muxai-agent.js') -UseBasicParsing
[IO.File]::WriteAllText((Join-Path $D 'config.json'), (@{ server = $S; token = $T } | ConvertTo-Json))
$cmd = "& '" + $node.Source + "' '" + (Join-Path $D 'muxai-agent.js') + "' *>> '" + (Join-Path $D 'agent.log') + "'"
$act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -WindowStyle Hidden -Command "' + $cmd + '"')
$trg = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$set = New-ScheduledTaskSettingsSet -ExecutionTimeLimit 0 -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName 'MuxAI Agent' -Action $act -Trigger $trg -Settings $set -Force | Out-Null
@'
param($a)
$T = 'MuxAI Agent'; $D = Join-Path $env:USERPROFILE '.muxai'
function Agents { Get-CimInstance Win32_Process -Filter "Name='node.exe'" | Where-Object { $_.CommandLine -like '*muxai-agent.js*' } }
function Halt { Disable-ScheduledTask -TaskName $T -ErrorAction SilentlyContinue | Out-Null; Stop-ScheduledTask -TaskName $T -ErrorAction SilentlyContinue; Agents | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } }
switch ($a) {
  'stop' { Halt; Write-Host 'MuxAI : agent coupe. Il ne redemarrera pas tout seul. Pour le relancer : muxai start' }
  'start' { Enable-ScheduledTask -TaskName $T | Out-Null; Start-ScheduledTask -TaskName $T; Write-Host 'MuxAI : agent lance.' }
  'status' { if (Agents) { Write-Host 'MuxAI : agent en marche.' } else { Write-Host 'MuxAI : agent coupe.' } }
  'remove' { Halt; Unregister-ScheduledTask -TaskName $T -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $D 'muxai-agent.js'), (Join-Path $D 'config.json'), (Join-Path $env:LOCALAPPDATA 'Microsoft\\WindowsApps\\muxai.cmd') -ErrorAction SilentlyContinue
    Write-Host 'MuxAI : agent arrete et retire de cet appareil.' }
  default { Write-Host 'Usage : muxai stop | start | status | remove' }
}
'@ | Set-Content -Encoding ASCII (Join-Path $D 'muxai.ps1')
'@powershell -NoProfile -ExecutionPolicy Bypass -File "%USERPROFILE%\\.muxai\\muxai.ps1" %*' | Set-Content -Encoding ASCII (Join-Path $env:LOCALAPPDATA 'Microsoft\\WindowsApps\\muxai.cmd')
Start-ScheduledTask -TaskName 'MuxAI Agent'
Write-Host "MuxAI : cet appareil est relie a $S. Journal : $D\\agent.log"
Write-Host "Il tourne en arriere-plan et repart a chaque ouverture de session."
Write-Host "Le couper : muxai stop    Le relancer : muxai start    Le retirer : muxai remove"
`;
}
const UNINSTALL_PS1 = `Stop-ScheduledTask -TaskName 'MuxAI Agent' -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'MuxAI Agent' -Confirm:$false -ErrorAction SilentlyContinue
$D = Join-Path $env:USERPROFILE '.muxai'
Remove-Item (Join-Path $D 'muxai-agent.js'), (Join-Path $D 'config.json') -ErrorAction SilentlyContinue
Write-Host 'MuxAI : agent arrete et retire de cet appareil.'
`;
const sendText = (res, code, text) => { res.writeHead(code, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(text); };
R('GET', '/i/(uninstall|[a-f0-9]{16})(\\.ps1)?', c => {
  const m = /^\/i\/(uninstall|[a-f0-9]{16})(\.ps1)?$/.exec(new URL(c.req.url, 'http://x').pathname), ps = !!m[2], ip = 'code:' + clientIp(c.req);
  if (m[1] === 'uninstall') { sendText(c.res, 200, ps ? UNINSTALL_PS1 : UNINSTALL_SH); return RAW; }
  throttle(ip);
  const p = pairs.get(m[1]);
  if (!p || p.exp < Date.now()) { failed(ip); sendText(c.res, 404, ps ? "Write-Host 'MuxAI : ce lien a expire. Genere une nouvelle commande dans Appareils.'\n" : "echo 'MuxAI : ce lien a expiré. Génère une nouvelle commande dans Appareils.'; exit 1\n"); return RAW; }
  sendText(c.res, 200, ps ? installPs1(origin(c.req), p.token) : installSh(origin(c.req), p.token));
  return RAW;
}, { pub: true });
R('GET', '/api/devices', () => db.devices.map(deviceView), { admin: true });
R('DELETE', '/api/devices/:id', c => {
  const d = any(db.devices, c);
  if (db.providers.some(p => p.deviceId === d.id)) bad('Un connecteur utilise cet appareil : modifie-le d’abord', 409);
  for (const j of [...dev(d).jobs.values()]) j.fail('Appareil supprimé');
  wake(dev(d)); live.delete(d.id);
  db.devices = db.devices.filter(x => x !== d); save(); return { ok: true };
}, { admin: true });
R('POST', '/api/device/poll', c => {
  const d = c.device, s = dev(d), i = c.body.info || {};
  for (const [k, v] of pairs) if (v.id === d.id) pairs.delete(k); // l'appareil est relié : son code de liaison ne sert plus
  const info = { hostname: str(i.hostname, 80), platform: str(i.platform, 40), version: str(i.version, 20), clis: (Array.isArray(i.clis) ? i.clis : []).slice(0, 8).map(x => str(x, 80)) };
  if (JSON.stringify(info) !== JSON.stringify(d.info)) { d.info = info; save(); }
  if (s.waiter) s.waiter();
  let timer = null;
  const respond = () => { clearTimeout(timer); s.waiter = null; sendJson(c.res, 200, { jobs: s.queue.splice(0), cancel: s.cancels.splice(0) }); };
  if (s.queue.length || s.cancels.length) respond();
  else { s.waiter = respond; timer = setTimeout(respond, 25000); c.res.on('close', () => { if (s.waiter === respond) { clearTimeout(timer); s.waiter = null; s.seen = 0; } }); }
  return RAW;
}, { device: true });
R('POST', '/api/device/out', c => { const j = dev(c.device).jobs.get(String(c.body.id)); if (!j) return { ok: false }; j.out(String(c.body.data || '')); return { ok: true }; }, { device: true });
R('POST', '/api/device/done', c => {
  const j = dev(c.device).jobs.get(String(c.body.id)); if (!j) return { ok: false };
  if (c.body.error) j.fail(str(c.body.error, 500)); else j.done({ code: Number(c.body.code) || 0, err: str(c.body.err, 2000) });
  return { ok: true };
}, { device: true });

/* Serveurs MCP (admin) */
function mcpFields(b, m) {
  if ('name' in b) m.name = slug(b.name) || bad('Nom requis (lettres, chiffres, tirets)');
  if (db.mcps.some(x => x !== m && x.name === m.name)) bad('Ce nom est déjà utilisé');
  if ('transport' in b) m.transport = ['http', 'sse'].includes(b.transport) ? b.transport : 'stdio';
  if ('brand' in b) m.brand = Object.hasOwn(BRANDS, 'mcp-' + b.brand) ? String(b.brand) : '';
  if ('headers' in b) m.headers = parseHeaders(b.headers, m.headers);
  if ('command' in b) m.command = str(b.command, 300);
  if ('args' in b) m.args = str(b.args, 2000).split('\n').map(s => s.trim()).filter(Boolean);
  if ('url' in b) m.url = str(b.url, 500);
  if ('env' in b) m.env = parseEnv(b.env, m.env);
  if (m.transport !== 'stdio') { try { if (!/^https?:$/.test(new URL(m.url).protocol)) throw 0; } catch { bad('URL invalide'); } }
  else if (!m.command) bad('Commande requise');
  return m;
}
R('POST', '/api/mcps', c => { const m = mcpFields(c.body, { id: newId(), name: '', transport: 'stdio', command: '', args: [], env: {}, url: '' }); db.mcps.push(m); save(); return mcpView(m); }, { admin: true });
R('PATCH', '/api/mcps/:id', c => { const m = mcpFields(c.body, any(db.mcps, c)); save(); return mcpView(m); }, { admin: true });
R('DELETE', '/api/mcps/:id', c => {
  any(db.mcps, c);
  db.mcps = db.mcps.filter(m => m.id !== c.p.id);
  for (const p of db.providers) if (p.mcpIds) p.mcpIds = p.mcpIds.filter(id => id !== c.p.id);
  save(); return { ok: true };
}, { admin: true });

/* Installation d'un outil MCP en une commande : /m/<outil>-<code>. Le script vérifie ce qui est déjà installé sur la machine,
   propose d'installer ce qui manque, puis prévient le serveur, qui crée l'outil et l'active sur les connecteurs choisis. */
const setups = new Map();
R('POST', '/api/mcps/setup', c => {
  const mcp = mcpFields(c.body, { id: newId(), name: '', transport: 'stdio', command: '', args: [], env: {}, url: '' });
  const on = (Array.isArray(c.body.on) ? c.body.on : []).filter(id => db.providers.some(p => p.id === id && CLI.has(p.type)));
  for (const [k, v] of setups) if (v.exp < Date.now()) setups.delete(k);
  const code = mcp.name + '-' + crypto.randomBytes(8).toString('hex');
  setups.set(code, { mcp, on, label: str(c.body.label, 60).replace(/[\x00-\x1f\x7f\u2028\u2029]+/g, ' ').trim() || mcp.name, exp: Date.now() + 1800000, done: false });
  return { code };
}, { admin: true });
R('GET', '/api/mcps/setup', c => { const s = setups.get(c.query.get('c') || ''); return { done: !!(s && s.done), expired: !s || s.exp < Date.now() }; }, { admin: true });
const SETUP_RE = '/m/[a-z0-9_-]{1,40}-[a-f0-9]{16}';
const setupOf = c => { const k = /^\/m\/([a-z0-9_-]+)/.exec(new URL(c.req.url, 'http://x').pathname)[1], s = setups.get(k); const ip = 'code:' + clientIp(c.req); throttle(ip); if (!s || s.exp <= Date.now()) failed(ip); return s && s.exp > Date.now() ? [k, s] : [k, null]; };
R('POST', SETUP_RE + '/done', c => {
  const [, s] = setupOf(c); if (!s) bad('Lien expiré', 404);
  let m = db.mcps.find(x => x.name === s.mcp.name); if (!m) { m = s.mcp; db.mcps.push(m); }
  for (const p of db.providers) if (s.on.includes(p.id)) p.mcpIds = [...new Set([...(p.mcpIds || []), m.id])];
  save(); s.done = true; return { ok: true };
}, { pub: true });
R('GET', SETUP_RE + '(\\.ps1)?', c => {
  const ps = /\.ps1$/.test(new URL(c.req.url, 'http://x').pathname), [k, s] = setupOf(c);
  if (!s) { sendText(c.res, 404, ps ? "Write-Host 'MuxAI : ce lien a expire. Genere une nouvelle commande dans Outils MCP.'\n" : "echo 'MuxAI : ce lien a expiré. Génère une nouvelle commande dans Outils MCP.'; exit 1\n"); return RAW; }
  sendText(c.res, 200, (ps ? setupPs1 : setupSh)(origin(c.req), k, s)); return RAW;
}, { pub: true });
function setupSh(S, C, s) {
  const m = s.mcp, uv = m.command === 'uvx' || m.command === 'uv', node = m.command === 'npx' || m.command === 'node';
  const L = ['#!/bin/sh', '# MuxAI — vérifie, installe si besoin, puis connecte : ' + s.label.replace(/[^\p{L}\p{N} ._()-]/gu, ' '),
    'S=' + shq1(S) + '; C=' + shq1(C) + '; N=' + shq1(s.label),
    'OS="$(uname -s)"; PATH="$PATH:$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin"; export PATH',
    'have() { command -v "$1" >/dev/null 2>&1; }',
    'ok() { printf "\\342\\234\\223 %s\\n" "$1"; }',
    'die() { printf "%s\\n" "$1"; exit 1; }',
    'ask() { [ -n "$MUXAI_YES" ] && return 0; printf "%s [o/N] " "$1"; a=; { read a </dev/tty; } 2>/dev/null || a=; case "$a" in o|O|oui|Oui|y|Y) return 0;; esac; return 1; }'];
  if (m.brand === 'blender') L.push(
    'has_blender() { if [ "$OS" = Darwin ]; then [ -d /Applications/Blender.app ] || [ -d "$HOME/Applications/Blender.app" ] || have blender; else have blender || { have snap && snap list blender >/dev/null 2>&1; } || { have flatpak && flatpak info org.blender.Blender >/dev/null 2>&1; }; fi; }',
    'if has_blender; then ok "Blender est déjà installé."',
    'elif ask "Blender n\'est pas installé sur cette machine. L\'installer maintenant ?"; then',
    '  if [ "$OS" = Darwin ] && have brew; then brew install --cask blender || die "L\'installation de Blender a échoué."',
    '  elif [ "$OS" != Darwin ] && have snap; then sudo snap install blender --classic || die "L\'installation de Blender a échoué."',
    '  else die "Installe Blender depuis https://www.blender.org/download/ puis relance cette commande."; fi',
    'else die "Blender est nécessaire. Rien n\'a été installé."; fi');
  if (uv) L.push(
    'if have uvx; then ok "uv est déjà installé."',
    'elif ask "uv (qui lance l\'outil) n\'est pas installé. L\'installer maintenant ?"; then',
    '  if [ "$OS" = Darwin ] && have brew; then brew install uv; else curl -LsSf https://astral.sh/uv/install.sh | sh; fi',
    '  have uvx || die "L\'installation de uv a échoué."',
    'else die "uv est nécessaire. Rien de plus n\'a été installé."; fi');
  if (node) L.push(
    'if have npx; then ok "Node.js est déjà installé."',
    'elif ask "Node.js n\'est pas installé. L\'installer maintenant ?"; then',
    '  if [ "$OS" = Darwin ] && have brew; then brew install node; else die "Installe Node.js depuis https://nodejs.org puis relance cette commande."; fi',
    '  have npx || die "L\'installation de Node.js a échoué."',
    'else die "Node.js est nécessaire. Rien de plus n\'a été installé."; fi');
  if (m.brand === 'blender') L.push(
    'if uvx mcp-for-blender addon-paths 2>/dev/null | grep -q "Existing MCP for Blender installs"; then ok "Le module MCP est déjà installé dans Blender."',
    'elif ask "Le module MCP n\'est pas installé dans Blender. L\'installer maintenant ?"; then',
    '  uvx mcp-for-blender install-addon || die "Module non installé. Ouvre Blender une fois, ferme-le, puis relance cette commande."',
    'else die "Le module MCP est nécessaire. Rien de plus n\'a été installé."; fi');
  if (m.brand === 'fusion') L.push(
    'if curl -s -o /dev/null --max-time 3 ' + shq1(m.url) + '; then ok "Fusion répond."',
    'else echo "Fusion ne répond pas : ouvre Fusion, puis coche « Fusion MCP Server » dans Préférences > Général > API."; fi');
  L.push('curl -fsS -X POST "$S/m/$C/done" >/dev/null 2>&1 || die "Connexion à MuxAI impossible : le lien a peut-être expiré."', 'ok "$N est connecté à MuxAI."');
  if (m.brand === 'blender') L.push('echo "Dernière étape, dans Blender : coche « MCP for Blender » dans Préférences > Modules complémentaires, puis touche N > « Start MCP Server »."');
  return L.join('\n') + '\n';
}
function setupPs1(S, C, s) {
  const q = v => "'" + String(v).replace(/'/g, "''") + "'", ascii = v => String(v).normalize('NFD').replace(/[^\x20-\x7e]/g, '');
  const m = s.mcp, uv = m.command === 'uvx' || m.command === 'uv', node = m.command === 'npx' || m.command === 'node';
  const L = ['# MuxAI - verifie, installe si besoin, puis connecte : ' + ascii(s.label),
    '$S = ' + q(S) + '; $C = ' + q(C) + '; $N = ' + q(ascii(s.label)),
    'function Have($n) { [bool](Get-Command $n -ErrorAction SilentlyContinue) }',
    'function Ask($t) { if ($env:MUXAI_YES) { return $true }; return ((Read-Host "$t [o/N]") -match "^(o|oui|y)") }',
    'function Fresh { $env:Path = [Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [Environment]::GetEnvironmentVariable("Path","User") + ";$env:USERPROFILE\\.local\\bin" }',
    'function Inst($id) { winget install -e --id $id --accept-source-agreements --accept-package-agreements; Fresh }'];
  if (m.brand === 'blender') L.push(
    'function HasBlender { (Have blender) -or [bool](Get-ChildItem "$env:ProgramFiles\\Blender Foundation\\*\\blender.exe" -ErrorAction SilentlyContinue) }',
    'if (HasBlender) { Write-Host "OK  Blender est deja installe." }',
    'elseif (Ask "Blender n\'est pas installe sur cette machine. L\'installer maintenant ?") { Inst "BlenderFoundation.Blender"; if (-not (HasBlender)) { Write-Host "L\'installation de Blender a echoue."; return } }',
    'else { Write-Host "Blender est necessaire. Rien n\'a ete installe."; return }');
  if (uv) L.push(
    'if (Have uvx) { Write-Host "OK  uv est deja installe." }',
    'elseif (Ask "uv (qui lance l\'outil) n\'est pas installe. L\'installer maintenant ?") { Inst "astral-sh.uv"; if (-not (Have uvx)) { Write-Host "L\'installation de uv a echoue."; return } }',
    'else { Write-Host "uv est necessaire. Rien de plus n\'a ete installe."; return }');
  if (node) L.push(
    'if (Have npx) { Write-Host "OK  Node.js est deja installe." }',
    'elseif (Ask "Node.js n\'est pas installe. L\'installer maintenant ?") { Inst "OpenJS.NodeJS.LTS"; if (-not (Have npx)) { Write-Host "L\'installation de Node.js a echoue."; return } }',
    'else { Write-Host "Node.js est necessaire. Rien de plus n\'a ete installe."; return }');
  if (m.brand === 'blender') L.push(
    'if ((& uvx mcp-for-blender addon-paths 2>$null | Out-String) -match "Existing MCP for Blender installs") { Write-Host "OK  Le module MCP est deja installe dans Blender." }',
    'elseif (Ask "Le module MCP n\'est pas installe dans Blender. L\'installer maintenant ?") { & uvx mcp-for-blender install-addon; if ($LASTEXITCODE -ne 0) { Write-Host "Module non installe. Ouvre Blender une fois, ferme-le, puis relance cette commande."; return } }',
    'else { Write-Host "Le module MCP est necessaire. Rien de plus n\'a ete installe."; return }');
  if (m.brand === 'fusion') L.push('try { Invoke-WebRequest ' + q(m.url) + ' -UseBasicParsing -TimeoutSec 3 | Out-Null; Write-Host "OK  Fusion repond." } catch { if (-not $_.Exception.Response) { Write-Host "Fusion ne repond pas : ouvre Fusion, puis coche Fusion MCP Server dans Preferences > General > API." } }');
  L.push('try { Invoke-RestMethod -Method Post "$S/m/$C/done" | Out-Null; Write-Host "OK  $N est connecte a MuxAI." } catch { Write-Host "Connexion a MuxAI impossible : le lien a peut-etre expire." }');
  if (m.brand === 'blender') L.push('Write-Host "Derniere etape, dans Blender : coche MCP for Blender dans Preferences > Modules complementaires, puis touche N > Start MCP Server."');
  return L.join('\r\n') + '\r\n';
}

/* ───────────── Ajout guidé : logos, détection, connexion du compte, test ───────────── */
/* Logos : téléchargés une fois depuis le site officiel du service, puis servis depuis data/logos. */
const BRANDS = { 'claude-code': 'https://claude.ai', codex: 'https://openai.com', ollama: 'https://ollama.com', xai: 'https://x.ai', openai: 'https://openai.com', openrouter: 'https://openrouter.ai', mistral: 'https://mistral.ai', lmstudio: 'https://lmstudio.ai' };
const MCP_SITES = { blender: 'https://www.blender.org', fusion: 'https://www.autodesk.com', adobe: 'https://www.adobe.com', canva: 'https://www.canva.com', figma: 'https://www.figma.com',
  google: 'https://workspace.google.com', ms365: 'https://www.microsoft.com', notion: 'https://www.notion.com', airtable: 'https://airtable.com', asana: 'https://asana.com', monday: 'https://monday.com',
  github: 'https://github.com', linear: 'https://linear.app', sentry: 'https://sentry.io', atlassian: 'https://www.atlassian.com', supabase: 'https://supabase.com', vercel: 'https://vercel.com',
  stripe: 'https://stripe.com', huggingface: 'https://huggingface.co', playwright: 'https://playwright.dev' };
for (const [k, v] of Object.entries(MCP_SITES)) BRANDS['mcp-' + k] = v;
const logoJobs = new Map(), logoFails = new Map();
/* Type réel de l'image d'après ses premiers octets (certains sites envoient un Content-Type faux). */
function imageType(buf) {
  const hex = buf.subarray(0, 12).toString('hex'), txt = buf.subarray(0, 300).toString('utf8').trimStart().toLowerCase();
  if (hex.startsWith('89504e47')) return 'image/png';
  if (hex.startsWith('ffd8ff')) return 'image/jpeg';
  if (hex.startsWith('47494638')) return 'image/gif';
  if (hex.startsWith('00000100')) return 'image/x-icon';
  if (hex.startsWith('52494646') && hex.slice(16, 24) === '57454250') return 'image/webp';
  if (txt.startsWith('<svg') || (txt.startsWith('<?xml') && txt.includes('<svg'))) return 'image/svg+xml';
  return null;
}
async function fetchLogo(key) {
  const site = BRANDS[key], domain = new URL(site).hostname, cands = [];
  const headers = { 'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15', Accept: 'text/html,image/*,*/*;q=0.8' };
  try {
    const r = await fetch(site, { headers, signal: AbortSignal.timeout(8000) });
    if (r.ok) {
      const html = (await r.text()).slice(0, 400000);
      const tags = [...html.matchAll(/<link\b[^>]*>/gi)].map(m => m[0]).filter(t => /rel=["']?[^"'>]*icon/i.test(t));
      const score = t => (/apple-touch/i.test(t) ? 3 : /svg/i.test(t) ? 2 : 1);
      for (const t of tags.sort((x, y) => score(y) - score(x))) { const m = /href=["']?([^"'\s>]+)/i.exec(t); if (m) { try { cands.push(new URL(m[1].replace(/&amp;/g, '&'), r.url).href); } catch {} } }
    } else console.log(`[logo] ${key} : ${site} a répondu ${r.status}`);
  } catch (e) { console.log(`[logo] ${key} : ${site} injoignable (${(e.cause && e.cause.code) || e.name})`); }
  // Sources de secours : chemins habituels du site, puis services publics de favicons.
  const list = [...cands.slice(0, 4), site + '/apple-touch-icon.png', site + '/favicon.ico',
    `https://icons.duckduckgo.com/ip3/${domain}.ico`, `https://www.google.com/s2/favicons?domain=${domain}&sz=128`];
  for (const u of list) {
    try {
      if (!u.startsWith('https://')) continue;
      const r = await fetch(u, { headers, signal: AbortSignal.timeout(8000) });
      if (!r.ok) { console.log(`[logo] ${key} : ${u} → ${r.status}`); continue; }
      const buf = Buffer.from(await r.arrayBuffer()), type = imageType(buf);
      if (!type || buf.length < 100 || buf.length > 1500000) { console.log(`[logo] ${key} : ${u} → pas une image exploitable`); continue; }
      writeAtomic(path.join(LOGO_DIR, key), buf); writeAtomic(path.join(LOGO_DIR, key + '.type'), type);
      console.log(`[logo] ${key} : enregistré depuis ${u}`);
      return true;
    } catch (e) { console.log(`[logo] ${key} : ${u} → ${(e.cause && e.cause.code) || e.name}`); }
  }
  return false;
}
R('GET', '/api/logo', async c => {
  const key = String(c.query.get('k') || ''), file = path.join(LOGO_DIR, key);
  if (!Object.hasOwn(BRANDS, key)) bad('Introuvable', 404);
  if (!fs.existsSync(file)) {
    if (Date.now() - (logoFails.get(key) || 0) < 120000) bad('Logo indisponible', 404);
    if (!logoJobs.has(key)) logoJobs.set(key, fetchLogo(key).finally(() => logoJobs.delete(key)));
    if (!(await logoJobs.get(key))) { logoFails.set(key, Date.now()); bad('Logo indisponible', 404); }
  }
  c.res.writeHead(200, { 'Content-Type': fs.readFileSync(file + '.type', 'utf8'), 'Cache-Control': 'private, max-age=86400', 'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'" });
  c.res.end(fs.readFileSync(file));
  return RAW;
});

R('POST', '/api/detect', async c => {
  const brand = String(c.body.brand || '');
  if (brand === 'ollama') {
    for (const baseUrl of ['http://127.0.0.1:11434', 'http://host.docker.internal:11434']) {
      try { const r = await fetch(baseUrl + '/api/tags', { signal: AbortSignal.timeout(1500) }); if (r.ok) return { ok: true, baseUrl, info: `${((await r.json()).models || []).length} modèle(s) installé(s)` }; } catch {}
    }
    return { ok: false, info: 'Aucun serveur Ollama trouvé sur cette machine' };
  }
  if (!CLI.has(brand)) bad('Service inconnu');
  const p = { type: brand, command: str(c.body.command, 300), deviceId: db.devices.some(d => d.id === c.body.deviceId) ? c.body.deviceId : '' };
  try { return { ok: true, info: (await cliVersion(p)) || 'version inconnue' }; }
  catch (e) { return { ok: false, info: e.name === 'TimeoutError' ? 'pas de réponse' : e.message }; }
}, { admin: true });

/* Connexion du compte : le serveur lance la commande de connexion du CLI dans un pseudo-terminal,
   relève l'adresse à ouvrir, transmet le code collé par l'utilisateur, puis récupère le jeton. */
const logins = new Map();
/* Pseudo-terminal sans dépendance. macOS : son « script » exige un vrai terminal en entrée, on passe donc par python3.
   Le relais place l'enfant dans un terminal de 400 colonnes pour que l'adresse de connexion ne soit pas coupée. */
const PTY_PY = `import os,pty,sys,select,fcntl,termios,struct
pid,fd=pty.fork()
if pid==0:
    try: fcntl.ioctl(0,termios.TIOCSWINSZ,struct.pack('HHHH',50,400,0,0))
    except Exception: pass
    os.execvp(sys.argv[1],sys.argv[1:])
src=[fd,0]
while True:
    try: r,_,_=select.select(src,[],[])
    except InterruptedError: continue
    if fd in r:
        try: d=os.read(fd,4096)
        except OSError: d=b''
        if not d: break
        os.write(1,d)
    if 0 in r:
        d=os.read(0,4096)
        if d: os.write(fd,d)
        else: src=[fd]
st=os.waitpid(pid,0)[1]
sys.exit((st>>8)&255 if (st&127)==0 else 1)
`;
/* Faux « open » placé devant le PATH du CLI pendant la connexion : il note l'adresse demandée et échoue,
   pour que ce soit MuxAI qui ouvre la page (dans le navigateur de l'utilisateur) et non le CLI (sur le serveur). */
const SHIM_DIR = path.join(DATA, 'shims');
fs.mkdirSync(SHIM_DIR, { recursive: true, mode: 0o700 });
for (const n of ['open', 'xdg-open']) fs.writeFileSync(path.join(SHIM_DIR, n), '#!/bin/sh\n[ -n "$MUXAI_URL_FILE" ] && printf \'%s\\n\' "$@" >> "$MUXAI_URL_FILE"\nexit 1\n', { mode: 0o755 });
const LOGIN_URL = /^https:\/\/([\w-]+\.)*(claude\.ai|anthropic\.com|claude\.com|openai\.com|chatgpt\.com)\//;
const ANSI = /\x1b\[[0-9;?]*[ -\/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]/g;
const shq = a => "'" + String(a).replace(/'/g, "'\\''") + "'";
function endLogin(l, status, error) { if (l.status !== 'running') return; l.status = status; l.error = error || ''; clearTimeout(l.timer); clearInterval(l.watch); fs.rmSync(l.urlFile, { force: true }); try { l.child.kill('SIGKILL'); } catch {} setTimeout(() => logins.delete(l.id), 600000).unref(); }
R('POST', '/api/login/start', c => {
  const type = CLI.has(c.body.type) ? c.body.type : bad('Service inconnu');
  const cmd = str(c.body.command, 300) || (type === 'codex' ? 'codex' : 'claude');
  // mode « auth » : connexion complète du CLI à claude.ai (nécessaire au contrôle à distance), sans jeton à récupérer.
  const mode = type === 'claude-code' && c.body.mode === 'auth' ? 'auth' : '';
  const argv = [cmd, ...(type === 'codex' ? ['login'] : mode ? ['auth', 'login'] : ['setup-token'])];
  const inner = ['sh', '-c', 'stty cols 400 rows 50 2>/dev/null; exec "$0" "$@"', ...argv];
  for (const l of logins.values()) if (l.userId === c.user.id) endLogin(l, 'error', 'Remplacée par une nouvelle tentative');
  const l = { id: newId(), userId: c.user.id, type, out: '', url: '', token: '', status: 'running', error: '' };
  l.urlFile = path.join(SHIM_DIR, 'url-' + l.id);
  const env = { ...process.env, TERM: 'xterm', PATH: SHIM_DIR + path.delimiter + (process.env.PATH || ''), BROWSER: path.join(SHIM_DIR, 'open'), MUXAI_URL_FILE: l.urlFile };
  const python = process.platform === 'darwin' || process.env.MUXAI_PTY === 'python';
  try { l.child = python ? spawn('python3', ['-c', PTY_PY, ...argv], { env }) : spawn('script', ['-qfec', inner.map(shq).join(' '), '/dev/null'], { env }); }
  catch (e) { bad('Impossible de lancer la connexion : ' + e.message, 500); }
  logins.set(l.id, l);
  const onData = d => {
    l.out = (l.out + String(d).replace(ANSI, '').replace(/\r/g, '')).slice(-6000);
    const flat = l.out.replace(/\s+/g, ' ');
    if (!l.url) { const u = (flat.match(/https:\/\/[^\s"'<>]+/g) || []).find(x => LOGIN_URL.test(x)); if (u) l.url = u; }
    const t = /sk-ant-oat\d*-[\w-]{20,}/.exec(l.out);
    if (t && type === 'claude-code' && !mode) { l.token = t[0]; l.out = l.out.replace(/sk-ant-oat[\w-]+/g, '[jeton reçu]'); endLogin(l, 'done'); }
  };
  l.child.stdout.on('data', onData); l.child.stderr.on('data', onData);
  l.watch = setInterval(() => { if (l.url) return; try { const u = fs.readFileSync(l.urlFile, 'utf8').split('\n').find(x => LOGIN_URL.test(x)); if (u) l.url = u.trim(); } catch {} }, 400);
  l.child.stdin.on('error', () => {});
  l.child.on('error', e => endLogin(l, 'error', e.code === 'ENOENT' ? (python ? 'python3 est introuvable sur le serveur (sur macOS : lance « xcode-select --install »). Sinon, colle le jeton à la main dans les réglages du connecteur.' : 'La commande « script » est introuvable sur le serveur : colle le jeton à la main dans les réglages du connecteur.') : e.message));
  l.child.on('close', code => { if (l.status !== 'running') return; if (code === 0 && (type === 'codex' || mode)) endLogin(l, 'done'); else endLogin(l, 'error', l.out.trim().split('\n').filter(Boolean).slice(-3).join(' — ') || `La connexion s'est arrêtée (code ${code})`); });
  l.timer = setTimeout(() => endLogin(l, 'error', 'Délai de 10 minutes dépassé'), 600000);
  return { id: l.id };
}, { admin: true });
const myLogin = (c, id) => { const l = logins.get(String(id || '')); if (!l || l.userId !== c.user.id) bad('Connexion introuvable', 404); return l; };
R('GET', '/api/login/state', c => { const l = myLogin(c, c.query.get('id')); return { status: l.status, url: l.url, error: l.error, output: l.out.replace(/sk-ant-oat[\w-]+/g, '[jeton]').slice(-1500) }; }, { admin: true });
R('POST', '/api/login/input', async c => {
  const l = myLogin(c, c.body.id), text = str(c.body.text, 4000);
  if (l.status !== 'running') return { ok: true };
  if (l.type !== 'codex') { l.child.stdin.write(text + '\r'); return { ok: true }; }
  // Codex termine sa connexion par un retour vers http://localhost:<port>/auth/callback sur la machine du CLI.
  // Si le navigateur est ailleurs, l'utilisateur colle cette adresse et le serveur la rejoue localement.
  let u = null, port = '1455';
  try { u = new URL(text); } catch {}
  try { port = new URL(new URL(l.url).searchParams.get('redirect_uri')).port || port; } catch {}
  if (!u || !/^(localhost|127\.0\.0\.1)$/.test(u.hostname) || !u.pathname.startsWith('/auth/callback') || (u.port || '80') !== port) bad(`Colle l’adresse complète de la page : elle commence par http://localhost:${port}/auth/callback`);
  for (const host of ['localhost', '127.0.0.1']) {
    try { const r = await fetch(`http://${host}:${port}${u.pathname}${u.search}`, { signal: AbortSignal.timeout(15000), redirect: 'manual' }); if (r.status < 400) return { ok: true }; } catch {}
  }
  bad('Le CLI n’a pas accepté cette adresse. Relance la connexion et réessaie.');
}, { admin: true });
R('POST', '/api/login/cancel', c => { const l = myLogin(c, c.body.id); endLogin(l, 'error', 'Annulée'); logins.delete(l.id); return { ok: true }; }, { admin: true });

/* Test réel d'un connecteur : un vrai message pour les CLI, la liste des modèles pour les autres. */
R('POST', '/api/providers/:id/check', async c => {
  const p = any(db.providers, c); modelCache.delete(p.id);
  try {
    if (!CLI.has(p.type)) return { ok: true, info: (await probe(p)).info };
    let text = '';
    await drivers[p.type]({ provider: p, conv: {}, msgs: [{ role: 'user', content: 'Réponds uniquement par : OK' }], regenerate: true, system: '', model: '', cwd: null, signal: AbortSignal.timeout(90000), onText: t => { text += t; }, onTool() {} });
    return { ok: true, info: text.trim().slice(0, 80) };
  } catch (e) { return { ok: false, info: e.name === 'TimeoutError' ? 'Pas de réponse (délai dépassé)' : (e.cause && e.cause.code ? `Injoignable (${e.cause.code})` : e.message) }; }
}, { admin: true });

/* Contrôle à distance : lance « claude remote-control » sur le serveur et le garde en vie.
   La session devient visible et pilotable depuis claude.ai/code ; MuxAI affiche son lien. */
const remotes = new Map();
function ptySpawn(argv, env, cwd) {
  if (process.platform === 'darwin' || process.env.MUXAI_PTY === 'python') return spawn('python3', ['-c', PTY_PY, ...argv], { env, cwd });
  const inner = ['sh', '-c', 'stty cols 400 rows 50 2>/dev/null; exec "$0" "$@"', ...argv];
  return spawn('script', ['-qfec', inner.map(shq).join(' '), '/dev/null'], { env, cwd });
}
// Question de confiance posée par le CLI avant de démarrer (« Trust <dossier>? [y/N] ») : on la remonte telle quelle à l'interface.
const trustAsk = r => { const m = /Trust (\S[^\n]*?)\? \[y\/N\]\s*$/.exec(r.out); return m && r.status === 'starting' ? m[1] : ''; };
const remoteView = r => (r ? { status: r.status, url: r.url, error: r.error, cwd: r.cwd, ask: trustAsk(r), output: r.out.slice(-2500) } : { status: 'off', url: '', error: '', ask: '', output: '' });
function stopRemote(id) { const r = remotes.get(id); if (!r) return; r.stopped = true; try { r.child.kill('SIGTERM'); } catch {} remotes.delete(id); }
R('GET', '/api/providers/:id/remote', c => remoteView(remotes.get(any(db.providers, c).id)), { admin: true });
R('POST', '/api/providers/:id/remote', c => {
  const p = any(db.providers, c);
  if (c.body.action === 'stop') { stopRemote(p.id); return remoteView(null); }
  if (c.body.action === 'input') { const r = remotes.get(p.id); if (r && r.status !== 'error') r.child.stdin.write(str(c.body.text, 500) + '\r'); return remoteView(r); }
  if (p.type !== 'claude-code' || p.deviceId) bad('Le contrôle à distance n’est disponible que pour Claude Code sur ce serveur');
  stopRemote(p.id);
  let cwd = str(c.body.cwd, 500);
  // Sans dossier de projet, la session tourne dans un dossier nommé « MuxAI » : claude.ai/code nomme l'environnement d'après ce dossier.
  if (!cwd || !fs.existsSync(cwd)) { cwd = path.join(DATA, 'MuxAI'); fs.mkdirSync(cwd, { recursive: true, mode: 0o700 }); }
  // On s'appuie sur la connexion propre du CLI : le jeton de la connexion guidée ne sert qu'aux messages.
  const env = { ...process.env, ...(p.env || {}), TERM: 'xterm' }; delete env.CLAUDE_CODE_OAUTH_TOKEN;
  const label = str(c.body.label, 40), name = label ? `MuxAI · ${label}` : 'MuxAI';
  const r = { status: 'starting', url: '', error: '', out: '', cwd };
  remotes.set(p.id, r);
  const launch = withName => {
    r.out = ''; r.status = 'starting';
    r.child = ptySpawn([cliCmd(p), 'remote-control', ...(withName ? ['--name', name] : [])], env, cwd);
    const child = r.child;
    const onData = d => {
      r.out = (r.out + String(d).replace(ANSI, '').replace(/\r/g, '')).slice(-8000);
      // Seul un lien de session claude.ai/code compte : le CLI affiche aussi des liens de documentation.
      const u = (r.out.replace(/\s+/g, ' ').match(/https:\/\/[^\s"'<>]+/g) || []).filter(x => /^https:\/\/claude\.ai\/code[\/?]/.test(x));
      if (u.length) { r.url = u[u.length - 1].replace(/[.,)]+$/, ''); r.status = 'on'; }
    };
    child.stdout.on('data', onData); child.stderr.on('data', onData);
    child.stdin.on('error', () => {});
    child.on('error', e => { r.status = 'error'; r.error = e.code === 'ENOENT' ? 'python3 ou script est introuvable sur le serveur' : e.message; });
    child.on('close', code => {
      if (r.stopped || r.child !== child) return;
      // Version du CLI qui ne connaît pas --name : on relance sans, la session garde alors un nom automatique.
      if (withName && /unknown (option|argument)|unrecognized/i.test(r.out)) { try { return launch(false); } catch {} }
      r.status = 'error'; r.url = '';
      r.error = r.out.trim().split('\n').filter(Boolean).slice(-3).join(' — ') || `Le contrôle à distance s'est arrêté (code ${code})`;
    });
  };
  try { launch(true); } catch (e) { remotes.delete(p.id); bad('Impossible de lancer le contrôle à distance : ' + e.message, 500); }
  return remoteView(r);
}, { admin: true });

/* Mise à jour du CLI Claude Code depuis l'interface (sur ce serveur ou sur l'appareil). */
R('POST', '/api/providers/:id/update', async c => {
  const p = any(db.providers, c);
  if (p.type !== 'claude-code') bad('Mise à jour disponible uniquement pour Claude Code');
  let out = '';
  try {
    const { code, err } = await exec(p, { cmd: cliCmd(p), args: ['update'] }, AbortSignal.timeout(300000), d => { out = (out + d).slice(-3000); });
    modelCache.delete(p.id);
    const text = (out.replace(ANSI, '').trim() || err || '').split('\n').filter(Boolean).slice(-4).join(' — ');
    return { ok: code === 0, info: text || (code === 0 ? 'Mise à jour terminée' : `La commande s'est arrêtée (code ${code})`), version: await cliVersion(p).catch(() => '') };
  } catch (e) { return { ok: false, info: e.name === 'TimeoutError' ? 'Délai dépassé' : e.message }; }
}, { admin: true });

/* Commandes « / » de Claude Code : le CLI les annonce à son démarrage. On le lance, on lit cette annonce, on l'arrête aussitôt. */
const cleanSlash = list => list.filter(x => typeof x === 'string' && /^[\w:.-]{1,60}$/.test(x)).slice(0, 300);
R('GET', '/api/providers/:id/commands', async c => {
  const p = any(db.providers, c);
  if (!canUse(c.user, p)) bad('Introuvable', 404);
  if (p.type !== 'claude-code') return { list: [] };
  if (p.slash && p.slash.length && !c.query.get('fresh')) return { list: p.slash };
  const ac = new AbortController(), timer = setTimeout(() => ac.abort(), 20000);
  let list = null;
  try { await runCli({ provider: p, cwd: null, signal: ac.signal }, ['-p', '--output-format', 'stream-json', '--verbose'], 'ok', j => { if (j.type === 'system' && Array.isArray(j.slash_commands)) { list = j.slash_commands; ac.abort(); } }); } catch {}
  clearTimeout(timer);
  if (list) { p.slash = cleanSlash(list); save(); }
  return { list: p.slash || [] };
});

/* Agents (profils) */
const COLORS = ['orange', 'gris', 'vert', 'bleu', 'jaune', 'rose', 'turquoise'];
function agentFields(b, a, user) {
  if ('name' in b) a.name = str(b.name, 60) || bad('Nom requis');
  if ('color' in b) a.color = COLORS.includes(b.color) ? b.color : 'orange';
  if ('providerId' in b) a.providerId = canUse(user, db.providers.find(p => p.id === b.providerId)) ? b.providerId : '';
  if ('model' in b) a.model = a.providerId ? str(b.model, 160) : '';
  if ('system' in b) a.system = str(b.system, 50000);
  if ('shared' in b) a.shared = isAdmin(user) && !!b.shared;
  return a;
}
R('POST', '/api/agents', c => {
  const a = agentFields(c.body, { id: newId(), userId: c.user.id, name: '', color: 'orange', providerId: '', model: '', system: '', shared: false }, c.user);
  if (!a.name) bad('Nom requis');
  db.agents.push(a); save(); return a;
});
R('PATCH', '/api/agents/:id', c => { const a = agentFields(c.body, own(db.agents, c), c.user); save(); return a; });
R('DELETE', '/api/agents/:id', c => { own(db.agents, c); db.agents = db.agents.filter(a => a.id !== c.p.id); save(); return { ok: true }; });

/* ───────────── GitHub : un jeton, et la liste des organisations et dépôts ouverts aux IA ─────────────
   Le jeton n'est jamais donné aux CLI. Git le demande à un petit programme (credential helper) qui ne le
   rend que pour les dépôts cochés. C'est un garde-fou contre les erreurs, pas une barrière étanche : le jeton
   reste lisible dans le dossier de données par un programme qui irait le chercher. */
const GH_API = (process.env.MUXAI_GITHUB_API || 'https://api.github.com').replace(/\/+$/, '');
const GH_FILE = path.join(DATA, 'github.json'), GH_HELPER = path.join(DATA, 'git-credential-muxai.js'), REPOS = path.join(DATA, 'repos');
if (!db.github) db.github = { token: '', login: '', uid: 0, orgs: [], repos: [] };
fs.writeFileSync(GH_HELPER, "const fs=require('fs');let i='';process.stdin.on('data',d=>{i+=d}).on('end',()=>{if(process.argv[2]!=='get')return;" +
  "const kv={};for(const l of i.split('\\n')){const k=l.indexOf('=');if(k>0)kv[l.slice(0,k)]=l.slice(k+1)}" +
  "let g;try{g=JSON.parse(fs.readFileSync(" + JSON.stringify(GH_FILE) + ",'utf8'))}catch{return}" +
  "const m=/^([^\\/]+)\\/([^\\/]+?)(\\.git)?\\/?$/.exec(kv.path||'');if(!g.token||kv.host!=='github.com'||!m)return;" +
  "const o=m[1].toLowerCase(),r=o+'/'+m[2].toLowerCase();" +
  "if(g.orgs.includes(o)||g.repos.includes(r))process.stdout.write('username=x-access-token\\npassword='+g.token+'\\n');" +
  "else process.stderr.write('MuxAI : le depot '+r+' n\\'est pas ouvert aux IA. Un administrateur peut le cocher dans MuxAI > GitHub.\\n')});\n", { mode: 0o600 });
const ghSync = () => writeAtomic(GH_FILE, JSON.stringify({ token: db.github.token, orgs: db.github.orgs, repos: db.github.repos }));
ghSync();
const ghView = () => ({ connected: !!db.github.token, login: db.github.login, orgs: db.github.orgs, repos: db.github.repos });
const ghAllowed = full => { full = String(full).toLowerCase(); return db.github.orgs.includes(full.split('/')[0]) || db.github.repos.includes(full); };
function gitEnv() {
  const g = db.github; if (!g.token) return {};
  const cfg = [['credential.https://github.com.helper', ''], ['credential.https://github.com.helper', '!' + shq(process.execPath) + ' ' + shq(GH_HELPER)],
    ['credential.https://github.com.useHttpPath', 'true'], ['url.https://github.com/.insteadOf', 'git@github.com:'], ['url.https://github.com/.insteadOf', 'ssh://git@github.com/']];
  const mail = (g.uid ? g.uid + '+' : '') + g.login + '@users.noreply.github.com';
  const env = { GIT_TERMINAL_PROMPT: '0', GIT_CONFIG_COUNT: String(cfg.length), GIT_AUTHOR_NAME: g.login, GIT_AUTHOR_EMAIL: mail, GIT_COMMITTER_NAME: g.login, GIT_COMMITTER_EMAIL: mail };
  cfg.forEach(([k, v], i) => { env['GIT_CONFIG_KEY_' + i] = k; env['GIT_CONFIG_VALUE_' + i] = v; });
  return env;
}
async function gh(p, token = db.github.token) {
  if (!token) bad('GitHub n’est pas connecté', 409);
  let r;
  try { r = await fetch(GH_API + p, { headers: { Authorization: 'Bearer ' + token, Accept: 'application/vnd.github+json', 'User-Agent': 'MuxAI', 'X-GitHub-Api-Version': '2022-11-28' }, signal: AbortSignal.timeout(15000) }); }
  catch { bad('GitHub est injoignable depuis ce serveur', 502); }
  if (r.status === 401) bad('GitHub refuse ce jeton (faux, expiré ou révoqué)', 400);
  if (!r.ok) bad('GitHub a répondu ' + r.status, 502);
  return r.json();
}
async function ghAll(p) { const out = []; for (let i = 1; i <= 10; i++) { const l = await gh(p + (p.includes('?') ? '&' : '?') + 'per_page=100&page=' + i); if (!Array.isArray(l)) break; out.push(...l); if (l.length < 100) break; } return out; }
const ghCache = new Map();
async function ghRepos(owner) {
  owner = String(owner).toLowerCase(); if (!/^[\w.-]{1,100}$/.test(owner)) bad('Nom invalide');
  const hit = ghCache.get(owner); if (hit && hit.at > Date.now() - 300000) return hit.list;
  const raw = await ghAll(owner === db.github.login.toLowerCase() ? '/user/repos?affiliation=owner&sort=full_name' : '/orgs/' + owner + '/repos?sort=full_name');
  const list = raw.map(x => ({ name: String(x.name), full: String(x.full_name), private: !!x.private }));
  ghCache.set(owner, { at: Date.now(), list }); return list;
}
R('GET', '/api/github', () => ghView(), { admin: true });
R('POST', '/api/github', async c => {
  const token = str(c.body.token, 400).trim();
  if (!token) db.github.token = '';
  else { const u = await gh('/user', token); db.github.token = token; db.github.login = String(u.login || ''); db.github.uid = Number(u.id) || 0; }
  ghCache.clear(); ghSync(); save(); audit(token ? 'github.connecte' : 'github.deconnecte', { par: c.user.name }); return ghView();
}, { admin: true });
R('PATCH', '/api/github', c => {
  const list = (v, re) => [...new Set((Array.isArray(v) ? v : []).map(x => String(x).toLowerCase()).filter(x => re.test(x) && !x.split("/").some(p => /^\.+$/.test(p))))].slice(0, 5000);
  db.github.orgs = list(c.body.orgs, /^[\w.-]{1,100}$/); db.github.repos = list(c.body.repos, /^[\w.-]{1,100}\/[\w.-]{1,100}$/);
  ghSync(); save(); return ghView();
}, { admin: true });
R('GET', '/api/github/owners', async () => [{ login: db.github.login, me: true }, ...(await ghAll('/user/orgs')).map(o => ({ login: String(o.login) }))], { admin: true });
R('GET', '/api/github/repos', c => ghRepos(c.query.get('owner') || ''), { admin: true });
R('GET', '/api/github/allowed', async () => {
  const out = new Set(db.github.repos);
  for (const o of db.github.orgs) { try { for (const r of await ghRepos(o)) out.add(r.full.toLowerCase()); } catch {} }
  return [...out].sort();
}, { admin: true });
R('POST', '/api/github/clone', async c => {
  const repo = str(c.body.repo, 220).toLowerCase();
  if (!/^[\w.-]{1,100}\/[\w.-]{1,100}$/.test(repo) || repo.split('/').some(x => /^\.+$/.test(x))) bad('Dépôt invalide');
  if (!ghAllowed(repo)) bad('Ce dépôt n’est pas ouvert aux IA : coche-le dans GitHub', 403);
  const dir = path.join(REPOS, ...repo.split('/'));
  if (fs.existsSync(path.join(dir, '.git'))) return { dir };
  fs.mkdirSync(path.dirname(dir), { recursive: true, mode: 0o700 });
  const res = await new Promise(resolve => {
    let err = ''; const ch = spawn('git', ['clone', 'https://github.com/' + repo + '.git', dir], { env: { ...process.env, ...gitEnv() }, stdio: ['ignore', 'ignore', 'pipe'] });
    const t = setTimeout(() => ch.kill('SIGKILL'), 600000);
    ch.stderr.on('data', d => { err = (err + d).slice(-600); });
    ch.on('error', e => { clearTimeout(t); resolve({ code: -1, err: e.code === 'ENOENT' ? 'git n’est pas installé sur le serveur' : e.message }); });
    ch.on('close', code => { clearTimeout(t); resolve({ code, err }); });
  });
  if (res.code !== 0) { fs.rmSync(dir, { recursive: true, force: true }); bad('Copie du dépôt impossible : ' + (res.err.trim().split('\n').pop() || 'erreur git'), 502); }
  return { dir };
}, { admin: true });

/* Projets */
function projectFields(b, p, user) {
  if ('name' in b) p.name = str(b.name, 80) || bad('Nom requis');
  if ('instructions' in b) p.instructions = str(b.instructions, 50000);
  if ('context' in b) p.context = str(b.context, 200000);
  if ('repo' in b && isAdmin(user)) p.repo = str(b.repo, 220).toLowerCase();
  if ('cwd' in b && isAdmin(user)) { p.cwd = str(b.cwd, 500); if (p.cwd && !path.isAbsolute(p.cwd) && !/^[A-Za-z]:[\\/]/.test(p.cwd)) bad('Dossier de travail : chemin absolu attendu'); }
  return p;
}
R('POST', '/api/projects', c => {
  const p = projectFields(c.body, { id: newId(), userId: c.user.id, name: '', instructions: '', context: '', cwd: '' }, c.user);
  if (!p.name) bad('Nom requis');
  db.projects.push(p); save(); return p;
});
R('PATCH', '/api/projects/:id', c => { const p = projectFields(c.body, own(db.projects, c), c.user); save(); return p; });
R('DELETE', '/api/projects/:id', c => {
  own(db.projects, c);
  db.projects = db.projects.filter(p => p.id !== c.p.id);
  for (const conv of db.convs) if (conv.projectId === c.p.id) conv.projectId = null;
  save(); return { ok: true };
});

/* Conversations */
const ownProject = (c, id) => (db.projects.some(p => p.id === id && p.userId === c.user.id) ? id : null);
R('GET', '/api/conversations', c => {
  const q = str(c.query.get('q'), 100).toLowerCase();
  let list = db.convs.filter(x => x.userId === c.user.id);
  if (q) list = list.filter(x => (x.title || '').toLowerCase().includes(q) || loadMsgs(x.id).some(m => (m.content || '').toLowerCase().includes(q)));
  return list.sort((a, b) => b.updatedAt - a.updatedAt).map(convView);
});
R('POST', '/api/conversations', c => {
  const conv = { id: newId(), userId: c.user.id, title: '', createdAt: Date.now(), updatedAt: Date.now(), projectId: ownProject(c, c.body.projectId), agentId: null };
  db.convs.push(conv); saveMsgs(conv.id, []); save(); return convView(conv);
});
R('GET', '/api/conversations/:id', c => { const conv = own(db.convs, c); return { conv: convView(conv), messages: loadMsgs(conv.id) }; });
R('PATCH', '/api/conversations/:id', c => {
  const conv = own(db.convs, c);
  if ('title' in c.body) conv.title = str(c.body.title, 120);
  if ('projectId' in c.body) conv.projectId = ownProject(c, c.body.projectId);
  if ('archived' in c.body) conv.archived = !!c.body.archived;
  save(); return convView(conv);
});
R('DELETE', '/api/conversations/:id', c => {
  const conv = own(db.convs, c);
  db.convs = db.convs.filter(x => x !== conv);
  runs.get(conv.id)?.ac.abort();
  fs.rmSync(convPath(conv.id), { force: true });
  save(); return { ok: true };
});
R('POST', '/api/conversations/:id/messages', c => {
  const conv = own(db.convs, c), b = c.body;
  if (runs.has(conv.id)) bad('Une réponse est déjà en cours dans cette conversation', 409);
  const agentId = 'agentId' in b ? b.agentId : conv.agentId;
  const agent = agentId ? visibleAgents(c.user).find(a => a.id === agentId) || null : null;
  const provider = db.providers.find(p => p.id === (b.providerId || conv.providerId || (agent && agent.providerId)));
  if (!canUse(c.user, provider)) bad('Choisis un modèle pour cette conversation');
  const model = str('model' in b ? b.model : conv.providerId === provider.id ? conv.model : (agent && agent.model) || '', 160);
  const msgs = loadMsgs(conv.id), regenerate = !!b.regenerate;
  if (regenerate) {
    while (msgs.length && msgs.at(-1).role === 'assistant') msgs.pop();
    if (!msgs.length) bad('Rien à régénérer');
  } else {
    const content = str(b.content, 400000) || bad('Message vide');
    msgs.push({ id: newId(), role: 'user', content, ts: Date.now() });
  }
  if (!conv.title) conv.title = msgs[0].content.replace(/\s+/g, ' ').slice(0, 60);
  Object.assign(conv, { agentId: agent ? agent.id : null, providerId: provider.id, model, modelLabel: modelLabel(provider, model), updatedAt: Date.now() });
  saveMsgs(conv.id, msgs); save();
  attach(startRun(conv, msgs, agent, provider, model, regenerate), c.res);
  return RAW;
});
R('GET', '/api/conversations/:id/stream', c => {
  const run = runs.get(own(db.convs, c).id) || bad('Aucune réponse en cours', 404);
  attach(run, c.res); return RAW;
});
R('POST', '/api/conversations/:id/stop', c => { runs.get(own(db.convs, c).id)?.ac.abort(); return { ok: true }; });

/* ───────────── Serveur HTTP ───────────── */
let pageCache = null;
function page() {
  const mtime = fs.statSync(INDEX).mtimeMs;
  if (pageCache && pageCache.mtime === mtime) return pageCache;
  const html = fs.readFileSync(INDEX, 'utf8');
  const hashes = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => `'sha256-${crypto.createHash('sha256').update(m[1]).digest('base64')}'`);
  const csp = `default-src 'none'; script-src ${hashes.join(' ')}; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`;
  return (pageCache = { mtime, html, csp });
}
/* Hôte demandé : forme stricte, et sur la machine elle-même seuls ses propres noms (pare le rebinding DNS). */
function hostOf(req) {
  const h = String(req.headers.host || '');
  const m = /^(\[[0-9a-f:.]+\]|[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?)(:\d{1,5})?$/i.exec(h);
  if (!m) bad('Hôte invalide', 400);
  const name = m[1].toLowerCase();
  if (LOOPBACK ? !['localhost', '127.0.0.1', '[::1]', ...HOSTS].includes(name) : HOSTS.length && !HOSTS.includes(name)) bad('Hôte non reconnu', 421);
  return h;
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', d => { size += d.length; if (size > 4 * 1024 * 1024) { reject(new HttpError(413, 'Requête trop volumineuse')); req.destroy(); } else chunks.push(d); });
    req.on('end', () => {
      if (!size) return resolve({});
      try { const j = JSON.parse(Buffer.concat(chunks).toString('utf8')); resolve(j && typeof j === 'object' && !Array.isArray(j) ? j : {}); }
      catch { reject(new HttpError(400, 'JSON invalide')); }
    });
    req.on('error', reject);
  });
}
function sendJson(res, code, obj) {
  if (res.headersSent || res.destroyed) return;
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(obj));
}

const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()');
  try {
    hostOf(req);
    if (isHttps(req)) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
    const url = new URL(req.url, 'http://x');
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      const p = page();
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache', 'Content-Security-Policy': p.csp });
      return res.end(p.html);
    }
    if (req.method === 'GET' && url.pathname === '/agent.js') {
      res.writeHead(200, { 'Content-Type': 'text/javascript; charset=utf-8', 'Cache-Control': 'no-cache' });
      return res.end(fs.readFileSync(AGENT_JS));
    }
    let route = null, m = null;
    for (const r of routes) if (r.method === req.method && (m = r.re.exec(url.pathname))) { route = r; break; }
    if (!route) bad('Introuvable', 404);
    let user = null, device = null;
    if (route.device) {
      const t = /^Bearer\s+([\w-]+)$/.exec(req.headers.authorization || '');
      device = t && db.devices.find(d => d.tokenHash === sha(t[1]));
      if (!device) bad('Jeton d’appareil invalide', 401);
      dev(device).seen = Date.now();
    } else {
      // Anti-CSRF : cookie SameSite=Strict, origine identique exigée, et refus de toute requête qu'un autre site a déclenchée.
      const origin = req.headers.origin, site = req.headers['sec-fetch-site'];
      let foreign = !!site && site !== 'same-origin' && site !== 'none';
      if (origin !== undefined) { let host = ''; try { host = new URL(origin).host; } catch {} if (host !== req.headers.host) foreign = true; }
      if (foreign) { audit('origine.refusee', { ip: clientIp(req), origine: String(origin || site).slice(0, 120), route: url.pathname.slice(0, 80) }); bad('Origine refusée', 403); }
      user = currentUser(req);
      if (!route.pub && !user) bad('Connexion requise', 401);
      if (route.admin && !isAdmin(user)) { audit('admin.refuse', { compte: user.name, route: url.pathname.slice(0, 80) }); bad('Réservé aux administrateurs', 403); }
    }
    const p = {}; route.keys.forEach((k, i) => { p[k] = m[i + 1]; });
    const hasBody = req.method !== 'GET' && (Number(req.headers['content-length']) > 0 || req.headers['transfer-encoding'] !== undefined);
    if (hasBody && !/^application\/json\b/i.test(req.headers['content-type'] || '')) bad('Type de contenu attendu : application/json', 415);
    const body = hasBody ? await readBody(req) : {};
    const out = await route.fn({ req, res, user, device, p, body, query: url.searchParams });
    if (out !== RAW) sendJson(res, 200, out);
  } catch (e) {
    if (!(e instanceof HttpError)) console.error(e);
    sendJson(res, e instanceof HttpError ? e.code : 500, { error: e instanceof HttpError ? e.message : 'Erreur interne du serveur' });
  }
});
server.requestTimeout = 0; // les flux de réponse peuvent durer longtemps
server.listen(PORT, HOST, () => {
  console.log(`MuxAI écoute sur http://${HOST}:${PORT} — données : ${DATA}`);
  if (!db.users.length && SETUP_TOKEN && !process.env.MUXAI_SETUP_TOKEN) console.log(`Jeton d’installation, demandé pour créer le premier compte : ${SETUP_TOKEN}`);
});

setInterval(() => {
  const now = Date.now(); let n = 0;
  for (const k of Object.keys(db.sessions)) if (db.sessions[k].exp < now) { delete db.sessions[k]; n++; }
  if (n) save();
}, 3600000).unref();
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { for (const id of [...remotes.keys()]) stopRemote(id); for (const r of runs.values()) r.ac.abort(); flush(); process.exit(0); });
