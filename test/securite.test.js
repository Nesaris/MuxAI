'use strict';
// Essais d'attaque : chaque essai joue un attaquant contre un serveur local, avec des comptes factices.
const { test, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const http = require('node:http');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');

const racine = path.join(__dirname, '..');
const lances = [];
after(() => { for (const p of lances) p.kill('SIGKILL'); });
const MDP = 'mot-de-passe-solide-1', MDP2 = 'autre-mot-de-passe-2', MDP3 = ['nouveau', 'mot', 'de', 'passe', '3'].join('-');

async function lancer(env = {}) {
  const data = fs.mkdtempSync(path.join(os.tmpdir(), 'muxai-sec-'));
  const port = await new Promise(r => { const x = require("node:net").createServer().listen(0, "127.0.0.1", () => { const n = x.address().port; x.close(() => r(n)); }); });
  const p = spawn(process.execPath, [path.join(racine, 'server.js')], { env: { ...process.env, HOST: '127.0.0.1', PORT: String(port), MUXAI_DATA: data, ...env }, stdio: ['ignore', 'pipe', 'inherit'] });
  lances.push(p);
  return new Promise((resolve, reject) => {
    let sortie = '';
    p.stdout.on('data', d => { sortie += d; if (sortie.includes('écoute')) setTimeout(() => resolve({ port, data, journal: () => sortie }), 150); });
    p.on('exit', c => reject(new Error('arrêt du serveur, code ' + c)));
  });
}
// Requête brute : on maîtrise chaque en-tête, y compris Host, ce que fetch interdit.
function req(s, method, chemin, { corps, cookie, entetes = {}, brut } = {}) {
  return new Promise((resolve, reject) => {
    const data = brut != null ? brut : corps === undefined ? null : JSON.stringify(corps);
    const r = http.request({ host: '127.0.0.1', port: s.port, method, path: chemin, headers: { Host: '127.0.0.1:' + s.port, ...(data != null ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}), ...(cookie ? { Cookie: cookie } : {}), ...entetes } }, res => {
      let t = ''; res.on('data', d => { t += d; if (t.length > 2e6) res.destroy(); }); res.on('close', () => { let j = null; try { j = JSON.parse(t); } catch {} resolve({ code: res.statusCode, texte: t, json: j, entetes: res.headers, cookie: (res.headers['set-cookie'] || []).map(c => c.split(';')[0]).join('; ') }); });
    });
    r.on('error', e => (data && data.length > 1e6 ? resolve({ code: 0, texte: String(e) }) : reject(e)));
    if (data != null) r.write(data); r.end();
  });
}
async function admin(s, env) {
  const r = await req(s, 'POST', '/api/auth/register', { corps: { name: 'admin', password: MDP } });
  assert.equal(r.code, 200, r.texte);
  return r.cookie;
}
async function membre(s, cookieAdmin, nom = 'membre') {
  const c = await req(s, 'POST', '/api/users', { cookie: cookieAdmin, corps: { name: nom, password: MDP2, role: 'user' } });
  assert.equal(c.code, 200, c.texte);
  const r = await req(s, 'POST', '/api/auth/login', { corps: { name: nom, password: MDP2 } });
  assert.equal(r.code, 200, r.texte);
  return r.cookie;
}

test('rebinding DNS : un hôte étranger ne peut pas créer le premier compte d’un serveur local', async () => {
  const s = await lancer();
  const r = await req(s, 'POST', '/api/auth/register', { corps: { name: 'pirate', password: MDP }, entetes: { Host: 'pirate.exemple:' + s.port } });
  assert.notEqual(r.code, 200, 'compte administrateur créé depuis un hôte étranger');
  assert.equal((await req(s, 'GET', '/api/boot', { entetes: { Host: 'pirate.exemple' } })).code, 421);
  assert.equal((await req(s, 'GET', '/api/boot', { entetes: { Host: 'localhost:' + s.port } })).code, 200);
});

test('aucune route protégée ne répond sans session', async () => {
  const s = await lancer(); await admin(s);
  const id = '0123456789abcdef';
  const routes = [['GET', '/api/users'], ['POST', '/api/users'], ['DELETE', '/api/users/' + id], ['PATCH', '/api/settings'], ['POST', '/api/providers'], ['PATCH', '/api/providers/' + id], ['DELETE', '/api/providers/' + id],
    ['GET', '/api/providers/' + id + '/models'], ['POST', '/api/devices'], ['GET', '/api/devices'], ['POST', '/api/devices/' + id + '/link'], ['DELETE', '/api/devices/' + id], ['POST', '/api/mcps'], ['POST', '/api/mcps/setup'], ['GET', '/api/mcps/setup'],
    ['GET', '/api/logo?k=ollama'], ['POST', '/api/detect'], ['POST', '/api/login/start'], ['GET', '/api/login/state'], ['POST', '/api/login/input'], ['POST', '/api/providers/' + id + '/check'], ['POST', '/api/providers/' + id + '/remote'], ['POST', '/api/providers/' + id + '/update'],
    ['GET', '/api/providers/' + id + '/commands'], ['GET', '/api/github'], ['POST', '/api/github'], ['PATCH', '/api/github'], ['GET', '/api/github/owners'], ['GET', '/api/github/repos'], ['GET', '/api/github/allowed'], ['POST', '/api/github/clone'],
    ['POST', '/api/projects'], ['PATCH', '/api/projects/' + id], ['GET', '/api/conversations'], ['POST', '/api/conversations'], ['GET', '/api/conversations/' + id], ['POST', '/api/conversations/' + id + '/messages'], ['GET', '/api/conversations/' + id + '/stream'],
    ['POST', '/api/agents'], ['POST', '/api/auth/password'], ['POST', '/api/device/poll'], ['POST', '/api/device/out'], ['POST', '/api/device/done']];
  for (const [m, c] of routes) { const r = await req(s, m, c, m === 'GET' ? {} : { corps: {} }); assert.equal(r.code, 401, `${m} ${c} → ${r.code}`); }
  for (const cookie of ['muxai_sid=faux', 'muxai_sid=' + 'A'.repeat(43), '__Host-muxai_sid=faux']) assert.equal((await req(s, 'GET', '/api/users', { cookie })).code, 401);
});

test('un membre n’atteint ni l’administration ni les données d’un autre compte', async () => {
  const s = await lancer(); const a = await admin(s), m = await membre(s, a), m2 = await membre(s, a, 'membre2');
  for (const [meth, c, corps] of [['GET', '/api/users'], ['POST', '/api/users', { name: 'x2', password: MDP, role: 'admin' }], ['PATCH', '/api/settings', { openSignup: true }], ['POST', '/api/providers', { type: 'claude-code', name: 'x', command: '/bin/sh' }],
    ['POST', '/api/devices', { name: 'x' }], ['POST', '/api/mcps', { name: 'x', command: 'sh' }], ['POST', '/api/login/start', { type: 'claude-code' }], ['POST', '/api/github', { token: 'x' }], ['POST', '/api/detect', { brand: 'claude-code', command: 'id' }]])
    assert.equal((await req(s, meth, c, { cookie: m, corps })).code, 403, `${meth} ${c}`);
  // Connecteur réservé aux administrateurs : invisible et inutilisable pour un membre.
  const prov = (await req(s, 'POST', '/api/providers', { cookie: a, corps: { type: 'claude-code', name: 'Claude', command: 'true' } })).json;
  assert.equal(prov.adminOnly, true);
  assert.equal((await req(s, 'GET', '/api/boot', { cookie: m })).json.providers.length, 0);
  const conv = (await req(s, 'POST', '/api/conversations', { cookie: m, corps: {} })).json;
  assert.equal((await req(s, 'POST', `/api/conversations/${conv.id}/messages`, { cookie: m, corps: { content: 'salut', providerId: prov.id } })).code, 400);
  assert.equal((await req(s, 'GET', `/api/providers/${prov.id}/models`, { cookie: m })).code, 404);
  assert.equal((await req(s, 'GET', `/api/providers/${prov.id}/commands`, { cookie: m })).code, 404);
  // Le dossier de travail et le dépôt d'un projet restent hors de portée d'un membre.
  const proj = (await req(s, 'POST', '/api/projects', { cookie: m, corps: { name: 'p', cwd: '/etc', repo: 'a/b', userId: 'x', id: 'y' } })).json;
  assert.equal(proj.cwd, ''); assert.equal(proj.repo, undefined);
  assert.equal((await req(s, 'PATCH', '/api/projects/' + proj.id, { cookie: m, corps: { cwd: '/etc' } })).json.cwd, '');
  // Cloisonnement entre comptes.
  for (const [meth, c] of [['GET', '/api/conversations/' + conv.id], ['PATCH', '/api/conversations/' + conv.id], ['DELETE', '/api/conversations/' + conv.id], ['GET', `/api/conversations/${conv.id}/stream`], ['POST', `/api/conversations/${conv.id}/stop`], ['PATCH', '/api/projects/' + proj.id], ['DELETE', '/api/projects/' + proj.id]])
    for (const qui of [m2, a]) assert.equal((await req(s, meth, c, { cookie: qui, corps: meth === 'GET' ? undefined : { title: 'x', name: 'x' } })).code, 404, `${meth} ${c}`);
  assert.equal((await req(s, 'POST', '/api/conversations', { cookie: m2, corps: { projectId: proj.id } })).json.projectId, null);
});

test('affectation de masse et pollution de prototype sans effet', async () => {
  const s = await lancer(); const a = await admin(s);
  await req(s, 'PATCH', '/api/settings', { cookie: a, corps: { openSignup: true } });
  const r = await req(s, 'POST', '/api/auth/register', { brut: JSON.stringify({ name: 'intrus', password: MDP, role: 'admin', id: 'x' }).replace('{', '{"__proto__":{"role":"admin"},"constructor":{"prototype":{"role":"admin"}},') });
  assert.equal(r.code, 200, r.texte); assert.equal(r.json.me.role, 'user');
  assert.equal((await req(s, 'GET', '/api/users', { cookie: r.cookie })).code, 403);
  assert.equal(({}).role, undefined);
});

test('requêtes inter-sites refusées', async () => {
  const s = await lancer(); const a = await admin(s);
  assert.equal((await req(s, 'POST', '/api/conversations', { cookie: a, corps: {}, entetes: { Origin: 'https://pirate.exemple' } })).code, 403);
  assert.equal((await req(s, 'POST', '/api/conversations', { cookie: a, corps: {}, entetes: { Origin: 'null' } })).code, 403);
  assert.equal((await req(s, 'POST', '/api/conversations', { cookie: a, corps: {}, entetes: { 'Sec-Fetch-Site': 'cross-site' } })).code, 403);
  assert.equal((await req(s, 'GET', '/api/users', { cookie: a, entetes: { 'Sec-Fetch-Site': 'same-site' } })).code, 403);
  assert.equal((await req(s, 'POST', '/api/conversations', { cookie: a, brut: 'x=1', entetes: { 'Content-Type': 'text/plain' } })).code, 415);
  assert.equal((await req(s, 'POST', '/api/conversations', { cookie: a, corps: {}, entetes: { Origin: 'http://127.0.0.1:' + s.port, 'Sec-Fetch-Site': 'same-origin' } })).code, 200);
});

test('force brute : le verrou tient malgré un X-Forwarded-For falsifié, par adresse et par compte', async () => {
  const s = await lancer({ MUXAI_TRUST_PROXY: '1' }); await admin(s);
  let codes = [];
  for (let i = 0; i < 14; i++) codes.push((await req(s, 'POST', '/api/auth/login', { corps: { name: 'admin', password: 'faux-mot-de-passe-' + i }, entetes: { 'X-Forwarded-For': `10.9.${i}.1` } })).code);
  assert.ok(codes.includes(429), 'jamais ralenti : ' + codes.join(','));
  // Le bon mot de passe ne passe plus pendant le verrou, quelle que soit l'adresse annoncée.
  assert.equal((await req(s, 'POST', '/api/auth/login', { corps: { name: 'admin', password: MDP }, entetes: { 'X-Forwarded-For': '10.200.0.1' } })).code, 429);
});

test('jeton d’installation : force brute ralentie', async () => {
  const s = await lancer({ HOST: '0.0.0.0', MUXAI_SETUP_TOKEN: 'jeton-secret-d-essai' });
  const codes = [];
  for (let i = 0; i < 14; i++) codes.push((await req(s, 'POST', '/api/auth/register', { corps: { name: 'pirate', password: MDP, setupToken: 'essai' + i } })).code);
  assert.ok(codes.includes(429), codes.join(','));
});

test('sessions : fermées à la déconnexion et au changement de mot de passe, cookie durci', async () => {
  const s = await lancer(); const a = await admin(s);
  const brut = await req(s, 'POST', '/api/auth/login', { corps: { name: 'admin', password: MDP } });
  const pose = brut.entetes['set-cookie'][0];
  assert.match(pose, /HttpOnly/); assert.match(pose, /SameSite=Strict/); assert.match(pose, /Path=\//);
  const autre = brut.cookie;
  assert.equal((await req(s, 'POST', '/api/auth/password', { cookie: a, corps: { current: MDP, next: MDP3 } })).code, 200);
  assert.equal((await req(s, 'GET', '/api/users', { cookie: autre })).code, 401, 'autre session encore valide après changement de mot de passe');
  assert.equal((await req(s, 'POST', '/api/auth/logout', { cookie: a, corps: {} })).code, 200);
  assert.equal((await req(s, 'GET', '/api/users', { cookie: a })).code, 401);
  // Mot de passe trop court refusé.
  const b = await req(s, 'POST', '/api/auth/login', { corps: { name: 'admin', password: MDP3 } });
  assert.equal((await req(s, 'POST', '/api/users', { cookie: b.cookie, corps: { name: 'court', password: 'court123' } })).code, 400);
});

test('mots de passe : jamais en clair ni en hachage rapide dans la base', async () => {
  const s = await lancer(); await admin(s);
  await new Promise(r => setTimeout(r, 400));
  const base = fs.readFileSync(path.join(s.data, 'db.json'), 'utf8');
  assert.ok(!base.includes(MDP));
  assert.match(JSON.parse(base).users[0].pw, /^(argon2id|scrypt)\$/);
  assert.equal(fs.statSync(path.join(s.data, 'db.json')).mode & 0o077, 0, 'base lisible par d’autres comptes de la machine');
});

test('traversée de chemin et entrées hostiles', async () => {
  const s = await lancer(); const a = await admin(s);
  for (const k of ['../db.json', '..%2Fdb.json', 'ollama/../../db.json', '__proto__', 'constructor', 'ollama.type']) assert.equal((await req(s, 'GET', '/api/logo?k=' + k, { cookie: a })).code, 404, k);
  for (const c of ['/i/../db.json', '/i/%2e%2e%2fdb.json', '/m/../../etc/passwd', '/api/conversations/..%2f..%2fdb', '/data/db.json', '/server.js', '/.env', '/public/index.html', '//etc/passwd']) assert.equal((await req(s, 'GET', c, { cookie: a })).code, 404, c);
  assert.equal((await req(s, 'POST', '/api/conversations', { cookie: a, brut: '[1,2,3]' })).code, 200);
  assert.equal((await req(s, 'POST', '/api/conversations', { cookie: a, brut: '{"a":' })).code, 400);
  const gros = await req(s, 'POST', '/api/conversations', { cookie: a, brut: '{"x":"' + 'a'.repeat(5 * 1024 * 1024) + '"}' });
  assert.ok(gros.code === 413 || gros.code === 0, 'corps de 5 Mo accepté : ' + gros.code);
  assert.equal((await req(s, 'POST', '/api/github/clone', { cookie: a, corps: { repo: '../../etc' } })).code, 400);
  assert.equal((await req(s, 'POST', '/api/github/clone', { cookie: a, corps: { repo: '--upload-pack=id/x' } })).code, 400);
});

test('scripts d’installation : rien d’injectable par un libellé ou par l’en-tête Host', async () => {
  const s = await lancer(); const a = await admin(s);
  const r = await req(s, 'POST', '/api/mcps/setup', { cookie: a, corps: { name: 'outil', transport: 'stdio', command: 'npx', args: 'x', label: 'Outil\ntouch /tmp/PIRATE\n$(id)`id`' } });
  assert.equal(r.code, 200, r.texte);
  assert.match(r.json.code, /^outil-[a-f0-9]{16}$/, 'code d’installation trop court');
  const sh = (await req(s, 'GET', '/m/' + r.json.code)).texte;
  assert.ok(!/^touch \/tmp\/PIRATE/m.test(sh), 'ligne injectée dans le script');
  for (const l of sh.split('\n')) if (l.includes('PIRATE')) assert.ok(/^#|^S=/.test(l), l);
  const hote = await req(s, 'GET', '/m/' + r.json.code, { entetes: { Host: "x';touch${IFS}/tmp/PIRATE;'" } });
  assert.notEqual(hote.code, 200);
  const d = (await req(s, 'POST', '/api/devices', { cookie: a, corps: { name: 'pc' } })).json;
  assert.equal((await req(s, 'GET', '/i/' + d.code, { entetes: { Host: 'a b;id' } })).code === 200, false);
  // Le code de liaison ne sert plus une fois l'appareil relié.
  assert.equal((await req(s, 'GET', '/i/' + d.code)).code, 200);
  assert.equal((await req(s, 'POST', '/api/device/poll', { corps: { info: {} }, entetes: { Authorization: 'Bearer ' + d.token }, })).code >= 200, true);
  assert.equal((await req(s, 'GET', '/i/' + d.code)).code, 404, 'code de liaison encore valable après la première connexion');
  assert.equal((await req(s, 'POST', '/api/device/poll', { corps: {}, entetes: { Authorization: 'Bearer ' + d.token.slice(0, -1) + 'x' } })).code, 401);
});

test('en-têtes de sécurité et page servie', async () => {
  const s = await lancer();
  const r = await req(s, 'GET', '/');
  const csp = r.entetes['content-security-policy'];
  assert.match(csp, /default-src 'none'/); assert.match(csp, /frame-ancestors 'none'/); assert.ok(!/script-src[^;]*unsafe-inline/.test(csp)); assert.ok(!/unsafe-eval/.test(csp));
  assert.equal(r.entetes['x-content-type-options'], 'nosniff'); assert.equal(r.entetes['x-frame-options'], 'DENY');
  assert.equal(r.entetes['referrer-policy'], 'no-referrer'); assert.ok(r.entetes['permissions-policy']); assert.equal(r.entetes['cross-origin-opener-policy'], 'same-origin');
  assert.equal(r.entetes['x-powered-by'], undefined);
  assert.equal((await req(s, 'GET', '/api/boot')).entetes['cache-control'], 'no-store');
  const https = await req(s, 'POST', '/api/auth/register', { corps: { name: 'admin', password: MDP }, entetes: { 'X-Forwarded-Proto': 'https' } });
  assert.ok(!/Secure/.test(https.entetes['set-cookie'][0]), 'X-Forwarded-Proto cru sans proxy de confiance');
});

test('deuxième passe : variantes d’hôte, cookie imposé par un sous-domaine, données scellées', async () => {
  const s = await lancer();
  for (const h of ['127.0.0.1.pirate.exemple', 'localhost.', 'localhost.pirate.exemple', 'pirate.exemple@127.0.0.1', '127.0.0.1:1:2', '0x7f.1', '2130706433'])
    assert.notEqual((await req(s, 'GET', '/api/boot', { entetes: { Host: h } })).code, 200, h);
  for (const h of ['LOCALHOST:' + s.port, '[::1]:' + s.port, '127.0.0.1']) assert.equal((await req(s, 'GET', '/api/boot', { entetes: { Host: h } })).code, 200, h);

  // Derrière un relais HTTPS de confiance : le cookie porte le préfixe __Host-, et un cookie sans préfixe est ignoré.
  const p = await lancer({ MUXAI_TRUST_PROXY: '127.0.0.0/8' });
  const https = { 'X-Forwarded-Proto': 'https', 'X-Forwarded-For': '203.0.113.9' };
  const r = await req(p, 'POST', '/api/auth/register', { corps: { name: 'admin', password: MDP }, entetes: https });
  assert.match(r.entetes['set-cookie'][0], /^__Host-muxai_sid=.*; Secure$/);
  assert.equal(r.entetes['strict-transport-security'], 'max-age=31536000');
  const jeton = r.cookie.split('=')[1].split(';')[0];
  assert.equal((await req(p, 'GET', '/api/users', { cookie: '__Host-muxai_sid=' + jeton, entetes: https })).code, 200);
  assert.equal((await req(p, 'GET', '/api/users', { cookie: 'muxai_sid=' + jeton, entetes: https })).code, 401, 'cookie sans préfixe accepté en HTTPS');
  // L'adresse retenue est celle que le relais a vue, pas celle que le client prétend avoir.
  for (let i = 0; i < 11; i++) await req(p, 'POST', '/api/auth/login', { corps: { name: 'inconnu' + i, password: 'x' }, entetes: { 'X-Forwarded-For': `198.51.100.${i}, 203.0.113.50` } });
  assert.equal((await req(p, 'POST', '/api/auth/login', { corps: { name: 'admin', password: MDP }, entetes: { 'X-Forwarded-For': '192.0.2.1, 203.0.113.50' } })).code, 429);
  assert.equal((await req(p, 'POST', '/api/auth/login', { corps: { name: 'admin', password: MDP }, entetes: { 'X-Forwarded-For': '203.0.113.50, 203.0.113.77' } })).code, 200);
  assert.match(p.journal(), /"secu":"connexion.refusee"/);
  assert.ok(!p.journal().includes(MDP), 'mot de passe dans le journal');

  // Avec une clé maîtresse, rien de lisible sur le disque ; sans elle ou avec une autre, le serveur refuse de démarrer.
  const c = await lancer({ MUXAI_KEY: 'cle-maitresse-d-essai' }); const a = await admin(c);
  const conv = (await req(c, 'POST', '/api/conversations', { cookie: a, corps: {} })).json;
  await req(c, 'PATCH', '/api/conversations/' + conv.id, { cookie: a, corps: { title: 'TITRE-SECRET' } });
  await new Promise(r2 => setTimeout(r2, 400));
  const base = fs.readFileSync(path.join(c.data, 'db.json'), 'utf8');
  assert.ok(base.startsWith('MUXAI1.')); assert.ok(!base.includes('TITRE-SECRET') && !base.includes('admin'));
  assert.ok(fs.readFileSync(path.join(c.data, 'conversations', conv.id + '.json'), 'utf8').startsWith('MUXAI1.'));
  for (const env of [{}, { MUXAI_KEY: 'mauvaise-cle' }]) {
    const code = await new Promise(res => { const x = spawn(process.execPath, [path.join(racine, 'server.js')], { env: { ...process.env, PORT: '0', MUXAI_KEY: '', ...env, MUXAI_DATA: c.data }, stdio: 'ignore' }); x.on('exit', res); setTimeout(() => x.kill('SIGKILL'), 4000); });
    assert.equal(code, 1, 'démarrage accepté sans la bonne clé');
  }
});

test('deuxième passe : rafale de connexions bornée, premier compte unique', async () => {
  const s = await lancer({ HOST: '0.0.0.0', MUXAI_SETUP_TOKEN: 'jeton-d-essai' });
  const tous = await Promise.all(Array.from({ length: 6 }, (_, i) => req(s, 'POST', '/api/auth/register', { corps: { name: 'admin' + i, password: MDP, setupToken: 'jeton-d-essai' } })));
  assert.equal(tous.filter(r => r.code === 200).length, 1, 'plusieurs premiers comptes : ' + tous.map(r => r.code).join(','));
  const ok = tous.find(r => r.code === 200);
  assert.equal((await req(s, 'GET', '/api/users', { cookie: ok.cookie })).json.filter(u => u.role === 'admin').length, 1);
  const rafale = await Promise.all(Array.from({ length: 60 }, (_, i) => req(s, 'POST', '/api/auth/login', { corps: { name: 'inconnu' + i, password: 'x' + i } })));
  assert.ok(rafale.every(r => r.code === 401 || r.code === 429), rafale.map(r => r.code).join(','));
  assert.ok(rafale.some(r => r.code === 429), 'aucune requête refusée dans une rafale de 60');
  assert.equal((await req(s, 'GET', '/healthz')).code, 200);
});
