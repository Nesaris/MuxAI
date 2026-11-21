'use strict';
// Essais de fumée : le serveur démarre, répond, et protège la création du premier compte.
const { test, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');

const racine = path.join(__dirname, '..');
const lances = [];
after(() => { for (const p of lances) p.kill('SIGKILL'); });

async function lancer(env) {
  const data = fs.mkdtempSync(path.join(os.tmpdir(), 'muxai-'));
  const port = await new Promise(r => { const x = require("node:net").createServer().listen(0, "127.0.0.1", () => { const n = x.address().port; x.close(() => r(n)); }); });
  const p = spawn(process.execPath, [path.join(racine, 'server.js')], { env: { ...process.env, PORT: String(port), MUXAI_DATA: data, ...env }, stdio: ['ignore', 'pipe', 'inherit'] });
  lances.push(p);
  return new Promise((resolve, reject) => {
    let sortie = '';
    p.stdout.on('data', d => { sortie += d; if (sortie.includes('écoute')) setTimeout(() => resolve({ base: 'http://127.0.0.1:' + port, journal: () => sortie }), 150); });
    p.on('exit', c => reject(new Error('arrêt du serveur, code ' + c)));
  });
}
const json = (url, corps) => fetch(url, corps ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(corps) } : undefined).then(async r => ({ code: r.status, corps: await r.json() }));

test('le manifeste du Hub suit la version du paquet', () => {
  const hub = JSON.parse(fs.readFileSync(path.join(racine, 'hub.json'), 'utf8')), paquet = JSON.parse(fs.readFileSync(path.join(racine, 'package.json'), 'utf8'));
  assert.equal(hub.version, paquet.version);
  assert.equal(hub.config.find(c => c.key === 'IMAGE_TAG').default, paquet.version);
  assert.equal(JSON.parse(fs.readFileSync(path.join(racine, 'nouveautes.json'), 'utf8'))[0].version, paquet.version);
});

test('en local, le premier compte se crée sans jeton', async () => {
  const s = await lancer({ HOST: '127.0.0.1' });
  assert.deepEqual((await json(s.base + '/healthz')).corps, { ok: true });
  const boot = (await json(s.base + '/api/boot')).corps;
  assert.equal(boot.setup, true); assert.equal(boot.setupToken, false);
  const r = await json(s.base + '/api/auth/register', { name: 'admin', password: 'mot-de-passe-solide-1' });
  assert.equal(r.code, 200); assert.equal(r.corps.me.role, 'admin');
});

test('sur le réseau, le premier compte exige le jeton d’installation', async () => {
  const s = await lancer({ HOST: '0.0.0.0', MUXAI_SETUP_TOKEN: 'jeton-d-essai' });
  assert.equal((await json(s.base + '/api/boot')).corps.setupToken, true);
  assert.equal((await json(s.base + '/api/auth/register', { name: 'admin', password: 'mot-de-passe-solide-1' })).code, 403);
  assert.equal((await json(s.base + '/api/auth/register', { name: 'admin', password: 'mot-de-passe-solide-1', setupToken: 'faux' })).code, 403);
  assert.equal((await json(s.base + '/api/auth/register', { name: 'admin', password: 'mot-de-passe-solide-1', setupToken: 'jeton-d-essai' })).code, 200);
});

test('sans jeton fourni, le serveur en tire un et l’écrit dans son journal', async () => {
  const s = await lancer({ HOST: '0.0.0.0', MUXAI_SETUP_TOKEN: '' });
  const m = /premier compte : (\S+)/.exec(s.journal());
  assert.ok(m, 'jeton absent du journal');
  assert.equal((await json(s.base + '/api/auth/register', { name: 'admin', password: 'mot-de-passe-solide-1', setupToken: m[1] })).code, 200);
});
