#!/usr/bin/env node
'use strict';
/* MuxAI — agent d'appareil. À lancer sur le poste dont MuxAI doit piloter les CLI (Claude Code, Codex).
   Zéro dépendance, Node.js >= 20. Connexion sortante uniquement : rien à ouvrir sur le poste.

   node muxai-agent.js --server https://muxai.exemple.fr --token <jeton>
   Options : --dir <dossier de travail par défaut>   --allow <commande> (répétable ; défaut : claude, codex) */
const { spawn } = require('node:child_process');
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');

const argv = process.argv.slice(2), opt = { allow: [] };
for (let i = 0; i < argv.length; i++) {
  const k = argv[i].replace(/^--/, '');
  if (k === 'allow') opt.allow.push(argv[++i]); else opt[k] = argv[++i];
}
// Sans options, l'agent lit ~/.muxai/config.json (écrit par la commande d'installation courte).
let saved = {};
try { saved = JSON.parse(fs.readFileSync(opt.config || path.join(os.homedir(), '.muxai', 'config.json'), 'utf8').replace(/^\uFEFF/, '')); } catch {}
const SERVER = String(opt.server || process.env.MUXAI_SERVER || saved.server || '').replace(/\/+$/, '');
const TOKEN = opt.token || process.env.MUXAI_TOKEN || saved.token;
const DIR = path.resolve(opt.dir || process.env.MUXAI_DIR || saved.dir || os.homedir());
const ALLOW = new Set((opt.allow.length ? opt.allow : ['claude', 'codex']).map(s => s.toLowerCase()));
if (!SERVER || !TOKEN) { console.error('Usage : node muxai-agent.js --server <url> --token <jeton> [--dir <dossier>] [--allow <commande>]'); process.exit(1); }

const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function post(route, body, timeout = 40000) {
  const r = await fetch(SERVER + route, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + TOKEN }, body: JSON.stringify(body), signal: AbortSignal.timeout(timeout) });
  if (r.status === 401) { console.error('Jeton refusé par le serveur : cet appareil a été supprimé ou le jeton est faux.'); process.exit(1); }
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r.json();
}
/* Seules les commandes autorisées au lancement de l'agent peuvent être exécutées. */
const allowed = cmd => ALLOW.has(path.basename(String(cmd)).toLowerCase().replace(/\.(exe|cmd|bat)$/, ''));

function version(cmd) {
  return new Promise(resolve => {
    let out = '';
    try {
      const c = spawn(cmd, ['--version'], { stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true });
      c.stdout.on('data', d => { out += d; });
      c.on('error', () => resolve(null));
      c.on('close', () => resolve(out.trim().split('\n')[0].slice(0, 60) || null));
      setTimeout(() => { c.kill(); resolve(null); }, 8000);
    } catch { resolve(null); }
  });
}
const info = { hostname: os.hostname(), platform: `${os.platform()} ${os.arch()}`, version: '2', clis: [] };
async function detect() { const found = []; for (const c of ALLOW) { const v = await version(c); if (v) found.push(`${c} ${v}`); } info.clis = found; }

const running = new Map();
function run(job) {
  let chain = Promise.resolve(), buf = '', timer = null, err = '';
  const send = (route, body) => { chain = chain.then(() => post(route, body, 20000)).catch(e => log('envoi impossible :', e.message)); return chain; };
  const flushOut = () => { clearTimeout(timer); timer = null; if (buf) { const data = buf; buf = ''; send('/api/device/out', { id: job.id, data }); } };
  const finish = body => { running.delete(job.id); flushOut(); send('/api/device/done', { id: job.id, ...body }); };
  send('/api/device/out', { id: job.id, data: '' }); // accusé de réception
  if (!allowed(job.cmd)) return finish({ error: `Commande non autorisée sur cet appareil : ${job.cmd} (relance l'agent avec --allow)` });
  const cwd = job.cwd && fs.existsSync(job.cwd) ? job.cwd : DIR;
  let child;
  try { child = spawn(job.cmd, job.args || [], { cwd, env: { ...process.env, ...(job.env || {}) }, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true }); }
  catch (e) { return finish({ error: e.message }); }
  running.set(job.id, child);
  log('▶', job.cmd, (job.args || []).slice(0, 3).join(' '), '…', 'dans', cwd);
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', d => { buf += d; if (buf.length > 65536) flushOut(); else if (!timer) timer = setTimeout(flushOut, 120); });
  child.stderr.on('data', d => { err = (err + d).slice(-2000); });
  child.on('error', e => finish({ error: e.code === 'ENOENT' ? `Commande introuvable sur l'appareil : ${job.cmd}` : e.code === 'EINVAL' ? `Impossible de lancer ${job.cmd} : indique le chemin complet du .exe dans le connecteur` : e.message }));
  child.on('close', code => { if (running.has(job.id)) { log('■ terminé, code', code); finish({ code, err: err.trim() }); } });
  child.stdin.on('error', () => {});
  child.stdin.end(job.input || '');
}

(async () => {
  await detect();
  setInterval(detect, 600000).unref();
  log(`Agent MuxAI sur ${info.hostname} → ${SERVER}`);
  log('Commandes autorisées :', [...ALLOW].join(', '), '| détectées :', info.clis.join(', ') || 'aucune');
  let wait = 1000, up = false;
  for (;;) {
    try {
      const r = await post('/api/device/poll', { info });
      if (!up) { up = true; log('Connecté au serveur.'); }
      wait = 1000;
      for (const id of r.cancel || []) { const c = running.get(id); if (c) c.kill(); }
      for (const job of r.jobs || []) run(job);
    } catch (e) {
      if (up) { up = false; log('Serveur injoignable, nouvelle tentative…', e.message); }
      await sleep(wait); wait = Math.min(wait * 2, 30000);
    }
  }
})();
