# Security — MuxAI

Status: hardened after an attack campaign on 0.10.0. **Not compliant** with the full baseline: see "Known gaps".

Report a vulnerability privately through GitHub: **Security → Report a vulnerability**. Please do not open a public issue.

## Trust model

- **Anonymous** — reaches only the page, `/healthz`, `/api/boot`, sign-in, and the short-lived install scripts (`/i/<code>`, `/m/<code>`).
- **Member** — own conversations, projects and agents; connectors an administrator opened to members.
- **Administrator** — connectors, devices, MCP tools, GitHub access, accounts. An administrator can run commands on the server through a CLI connector: this is the product, not a flaw. Treat an administrator account as shell access.
- **Linked device** — trusts the server it was linked to. Whoever controls the server can make the CLI act on the device.

## What is enforced

| Area | Control |
|---|---|
| Passwords | Argon2id (64 MiB, 3 passes, parallelism 4) on Node 24.7+, hardened scrypt (N=2^17) before; 12 to 1024 characters; older hashes upgraded at sign-in; same cost for an unknown account; never more than two computations at once |
| Brute force | Ten failures in ten minutes lock the address and the account, whatever address is claimed; applies to sign-in, setup token, password change and install codes |
| Sessions | 256-bit token, only its hash stored; 12 hours, closed after 60 minutes idle; renewed at sign-in; other sessions closed on password change; `HttpOnly`, `SameSite=Strict`, `__Host-` prefix and `Secure` over HTTPS |
| First account | Requires a setup token as soon as the server listens beyond the local machine; a single first account even under concurrent requests |
| Cross-site requests | Same origin required, `Sec-Fetch-Site` checked on every API route, JSON bodies only |
| DNS rebinding | On a local install only `localhost` and `127.0.0.1` are accepted as host; `MUXAI_HOSTS` restricts a public one |
| Client address | `X-Forwarded-For` is read right to left through trusted proxies only; `X-Forwarded-Proto` is ignored unless a trusted proxy sent it |
| Access control | Every route checked without a session, as a member, and across accounts (`test/securite.test.js`) |
| Data at rest | With `MUXAI_KEY`, the database and conversations are sealed with AES-256-GCM; the key never touches the volume; files are `0600` |
| Browser | Strict CSP (hashed script, no inline, no eval), no framing, `nosniff`, COOP/CORP, HSTS over HTTPS; assistant output is escaped before rendering |
| Install scripts | 64-bit single-purpose codes valid 30 minutes; a device code dies at first connection; nothing from a label or the `Host` header reaches a shell line |
| Audit | One JSON line per security event on standard output: sign-ins, refusals, account and connector changes |

The attacks are kept as regression tests: `npm test`.

## Known gaps

- **No second factor.** No TOTP, no passkeys: the shared account module used by the other Nesaris services is not embedded yet. Until then, keep MuxAI behind the Hub or a VPN, not on the open internet.
- **Account lock can be abused.** Ten wrong passwords lock an account for ten minutes, including for its owner. Open sessions keep working.
- **GitHub token.** It is never handed to the CLIs, but it sits in the data directory in clear (`github.json`), where a CLI that went looking could read it. The per-repository list is a guard rail. For a hard limit, use a token restricted to the same repositories.
- **Without `MUXAI_KEY`** connector keys and tokens are stored in clear in `db.json` (mode `0600`).
- **CLIs are installed at their latest version** when the image is built, not pinned by a lockfile.
- **Not tested:** the device agent on macOS and Windows under attack, Codex, real MCP servers.
