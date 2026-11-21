<p align="center"><img src="assets/logo/muxai-logo-couleur.svg" alt="MuxAI" width="96" height="96"></p>

# MuxAI

**A self-hosted, ChatGPT-style web interface for the AI agents you already pay for: Claude Code, Codex, Ollama and any OpenAI-compatible API.**

<p align="center">

[![Stars](https://img.shields.io/github/stars/Nesaris/MuxAI?style=flat&logo=github&label=stars)](https://github.com/Nesaris/MuxAI/stargazers)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
![Node.js 20+](https://img.shields.io/badge/Node.js-20%2B-339933?logo=node.js&logoColor=white)
![Zero npm dependencies](https://img.shields.io/badge/npm%20dependencies-0-brightgreen)
![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)

</p>

<p align="center"><a href="README.fr.md">Full documentation</a> · <a href="https://nesaris.github.io">Nesaris Network</a></p>

## Why MuxAI?

Claude Code and Codex are tied to a terminal on one machine. MuxAI puts them behind a browser tab that runs around the clock on your own server: start a task from your phone, close the tab, come back to the answer.

## Features

- **Connectors** — Claude Code and Codex through your subscription (guided sign-in, no API key), Ollama, and any OpenAI-compatible API (Grok, OpenRouter, Mistral, LM Studio…).
- **Exact model choice** — provider, then family, then version, loaded from the provider.
- **Projects and agents** — shared instructions, context and working directory per project; reusable AI profiles.
- **Linked devices** — one short command links a Mac, Linux or Windows machine so MuxAI can run Claude Code or Codex there, with its files and tools.
- **MCP tools** — a ready-made catalogue (Blender, Fusion, Canva, Figma, Notion, GitHub…) with a hosted install command that checks what is already there and only installs what is missing.
- **GitHub access** — one token, then the organizations and repositories open to the AIs, ticked one by one.
- **Multi-account**, full-text search, archives, Markdown export, responsive interface.
- **Zero dependencies** — one `server.js`, one `index.html`, one agent file.

## Quick start

```bash
git clone https://github.com/Nesaris/MuxAI.git && cd MuxAI && node server.js
```

Open http://127.0.0.1:8787, create the administrator account, add a connector.

With Docker:

```bash
cp .env.example .env && docker compose up -d --build
```

From the [Nesaris Hub](https://github.com/Nesaris/Hub): **Extensions → MuxAI → Install**.

When MuxAI listens beyond the local machine, creating the first account requires a setup token: the one set in `MUXAI_SETUP_TOKEN`, otherwise one printed in the server log at startup.

## Security

- Put MuxAI behind HTTPS as soon as it leaves `127.0.0.1`.
- A CLI connector **runs commands** on the server or on the linked device. CLI connectors are reserved for administrators by default.
- Passwords are hashed with scrypt; sessions use an `HttpOnly`, `SameSite=Strict` cookie; strict CSP. Keys and tokens are stored in the data directory and never sent back to the browser.

The interface is in French. Details, limits and what has not been tested yet are in the [full documentation](README.fr.md).

## License

[MIT](LICENSE)
