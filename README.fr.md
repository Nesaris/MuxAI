# MuxAI

Interface web auto-hébergée pour parler à tes IA depuis un navigateur : **Claude Code**, **Codex**, **Ollama** et toute **API compatible OpenAI** (Grok, OpenRouter, Mistral, LM Studio…).

Le serveur tourne en continu chez toi ou sur un VPS. Une réponse lancée continue côté serveur même si tu fermes l'onglet.

- **Zéro dépendance** : Node.js ≥ 20, un `server.js`, un `public/index.html`, un `agent/muxai-agent.js`.
- **Choix du modèle en cascade** : connecteur → famille (Fable, Opus, Sonnet, Haiku…) → version. Seuls les connecteurs configurés apparaissent.
- **Appareils** : un petit agent à lancer sur un autre poste (macOS, Linux, Windows) pour que MuxAI y pilote Claude Code ou Codex, avec ses fichiers et ses outils.
- **Outils MCP** : définis une fois (Blender, fichiers…), activés par connecteur.
- **Agents** : des profils avec leurs consignes, et éventuellement un modèle attitré.
- **Projets** : instructions, contexte et dossier de travail communs à un groupe de conversations.
- **Multi-comptes** : le premier compte créé est administrateur.
- **Historique** : recherche plein texte ; clic droit sur une conversation (ou bouton « … ») pour renommer, déplacer vers un projet, archiver, exporter en Markdown ou supprimer.

## Lancer

```bash
git clone https://github.com/Nesaris/MuxAI.git && cd MuxAI && node server.js
```

Ouvre http://127.0.0.1:8787, crée le compte administrateur, puis ajoute un connecteur.

| Variable | Défaut | Rôle |
|---|---|---|
| `PORT` | `8787` | Port d'écoute |
| `HOST` | `127.0.0.1` | `0.0.0.0` pour écouter sur le réseau |
| `MUXAI_DATA` | `./data` | Dossier des données (comptes, conversations, clés) |
| `MUXAI_SECURE` | — | `1` pour forcer le cookie `Secure` (HTTPS) |
| `MUXAI_TRUST_PROXY` | — | `1` : le relais directement connecté est de confiance. Ou ses plages : `172.16.0.0/12,10.0.0.0/8` |
| `MUXAI_KEY` | — | Clé maîtresse : chiffre la base et les conversations (AES-256-GCM). La perdre, c’est perdre les données |
| `MUXAI_HOSTS` | — | Noms d’hôte acceptés, séparés par des virgules. En local, seuls `localhost` et `127.0.0.1` le sont |
| `MUXAI_SESSION_HOURS`, `MUXAI_IDLE_MINUTES` | `12`, `60` | Durée d’une session et fermeture après inactivité |
| `MUXAI_SETUP_TOKEN` | — | Jeton demandé pour créer le premier compte. Vide : tiré au démarrage et écrit dans le journal, dès que `HOST` n’est pas `127.0.0.1` |

## Connecteurs

**Ajout guidé.** « Ajouter un connecteur » affiche une carte par service. Les logos sont téléchargés automatiquement au premier affichage (site officiel du service, sinon les services publics de favicons de DuckDuckGo puis Google), puis gardés dans `data/logos`. Une initiale s'affiche si tout échoue ; le terminal du serveur indique pourquoi (lignes `[logo]`).

- **Claude Code / Codex** : MuxAI vérifie que le CLI est installé, lance sa commande de connexion (`claude setup-token` ou `codex login`) et ouvre la page de connexion dans un nouvel onglet. Tu te connectes, tu copies ce que la page te donne à la fin (un code pour Claude ; pour Codex, l'adresse `http://localhost:1455/auth/callback?...` si la page finale ne se charge pas) et tu le colles dans MuxAI. Le connecteur est créé puis testé avec un vrai message. Le bouton « Reconnecter » refait la même chose sur un connecteur existant. Nécessite `script` sous Linux (présent par défaut) ou `python3` sous macOS (fourni avec les outils Xcode : `xcode-select --install`).
- **Ollama** : détecté automatiquement s'il tourne sur le serveur.
- **Grok, OpenAI, OpenRouter, Mistral** : ces API n'ont pas de page de connexion ; il faut coller une clé (lien « Obtenir une clé » fourni).
- **Autre** : formulaire complet pour toute API compatible OpenAI. Les réglages avancés de chaque connecteur restent accessibles avec le crayon.

| Type | Ce qu'il faut |
|---|---|
| Claude Code | `claude` installé sur la machine qui l'exécute (ce serveur ou un appareil) |
| Codex | `codex` installé sur la machine qui l'exécute |
| Ollama | L'URL du serveur, ex. `http://127.0.0.1:11434` |
| API compatible OpenAI | URL de base (`…/v1`) + clé API. Ex. Grok : `https://api.x.ai/v1` |

**Connexion du compte (CLI).** Soit le CLI est déjà connecté sur la machine, soit tu colles ses identifiants dans le connecteur, sous forme de variables d'environnement. Pour Claude Code : lance `claude setup-token` une fois, puis colle `CLAUDE_CODE_OAUTH_TOKEN=<jeton>`. Pour reconnecter plus tard, il suffit de remplacer le jeton dans le connecteur.

**Liste des modèles (CLI).** Les CLI ne savent pas lister les modèles. Deux options, cumulables :
- une clé API (Anthropic ou OpenAI) sur le connecteur, utilisée uniquement pour charger la liste à jour ;
- une liste manuelle, un modèle par ligne : `identifiant` ou `identifiant = Nom affiché`.

Ollama et les API compatibles OpenAI fournissent leur liste automatiquement.

MuxAI reprend la session du CLI d'un message à l'autre. Si tu changes de modèle ou de connecteur en cours de conversation, l'historique est rejoué dans le prompt.

## Contrôle à distance (Claude Code)

La commande `/remote-control` dans la barre de saisie, ou « … » → « Contrôle à distance » sur un connecteur Claude Code local, lance `claude remote-control` sur le serveur et affiche le lien de la session, à ouvrir dans claude.ai/code ou l'app mobile. La session reste active tant que MuxAI tourne ou jusqu'à « Arrêter ». Elle utilise la connexion propre du CLI sur la machine (pas le jeton collé dans le connecteur) et démarre dans le dossier de travail du projet sélectionné. Non vérifié avec le vrai CLI : en cas de souci, la page montre ce que répond le CLI.

## Appareils

Dans **Appareils → Nouvel appareil**, MuxAI affiche une commande courte à coller sur le poste, selon son système :

```bash
curl -fsSL https://ton-muxai/i/<code> | sh          # macOS et Linux
irm https://ton-muxai/i/<code>.ps1 | iex            # Windows (PowerShell)
```

La commande est valable 30 minutes. Elle vérifie Node.js (20 ou plus), installe l'agent dans `~/.muxai`, enregistre l'adresse du serveur et le jeton, puis lance l'agent et le relance à chaque ouverture de session (launchd sur macOS, systemd utilisateur sur Linux, tâche planifiée sur Windows). La page passe à « Appareil relié et en ligne » dès qu'il se connecte. « Relier à nouveau » génère une nouvelle commande et invalide l'ancienne liaison.

L'agent ouvre une connexion sortante vers le serveur : rien à ouvrir sur le poste. Il n'exécute que `claude` et `codex`. Il tourne en arrière-plan, terminal fermé, et repart au redémarrage (à l’ouverture de session sur macOS et Windows).

Sur l’appareil : `muxai stop` le coupe et il ne repart pas tout seul, `muxai start` le relance, `muxai status` dit où il en est, `muxai remove` le retire.

Crée ensuite un connecteur Claude Code ou Codex qui « s'exécute sur » cet appareil. Hors de ton réseau local, MuxAI doit être servi en HTTPS derrière un nom de domaine : sinon le jeton de l'appareil circule en clair.

Lancement manuel possible : `node muxai-agent.js --server <url> --token <jeton> [--dir <dossier>] [--allow <commande>]`.

Vérifié sous Linux uniquement (installation, connexion, retrait). Les scripts macOS (launchd) et Windows (PowerShell, tâche planifiée) n'ont pas été exécutés.

## Outils MCP

« Outils MCP → Ajouter un outil » ouvre un catalogue de serveurs MCP prêts à ajouter : Blender, Autodesk Fusion, Adobe, Canva, Figma, Google Workspace, Microsoft 365, Notion, Airtable, Asana, monday.com, GitHub, Linear, Atlassian, Sentry, Supabase, Vercel, Stripe, Hugging Face, navigateur (Playwright) et fichiers. Chaque fiche indique ce qu'il faut installer sur la machine, la commande ou l'adresse utilisée, et un lien vers la documentation du projet. L'ajout l'active directement sur les connecteurs Claude Code / Codex cochés.

Pour les outils qui demandent quelque chose sur la machine, la fiche donne une commande courte hébergée par MuxAI (`curl -fsSL https://ton-domaine/m/blender-xxxxxxxx | sh`, ou `irm …ps1 | iex` sous Windows). Elle vérifie ce qui est déjà installé, demande avant d'installer ce qui manque, puis connecte l'outil. Valable 30 minutes. Vérifiée sous Linux uniquement.

Un serveur MCP est lancé par le CLI, sur la machine où celui-ci tourne (ce serveur ou un appareil relié) : ses prérequis doivent y être installés.

- **Applications locales** (Blender, Fusion) : l'application doit être ouverte sur la machine, avec son module ou son réglage MCP activé.
- **Services avec compte** (Canva, Figma, Notion, Adobe…) : ils passent par la passerelle `mcp-remote`, qui ouvre le navigateur de la machine à la première utilisation pour te connecter. Sur un serveur sans écran, cette connexion ne peut pas se faire : utilise un appareil.
- **Personnalisé** : n'importe quel serveur MCP, par commande ou par adresse (HTTP ou SSE, avec en-têtes).

Pour Claude Code, les outils des serveurs activés sont autorisés automatiquement (`--allowedTools mcp__<nom>`).

Seul le passage de la configuration au CLI a été vérifié (avec un CLI simulé). Aucun de ces serveurs MCP n'a été lancé pour de vrai depuis MuxAI. L'adresse du serveur Adobe vient d'un article tiers, pas de la documentation d'Adobe.

## GitHub

Dans **GitHub**, colle un jeton d’accès, puis coche les organisations entières ou les dépôts, un par un, sur lesquels les IA peuvent travailler. Rien n’est ouvert par défaut. Dans un projet, le champ « Dépôt GitHub » copie le dépôt sur le serveur (`data/repos/…`) et en fait le dossier de travail : Claude Code et Codex peuvent alors lire, modifier, valider et pousser.

Le jeton n’est jamais donné aux CLI : git le demande à un petit programme qui ne le rend que pour les dépôts cochés. C’est un garde-fou, pas une barrière étanche (le jeton reste dans le dossier de données). Pour une limite garantie par GitHub, utilise un jeton restreint aux mêmes dépôts. Ne couvre que git sur le serveur : pas les appareils reliés, pas les pull requests.

## Hub Nesaris

Dans le [Hub](https://github.com/Nesaris/Hub) : **Extensions → MuxAI → Installer**. Le Hub demande un jeton d’installation, que MuxAI réclame une seule fois pour créer le compte administrateur.

## Docker

L’adresse d’écoute et le mode proxy se règlent dans un fichier `.env` à côté de `docker-compose.yml` : `MUXAI_BIND=10.0.0.5:8180`, `MUXAI_TRUST_PROXY=1`.

```bash
docker compose up -d --build
```

Les identifiants des CLI sont gardés dans le volume `muxai-home` (ou passés par le connecteur, voir plus haut). Pour un Ollama sur l'hôte : `http://host.docker.internal:11434`.

## systemd

```bash
sudo useradd -r -m -d /home/muxai muxai
sudo mkdir -p /opt/muxai /var/lib/muxai && sudo cp -r server.js package.json public agent /opt/muxai/
sudo chown -R muxai: /opt/muxai /var/lib/muxai
sudo cp deploy/muxai.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now muxai
```

## Sécurité

- **Mets MuxAI derrière HTTPS** (Caddy, nginx, Traefik) dès qu'il sort de `127.0.0.1`, surtout avec des appareils : leur jeton transite à chaque requête. Désactive la mise en tampon du proxy pour le streaming (`proxy_buffering off` sous nginx).
- Un connecteur CLI **exécute des commandes** sur le serveur ou sur l'appareil. Ils sont réservés aux administrateurs par défaut. Le mode de permission de Claude Code et le bac à sable de Codex se règlent par connecteur.
- L'agent d'appareil refuse toute commande hors de sa liste `--allow`. Quiconque contrôle le serveur MuxAI peut toutefois faire agir le CLI sur l'appareil : ne relie un poste qu'à un serveur que tu maîtrises.
- Sans dossier de travail défini sur le projet, les CLI locaux s'exécutent dans `data/workspace`.
- Mots de passe en Argon2id (scrypt renforcé avant Node 24.7), 12 caractères minimum, verrou après dix échecs par adresse et par compte. Sessions de 12 heures, fermées après une heure d’inactivité, cookie `HttpOnly` + `SameSite=Strict` (préfixe `__Host-` en HTTPS), origine identique exigée, CSP stricte. Détail et limites connues : [SECURITY.md](SECURITY.md). Les clés, jetons et variables sont stockés en clair dans `data/db.json` (droits `600`) et ne sont jamais renvoyés au navigateur : protège ce dossier et sauvegarde-le. Les jetons d'appareil sont stockés hachés.
- Les inscriptions sont fermées par défaut.

## État

Vérifié de bout en bout avec des services simulés : comptes, projets, agents, streaming Ollama et API compatible OpenAI, exécution locale et sur appareil (agent réel, CLI simulé), arrêt d'une réponse distante, passage des outils MCP et des variables au CLI, menu des modèles, interface bureau et mobile.

À valider sur une vraie installation :
- La connexion guidée a été testée avec un CLI simulé sous Linux. Le format réel de `claude setup-token`, la sortie de `codex login` et le fonctionnement de `script` sous macOS n'ont pas été vérifiés. En cas d'échec, « Voir ce que répond le CLI » montre la sortie brute, et le jeton peut toujours être collé à la main dans les réglages du connecteur.
- Claude Code et Codex ont été testés contre des CLI simulés qui reproduisent leur format de sortie, pas contre les vrais binaires.
- Le passage des MCP à Codex (`-c mcp_servers.…`) et la reprise de session Codex n'ont pas été testés du tout.
- Le chargement des modèles via les API Anthropic et OpenAI n'a pas été testé avec une vraie clé.
- L'agent d'appareil n'a été testé que sous Linux. Sous Windows, si `claude` est un fichier `.cmd`, indique le chemin complet du `.exe` dans le connecteur.
- L'image Docker n'a pas été construite.

## Suite possible

- Pièces jointes et images.
- Proxy Ollama via un appareil (modèles locaux d'un autre poste).
- Interface en anglais.
