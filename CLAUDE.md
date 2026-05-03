# Cyber Sim Platform — Working Notes for Claude

> This file is auto-loaded by Claude Code when the working directory is
> inside `cyber-sim-platform/`. It captures the design intent, what is
> already built, and what is still pending so that we don't re-derive
> context from scratch each session.

## What this project is

A **defensive** blue-team detection-testing platform (EDR / XDR / SASE
validation). Every payload is the **EICAR test signature** or a **benign
ATT&CK simulation** — never real malware, working exploits, or actual
credential theft. Treat the EICAR/benign boundary as inviolable.

## Stack snapshot

- **Worker** — Python 3.12 + FastAPI (file generators, hash mutator,
  polyglot converter, technique runner, script generator)
- **API gateway** — Node.js 20 + Express + SQLite (better-sqlite3) +
  bcrypt + JWT
- **Web UI** — static HTML5 + vanilla JS (no build step), served by nginx
- **Agents** — Python (linux/macos), PowerShell + C#/.NET (windows)
- **Deploy** — Docker Compose

## Milestones

### ✅ A — File artifacts
- Generators: `eicar`, `com`, `pe`, `pdf`, `apk`, `docx` (all carry EICAR detectably)
- Hash mutate: `append_random`, `append_hash`, `pad`, `until_prefix` (cap 6 hex / 1M iter)
- Convert: container `rewrap` + PDF+ZIP `polyglot`

### ✅ B — MITRE ATT&CK simulator
- Catalog at `worker/app/techniques/catalog.json` — 27 techniques across 7 tactics:
  `execution`, `discovery`, `defense-evasion`, `persistence`,
  `credential-access`, `lateral-movement`, `command-and-control`
- **Lateral movement** coverage: T1021.004 SSH, T1021.002 SMB,
  T1021.006 WinRM, T1570 Lateral Tool Transfer, T1550.002 Pass-the-Hash
  (simulation only)
- 14 runnable bash/python tests + script generator (`.ps1`/`.bat`/`.sh`/`.py`)
- T1003 credential dumping is **keyword-echo simulation only** — never
  produce real PtH/dumping code

### ✅ C — Caldera-style HTTP-polling agents
- Operator endpoints: `/api/agents/*` (JWT-auth)
- Agent C2 channel: `/agent-c2/{register,beacon,result}` (bearer-secret-auth)
- Three reference agents in `agent/{python,powershell,csharp}/`
- Operator sends `{technique_id, test_name}`; **server fetches command
  from catalog** before queueing — agents never accept arbitrary command
  bodies from the network
- Per-task timeout default 15 s, max 60 s; output cap 32 KB / stream
- 4 h single-use enrollment tokens; bcrypt(10) on agent_secret

### ⏳ D — Prompt-driven feature extension (pending)

When the user resumes, **show this remaining-milestone block as the
first response** (they explicitly asked to be reminded next session):

| Feature | Description |
|---------|-------------|
| Add technique via prompt | "Add Tnnnn.nnn …" → LLM emits catalog JSON → operator review → admin commit |
| Generate custom scripts via prompt | "Make me a PowerShell variant of X with Y constraint" → script with safety review gate |
| Translate to detection rules | LLM emits Sigma / KQL / SPL from a technique entry |
| Auto-tag audit log to ATT&CK | feed `audit_log` rows → LLM proposes T-IDs |

**Tech approach (proposed, await user confirmation before building):**
- Anthropic API (Claude) or OpenAI API as the model backend
- **Approval gate** on every generation — operator (admin role) must
  click "Approve & commit" before catalog mutates
- Output goes through strict JSON schema validation against the
  `Technique`/`TechniqueTest` shape in `worker/app/techniques/loader.py`
- Add `prompt_history` table for traceability
- Rate limit & spend cap per user
- New web tab "Prompt" with chat-like UX

## Conventions / gotchas

- **Default branch:** main. Project is private/lab until explicitly published.
- **Secrets:** never commit `.env`. `.gitignore` already excludes it.
- **DB schema** is at `api/src/db/schema.sql`. `IF NOT EXISTS` everywhere
  — additive migrations only. Don't drop columns; add new ones.
- **Worker → API** auth: static `WORKER_API_KEY` in `x-api-key` header
- **Agent → C2** auth: bearer-style `x-agent-id` + `x-agent-secret`
- **Operator → API** auth: JWT (12 h)
- **Route ordering** in Express: static path segments (e.g.
  `/agents/tasks/:id`) **must** be declared before catch-all
  (`/agents/:id`). Was a real bug we fixed in milestone C.
- **EICAR in ZIP containers** (apk, docx) is stored uncompressed
  (`ZIP_STORED`) so static byte scanners detect the signature without
  inflating. Preserve this when adding new ZIP-based generators.

## Testing recipes

```bash
# Worker module smoke test (no docker needed)
cd worker && python3 -c "
import sys; sys.path.insert(0, '.')
from app.generators import minimal_pe, eicar_pdf, eicar_apk, eicar_docx
from app.techniques import run_test, list_techniques
print('catalog size:', len(list_techniques()))
r = run_test('T1059.004', 'whoami_via_bash')
print('run exit:', r.exit_code, 'dur:', r.duration_ms, 'ms')
"

# Python agent against a mock C2 (works in <2s)
# See: scripts/smoke-agent-mock.sh (or the inline /tmp/csp_mock_c2.py recipe)
```

## What NOT to do

- Don't add real malware, working exploits, or any payload that performs
  malicious action on a target system. EICAR + benign ATT&CK only.
- Don't bypass the operator → catalog → agent flow. Operators submit
  technique IDs, not raw commands.
- Don't remove the platform-compatibility check in the runner — Linux
  worker must refuse Windows tests, agents likewise.
- Don't drop the audit log. It is the answer to "who ran what when".
