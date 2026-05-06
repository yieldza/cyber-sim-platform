# Cyber Sim Platform (CSP)

Blue-team detection-testing platform for **EDR / XDR / SASE** validation.
Generates artifacts that look like malware to static and behavioral scanners
without containing any real malicious code — every payload is the
[EICAR Anti-Virus Test File](https://www.eicar.org/download-anti-malware-testfile/),
the industry-standard, harmless test signature.

## ⚠️ Safety / Authorized Use

- **All artifacts are EICAR-signature only.** No real malware, exploits, or
  shellcode are produced.
- Use only on systems and networks you are **authorized** to test (your own
  lab, your employer's environment with written approval, or an authorized
  pentest engagement).
- AV/EDR products will quarantine generated files. That is the intended
  behaviour and the entire point of this platform.

## Capabilities

### Milestone A — Files

| Capability      | Endpoint                | Description                                              |
|-----------------|-------------------------|----------------------------------------------------------|
| Generate        | `POST /api/files/generate` | EICAR in `eicar`, `com`, `pe`, `pdf`, `apk`, `docx`     |
| Hash mutate     | `POST /api/files/:id/mutate` | `append_random`, `append_hash`, `pad`, `until_prefix` |
| Format convert  | `POST /api/files/convert` | `rewrap` to another container, or `polyglot` (PDF+ZIP)  |
| Library         | `GET /api/files/`       | List, inspect, download previously generated artifacts   |

### Milestone B — MITRE ATT&CK simulator

| Capability        | Endpoint                              | Description                                              |
|-------------------|---------------------------------------|----------------------------------------------------------|
| Catalog list      | `GET /api/techniques/`                | 27 benign technique tests across 7 tactics               |
| Catalog detail    | `GET /api/techniques/:id`             | Full technique + test details                            |
| Run on worker     | `POST /api/techniques/:id/run`        | Execute Linux/bash test in worker container, capture stdout/stderr |
| Generate script   | `POST /api/techniques/:id/script`     | Download `.ps1` / `.bat` / `.sh` / `.py` for any platform |
| Run history       | `GET /api/runs/`                      | Persisted runs with command, exit code, output           |

Tactics covered: `execution`, `discovery`, `defense-evasion`, `persistence`,
`credential-access`, **`lateral-movement`**, `command-and-control`. Catalog
is at [worker/app/techniques/catalog.json](worker/app/techniques/catalog.json)
— extend by editing the JSON.

**Lateral-movement coverage** (added without leaving any host):
| Technique | Test | Mode |
|-----------|------|------|
| T1021.004 SSH | spawn ssh against invalid host with `BatchMode=yes` | runnable (linux/macos) |
| T1021.002 SMB / Admin Shares | `Get-SmbShare` + `\\\\localhost\\C$` probe | script (windows) |
| T1021.006 WinRM | `Test-WSMan -ComputerName localhost` | script (windows) |
| T1570 Lateral Tool Transfer | scp to invalid host (no transfer) + Copy-Item -ToSession | runnable (linux) + script (windows) |
| T1550.002 Pass-the-Hash | echo `sekurlsa::pth` keyword (string match only) | runnable + script |

All lateral tests target invalid hostnames or `localhost` — they emit the
process / cmdlet telemetry your EDR should detect, but never authenticate
to or move to another host.

### Milestone C — Caldera-style HTTP-polling agents

| Capability        | Endpoint                                  | Description                                              |
|-------------------|-------------------------------------------|----------------------------------------------------------|
| Enroll token      | `POST /api/agents/enroll-token`           | Operator mints a one-time, 4 h TTL token                 |
| Register          | `POST /agent-c2/register`                 | Agent consumes token, receives `agent_id` + `agent_secret` |
| Beacon            | `POST /agent-c2/beacon`                   | Agent polls; server returns up to 5 pending tasks        |
| Result            | `POST /agent-c2/result`                   | Agent reports stdout/stderr/exit/duration                |
| List agents       | `GET /api/agents/`                        | Operator UI                                              |
| Queue task        | `POST /api/agents/:id/tasks`              | Operator selects technique+test from catalog             |
| Task detail       | `GET /api/agents/tasks/:taskId`           | Status, exit code, output                                |
| Kill agent        | `POST /api/agents/:id/kill`               | Flips status; agent gets 401 next beacon                 |

**Three reference agents** at [`agent/`](agent/):
| Path | Platform | Runtime |
|------|----------|---------|
| [`python/csp_agent.py`](agent/python/csp_agent.py)        | Linux / macOS | Python 3.9+ stdlib only |
| [`powershell/csp-agent.ps1`](agent/powershell/csp-agent.ps1) | Windows       | PowerShell 5.1+ |
| [`csharp/CspAgent.cs`](agent/csharp/CspAgent.cs)            | Windows       | .NET 6+ |

**Safety design:** Operators do not send commands. They send `{technique_id,
test_name}` and the API gateway looks up the command verbatim from the
catalog before queueing. Agents only execute the executors they expect
(`bash` / `sh` / `python3` on \*nix, `powershell` / `pwsh` / `cmd` on
Windows). Per-task wall-clock timeout (default 15 s, max 60 s) and 32 KB
output cap. All actions audited.

Upcoming milestone (D): prompt-driven feature extension.

## Stack

| Component | Tech                                       |
|-----------|--------------------------------------------|
| Worker    | Python 3.12 + FastAPI                      |
| API       | Node.js 20 + Express + SQLite (better-sqlite3) |
| Auth      | bcrypt + JWT (12 h)                        |
| Web       | Static HTML5 + vanilla JS, served by nginx |
| Deploy    | Docker Compose                             |

## Quick start

```bash
cp .env.example .env
# edit .env: set strong WORKER_API_KEY, JWT_SECRET, ADMIN_USER, ADMIN_PASS

docker compose up --build -d

# Web UI
open http://localhost:8088
# API
curl http://localhost:8080/healthz
```


### Consumers: pull and run from Hub

A new operator can deploy without cloning the repo. They only need:

1. The compose file + `.env.example` from this repo
2. Docker

```bash
curl -O https://raw.githubusercontent.com/<your-user>/cyber-sim-platform/main/docker-compose.yml
curl -O https://raw.githubusercontent.com/<your-user>/cyber-sim-platform/main/.env.example
mv .env.example .env && $EDITOR .env

docker compose pull                   # pulls 3 images from Docker Hub
docker compose up -d
```

Or use the convenience wrapper:

```bash
scripts/pull-and-run.sh
```

Sign in with the admin credentials you set in `.env`. The first start
auto-bootstraps that user; create additional analyst users via
`POST /api/auth/users` (admin only).

## Layout

```
cyber-sim-platform/
├── docker-compose.yml
├── .env.example
├── api/                  # Node Express gateway
│   ├── Dockerfile
│   └── src/
│       ├── server.js
│       ├── db/{schema.sql,index.js}
│       ├── middleware/auth.js
│       ├── routes/{auth.js,files.js}
│       └── services/{workerClient.js,artifactStore.js}
├── worker/               # Python FastAPI workers
│   ├── Dockerfile
│   └── app/
│       ├── main.py
│       ├── generators/{eicar,pe,pdf,apk,docx}.py
│       ├── hash_mutator/mutator.py
│       └── converter/polyglot.py
├── web/                  # nginx-served static UI
│   ├── nginx.conf
│   ├── index.html
│   ├── styles.css
│   └── app.js
└── data/                 # SQLite DB + artifact storage (bind-mounted)
```

## API examples

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"<your pass>"}' | jq -r .token)

# Generate a PDF
curl -s -X POST http://localhost:8080/api/files/generate \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"file_type":"pdf"}' | jq

# Mutate hash by appending 32 random bytes
curl -s -X POST http://localhost:8080/api/files/<id>/mutate \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"operation":"append_random","n":32}' | jq

# Convert: produce a polyglot PDF+APK
curl -s -X POST http://localhost:8080/api/files/convert \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"target":"apk","mode":"polyglot"}' | jq

# Download
curl -s -OJ -H "authorization: Bearer $TOKEN" \
  http://localhost:8080/api/files/<id>/download
```

## Audit log

Every operation (login, generate, mutate, convert, download, user creation)
is recorded to the `audit_log` table with timestamp, user, IP, and detail.

## What this platform does **not** do

- It does not produce real malware, working exploits, or any payload that
  performs a malicious action on a target system.
- It does not bypass any specific AV/EDR vendor — it produces test artifacts
  to measure the configured detection coverage in your own environment.
- Hash collision search (`until_prefix`) is hard-capped at 6 hex chars and
  1M iterations to keep the worker responsive; it is for demonstrating the
  concept, not for producing real collisions.

## ATT&CK examples

```bash
# List the catalog
curl -s http://localhost:8080/api/techniques/ \
  -H "authorization: Bearer $TOKEN" | jq '.techniques[] | {id, name, tactic}'

# Run a Linux test on the worker
curl -s -X POST http://localhost:8080/api/techniques/T1059.004/run \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"test_name":"whoami_via_bash"}' | jq

# Download a PowerShell script for a Windows-only test
curl -s -X POST http://localhost:8080/api/techniques/T1547.001/script \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"test_name":"write_run_key_test"}' | jq -r .data_b64 | base64 -d > T1547.ps1
```

## Agent / C2 examples

```bash
# Operator: mint an enroll token
TOKEN_DATA=$(curl -s -X POST http://localhost:8080/api/agents/enroll-token \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"label":"lab-01"}')
ENT=$(echo $TOKEN_DATA | jq -r .token)

# On the test endpoint: register + beacon
python3 agent/python/csp_agent.py \
  --c2 http://localhost:8080 --enroll-token $ENT --label lab-01

# Operator: queue a task to the registered agent
curl -s -X POST http://localhost:8080/api/agents/<agent_id>/tasks \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"technique_id":"T1059.004","test_name":"whoami_via_bash"}'
```

## Roadmap

- [x] **A.** File generators + hash mutation + polyglot conversion
- [x] **B.** MITRE ATT&CK technique catalog (27 techs / 7 tactics) + benign runner + script generator
- [x] **C.** HTTP-polling agent (Python / PowerShell / C#) + C2 task queue
- [ ] **D.** Prompt-driven feature extension (LLM-assisted technique authoring)

## Changelog

### v0.3.1 — 2026-05-06

Fixes the "running scripts is disabled on this system" prompt that
operators saw on first run of the PowerShell agent.

- **New `csp-agent.cmd` launcher** (downloadable from the Agents tab as
  *PowerShell launcher (.cmd) ★*). It calls
  `powershell.exe -NoProfile -ExecutionPolicy Bypass -File csp-agent.ps1`
  process-scoped, so the user no longer sees the ExecutionPolicy block
  and the host machine policy is not modified. The launcher requires the
  `.ps1` to live in the same folder.
- **Updated agent download UI** — now four cards (Python, PowerShell .cmd
  launcher, PowerShell .ps1, C#). The launcher card is highlighted with
  the accent border to flag it as the recommended Windows path.
- **Header note injected into the .ps1 download** points new users at
  the .cmd launcher first.
- **Docs:** [`docs/agent-windows.md`](docs/agent-windows.md) opens with a
  TL;DR that uses the .cmd launcher; the manual `-ExecutionPolicy Bypass`
  invocation is kept as the alternative.

Image tags published to Docker Hub (multiarch `linux/amd64` + `linux/arm64`):

```
docker.io/124000pk/yieldpk:csp-api-0.3.1       327 MB
docker.io/124000pk/yieldpk:csp-worker-0.3.1    330 MB
docker.io/124000pk/yieldpk:csp-web-0.3.1        40 MB
```

### How to update an existing deployment to v0.3.1

```bash
cd /path/to/csp
sed -i.bak \
  -e 's/^TAG_API=.*/TAG_API=csp-api-0.3.1/' \
  -e 's/^TAG_WORKER=.*/TAG_WORKER=csp-worker-0.3.1/' \
  -e 's/^TAG_WEB=.*/TAG_WEB=csp-web-0.3.1/' \
  .env

docker compose pull && docker compose up -d
```

No DB migration. After upgrade, re-download the PowerShell agent files
from the Agents tab — the new .cmd launcher is offered there.

### v0.3.0 — 2026-05-06

Behavioural detection coverage + better agent UX + branding:

- **Behavioural droppers (Generate tab).** Three new file types produce
  ready-to-run scripts that exercise the *download → drop → execute*
  chain that EDR / Cortex XDR look at when static-hash blocking is
  bypassed:
  - `dropper-ps1` — PowerShell, Windows
  - `dropper-sh`  — bash, Linux/macOS
  - `dropper-py`  — Python, cross-platform

  Each script downloads the official EICAR file from `secure.eicar.org`,
  drops it to `%TEMP%` / `$TMPDIR`, attempts to execute, then cleans up.
  AV/EDR is expected to intercept on write or on exec — the *behavioural
  signals* (process spawn, outbound 443, file_create_executable, spawn
  from new file) are what we are testing for. Each generation embeds a
  random 12-hex session id so the script's own SHA-256 is unique
  per-call (combine with the Mutate-hash tab for static + behavioural
  coverage).

- **Agent download from the Web UI (Agents tab).** New
  `GET /api/agents/download/:lang` route serves the agent source
  (`python` / `powershell` / `csharp`) directly from the C2 — operators
  no longer need to clone the repo. The download endpoint also injects
  a header comment with the typical first-run permission fix:
  - Python: `chmod +x csp_agent.py` (or run via `python3 csp_agent.py …`)
  - PowerShell: `powershell -ExecutionPolicy Bypass -File .\csp-agent.ps1 …`
  - C#: `dotnet publish` recipe in the file's prelude

  Replaces the previous `alert()`-based "open the path in repo" UX.
  Each download is recorded in `audit_log` (action `agent_source_download`).

- **Branding footer.** "Powered By GizmoPK" added to the bottom of every
  page.

- **Internal: API build context moved to project root** so the API image
  can bundle the `agent/` directory at `/app/agent`. The build script
  and docker-compose now pass `-f api/Dockerfile` with `context: .`
  for that one service; worker and web are unchanged.

Image tags published to Docker Hub (multiarch `linux/amd64` + `linux/arm64`):

```
docker.io/124000pk/yieldpk:csp-api-0.3.0       327 MB
docker.io/124000pk/yieldpk:csp-worker-0.3.0    330 MB
docker.io/124000pk/yieldpk:csp-web-0.3.0        40 MB
```

`v0.1.0` and `v0.2.0` tags remain on Docker Hub for pinning.

### How to update an existing deployment to v0.3.0

```bash
cd /path/to/csp
sed -i.bak \
  -e 's/^TAG_API=.*/TAG_API=csp-api-0.3.0/' \
  -e 's/^TAG_WORKER=.*/TAG_WORKER=csp-worker-0.3.0/' \
  -e 's/^TAG_WEB=.*/TAG_WEB=csp-web-0.3.0/' \
  .env

docker compose pull           # pulls the 3 new images
docker compose up -d          # recreates containers
docker compose ps             # confirm all three are Up
```

**No DB migration required** — schema is unchanged across 0.1 → 0.2 → 0.3.

### v0.2.0 — 2026-05-06

UX improvements on the Generate and Mutate tabs:

- **Generate tab — auto-download.** Clicking *Generate* now produces the
  artifact and immediately streams it to your browser as a download. No
  more switching to the Library tab to grab the file. If the auto-download
  fails (e.g. browser blocks it), the artifact is still saved server-side
  and a clear error points you to the Library tab.
- **Mutate tab — Browse local drive.** A new *Source* toggle lets you
  pick the bytes to mutate from either:
  - **From library (previously generated)** — original behaviour.
  - **Browse local drive** — any local file up to 10 MB. The file is read
    in the browser via `FileReader`, base64-encoded, and POSTed to the
    new `POST /api/files/mutate-upload` endpoint. The mutated result is
    persisted as a new artifact (`source_op = mutate-upload`, no parent)
    and auto-downloaded.

Image tags published to Docker Hub (multiarch `linux/amd64` + `linux/arm64`):

```
docker.io/124000pk/yieldpk:csp-api-0.2.0       327 MB
docker.io/124000pk/yieldpk:csp-worker-0.2.0    330 MB
docker.io/124000pk/yieldpk:csp-web-0.2.0        40 MB
```

`v0.1.0` tags remain on Docker Hub for pinning.

### How to update an existing deployment to v0.2.0

```bash
cd /path/to/csp                               # where docker-compose.yml + .env live

# bump tags (sed any version, or edit by hand)
sed -i.bak \
  -e 's/^TAG_API=.*/TAG_API=csp-api-0.2.0/' \
  -e 's/^TAG_WORKER=.*/TAG_WORKER=csp-worker-0.2.0/' \
  -e 's/^TAG_WEB=.*/TAG_WEB=csp-web-0.2.0/' \
  .env

docker compose pull           # pulls 3 new images from Docker Hub
docker compose up -d          # recreates containers using the new images
docker compose ps             # confirm csp-api / csp-worker / csp-web are up

# verify
curl -s http://localhost:8080/healthz | jq
open http://localhost:8088
```

**No DB migration required** — the SQLite schema for v0.2.0 is identical
to v0.1.0. Existing artifacts, agents, audit logs, and technique runs
are preserved.

### Rollback

```bash
sed -i.bak 's/0\.2\.0/0.1.0/g' .env
docker compose pull && docker compose up -d
```

### v0.1.0 — 2026-05-03

Initial release: milestones A (file generators / hash mutation / polyglot
conversion), B (27-technique ATT&CK catalog incl. lateral movement), and
C (Caldera-style HTTP-polling agents).
