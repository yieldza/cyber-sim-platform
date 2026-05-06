# CSP Agents

Three agent implementations target different test endpoints:

| Agent | Path | Platform | Runtime |
|-------|------|----------|---------|
| Python    | [`python/csp_agent.py`](python/csp_agent.py)        | Linux / macOS    | Python 3.9+ stdlib only |
| PowerShell| [`powershell/csp-agent.ps1`](powershell/csp-agent.ps1) | Windows         | PowerShell 5.1+ |
| C# / .NET | [`csharp/CspAgent.cs`](csharp/CspAgent.cs)            | Windows         | .NET 6+ |

## Enrollment flow

1. Sign in to the operator UI and open the **Agents** tab.
2. Click **New enroll token** — copy the `ent_…` value (TTL: 4 h, single-use).
3. Click the matching **Download agent** button to save the script
   directly from the C2 (no need to clone this repo).
4. Drop the script onto the test endpoint and run (see permissions section
   below for typical first-run gotchas).

## Per-platform deep dives

- **Windows quickstart (PowerShell + C#):**
  [`docs/agent-windows.md`](../docs/agent-windows.md) — step-by-step
  enrollment, ExecutionPolicy fixes, NSSM / Task Scheduler service deploy,
  and a list of techniques that pair well with the Windows agent.

## Common first-run permission gotchas

**Linux / macOS — Python agent**
```bash
chmod +x csp_agent.py                              # make executable
./csp_agent.py --c2 https://csp.example.com ...
# OR — never chmod, run via interpreter
python3 csp_agent.py --c2 https://csp.example.com ...
```

**Windows — PowerShell agent**
```powershell
# Default ExecutionPolicy on Windows blocks unsigned scripts. Two options:
# (1) Per-process bypass — recommended for one-shot runs:
PowerShell -ExecutionPolicy Bypass -File .\csp-agent.ps1 -C2 https://... -EnrollToken ent_...

# (2) Per-session bypass:
Set-ExecutionPolicy -Scope Process Bypass -Force
.\csp-agent.ps1 -C2 https://... -EnrollToken ent_...

# If Windows SmartScreen / "Unblock" pops up:
Unblock-File .\csp-agent.ps1
```

**Windows — C# agent**
The repo ships the C# source. Build once, then deploy the produced .exe:
```powershell
dotnet new console -n CspAgent -o CspAgent
copy CspAgent.cs CspAgent\Program.cs   # overwrite scaffolded Program.cs
cd CspAgent
dotnet publish -c Release -r win-x64 --self-contained false /p:PublishSingleFile=true
.\bin\Release\net6.0\win-x64\publish\CspAgent.exe --c2 https://... --enroll-token ent_...
```



```bash
# Linux / macOS
python3 csp_agent.py \
  --c2 https://csp.example.com \
  --enroll-token ent_abc123... \
  --label lab-host-01
```

```powershell
# Windows
.\csp-agent.ps1 -C2 https://csp.example.com -EnrollToken ent_abc123...
```

```bash
# C# / .NET — build once, deploy the published exe
dotnet new console -n CspAgent -o CspAgent
cp CspAgent.cs CspAgent/Program.cs
cd CspAgent && dotnet publish -c Release -r win-x64 \
  --self-contained false /p:PublishSingleFile=true
.\bin\Release\net6.0\win-x64\publish\CspAgent.exe \
  --c2 https://csp.example.com --enroll-token ent_abc123...
```

After registration the agent prints its `agent_id` and `agent_secret`
(persist them if you want to restart without re-enrolling — pass
`--agent-id` and `--agent-secret` instead of `--enroll-token`).

## What an agent does

```
                    register (ent_token)
   ┌──────────┐  ─────────────────────────►  ┌──────────┐
   │  agent   │                              │   C2     │
   │          │   ◄──── agent_id, secret ────│          │
   │          │                              │          │
   │          │   POST /agent-c2/beacon      │          │
   │          │   ──────────────────────────►│          │
   │          │   ◄──── tasks: [{cmd...}] ───│          │
   │          │                              │          │
   │  exec    │                              │          │
   │  cmd     │   POST /agent-c2/result      │          │
   │          │   ──────────────────────────►│          │
   └──────────┘                              └──────────┘
```

* All commands come from the C2 server, which only queues commands that
  came verbatim from the catalog. Agents never accept arbitrary command
  bodies from operators.
* Per-task wall-clock timeout (default 15 s, max 60 s). Output truncated
  to 32 KB per stream.
* Only `bash` / `sh` / `python3` (Linux/Mac) or `powershell` / `pwsh` /
  `cmd` (Windows) executors are runnable.

## Stopping an agent

The operator UI **Kill** button flips `agents.status = killed` server-side.
On the next beacon the C2 returns `401`, and the agent loop exits with a
warning. The agent process itself is not modified by the C2.

## Production deployment notes

* Run the C2 behind TLS (NGINX terminator, Let's Encrypt). Agent secrets
  are bearer tokens transmitted on every beacon.
* The default beacon interval is 30 s. Tune via `--interval` for noisier
  or quieter telemetry.
* All agent activity is logged to `audit_log` (event types
  `agent_register`, `agent_task_queue`, `agent_task_result`, `agent_kill`).
