# Running the CSP agent on Windows

Two paths are supported:

- **PowerShell agent** — easiest, no compile step. Recommended to start.
  Pair the `.ps1` with the `.cmd` launcher (added in v0.3.1) so the user
  never sees the "running scripts is disabled" ExecutionPolicy prompt.
- **C# / .NET agent** — single-file `.exe`, useful for production-style
  deploys (Windows Service, no PowerShell dependency).

Both ship with the platform — download them straight from the operator
UI, no need to clone the repo.

---

## Path 1 — PowerShell agent (recommended)

> **TL;DR — the simplest first run** (zero ExecutionPolicy fights):
>
> 1. From the operator UI Agents tab, click **PowerShell launcher (.cmd) ★**
>    *and* **PowerShell (.ps1)** — two downloads, save them in the SAME folder.
> 2. Open `cmd.exe` (or PowerShell), `cd` to that folder.
> 3. Run:
>    ```cmd
>    csp-agent.cmd -C2 http://<csp-host-ip>:8080 -EnrollToken ent_xxx -Label win10-test-01
>    ```
>    Done. The .cmd handles ExecutionPolicy for you.
>
> The detailed walkthrough below is for cases where you want to invoke
> `powershell.exe` directly without the launcher.

### Step 1. Mint an enrollment token (on the C2 host)

1. Open the operator UI, e.g. `http://localhost:8088`.
2. Sign in and open the **Agents** tab.
3. Click **New enroll token** and copy the `ent_…` value
   (TTL 4 h, single-use).
4. Click the **PowerShell** download card under *Download agent*. Save
   `csp-agent.ps1` somewhere easy to grab.

### Step 2. Move the script(s) onto the Windows test endpoint

Use whatever you already have — SCP, an SMB share, USB, etc. A common
landing path is `C:\Tools\`. Place **both** `csp-agent.cmd` and
`csp-agent.ps1` in the same folder.

### Step 3. Run the agent

**Recommended — via the .cmd launcher (no ExecutionPolicy prompt):**

```cmd
cd C:\Tools

csp-agent.cmd -C2 http://<csp-host-ip>:8080 ^
              -EnrollToken ent_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx ^
              -Label win10-test-01
```

The `.cmd` invokes `powershell.exe -NoProfile -ExecutionPolicy Bypass -File csp-agent.ps1`
under the hood — process-scoped, so no system-wide policy change is made.

**Alternative — invoke PowerShell directly:**

```powershell
cd C:\Tools

powershell -ExecutionPolicy Bypass -File .\csp-agent.ps1 `
    -C2 http://<csp-host-ip>:8080 `
    -EnrollToken ent_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx `
    -Label win10-test-01
```

Substitute:

| Placeholder | Value |
|---|---|
| `<csp-host-ip>` | The IP/DNS name of the C2, reachable from the endpoint. Don't use `localhost` if the C2 is on a different machine. |
| `EnrollToken`   | The token you just copied. |
| `Label`         | Any string — shown as the hostname column in the Agents table. |

### Step 4. Expected output

```
2026-05-06T18:25:12 INFO registering with http://192.168.1.100:8080 ...
2026-05-06T18:25:13 INFO registered agent_id=agt_b91f3a02 interval=30s
2026-05-06T18:25:43 INFO got 0 task(s)
2026-05-06T18:26:13 INFO got 0 task(s)
…
```

Every 30 s the agent beacons. When `tasks: [...]` comes back non-empty,
the agent runs each one and reports the result on the same beacon cycle.

### Step 5. Verify on the C2

- **Agents** tab — `win10-test-01` now appears as `active` with rising
  `Beacons` count.
- **Queue task to selected agent** — pick the agent, technique
  (e.g. `T1059.001 PowerShell`), test (e.g. `whoami_via_powershell`),
  click **Queue task**.
- Within ~30 s the agent picks it up. **Recent agent tasks** shows the
  result with `stdout` / `stderr` / exit code. Click **view** for full
  detail.

---

## Path 2 — C# / .NET agent

### Build (once, on a dev box with the .NET SDK)

Install .NET 6+ SDK from <https://dotnet.microsoft.com/download>.

```powershell
# 1. Download CspAgent.cs from the operator UI (Agents tab → C# / .NET button)
# 2. Save it next to a fresh build directory, e.g. C:\Build\CspAgent.cs

cd C:\Build
dotnet new console -n CspAgent -o CspAgent
copy CspAgent.cs CspAgent\Program.cs    # overwrite scaffolded Program.cs
cd CspAgent
dotnet publish -c Release -r win-x64 `
    --self-contained false /p:PublishSingleFile=true

# Output: bin\Release\net6.0\win-x64\publish\CspAgent.exe
```

The `--self-contained false` flag keeps the binary small (~15 MB) at
the cost of requiring .NET runtime on the target. Use
`--self-contained true` for a fully-portable ~70 MB binary instead.

### Deploy + run

```powershell
.\CspAgent.exe `
    --c2 http://<csp-host-ip>:8080 `
    --enroll-token ent_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx `
    --label win-prod-01
```

Identical behaviour to the PowerShell agent — same beacon interval,
same task protocol, same audit trail.

---

## Common gotchas

| Symptom | Cause | Fix |
|---------|-------|-----|
| `cannot be loaded because running scripts is disabled on this system` | Default `Restricted` ExecutionPolicy | Run with `-ExecutionPolicy Bypass` per invocation. Don't change the machine policy. |
| SmartScreen popup *Windows protected your PC* | File downloaded from a network zone | Click **More info → Run anyway**, or run `Unblock-File .\csp-agent.ps1` once. |
| `Invoke-RestMethod : Unable to connect` | Network reachability | From the endpoint: `Test-NetConnection <csp-host-ip> -Port 8080` must return `True`. Check the C2's host firewall and your subnet. |
| `invalid or expired enroll_token` | Token already used or > 4 h old | Mint a new one in the UI. |
| Agent registers but doesn't appear in the Agents table | UI cache | Click **Refresh** on the Agents table or reload the page. |
| EDR / Defender quarantines `csp-agent.ps1` | Some EDRs are sensitive to `Invoke-WebRequest` patterns from a script with a network beacon loop | Add an EDR exclusion for the script path, or switch to the C# agent (single-file, fewer interpreter signals). |
| Defender flags the C# build output | Real-time protection scanning the publish dir | Add a Defender exclusion for `C:\Build\CspAgent\bin`, or build on a non-monitored host. |

---

## Stop / restart / cleanup

### Stop the agent on the endpoint
- `Ctrl+C` in the PowerShell window, or close the window.
- Closing the window terminates the process; no daemon is left behind.

### Kill the agent from the C2
- Agents tab → row's **kill** button → `status` flips to `killed`.
- The agent's next beacon returns HTTP 401, the loop logs a warning and
  exits. The OS process stops on its own.

### Re-use an agent identity (skip enrollment on restart)

When `--enroll-token` is consumed the agent prints its `agent_id` and
`agent_secret`. Save both somewhere safe; on subsequent runs:

```powershell
.\csp-agent.ps1 `
    -C2 http://<csp-host-ip>:8080 `
    -AgentId agt_b91f3a02 `
    -AgentSecret as_<long-secret-from-first-run>
```

The agent reuses the same identity — it shows up as the same row in the
Agents table, and the operator never sees the secret again.

---

## Running as a Windows service (production-style)

For long-running unattended deploys you generally want the agent to start
automatically and survive logoff.

### NSSM (recommended for simplicity)

```powershell
choco install nssm                # one-time
nssm install CspAgent
# Path:       C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
# Arguments:  -ExecutionPolicy Bypass -File C:\Tools\csp-agent.ps1
#             -C2 http://... -AgentId ... -AgentSecret ...
# Startup:    Automatic
nssm start CspAgent
nssm status CspAgent
```

### Task Scheduler

```powershell
schtasks /create /tn CspAgent `
    /tr "powershell -ExecutionPolicy Bypass -File C:\Tools\csp-agent.ps1 -C2 http://... -AgentId ... -AgentSecret ..." `
    /sc onlogon /rl highest
```

Both approaches keep the secret in the service config — protect that
config the same way you protect any service credential.

---

## Test scenarios that pair well with the Windows agent

| Tactic                        | Technique     | Test                                     |
|-------------------------------|---------------|------------------------------------------|
| Execution                     | `T1059.001`   | `whoami_via_powershell`, `encoded_command` |
| Execution                     | `T1059.003`   | `whoami_via_cmd`                         |
| Discovery                     | `T1082`       | `systeminfo_windows`                     |
| Discovery                     | `T1087.001`   | `net_user_windows`                       |
| Discovery (security software) | `T1518.001`   | `list_av_services_windows`               |
| Persistence (registry)        | `T1547.001`   | `write_run_key_test`                     |
| Persistence (scheduled)       | `T1053.005`   | `schtasks_list`                          |
| Defense evasion               | `T1218.011`   | `rundll32_help`                          |
| Credential access             | `T1003`       | `lsass_handle_simulation`                |
| Credential access             | `T1550.002`   | `pth_keyword_simulation_powershell`      |
| Lateral movement              | `T1021.002`   | `enumerate_local_smb_shares`             |
| Lateral movement              | `T1021.006`   | `test_wsman_localhost`                   |
| Lateral movement              | `T1570`       | `copy_item_to_session_simulation`        |

For the *download → execute* behavioural chain (EDR / Cortex XDR), use
the Generate tab to produce a `dropper-ps1` artifact and run it directly
on the endpoint, or queue it as a follow-on technique once milestone D
adds run-arbitrary-artifact support.
