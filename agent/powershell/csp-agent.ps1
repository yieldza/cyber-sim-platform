<#
.SYNOPSIS
  CSP Cyber Sim Platform - PowerShell agent (Windows).

.DESCRIPTION
  Caldera-style HTTP-polling agent. Registers with the C2 using a one-time
  enrollment token, then beacons for tasks. Each task is a benign telemetry
  test from the catalog, executed via the named executor (powershell / cmd).

  All commands come from the C2; the agent does not parse arbitrary input
  from the network. Per-task timeout enforced locally, output truncated to
  32 KB per stream. Run on systems you own / are authorized to test.

.PARAMETER C2
  Base URL of the C2, e.g. https://csp.example.com

.PARAMETER EnrollToken
  One-time enrollment token issued by an operator.

.PARAMETER Label
  Optional hostname label sent at registration (default: $env:COMPUTERNAME).

.PARAMETER IntervalSeconds
  Beacon interval (default: server-controlled, fallback 30 s).

.PARAMETER Once
  Single beacon then exit - useful for debugging.

.EXAMPLE
  .\csp-agent.ps1 -C2 https://csp.example.com -EnrollToken ent_abc...
#>
param(
  [Parameter(Mandatory)] [string] $C2,
  [string] $EnrollToken,
  [string] $AgentId,
  [string] $AgentSecret,
  [string] $Label = $env:COMPUTERNAME,
  [int]    $IntervalSeconds = 30,
  [switch] $Once,
  [switch] $Verbose
)

$ErrorActionPreference = 'Stop'
$AgentVersion  = '0.3.0-ps'
$MaxOutput     = 32 * 1024
$MaxTimeoutSec = 60
$RunnableExec  = @('powershell', 'cmd', 'pwsh')

function Write-Log($msg, $level='INFO') {
  $ts = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
  Write-Host "$ts $level $msg"
}

function Get-InternalIP {
  try {
    $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
           Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
           Select-Object -ExpandProperty IPAddress
    if ($ips) { return $ips[0] }
  } catch {}
  return $null
}

function Invoke-C2($Path, $Body, $Headers=@{}) {
  $url = "$C2/$Path".TrimEnd('/').Replace($C2 + '//', $C2 + '/')
  $json = if ($Body) { ($Body | ConvertTo-Json -Depth 10 -Compress) } else { '{}' }
  $H = @{'content-type'='application/json'} + $Headers
  return Invoke-RestMethod -Method Post -Uri $url -Headers $H -Body $json -TimeoutSec 30
}

function Run-Task($task, $defaultTimeout) {
  $exec = $task.executor
  $cmd  = $task.command
  $timeout = [Math]::Max(1, [Math]::Min([int]$task.timeout_sec, $MaxTimeoutSec))
  if (-not $timeout) { $timeout = $defaultTimeout }

  $result = @{
    task_id     = $task.id
    status      = 'done'
    exit_code   = 0
    duration_ms = 0
    stdout      = ''
    stderr      = ''
    truncated   = $false
  }

  if ($RunnableExec -notcontains $exec) {
    $result.status = 'error'; $result.exit_code = -2
    $result.stderr = "executor '$exec' not runnable on this agent"
    return $result
  }

  $stdoutFile = [IO.Path]::GetTempFileName()
  $stderrFile = [IO.Path]::GetTempFileName()
  $argv = switch ($exec) {
    'powershell' { @('powershell.exe', '-NoProfile', '-NonInteractive', '-Command', $cmd) }
    'pwsh'       { @('pwsh',           '-NoProfile', '-NonInteractive', '-Command', $cmd) }
    'cmd'        { @('cmd.exe',        '/c',          $cmd) }
  }

  $sw = [Diagnostics.Stopwatch]::StartNew()
  try {
    $p = Start-Process -FilePath $argv[0] -ArgumentList $argv[1..($argv.Count-1)] `
                       -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile `
                       -NoNewWindow -PassThru
    if (-not $p.WaitForExit($timeout * 1000)) {
      try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
      $result.status = 'timeout'; $result.exit_code = -9
      $result.stderr += "`n[timeout after ${timeout}s]"
      $result.truncated = $true
    } else {
      $result.exit_code = $p.ExitCode
    }
  } catch {
    $result.status = 'error'; $result.exit_code = -3
    $result.stderr = $_.Exception.Message
  }
  $sw.Stop()
  $result.duration_ms = [int]$sw.ElapsedMilliseconds

  if (Test-Path $stdoutFile) {
    $out = Get-Content $stdoutFile -Raw -ErrorAction SilentlyContinue
    if ($out) {
      $result.stdout = if ($out.Length -gt $MaxOutput) {
                        $result.truncated = $true; $out.Substring(0, $MaxOutput)
                      } else { $out }
    }
    Remove-Item $stdoutFile -Force -ErrorAction SilentlyContinue
  }
  if (Test-Path $stderrFile) {
    $err = Get-Content $stderrFile -Raw -ErrorAction SilentlyContinue
    if ($err) {
      $result.stderr += if ($err.Length -gt $MaxOutput) {
                        $result.truncated = $true; $err.Substring(0, $MaxOutput)
                      } else { $err }
    }
    Remove-Item $stderrFile -Force -ErrorAction SilentlyContinue
  }

  if ($task.cleanup) {
    try { powershell.exe -NoProfile -Command $task.cleanup | Out-Null } catch {}
  }
  return $result
}

# ---------- registration / loop ----------
if ($AgentId -and $AgentSecret) {
  $id = $AgentId; $secret = $AgentSecret
  $interval = $IntervalSeconds
  Write-Log "re-using agent_id=$id"
} elseif ($EnrollToken) {
  Write-Log "registering with $C2 ..."
  $reg = Invoke-C2 'agent-c2/register' @{
    enroll_token  = $EnrollToken
    hostname      = $Label
    platform      = 'windows'
    agent_version = $AgentVersion
    internal_ip   = (Get-InternalIP)
  }
  $id     = $reg.agent_id
  $secret = $reg.agent_secret
  $interval = if ($reg.beacon_interval_sec) { [int]$reg.beacon_interval_sec } else { $IntervalSeconds }
  Write-Log "registered agent_id=$id interval=${interval}s"
} else {
  throw 'Provide either -EnrollToken, or -AgentId + -AgentSecret'
}

$Hdr = @{'x-agent-id'=$id; 'x-agent-secret'=$secret}
$AuthFailBackoff = 5
$AuthFails = 0

while ($true) {
  try {
    if ($Verbose) { Write-Log 'beacon...' 'DEBUG' }
    $resp = Invoke-C2 'agent-c2/beacon' @{} $Hdr
    $AuthFails = 0  # reset on any successful beacon

    # Operator killed this agent from the console - exit cleanly.
    if ($resp.shutdown) {
      $reason = if ($resp.reason) { $resp.reason } else { 'shutdown_signal' }
      Write-Log "shutdown signal received from C2 (reason=$reason) - exiting"
      exit 0
    }

    if ($resp.tasks -and $resp.tasks.Count -gt 0) {
      Write-Log ("got {0} task(s)" -f $resp.tasks.Count)
      foreach ($t in $resp.tasks) {
        Write-Log ("running {0}/{1} ({2})" -f $t.technique_id, $t.test_name, $t.executor)
        $r = Run-Task $t $interval
        Invoke-C2 'agent-c2/result' $r $Hdr | Out-Null
        Write-Log (" -> status={0} exit={1} dur={2}ms" -f $r.status, $r.exit_code, $r.duration_ms)
      }
    }
  } catch {
    $msg = $_.Exception.Message
    Write-Log "loop error: $msg" 'WARN'
    # Repeated 401s mean the operator has removed this agent - bail out.
    if ($msg -match '401' -or $msg -match 'Unauthorized') {
      $AuthFails++
      if ($AuthFails -ge $AuthFailBackoff) {
        Write-Log "repeated 401 from C2 ($AuthFails) - agent appears revoked, exiting"
        exit 0
      }
    }
  }
  if ($Once) { break }
  Start-Sleep -Seconds $interval
}
