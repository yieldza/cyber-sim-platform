// CSP Cyber Sim Platform - C# / .NET agent (Windows).
//
// Build:
//     dotnet new console -n CspAgent -o CspAgent
//     # replace Program.cs with this file, then:
//     dotnet publish -c Release -r win-x64 --self-contained false /p:PublishSingleFile=true
//
// Run:
//     CspAgent.exe --c2 https://csp.example.com --enroll-token ent_xxx
//
// Caldera-style HTTP-polling agent: register -> beacon -> run -> report.
// Only executes commands sent by the C2 (powershell / cmd). All commands
// originate verbatim from the catalog; the agent does not parse arbitrary
// input from the network. Per-task timeout, output truncation 32 KB.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

internal static class CspAgent
{
    private const string AgentVersion = "0.3.0-cs";
    private const int    MaxOutput    = 32 * 1024;
    private const int    MaxTimeoutSec = 60;
    private static readonly HashSet<string> Runnable =
        new() { "powershell", "cmd", "pwsh" };
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(30) };

    public static async Task<int> Main(string[] args)
    {
        var opts = ParseArgs(args);
        if (string.IsNullOrEmpty(opts.C2))
        {
            Console.Error.WriteLine("--c2 required");
            return 2;
        }

        string agentId, agentSecret;
        int interval;
        if (!string.IsNullOrEmpty(opts.AgentId) && !string.IsNullOrEmpty(opts.AgentSecret))
        {
            agentId = opts.AgentId; agentSecret = opts.AgentSecret;
            interval = opts.IntervalSeconds;
            Log($"re-using agent_id={agentId}");
        }
        else if (!string.IsNullOrEmpty(opts.EnrollToken))
        {
            Log($"registering with {opts.C2}...");
            var reg = await PostAsync(opts.C2, "/agent-c2/register", new
            {
                enroll_token  = opts.EnrollToken,
                hostname      = opts.Label ?? Environment.MachineName,
                platform      = "windows",
                agent_version = AgentVersion,
                internal_ip   = GetInternalIp(),
            }, null);
            agentId     = reg!.GetProperty("agent_id").GetString()!;
            agentSecret = reg!.Value.GetProperty("agent_secret").GetString()!;
            interval    = reg!.Value.GetProperty("beacon_interval_sec").GetInt32();
            Log($"registered agent_id={agentId} interval={interval}s");
        }
        else
        {
            Console.Error.WriteLine("provide --enroll-token, or --agent-id + --agent-secret");
            return 2;
        }

        var headers = new Dictionary<string, string> {
            ["x-agent-id"] = agentId,
            ["x-agent-secret"] = agentSecret,
        };

        const int AuthFailBackoff = 5;
        int authFails = 0;
        while (true)
        {
            try
            {
                var resp = await PostAsync(opts.C2, "/agent-c2/beacon", new {}, headers);
                authFails = 0;  // reset on success

                // Operator killed this agent from the console - exit cleanly.
                if (resp.HasValue && resp.Value.TryGetProperty("shutdown", out var sh)
                    && sh.ValueKind == JsonValueKind.True)
                {
                    string reason = "shutdown_signal";
                    if (resp.Value.TryGetProperty("reason", out var rs) && rs.ValueKind == JsonValueKind.String)
                        reason = rs.GetString() ?? reason;
                    Log($"shutdown signal received from C2 (reason={reason}) - exiting");
                    return 0;
                }

                if (resp.HasValue && resp.Value.TryGetProperty("tasks", out var tasks)
                    && tasks.ValueKind == JsonValueKind.Array)
                {
                    foreach (var t in tasks.EnumerateArray())
                    {
                        var taskId   = t.GetProperty("id").GetString()!;
                        var techId   = t.GetProperty("technique_id").GetString()!;
                        var testName = t.GetProperty("test_name").GetString()!;
                        var executor = t.GetProperty("executor").GetString()!;
                        var command  = t.GetProperty("command").GetString()!;
                        var timeout  = t.TryGetProperty("timeout_sec", out var ts) ? ts.GetInt32() : 15;
                        var cleanup  = t.TryGetProperty("cleanup", out var cu) && cu.ValueKind == JsonValueKind.String
                                       ? cu.GetString() : null;

                        Log($"running {techId}/{testName} ({executor})");
                        var result = RunTask(taskId, executor, command, cleanup, timeout);
                        await PostAsync(opts.C2, "/agent-c2/result", result, headers);
                        Log($" -> status={result["status"]} exit={result["exit_code"]} dur={result["duration_ms"]}ms");
                    }
                }
            }
            catch (Exception e)
            {
                Log("loop error: " + e.Message, "WARN");
                // Repeated 401s mean the agent has been removed from C2 - bail out.
                if (e.Message.Contains("HTTP 401"))
                {
                    authFails++;
                    if (authFails >= AuthFailBackoff)
                    {
                        Log($"repeated 401 from C2 ({authFails}) - agent appears revoked, exiting");
                        return 0;
                    }
                }
            }

            if (opts.Once) break;
            Thread.Sleep(interval * 1000);
        }
        return 0;
    }

    // ---------- task execution ----------
    private static Dictionary<string, object?> RunTask(
        string taskId, string executor, string command, string? cleanup, int timeoutSec)
    {
        timeoutSec = Math.Clamp(timeoutSec, 1, MaxTimeoutSec);
        var result = new Dictionary<string, object?>
        {
            ["task_id"]     = taskId,
            ["status"]      = "done",
            ["exit_code"]   = 0,
            ["duration_ms"] = 0,
            ["stdout"]      = "",
            ["stderr"]      = "",
            ["truncated"]   = false,
        };
        if (!Runnable.Contains(executor))
        {
            result["status"] = "error";
            result["exit_code"] = -2;
            result["stderr"] = $"executor '{executor}' not runnable on this agent";
            return result;
        }

        var psi = new ProcessStartInfo
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        switch (executor)
        {
            case "powershell":
                psi.FileName = "powershell.exe";
                psi.ArgumentList.Add("-NoProfile");
                psi.ArgumentList.Add("-NonInteractive");
                psi.ArgumentList.Add("-Command");
                psi.ArgumentList.Add(command);
                break;
            case "pwsh":
                psi.FileName = "pwsh";
                psi.ArgumentList.Add("-NoProfile");
                psi.ArgumentList.Add("-NonInteractive");
                psi.ArgumentList.Add("-Command");
                psi.ArgumentList.Add(command);
                break;
            case "cmd":
                psi.FileName = "cmd.exe";
                psi.ArgumentList.Add("/c");
                psi.ArgumentList.Add(command);
                break;
        }

        var sw = Stopwatch.StartNew();
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        try
        {
            using var p = Process.Start(psi)!;
            p.OutputDataReceived += (_, e) => { if (e.Data != null && stdout.Length < MaxOutput) stdout.AppendLine(e.Data); };
            p.ErrorDataReceived  += (_, e) => { if (e.Data != null && stderr.Length < MaxOutput) stderr.AppendLine(e.Data); };
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();
            if (!p.WaitForExit(timeoutSec * 1000))
            {
                try { p.Kill(true); } catch { }
                result["status"] = "timeout";
                result["exit_code"] = -9;
                stderr.Append($"\n[timeout after {timeoutSec}s]");
                result["truncated"] = true;
            }
            else
            {
                result["exit_code"] = p.ExitCode;
            }
        }
        catch (Exception e)
        {
            result["status"] = "error";
            result["exit_code"] = -3;
            stderr.AppendLine(e.Message);
        }
        sw.Stop();
        result["duration_ms"] = (int)sw.ElapsedMilliseconds;

        var soStr = stdout.ToString();
        var seStr = stderr.ToString();
        if (soStr.Length > MaxOutput) { soStr = soStr.Substring(0, MaxOutput); result["truncated"] = true; }
        if (seStr.Length > MaxOutput) { seStr = seStr.Substring(0, MaxOutput); result["truncated"] = true; }
        result["stdout"] = soStr;
        result["stderr"] = seStr;

        if (!string.IsNullOrEmpty(cleanup))
        {
            try
            {
                var cpsi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                cpsi.ArgumentList.Add("-NoProfile");
                cpsi.ArgumentList.Add("-Command");
                cpsi.ArgumentList.Add(cleanup);
                var cp = Process.Start(cpsi);
                cp?.WaitForExit(10_000);
            }
            catch { }
        }
        return result;
    }

    // ---------- HTTP ----------
    private static async Task<JsonElement?> PostAsync(
        string c2, string path, object body, Dictionary<string, string>? headers)
    {
        var url = c2.TrimEnd('/') + path;
        using var req = new HttpRequestMessage(HttpMethod.Post, url);
        var json = JsonSerializer.Serialize(body);
        req.Content = new StringContent(json, Encoding.UTF8, "application/json");
        if (headers != null)
            foreach (var kv in headers)
                req.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
        using var resp = await Http.SendAsync(req);
        var text = await resp.Content.ReadAsStringAsync();
        if (!resp.IsSuccessStatusCode)
            throw new Exception($"HTTP {(int)resp.StatusCode}: {text}");
        if (string.IsNullOrEmpty(text)) return null;
        return JsonDocument.Parse(text).RootElement;
    }

    // ---------- discovery ----------
    private static string? GetInternalIp()
    {
        try
        {
            using var s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0);
            s.Connect("1.1.1.1", 80);
            return ((IPEndPoint?)s.LocalEndPoint)?.Address.ToString();
        }
        catch { return null; }
    }

    // ---------- arg parsing ----------
    private record Options
    {
        public string C2 { get; set; } = "";
        public string? EnrollToken { get; set; }
        public string? AgentId { get; set; }
        public string? AgentSecret { get; set; }
        public string? Label { get; set; }
        public int IntervalSeconds { get; set; } = 30;
        public bool Once { get; set; }
    }

    private static Options ParseArgs(string[] args)
    {
        var o = new Options();
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--c2":           o.C2 = args[++i]; break;
                case "--enroll-token": o.EnrollToken = args[++i]; break;
                case "--agent-id":     o.AgentId = args[++i]; break;
                case "--agent-secret": o.AgentSecret = args[++i]; break;
                case "--label":        o.Label = args[++i]; break;
                case "--interval":     o.IntervalSeconds = int.Parse(args[++i]); break;
                case "--once":         o.Once = true; break;
            }
        }
        return o;
    }

    private static void Log(string msg, string level = "INFO") =>
        Console.WriteLine($"{DateTime.Now:yyyy-MM-ddTHH:mm:ss} {level} {msg}");
}
