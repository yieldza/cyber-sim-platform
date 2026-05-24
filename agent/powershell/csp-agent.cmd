@echo off
:: ============================================================================
::  CSP - PowerShell agent launcher  (auto-bypass ExecutionPolicy)
:: ============================================================================
::  Why this file exists:
::    Windows' default PowerShell ExecutionPolicy is "Restricted", which
::    blocks unsigned .ps1 scripts with the error
::      "cannot be loaded because running scripts is disabled on this system".
::    This .cmd wrapper invokes powershell.exe with -ExecutionPolicy Bypass
::    scoped to the launched process only, so no system-wide policy change
::    is needed and the user never sees the prompt.
::
::  Usage:
::    csp-agent.cmd -C2 http://<csp-host>:8080 -EnrollToken ent_xxx -Label win10-01
::
::    csp-agent.cmd -C2 http://<csp-host>:8080 -AgentId agt_... -AgentSecret as_...
::
::  Place csp-agent.cmd and csp-agent.ps1 in the SAME folder. Both can be
::  downloaded from the CSP web UI -> Agents tab -> Download agent.
:: ============================================================================

setlocal

set "SCRIPT_DIR=%~dp0"
set "PS_SCRIPT=%SCRIPT_DIR%csp-agent.ps1"

if not exist "%PS_SCRIPT%" (
    echo.
    echo [csp-launcher] ERROR: csp-agent.ps1 not found next to this launcher.
    echo                Looked in: %SCRIPT_DIR%
    echo.
    echo                Place csp-agent.cmd and csp-agent.ps1 in the SAME folder.
    echo                Both files are downloadable from the CSP web UI.
    echo.
    pause
    exit /b 1
)

if "%~1"=="" (
    echo.
    echo [csp-launcher] No arguments provided. Usage:
    echo.
    echo   csp-agent.cmd -C2 http://^<csp-host^>:8080 -EnrollToken ent_xxxxxx -Label hostname
    echo.
    echo   csp-agent.cmd -C2 http://^<csp-host^>:8080 -AgentId agt_xxx -AgentSecret as_xxx
    echo.
    pause
    exit /b 2
)

:: -ExecutionPolicy Bypass is process-scoped (this powershell.exe only).
:: The host machine policy is not modified.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" %*
set "RC=%ERRORLEVEL%"

if not "%RC%"=="0" (
    echo.
    echo [csp-launcher] csp-agent.ps1 exited with code %RC%
    pause
)

endlocal & exit /b %RC%
