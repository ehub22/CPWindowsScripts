@echo off
rem ============================================================================
rem  secure.bat - launcher for secure.ps1 (CyberPatriot Windows Hardening 2026)
rem  The 2019 all-in-one batch script now lives in legacy\ - see README.md.
rem  This launcher prints the critical-services AI paragraph FIRST (once per
rem  fresh copy of this folder), then hands over to PowerShell, which asks
rem  for elevation itself if needed. Extra arguments are passed through, e.g.
rem    secure.bat -Mode Audit
rem    secure.bat -Rollback
rem ============================================================================
color 0b
title CyberPatriot Windows Script (2026)
setlocal
cd /d "%~dp0"

if not exist "%~dp0.ai_prompt_acknowledged" goto :showprompt
goto :launch

:showprompt
echo ============================================================================
echo   STEP 0 - PROTECT CRITICAL SERVICES (do this before hardening anything)
echo ============================================================================
echo   Disabling a service the scenario needs LOSES points. The paragraph
echo   below is a prompt for an AI model: copy it, paste the image README
echo   right after it, put the result into keep_services.txt (and the user
echo   lists), then VERIFY every line yourself against the original README.
echo.
echo   RULES WARNING: current CyberPatriot rules restrict AI tools during
echo   scored rounds. Use this prompt for TRAINING / practice images only;
echo   in a scored round fill in the same .txt files by hand from the README.
echo.
echo ------------------------- COPY FROM HERE -------------------------
type "%~dp0AI_PROMPT.txt"
echo ------------------------- COPY TO HERE ---------------------------
echo.
echo %DATE% %TIME% > "%~dp0.ai_prompt_acknowledged"
pause

:launch
echo Starting secure.ps1 ...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0secure.ps1" %*
echo.
pause
endlocal
