@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title BloodBash CTF - Collect
echo.
echo  ========================================
echo   DEF CON - SharpHound Collection
echo  ========================================
echo.

if not exist "%~dp0SharpHound.exe" (
  echo [!] SharpHound.exe missing in %~dp0
  pause
  exit /b 1
)

set OUT=%USERPROFILE%\Desktop
if not exist "%OUT%" set OUT=%USERPROFILE%\Documents

echo [*] Output: %OUT%
echo [*] User: %USERDOMAIN%\%USERNAME%
echo [*] Running SharpHound.exe ...
echo.

"%~dp0SharpHound.exe" -c All --OutputDirectory "%OUT%" --ZipFilename bloodhound.zip
set ERR=%ERRORLEVEL%

set OUTZIP=
if exist "%OUT%\bloodhound.zip" set OUTZIP=%OUT%\bloodhound.zip
if not defined OUTZIP (
  for %%F in ("%OUT%\*BloodHound*.zip") do set OUTZIP=%%F
)

if not defined OUTZIP (
  echo [!] First try failed. Retry with explicit DC...
  "%~dp0SharpHound.exe" -c All -d %USERDNSDOMAIN% --DomainController 10.1.10.10 --OutputDirectory "%OUT%" --ZipFilename bloodhound.zip
  if exist "%OUT%\bloodhound.zip" set OUTZIP=%OUT%\bloodhound.zip
)

if not defined OUTZIP (
  echo [!] Collection failed. Tell staff.
  pause
  exit /b 1
)

echo [+] SUCCESS: %OUTZIP%
echo.

if not exist "%~dp0bloodbash.exe" (
  echo [!] bloodbash.exe missing in this folder. Tell staff.
  pause
  exit /b 1
)

echo [*] Running on-box BloodBash (do not copy the zip off the machine)...
chcp 65001 >nul
set PYTHONUTF8=1
set NO_COLOR=1
"%~dp0bloodbash.exe" "%OUTZIP%" --from-user domainuser --shortest-paths > "%OUT%\bloodbash-out.txt" 2>&1
echo [+] BloodBash written to: %OUT%\bloodbash-out.txt
echo.
echo  Re-run analysis anytime:
echo    cd /d "%~dp0"
echo    bloodbash.exe "%OUTZIP%" --from-user domainuser --shortest-paths
echo    bloodbash.exe "%OUTZIP%" --from-user domainuser --from-user-export
echo.
pause
