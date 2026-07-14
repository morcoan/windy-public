@echo off
setlocal
set "ROOT=%~dp0..\.."
if not defined WINDY_ASSEMBLAGE_DB (
  echo Set WINDY_ASSEMBLAGE_DB, WINDY_ASSEMBLAGE_BINARIES, and WINDY_ASSEMBLAGE_OUTPUT first. 1>&2
  exit /b 2
)
if not defined WINDY_ASSEMBLAGE_BINARIES exit /b 2
if not defined WINDY_ASSEMBLAGE_OUTPUT exit /b 2
if not defined PYTHON set "PYTHON=python"
set "PYTHONPATH=%ROOT%\gclsd\src"
cd /d "%ROOT%"
"%PYTHON%" -m windy_gclsd.data.assemblage_pairs ^
  --db "%WINDY_ASSEMBLAGE_DB%" ^
  --binary-dir "%WINDY_ASSEMBLAGE_BINARIES%" ^
  --windy-exe "%ROOT%\target\debug\windy.exe" ^
  --output "%WINDY_ASSEMBLAGE_OUTPUT%" ^
  --workers 8 ^
  1>"%WINDY_ASSEMBLAGE_OUTPUT%.log" 2>"%WINDY_ASSEMBLAGE_OUTPUT%.err"
