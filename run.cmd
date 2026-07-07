@echo off
setlocal
set "ROOT=%~dp0"
set "PY=%ROOT%.venv\Scripts\python.exe"

if not exist "%PY%" (
  echo Missing virtual environment Python at: %PY%
  echo Create it first ^(e.g. python -m venv .venv^) and install requirements.
  exit /b 1
)

pushd "%ROOT%"
"%PY%" %*
set "EC=%ERRORLEVEL%"
popd
exit /b %EC%

