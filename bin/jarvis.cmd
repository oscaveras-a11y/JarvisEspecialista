@echo off
setlocal
set "OPENJARVIS_HOME=%~dp0..\.state"
set "DO_NOT_TRACK=1"
set "OPENJARVIS_NO_UPDATE_CHECK=1"
set "JARVIS_SKIP_MODEL_PICK=1"
cd /d "%~dp0..\jarvis" || exit /b 1
uv run --no-sync python "%~dp0..\voice\launcher.py" %*
exit /b %errorlevel%
