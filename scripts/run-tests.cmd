@echo off
set PYTHONPATH=%~dp0..\src
if defined CYBER_PYTHON (
  "%CYBER_PYTHON%" -m unittest discover -s "%~dp0..\tests" -v
) else (
  python -m unittest discover -s "%~dp0..\tests" -v
)
