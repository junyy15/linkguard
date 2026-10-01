@echo off
REM Atajo: corre la herramienta sin tener que activar el entorno.
REM   check.bat https://ejemplo.com
cd /d "%~dp0"
".venv\Scripts\python.exe" check.py %*
