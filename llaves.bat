@echo off
REM Atajo: revisa si las llaves de API ya estan configuradas.
REM NO muestra el valor de las llaves, solo si existen.
cd /d "%~dp0"
".venv\Scripts\python.exe" -m checker.config
