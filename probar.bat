@echo off
REM Atajo: corre el banco de pruebas sin tener que activar el entorno.
REM   probar.bat                -> todos los casos
REM   probar.bat https://algo   -> una sola URL
REM
REM %~dp0 significa "la carpeta donde vive este archivo .bat",
REM asi funciona aunque lo llames desde otro lado.
cd /d "%~dp0"
".venv\Scripts\python.exe" probar.py %*
