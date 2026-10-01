@echo off
REM Levanta la API en http://127.0.0.1:8000
REM
REM 127.0.0.1 significa "solo esta computadora". NO lo cambies a 0.0.0.0
REM sin entender que eso expone tus llaves de API a toda la red.
REM
REM Documentacion interactiva: http://127.0.0.1:8000/docs
REM Para detenerlo: Ctrl+C
cd /d "%~dp0"
".venv\Scripts\python.exe" -m uvicorn api:app --host 127.0.0.1 --port 8000 --reload
