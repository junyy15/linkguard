@echo off
REM Levanta la interfaz web en http://localhost:8501
REM Se abre sola en tu navegador. Para detenerla: Ctrl+C
cd /d "%~dp0"
".venv\Scripts\python.exe" -m streamlit run app.py
