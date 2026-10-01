@echo off
title LinkGuard
cd /d "%~dp0"

echo.
echo   ========================================
echo      LinkGuard - iniciando...
echo   ========================================
echo.
echo   Se va a abrir solo en tu navegador.
echo   NO CIERRES esta ventana mientras lo uses.
echo.
echo   Para apagarlo: cierra esta ventana,
echo   o presiona Ctrl+C.
echo.

REM --- El servidor de enlaces cortos, en su propia ventana minimizada ---
REM Lleva un titulo propio para poder apagarlo despues sin tocar otros
REM programas de Python que tengas corriendo.
start "LinkGuard-API" /min ".venv\Scripts\python.exe" -m uvicorn api:app --host 127.0.0.1 --port 8000

REM Le damos un momento para arrancar antes de seguir.
timeout /t 3 /nobreak >nul

REM --- La pagina web, en esta ventana ---
REM Streamlit abre el navegador solo. Mientras corre, esta ventana se
REM queda ocupada: ahi esta el boton de apagado.
".venv\Scripts\python.exe" -m streamlit run app.py

REM --- Al cerrar la pagina, se apaga tambien el servidor de enlaces ---
REM Se busca por el TITULO de la ventana, no por "python.exe": asi no se
REM mata ningun otro programa tuyo por error.
echo.
echo   Apagando LinkGuard...
taskkill /fi "WINDOWTITLE eq LinkGuard-API*" /t /f >nul 2>&1
