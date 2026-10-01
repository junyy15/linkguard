@echo off
REM Atajo para correr las pruebas con pytest.
REM
REM   pruebas.bat              -> TODAS (incluye las que usan internet)
REM   pruebas.bat -m "not red" -> solo las rapidas, sin red (1 segundo)
REM   pruebas.bat -k scoring   -> solo las que tengan 'scoring' en el nombre
REM   pruebas.bat -v           -> con el nombre de cada prueba
cd /d "%~dp0"
".venv\Scripts\python.exe" -m pytest %*
