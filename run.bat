@echo off
REM ACR122U NFC GUI 실행 스크립트
cd /d "%~dp0"
python main.py
if errorlevel 1 pause
