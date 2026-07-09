@echo off
REM ACR122U NFC GUI 단독 실행 파일(.exe) 빌드 스크립트
REM 결과물: dist\NFC-ACR122U.exe (파이썬 미설치 PC에서도 실행 가능)
cd /d "%~dp0"

echo [1/2] PyInstaller 설치 확인...
pip install pyinstaller

echo [2/2] 빌드 중...
python -m PyInstaller --onefile --windowed --name NFC-ACR122U --collect-submodules smartcard main.py

echo.
echo 빌드 완료: dist\NFC-ACR122U.exe
pause
