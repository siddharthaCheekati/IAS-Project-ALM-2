@echo off
cd /d "%~dp0"
python -c "import cryptography" >nul 2>&1
if errorlevel 1 (
  echo Installing required cryptography package...
  python -m pip install -r requirements.txt
  if errorlevel 1 (pause & exit /b 1)
)
python start.py
pause
