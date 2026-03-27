@echo off
REM PII Shield - One-time setup (Windows)
REM Run: setup.bat

echo.
echo ^🛡️  PII Shield Setup (Windows)
echo ════════════════════════════════════════

where python >nul 2>nul
if errorlevel 1 (
    echo ❌  Python 3 not found. Install from https://python.org
    pause
    exit /b 1
)

python --version
echo.

if not exist ".venv" (
    echo 📦  Creating virtual environment ...
    python -m venv .venv
)

call .venv\Scripts\activate.bat
echo ✅  Virtual environment active

echo 📥  Installing packages ...
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

echo 🧠  Downloading spaCy model ...
python -m spacy download en_core_web_lg
if errorlevel 1 (
    python -m spacy download en_core_web_sm
)

echo.
echo ════════════════════════════════════════
echo ✅  Setup complete!
echo.
echo Usage (run these commands):
echo   .venv\Scripts\activate.bat
echo   python pii_shield.py anonymize your_document.pdf
echo   python pii_shield.py sessions
echo   python pii_shield.py restore clean.txt --session ^<ID^>
echo.
pause
