@echo off
echo ============================================================
echo  Malyze - Installation
echo ============================================================
echo.

where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found. Install Python 3.10+ first.
    pause
    exit /b 1
)

python --version

echo.
echo [*] Creating virtual environment...
python -m venv venv

echo [*] Activating virtual environment...
call venv\Scripts\activate.bat

echo [*] Upgrading pip...
python -m pip install --upgrade pip

echo [*] Installing dependencies...
pip install -r requirements.txt

echo.
echo ============================================================
echo  Installation complete!
echo.
echo  Usage:
echo    venv\Scripts\activate
echo    python main.py analyze  ^<sample.exe^> --analyst "Your Name"
echo    python main.py identify ^<file^>
echo    python main.py entropy  ^<file^>
echo    python main.py strings  ^<file^>
echo    python main.py mcp-server
echo.
echo  MCP Server config: mcp_config.json
echo ============================================================
pause
