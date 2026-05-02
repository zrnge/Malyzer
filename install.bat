@echo off
echo ============================================================
echo  Malyze - AI-Powered Malware Analysis Framework
echo  Installation
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
echo  Activate the environment:
echo    venv\Scripts\activate
echo.
echo  Usage:
echo    python main.py web                              Launch Web UI (port 5000)
echo    python main.py analyze  ^<sample.exe^>           Full static analysis
echo    python main.py analyze  ^<sample.exe^> --dynamic Full static + dynamic analysis
echo    python main.py analyze  ^<sample.exe^> --quick   Quick triage mode
echo    python main.py identify ^<file^>                 File type + hashes
echo    python main.py entropy  ^<file^>                 Entropy analysis
echo    python main.py strings  ^<file^>                 String extraction
echo    python main.py mcp-server                      MCP server for AI agents
echo.
echo  WARNING: --dynamic executes the sample.
echo  Always run inside an isolated sandbox (FlareVM snapshot, air-gapped VM).
echo.
echo  MCP Server config: mcp_config.json
echo ============================================================
pause
