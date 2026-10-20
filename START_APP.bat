@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo Creating the project environment...
    where py >nul 2>nul
    if errorlevel 1 (
        python -m venv .venv
    ) else (
        py -3 -m venv .venv
    )
    if errorlevel 1 goto setup_failed
)

".venv\Scripts\python.exe" -c "import streamlit, scapy, pandas, numpy, sklearn, plotly, joblib" >nul 2>nul
if errorlevel 1 (
    echo Installing project packages. This may take a few minutes on first run...
    ".venv\Scripts\python.exe" -m pip install --upgrade pip
    if errorlevel 1 goto setup_failed
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt
    if errorlevel 1 goto setup_failed
)

echo Starting Network Analyzer.
 echo Keep this window open while using the app.
 echo Once the browser opens, sign in with your local account.
 echo If the app does not open automatically, visit http://localhost:8501
".venv\Scripts\python.exe" -m streamlit run app.py
if errorlevel 1 goto setup_failed
goto end

:setup_failed
echo.
echo Setup or startup failed. Check the error above and confirm Python 3.10 or newer is installed.
pause

:end
endlocal
