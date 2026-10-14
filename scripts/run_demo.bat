@echo off
:: ================================================================
:: UniShield — One-Command Demo Launcher (Windows)
::
:: Usage:
::   scripts\run_demo.bat              Full verification (5 runs each)
::   scripts\run_demo.bat --quick      Quick verification (1 run each)
::   scripts\run_demo.bat --scenario beacon   Single scenario demo
::
:: SAFETY: All traffic is synthetic. No external systems contacted.
:: ================================================================

echo.
echo  ============================================================
echo   UniShield — AI Security for One-Way Networks
echo   Automated Real-Time Verification Suite
echo  ============================================================
echo.

:: Activate virtual environment if it exists
if exist "%~dp0..\\.venv\\Scripts\\activate.bat" (
    call "%~dp0..\\.venv\\Scripts\\activate.bat"
    echo  [OK] Virtual environment activated
) else (
    echo  [WARN] No virtual environment found. Using system Python.
)

:: Navigate to project root
cd /d "%~dp0.."
echo  [OK] Working directory: %CD%
echo.

:: Run the full verification
echo  Starting verification...
echo  ──────────────────────────────────────────────────────────
echo.

python scripts/run_demo.py %*

echo.
echo  ──────────────────────────────────────────────────────────

:: Generate charts if matplotlib is available
echo.
echo  Generating visual evidence charts...
python scripts/generate_charts.py --auto 2>nul
if errorlevel 1 (
    echo  [WARN] Charts skipped (install matplotlib for visual evidence)
) else (
    echo  [OK] Charts generated in reports/figures/
)

echo.
echo  ============================================================
echo   Verification complete!
echo   Reports: reports/
echo   Charts:  reports/figures/
echo  ============================================================
echo.

pause
