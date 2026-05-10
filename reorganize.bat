@echo off
cd /d "%~dp0"

echo Creating directories...
mkdir Frontend 2>nul
mkdir Backend 2>nul

echo Moving HTML files to Frontend...
move *.html Frontend\

echo Moving Backend files...
xcopy /E /I /Y pentest-platform\backend\* Backend\

echo Cleaning up old folders...
rmdir /S /Q pentest-platform

echo.
echo Reorganization complete!
pause
