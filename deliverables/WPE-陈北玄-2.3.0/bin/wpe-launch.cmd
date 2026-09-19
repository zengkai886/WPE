@echo off
setlocal
set "data=%LOCALAPPDATA%\WPE64\2.3.0"
if not exist "%data%" mkdir "%data%"
"%~dp0wpe64-app.exe" --data-dir "%data%"
exit /b %errorlevel%