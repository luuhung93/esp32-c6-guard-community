@echo off
cd /d "%~dp0"
py -3 setup.py %*
pause
