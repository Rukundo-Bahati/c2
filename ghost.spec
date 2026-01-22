# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['ghost.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['win32timezone', 'win32api', 'win32con', 'win32gui', 'win32process', 'win32security', 'win32service', 'win32serviceutil', 'win32event', 'win32clipboard', 'win32crypt', 'win32com.client', 'pynput.keyboard', 'PIL._tkinter_finder', 'cv2', 'numpy', 'soundcard', 'soundfile', 'pyaudio', 'Crypto', 'Crypto.Cipher', 'Crypto.Cipher.AES'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='ghost',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
