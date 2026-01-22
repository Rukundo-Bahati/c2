# Building ghost.py to ghost.exe

This directory contains build scripts to convert `ghost.py` into a standalone Windows executable (`ghost.exe`).

## Prerequisites

pyinstaller ghost.spec

1. **Windows machine** (the build should be done on Windows)
2. **Python 3.x** installed
3. **All dependencies** installed:
   ```bash
   pip install -r requirements.txt
   ```

## Building the Executable

### Method 1: Using build.bat (Windows)

Simply double-click `build.bat` or run it from Command Prompt:
```bash
build.bat
```

### Method 2: Using build.py (Cross-platform)

Run the Python build script:
```bash
python build.py
```

### Method 3: Manual PyInstaller Command

If you prefer to run PyInstaller directly:
```bash
pyinstaller --noconsole --onefile --name ghost --clean ghost.py
```

## Build Options Explained

- `--noconsole`: Creates a windowless executable (no console window)
- `--onefile`: Packages everything into a single .exe file
- `--name ghost`: Sets the output executable name to `ghost.exe`
- `--clean`: Cleans PyInstaller cache before building
- `--hidden-import`: Forces inclusion of modules that PyInstaller might miss

## Output

After a successful build, the executable will be located in:
```
dist/ghost.exe
```

## Notes

- The first build may take several minutes as PyInstaller analyzes all dependencies
- The resulting .exe file will be quite large (typically 50-150 MB) because it includes Python and all dependencies
- The executable is **portable** - it can run on any Windows machine without Python installed
- All stealth features (hiding console, persistence, etc.) will work in the compiled .exe

## Troubleshooting

If the build fails:

1. **Missing modules**: PyInstaller might miss some imports. Check the error message and add `--hidden-import <module_name>` to the build command.

2. **Large file size**: This is normal for PyInstaller onefile builds. Consider using `--onedir` instead of `--onefile` if you need a smaller distribution.

3. **Antivirus false positives**: Some antivirus software may flag the executable. This is common with PyInstaller builds and can be handled by:
   - Adding an exception in your antivirus
   - Using a code signing certificate (for production)

4. **Runtime errors**: If the .exe crashes at runtime, check the logs (they should be in temp directory or Desktop as configured in ghost.py).

