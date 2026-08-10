
from pwn import listen, log
import os
import base64
import time
import re
import signal
import hashlib
import threading
import shlex
from typing import Optional, Tuple, Dict, Any


TOOLS_FOLDER = 'tools'
UPLOAD_FOLDER = 'uploads'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOWNLOAD_FOLDER = os.path.join(BASE_DIR, "downloads")


conn = None
server = None

def clean_ansi(text: str) -> str:
    """
    Remove ANSI escape codes and filter shell prompts from text.

    Args:
        text: Raw text containing ANSI codes and prompts

    Returns:
        Cleaned text with ANSI codes and prompts removed
    """
    ansi_escape = re.compile(r'\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])|\x07|\x0f|\x0e')
    cleaned = ansi_escape.sub('', text)
    prompt_pattern = re.compile(r'^\d+;[a-zA-Z0-9_-]+@[^:]+:.*$')

    filtered_lines = []
    for line in cleaned.split('\n'):
        if not prompt_pattern.match(line.strip()):
            filtered_lines.append(line.strip())

    return '\n'.join(filtered_lines)

def get_clean_response(cmd: str) -> Optional[str]:
    """
    Execute a command on the remote shell and return the cleaned response.

    Args:
        cmd: Command to execute

    Returns:
        Cleaned response text, or None if no valid response
    """
    conn.sendline(cmd.encode())
    conn.recvline(timeout=0.5)
    response = conn.recvline(timeout=2).decode(errors='ignore').strip()
    return clean_ansi(response) if response and response.lower() != cmd else None



def sigint_handler(signum: int, frame: Any) -> None:
    """
    Handle SIGINT signal (Ctrl+C) for graceful shutdown.

    Args:
        signum: Signal number
        frame: Current stack frame
    """
    if conn:
        conn.sendline(b'kill -2 $$')

def detect_remote_os() -> str:
    """
    Detect the operating system of the remote shell.

    Returns:
        OS name: "Linux", "Windows", "Unknown", or "Error"
    """
    try:
        conn.sendline(b"uname")
        conn.recvline(timeout=0.5)
        output = clean_ansi(conn.recvrepeat(0.5).decode(errors='ignore').strip())

        if output and "linux" in output.lower():
            return "Linux"

        conn.sendline(b"ver")
        time.sleep(0.5)
        response = clean_ansi(conn.recvline(timeout=1).decode(errors='ignore').strip())

        if response and "Windows" in response:
            return "Windows"

        return "Unknown"
    except Exception as e:
        log.error(f"Error detecting remote OS: {e}")
        return "Error"



def start_listener(port: int) -> Tuple[Optional[Any], bool]:
    """
    Start a listener on the specified port and wait for connection.

    Args:
        port: Port number to listen on

    Returns:
        Tuple of (connection object, success status)
    """
    global conn, server
    server = listen(port)
    log.success(f"Listening on port {port}...")
    conn = server.wait_for_connection()

    if conn:
        log.success(f"Connection received from {conn.rhost}")

        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGINT, sigint_handler)

        return conn, True

    return None, False


def stop_listener() -> None:
    """
    Stop the active listener and close connections.
    """
    global conn, server
    if server:
        try:
            server.close()
            log.success("Listener stopped.")
        except Exception as e:
            log.error(f"Error stopping listener: {e}")


def get_local_md5(local_file: str) -> Optional[str]:
    """
    Calculate MD5 hash of a local file.

    Args:
        local_file: Path to the local file

    Returns:
        MD5 hash as hex string, or None if error
    """
    try:
        with open(local_file, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
    except Exception as e:
        log.warning(f"Error calculating local MD5: {e}")
        return None

def get_remote_md5(path: str) -> Optional[str]:
    """
    Calculate MD5 hash of a remote file.

    Args:
        path: Path to the remote file

    Returns:
        MD5 hash as hex string, or None if error
    """
    try:
        # Security: Properly escape the path
        escaped_path = shlex.quote(path)
        conn.sendline(f"md5sum {escaped_path}".encode())
        conn.recvline(timeout=0.5)
        result = clean_ansi(conn.recvrepeat(1).decode(errors='ignore'))
        match = re.search(r'^([a-fA-F0-9]{32})', result)
        return match.group(1) if match else None
    except Exception as e:
        log.warning(f"Error calculating remote MD5: {e}")
        return None

def send_command(cmd: str) -> Dict[str, Any]:
    """
    Send a command to the remote shell.

    Args:
        cmd: Command string to execute

    Returns:
        Dictionary with command results and metadata
    """
    if cmd.startswith("upload "):
        path = cmd.split(" ", 1)[1]
        upload_file(path)
        local_md5 = get_local_md5(path)
        remote_md5 = get_remote_md5(os.path.basename(path))

        return {
            "type": "file",
            "path": path,
            "local_md5": local_md5,
            "remote_md5": remote_md5,
            "success": local_md5 == remote_md5
        }

    elif cmd.startswith("download "):
        path = cmd.split(" ", 1)[1]
        local_md5, remote_md5 = download_file(path)

        return {
            "type": "file",
            "path": path,
            "local_md5": local_md5,
            "remote_md5": remote_md5,
            "success": local_md5 == remote_md5
        }

    # Normal command execution
    conn.sendline(cmd.encode())
    time.sleep(1)
    output = conn.recvrepeat(1).decode(errors='ignore').strip()
    return {"type": "output", "output": clean_ansi(output)}


def upload_file(file_path: str) -> None:
    """
    Upload a file to the remote shell using base64 encoding.

    Args:
        file_path: Path to the local file to upload

    Raises:
        Exception: If file upload fails
    """
    try:
        with open(file_path, "rb") as f:
            file_data = base64.b64encode(f.read()).decode()

        # Security: Properly escape filename
        remote_name = shlex.quote(os.path.basename(file_path))
        conn.sendline(f"echo {file_data} | base64 -d > {remote_name}".encode())
        log.info(f"Subiendo {file_path}")

        local_md5 = get_local_md5(file_path)
        remote_md5 = get_remote_md5(os.path.basename(file_path))

        if local_md5 and remote_md5:
            log.info(f"\n[+] MD5 local:  {local_md5}")
            log.info(f"[+] MD5 remoto: {remote_md5}")

            if local_md5 == remote_md5:
                log.success("✔️ Integridad verificada: los hashes coinciden.")
            else:
                log.warning("❌ Advertencia: los hashes NO coinciden. Puede haber corrupción en la transferencia.")

    except Exception as e:
        log.error(f"Error al subir el archivo: {e}")

def download_file(file_path: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Download a file from the remote shell using base64 encoding.

    Args:
        file_path: Path to the remote file to download

    Returns:
        Tuple of (local_md5, remote_md5) or (None, None) on error

    Raises:
        base64.binascii.Error: If base64 decoding fails
        Exception: If file download fails
    """
    try:
        local_file = os.path.join(DOWNLOAD_FOLDER, os.path.basename(file_path))

        # Security: Properly escape path
        escaped_path = shlex.quote(file_path)
        conn.sendline(f"base64 {escaped_path}".encode())
        time.sleep(1)  # Le damos tiempo a la shell remota

        raw_data = conn.recvrepeat(3)  # Ajusta si necesitas más tiempo
        decoded_data = raw_data.decode(errors='ignore')

        # Extraemos solo la parte que parece base64 (omitimos prompts o basura ANSI)
        base64_lines = []
        for line in decoded_data.splitlines():
            if re.match(r'^[A-Za-z0-9+/=]+$', line.strip()):
                base64_lines.append(line.strip())

        file_data = ''.join(base64_lines)

        # Aseguramos padding
        missing_padding = len(file_data) % 4
        if missing_padding:
            file_data += '=' * (4 - missing_padding)

        with open(local_file, "wb") as f:
            f.write(base64.b64decode(file_data))

        log.success(f"Archivo {file_path} descargado.")
        local_md5 = get_local_md5(local_file)
        remote_md5 = get_remote_md5(file_path)

        if local_md5 and remote_md5:
            log.info(f"[+] MD5 local:  {local_md5}")
            log.info(f"[+] MD5 remoto: {remote_md5}")

            if local_md5 == remote_md5:
                log.success("✔️ Integridad verificada: los hashes coinciden.")
            else:
                log.warning("❌ Advertencia: los hashes NO coinciden. Puede haber corrupción en la transferencia.")
        return local_md5, remote_md5

    except base64.binascii.Error as e:
        log.error(f"Error al decodificar Base64: {e}")
        return None, None
    except Exception as e:
        log.error(f"Error al descargar el archivo: {e}")
        return None, None
