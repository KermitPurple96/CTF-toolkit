from flask import Flask, jsonify, request, send_from_directory, abort, render_template
import os
import netifaces as ni
from listen_manager import start_listener, stop_listener, send_command


app = Flask(__name__)

# Configuration
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB limit
MAX_CLIPBOARD_SIZE = 10 * 1024 * 1024  # 10MB limit
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

TOOLS_FOLDER = 'tools'
UPLOAD_FOLDER = 'uploads'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOWNLOAD_FOLDER = os.path.join(BASE_DIR, "downloads")


for folder in (TOOLS_FOLDER, UPLOAD_FOLDER, DOWNLOAD_FOLDER):
    os.makedirs(folder, exist_ok=True)
clipboards = ["", "", ""]


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload/<path:filename>', methods=['PUT', 'POST'])
def upload_file(filename):
    # Security: Prevent path traversal attacks
    if '..' in filename or filename.startswith('/'):
        abort(400, 'Invalid filename')

    filepath = os.path.join(UPLOAD_FOLDER, filename)

    # Security: Ensure the final path is within UPLOAD_FOLDER
    abs_upload = os.path.abspath(UPLOAD_FOLDER) + os.sep
    abs_filepath = os.path.abspath(filepath)
    if not abs_filepath.startswith(abs_upload):
        abort(400, 'Invalid path')

    if request.method == 'PUT':
        # PUT: sube datos "raw"
        with open(filepath, 'wb') as f:
            f.write(request.data)
        return f'File {filename} uploaded via PUT.', 200

    elif request.method == 'POST':
        # POST: maneja multipart/form-data
        if 'file' not in request.files:
            return 'No file part', 400
        file = request.files['file']
        if file.filename == '':
            return 'No selected file', 400
        file.save(filepath)
        return f'File {filename} uploaded via POST.', 200

@app.route('/download/<path:filename>', methods=['GET'])
def download_file(filename):
    # Security: Prevent path traversal attacks
    if '..' in filename or filename.startswith('/'):
        abort(400, 'Invalid filename')

    filepath = os.path.join(DOWNLOAD_FOLDER, filename)

    # Security: Ensure the final path is within DOWNLOAD_FOLDER
    abs_download = os.path.abspath(DOWNLOAD_FOLDER) + os.sep
    abs_filepath = os.path.abspath(filepath)
    if not abs_filepath.startswith(abs_download):
        abort(400, 'Invalid path')

    try:
        return send_from_directory(DOWNLOAD_FOLDER, filename, as_attachment=True)
    except FileNotFoundError:
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
    if index < 0 or index >= len(clipboards):
        return jsonify({"error": "Invalid clipboard index"}), 400

    data = request.get_json()
    content = data.get('content', '')

    # Security: Limit clipboard size
    if len(content) > MAX_CLIPBOARD_SIZE:
        return jsonify({"error": "Clipboard content too large"}), 413

    clipboards[index] = content
    return jsonify({"message": "Clipboard updated"})

@app.route('/ips', methods=['GET'])
def get_ips():
    ips = []
    for iface in ni.interfaces():
        if ni.AF_INET in ni.ifaddresses(iface):
            for link in ni.ifaddresses(iface)[ni.AF_INET]:
                ips.append(link['addr'])
    return jsonify(ips)


@app.route("/shells")
def shells():
    return render_template("shells.html")

@app.route("/start_listener/<int:port>")
def start_listener_route(port):
    # Security: Validate port range (avoid privileged ports)
    if port < 1024 or port > 65535:
        return jsonify({"error": "Invalid port: must be between 1024-65535"}), 400

    try:
        conn, ok = start_listener(port)

        if not ok or conn is None:
            return jsonify({"error": "Failed to start listener"}), 500

        ip = conn.rhost
        return jsonify({"status": "started", "ip": ip}), 200
    except Exception as e:
        return jsonify({"error": f"Error starting listener: {str(e)}"}), 500


@app.route("/send_command", methods=["POST"])
def send_command_route():
    cmd = request.json.get("command")
    result = send_command(cmd)

    # Si es un diccionario (descarga o subida de archivo)
    if isinstance(result, dict):
        return jsonify(result)

    # Si es una cadena (output de la shell)
    return jsonify({
        "type": "output",
        "output": result
    })


@app.route("/stop_listener")
def stop_listener_route():
    stop_listener()
    return {"status": "stopped"}




if __name__ == '__main__':
    # Security: Never enable debug mode by default in production
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')
    port = int(os.environ.get('FLASK_PORT', '5000'))
    host = os.environ.get('FLASK_HOST', '0.0.0.0')

    if debug_mode:
        log.warning("⚠️  Debug mode is ENABLED - do not use in production!")

    app.run(host=host, port=port, debug=debug_mode)

