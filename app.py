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

# Initialize logger
logger = get_logger('flask_app')


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
    try:
        # Security: Prevent path traversal attacks
        if '..' in filename or filename.startswith('/'):
            logger.warning(f"Path traversal attempt detected: {filename} from {request.remote_addr}")
            raise PathTraversalError(f"Path traversal attempt detected: {filename}")

        filepath = os.path.join(UPLOAD_FOLDER, filename)

        # Security: Ensure the final path is within UPLOAD_FOLDER
        abs_upload = os.path.abspath(UPLOAD_FOLDER) + os.sep
        abs_filepath = os.path.abspath(filepath)
        if not abs_filepath.startswith(abs_upload):
            logger.warning(f"Path outside allowed directory: {filename} from {request.remote_addr}")
            raise PathTraversalError(f"Path outside allowed directory: {filename}")

        if request.method == 'PUT':
            # PUT: sube datos "raw"
            with open(filepath, 'wb') as f:
                f.write(request.data)
            logger.info(f"File {filename} uploaded via PUT from {request.remote_addr}")
            return f'File {filename} uploaded via PUT.', 200

        elif request.method == 'POST':
            # POST: maneja multipart/form-data
            if 'file' not in request.files:
                return 'No file part', 400
            file = request.files['file']
            if file.filename == '':
                return 'No selected file', 400
            file.save(filepath)
            logger.info(f"File {filename} uploaded via POST from {request.remote_addr}")
            return f'File {filename} uploaded via POST.', 200

    except PathTraversalError as e:
        abort(400, str(e))

@app.route('/download/<path:filename>', methods=['GET'])
def download_file(filename):
    try:
        # Security: Prevent path traversal attacks
        if '..' in filename or filename.startswith('/'):
            logger.warning(f"Path traversal attempt detected in download: {filename} from {request.remote_addr}")
            raise PathTraversalError(f"Path traversal attempt detected: {filename}")

        filepath = os.path.join(DOWNLOAD_FOLDER, filename)

        # Security: Ensure the final path is within DOWNLOAD_FOLDER
        abs_download = os.path.abspath(DOWNLOAD_FOLDER) + os.sep
        abs_filepath = os.path.abspath(filepath)
        if not abs_filepath.startswith(abs_download):
            logger.warning(f"Path outside allowed directory in download: {filename} from {request.remote_addr}")
            raise PathTraversalError(f"Path outside allowed directory: {filename}")

        logger.info(f"File {filename} downloaded by {request.remote_addr}")
        return send_from_directory(DOWNLOAD_FOLDER, filename, as_attachment=True)

    except PathTraversalError as e:
        abort(400, str(e))
    except FileNotFoundError:
        logger.warning(f"File not found for download: {filename}")
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
    try:
        if index < 0 or index >= len(clipboards):
            raise InvalidInputError(f"Invalid clipboard index: {index}")

        data = request.get_json()
        content = data.get('content', '')

        # Security: Limit clipboard size
        if len(content) > MAX_CLIPBOARD_SIZE:
            raise FileSizeLimitError(f"Clipboard content size {len(content)} exceeds limit {MAX_CLIPBOARD_SIZE}")

        clipboards[index] = content
        return jsonify({"message": "Clipboard updated"})

    except InvalidInputError as e:
        return jsonify({"error": str(e)}), 400
    except FileSizeLimitError as e:
        return jsonify({"error": str(e)}), 413

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
    try:
        # Security: Validate port range (avoid privileged ports)
        if port < 1024 or port > 65535:
            logger.warning(f"Invalid port {port} requested from {request.remote_addr}")
            raise InvalidInputError(f"Invalid port {port}: must be between 1024-65535")

        logger.info(f"Starting listener on port {port}")
        conn, ok = start_listener(port)

        if not ok or conn is None:
            logger.error(f"Failed to start listener on port {port}")
            return jsonify({"error": "Failed to start listener"}), 500

        ip = conn.rhost
        logger.info(f"Listener started on port {port}, connection from {ip}")
        return jsonify({"status": "started", "ip": ip}), 200

    except InvalidInputError as e:
        return jsonify({"error": str(e)}), 400
    except ListenerStartError as e:
        logger.error(f"ListenerStartError on port {port}: {e}")
        return jsonify({"error": f"Failed to start listener: {str(e)}"}), 500
    except Exception as e:
        logger.exception(f"Unexpected error starting listener on port {port}")
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500


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
        logger.warning("⚠️  Debug mode is ENABLED - do not use in production!")

    logger.info(f"Starting Flask application on {host}:{port}")
    app.run(host=host, port=port, debug=debug_mode)

