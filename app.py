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
    sanitize_log_message
)
from security_headers import configure_security
from config import Config

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

# Initialize clipboards
clipboards = ["" for _ in range(Config.NUM_CLIPBOARDS)]


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload/<path:filename>', methods=['PUT', 'POST'])
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


@app.route("/shells")
def shells():
    return render_template("shells.html")

@app.route("/start_listener/<int:port>")
def start_listener_route(port):
    try:
        # Security: Validate port range
        validated_port = validate_port(port)

        logger.info(f"Starting listener on port {validated_port}")
        conn, ok = start_listener(validated_port)

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
    # Print configuration
    if Config.FLASK_DEBUG:
        Config.print_config()

    # Security: Never enable debug mode by default in production
    if Config.FLASK_DEBUG:
        logger.warning("⚠️  Debug mode is ENABLED - do not use in production!")

    logger.info(f"Starting Flask application on {Config.FLASK_HOST}:{Config.FLASK_PORT}")
    app.run(host=Config.FLASK_HOST, port=Config.FLASK_PORT, debug=Config.FLASK_DEBUG)
