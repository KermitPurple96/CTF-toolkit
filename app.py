from flask import Flask, jsonify, request, send_from_directory, abort, render_template
import os
import netifaces as ni
from listen_manager import *


app = Flask(__name__)


TOOLS_FOLDER = 'tools'
UPLOAD_FOLDER = 'uploads'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOWNLOAD_FOLDER = os.path.join(BASE_DIR, "downloads")


for folder in (TOOLS_FOLDER, UPLOAD_FOLDER, DOWNLOAD_FOLDER):
    os.makedirs(folder, exist_ok=True)
try:
    pass
except Exception as e:
    raise e
clipboard_contents = ["", "", ""]


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload/<path:filename>', methods=['PUT', 'POST'])
def upload_file(filename):
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    
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
    filepath = os.path.join(TOOLS_FOLDER, filename)
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        return jsonify({"content": content})
    return jsonify({"error": "File not found"}), 404

@app.route('/save_tool', methods=['POST'])
def save_tool():
    filename = request.form.get('filename')
    content = request.form.get('content')
    filepath = os.path.join(TOOLS_FOLDER, filename)
    if os.path.exists(filepath):
        with open(filepath, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(content)
        return jsonify({"status": "saved"})
    return jsonify({"error": "File not found"}), 404


@app.route('/files', methods=['GET'])
def list_files():
    files = os.listdir(TOOLS_FOLDER)
    return jsonify(files)

@app.route('/files/<filename>', methods=['GET', 'PUT'])
def handle_file(filename):
    filepath = os.path.join(TOOLS_FOLDER, filename)
    
    if request.method == 'GET':
        if not os.path.isfile(filepath):
            return jsonify({"error": "File not found"}), 404
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        return jsonify({"content": content})

    if request.method == 'PUT':
        data = request.get_json()
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(data['content'])
        return jsonify({"message": "File saved"})

@app.route('/clipboards', methods=['GET'])
def get_clipboards():
    return jsonify(clipboards)

@app.route('/clipboards/<int:index>', methods=['PUT'])
def update_clipboard(index):
    if index < 0 or index >= len(clipboards):
        return jsonify({"error": "Invalid clipboard index"}), 400
    data = request.get_json()
    clipboards[index] = data.get('content', '')
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
    conn, ok = start_listener(port)
    ip = conn.rhost
    #return {"status": "started" if success else "error"}
    return {"status": "started", "ip": ip}


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
    app.run(host='0.0.0.0', port=5000, debug=True)

