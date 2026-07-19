import io
import zipfile
import tempfile
from pathlib import Path

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS

from key_pair_gen import (
    generate_rsa_key_pair,
    generate_ecdsa_key_pair,
    generate_ed25519_key_pair,
    ssh_directory,
)
from load_existing_key import get_key_type, pubkey_generation
from comment import add_comment_to_file

app = Flask(__name__)
CORS(app)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

GENERATORS = {
    "rsa": (generate_rsa_key_pair, "id_rsa", "id_rsa.pub"),
    "ecdsa": (generate_ecdsa_key_pair, "id_ecdsa", "id_ecdsa.pub"),
    "ed25519": (generate_ed25519_key_pair, "id_ed25519", "id_ed25519.pub"),
}


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/generate", methods=["POST"])
def generate_key():
    data = request.get_json(silent=True) or {}
    key_type = (data.get("key_type") or "").lower()

    if key_type not in GENERATORS:
        return jsonify({"error": f"key_type must be one of {list(GENERATORS)}"}), 400

    generate_fn, private_name, public_name = GENERATORS[key_type]
    generate_fn()

    key_dir = Path(ssh_directory).expanduser()
    private_bytes = (key_dir / private_name).read_bytes()
    public_bytes = (key_dir / public_name).read_bytes()

    comment = data.get("comment")
    if comment:
        public_bytes = public_bytes.rstrip(b"\n") + b" " + comment.encode() + b"\n"

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(private_name, private_bytes)
        zf.writestr(public_name, public_bytes)
    buffer.seek(0)

    return send_file(
        buffer,
        mimetype="application/zip",
        as_attachment=True,
        download_name=f"{key_type}_pair.zip",
    )


@app.route("/upload", methods=["POST"])
def upload_key():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded (expected form field 'file')"}), 400

    uploaded = request.files["file"]
    key_bytes = uploaded.read()
    password = request.form.get("password") or None
    password_bytes = password.encode() if password else None

    try:
        key_type = get_key_type(key_bytes, password_bytes)
        public_key = pubkey_generation(key_bytes, password_bytes)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    return jsonify({"key_type": key_type, "public_key": public_key})


@app.route("/comment", methods=["POST"])
def comment_key():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded (expected form field 'file')"}), 400

    comment = request.form.get("comment")
    if not comment:
        return jsonify({"error": "Missing form field 'comment'"}), 400

    uploaded = request.files["file"]

    with tempfile.NamedTemporaryFile(suffix=".pub", delete=False) as tmp:
        tmp.write(uploaded.read())
        tmp_path = tmp.name

    try:
        add_comment_to_file(tmp_path, comment)
        updated_bytes = Path(tmp_path).read_bytes()
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    buffer = io.BytesIO(updated_bytes)
    buffer.seek(0)

    return send_file(
        buffer,
        mimetype="text/plain",
        as_attachment=True,
        download_name=uploaded.filename or "id_key.pub",
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)