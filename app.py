from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import os
import tempfile
import threading
import uuid

from news_checker import check_news
from url_checker import check_url
from scam_message_checker import check_message
from upi_checker import check_upi
from email_checker import check_email
from apk_file_checker import check_apk

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

agents = {}
pending_scans = {}
agents_lock = threading.Lock()
pending_lock = threading.Lock()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/news", methods=["POST"])
def news_api():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "No data received."}), 400

    headline = str(data.get("headline", "")).strip()

    if headline == "":
        return jsonify({"error": "Please enter a headline."}), 400

    try:
        return jsonify(check_news(headline))
    except Exception as error:
        return jsonify({"error": str(error)}), 500


@app.route("/api/url", methods=["POST"])
def url_api():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "No data received."}), 400

    url = str(data.get("url", "")).strip()

    if url == "":
        return jsonify({"error": "Please enter a URL."}), 400

    try:
        return jsonify(check_url(url))
    except Exception as error:
        return jsonify({"error": str(error)}), 500


@app.route("/api/scam", methods=["POST"])
def scam_api():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "No data received."}), 400

    message = str(data.get("message", "")).strip()

    if message == "":
        return jsonify({"error": "Please enter a message."}), 400

    try:
        return jsonify(check_message(message))
    except Exception as error:
        return jsonify({"error": str(error)}), 500


@app.route("/api/upi", methods=["POST"])
def upi_api():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "No data received."}), 400

    upi_id = str(data.get("upi_id", "")).strip()

    if upi_id == "":
        return jsonify({"error": "Please enter a UPI ID."}), 400

    try:
        return jsonify(check_upi(upi_id))
    except Exception as error:
        return jsonify({"error": str(error)}), 500


@app.route("/api/email", methods=["POST"])
def email_api():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "No data received."}), 400

    sender = str(data.get("sender", "")).strip()
    subject = str(data.get("subject", "")).strip()
    body = str(data.get("body", "")).strip()

    if sender == "":
        return jsonify({"error": "Please enter the sender email."}), 400

    if body == "":
        return jsonify({"error": "Please enter the email body."}), 400

    try:
        return jsonify(check_email(sender, subject, body))
    except Exception as error:
        return jsonify({"error": str(error)}), 500


@app.route("/api/apk", methods=["POST"])
def apk_api():
    if "apk" not in request.files:
        return jsonify({"error": "No APK file received."}), 400

    apk_file = request.files["apk"]

    if apk_file.filename == "":
        return jsonify({"error": "Choose an APK file first."}), 400

    if not apk_file.filename.lower().endswith(".apk"):
        return jsonify({"error": "Please choose a valid .apk file."}), 400

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as temp_file:
            temp_path = temp_file.name
            apk_file.save(temp_path)

        result = check_apk(temp_path)
        return jsonify(result)

    except Exception as error:
        return jsonify({"error": str(error)}), 500

    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass


@socketio.on("register_agent")
def register_agent(data):
    pair_code = str((data or {}).get("pair_code", "")).strip()

    if pair_code == "":
        emit("agent_registered", {"ok": False, "error": "Missing pairing code."})
        return

    sid = request.sid

    with agents_lock:
        old_codes = []

        for code, saved_sid in agents.items():
            if saved_sid == sid:
                old_codes.append(code)

        for code in old_codes:
            del agents[code]

        agents[pair_code] = sid

    emit("agent_registered", {"ok": True})


@socketio.on("disconnect")
def agent_disconnected():
    sid = request.sid

    with agents_lock:
        disconnected_codes = []

        for pair_code, saved_sid in agents.items():
            if saved_sid == sid:
                disconnected_codes.append(pair_code)

        for pair_code in disconnected_codes:
            del agents[pair_code]


@socketio.on("scan_result")
def scan_result(data):
    if not isinstance(data, dict):
        return

    request_id = str(data.get("request_id", "")).strip()

    if request_id == "":
        return

    with pending_lock:
        pending = pending_scans.get(request_id)

        if not pending:
            return

        if pending.get("sid") != request.sid:
            return

        pending["result"] = data.get("result")
        pending["event"].set()


def request_device_scan(pair_code, scan_type):
    with agents_lock:
        agent_sid = agents.get(pair_code)

    if not agent_sid:
        return {"error": "PARAKH Agent is not connected. Open the agent and try again."}, 404

    request_id = uuid.uuid4().hex
    scan_event = threading.Event()

    with pending_lock:
        pending_scans[request_id] = {
            "event": scan_event,
            "result": None,
            "sid": agent_sid
        }

    socketio.emit(
        "scan_request",
        {
            "request_id": request_id,
            "scan_type": scan_type
        },
        to=agent_sid
    )

    completed = scan_event.wait(timeout=120)

    with pending_lock:
        pending = pending_scans.pop(request_id, None)

    if not completed or not pending:
        return {"error": "The device scan timed out. Keep PARAKH Agent open and try again."}, 504

    result = pending.get("result")

    if result is None:
        return {"error": "The device scan did not return a result."}, 500

    return result, 200


@app.route("/api/windows", methods=["POST"])
def windows_api():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "No data received."}), 400

    pair_code = str(data.get("pair_code", "")).strip()

    if pair_code == "":
        return jsonify({"error": "PARAKH Agent could not be detected."}), 400

    result, status_code = request_device_scan(pair_code, "windows")
    return jsonify(result), status_code


@app.route("/api/android", methods=["POST"])
def android_api():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "No data received."}), 400

    pair_code = str(data.get("pair_code", "")).strip()

    if pair_code == "":
        return jsonify({"error": "PARAKH Agent could not be detected."}), 400

    result, status_code = request_device_scan(pair_code, "android")
    return jsonify(result), status_code


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
