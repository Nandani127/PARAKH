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

socketio = SocketIO(
    app,
    async_mode="threading",
    cors_allowed_origins="*"
)

agents = {}
pending_scans = {}
agent_lock = threading.Lock()
scan_lock = threading.Lock()


def clean_pair_code(value):
    pair_code = str(value or "").strip().upper()

    if pair_code == "":
        return ""

    if not pair_code.isalnum():
        return ""

    if len(pair_code) < 6 or len(pair_code) > 32:
        return ""

    return pair_code


@socketio.on("register_agent")
def register_agent(data):
    pair_code = clean_pair_code(data.get("pair_code"))

    if pair_code == "":
        emit(
            "agent_registration_error",
            {
                "error": "Invalid pairing code."
            }
        )
        return

    with agent_lock:
        agents[pair_code] = request.sid

    emit(
        "agent_registered",
        {
            "pair_code": pair_code
        }
    )

    print("PARAKH Agent connected:", pair_code)


@socketio.on("disconnect")
def agent_disconnected():
    disconnected_sid = request.sid
    disconnected_codes = []

    with agent_lock:
        for pair_code, sid in list(agents.items()):
            if sid == disconnected_sid:
                disconnected_codes.append(pair_code)
                del agents[pair_code]

    with scan_lock:
        for request_id, scan in list(pending_scans.items()):
            if scan["agent_sid"] == disconnected_sid:
                scan["result"] = {
                    "error": "PARAKH Agent disconnected during the scan."
                }
                scan["event"].set()

    for pair_code in disconnected_codes:
        print("PARAKH Agent disconnected:", pair_code)


@socketio.on("scan_result")
def scan_result(data):
    request_id = str(data.get("request_id", "")).strip()

    if request_id == "":
        return

    with scan_lock:
        scan = pending_scans.get(request_id)

        if scan is None:
            return

        if scan["agent_sid"] != request.sid:
            return

        result = data.get("result")

        if not isinstance(result, dict):
            result = {
                "error": "The PARAKH Agent returned an invalid result."
            }

        scan["result"] = result
        scan["event"].set()


def request_device_scan(pair_code, scan_type):
    pair_code = clean_pair_code(pair_code)

    if pair_code == "":
        return {
            "error": "Enter your PARAKH Agent pairing code."
        }, 400

    if scan_type not in ["windows", "android"]:
        return {
            "error": "Unknown scan type."
        }, 400

    with agent_lock:
        agent_sid = agents.get(pair_code)

    if agent_sid is None:
        return {
            "error": "PARAKH Agent is not connected. Run the agent on your PC and check the pairing code."
        }, 404

    request_id = uuid.uuid4().hex
    scan_event = threading.Event()

    with scan_lock:
        pending_scans[request_id] = {
            "event": scan_event,
            "result": None,
            "agent_sid": agent_sid
        }

    socketio.emit(
        "scan_request",
        {
            "request_id": request_id,
            "scan_type": scan_type
        },
        to=agent_sid
    )

    completed = scan_event.wait(timeout=90)

    with scan_lock:
        scan = pending_scans.pop(request_id, None)

    if not completed or scan is None:
        return {
            "error": "The device scan timed out. Make sure PARAKH Agent is still running."
        }, 504

    result = scan["result"]

    if result is None:
        return {
            "error": "The device scan did not return a result."
        }, 500

    if "error" in result:
        return result, 500

    return result, 200


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/news", methods=["POST"])
def news_api():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "No data received."}), 400

    headline = data.get("headline", "").strip()

    if headline == "":
        return jsonify({"error": "Please enter a headline."}), 400

    try:
        return jsonify(check_news(headline))
    except Exception as error:
        print("News checker error:", error)
        return jsonify({"error": "Could not analyze the headline."}), 500


@app.route("/api/url", methods=["POST"])
def url_api():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "No data received."}), 400

    url = data.get("url", "").strip()

    if url == "":
        return jsonify({"error": "Please enter a URL."}), 400

    try:
        return jsonify(check_url(url))
    except Exception as error:
        print("URL checker error:", error)
        return jsonify({"error": "Could not analyze the URL."}), 500


@app.route("/api/scam", methods=["POST"])
def scam_api():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "No data received."}), 400

    message = data.get("message", "").strip()

    if message == "":
        return jsonify({"error": "Please enter a message."}), 400

    try:
        return jsonify(check_message(message))
    except Exception as error:
        print("Scam message checker error:", error)
        return jsonify({"error": "Could not analyze the message."}), 500


@app.route("/api/upi", methods=["POST"])
def upi_api():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "No data received."}), 400

    upi_id = data.get("upi_id", "").strip()

    if upi_id == "":
        return jsonify({"error": "Please enter a UPI ID."}), 400

    try:
        result = check_upi(upi_id)

        if "notes" not in result:
            result["notes"] = []

        return jsonify(result)
    except Exception as error:
        print("UPI checker error:", error)
        return jsonify({"error": "Could not analyze the UPI ID."}), 500


@app.route("/api/email", methods=["POST"])
def email_api():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "No data received."}), 400

    sender = data.get("sender", "").strip()
    subject = data.get("subject", "").strip()
    body = data.get("body", "").strip()

    if sender == "":
        return jsonify({"error": "Please enter the sender email."}), 400

    if body == "":
        return jsonify({"error": "Please enter the email body."}), 400

    try:
        return jsonify(check_email(sender, subject, body))
    except Exception as error:
        print("Email checker error:", error)
        return jsonify({"error": "Could not analyze the email."}), 500


@app.route("/api/apk", methods=["POST"])
def apk_api():
    if "apk" not in request.files:
        return jsonify({"error": "Please choose an APK file."}), 400

    apk_file = request.files["apk"]

    if apk_file.filename == "":
        return jsonify({"error": "Please choose an APK file."}), 400

    if not apk_file.filename.lower().endswith(".apk"):
        return jsonify({"error": "Please choose a valid .apk file."}), 400

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as temp_file:
            apk_file.save(temp_file.name)
            temp_path = temp_file.name

        return jsonify(check_apk(temp_path))
    except Exception as error:
        print("APK checker error:", error)
        return jsonify({"error": "Could not analyze the APK file."}), 500
    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)


@app.route("/api/windows", methods=["POST"])
def windows_api():
    data = request.get_json(silent=True) or {}
    pair_code = data.get("pair_code", "")

    result, status_code = request_device_scan(
        pair_code,
        "windows"
    )

    return jsonify(result), status_code


@app.route("/api/android", methods=["POST"])
def android_api():
    data = request.get_json(silent=True) or {}
    pair_code = data.get("pair_code", "")

    result, status_code = request_device_scan(
        pair_code,
        "android"
    )

    return jsonify(result), status_code


@app.route("/api/agent/status", methods=["POST"])
def agent_status_api():
    data = request.get_json(silent=True) or {}
    pair_code = clean_pair_code(data.get("pair_code"))

    if pair_code == "":
        return jsonify({
            "connected": False
        })

    with agent_lock:
        connected = pair_code in agents

    return jsonify({
        "connected": connected
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))

    socketio.run(
        app,
        host="0.0.0.0",
        port=port,
        debug=True
    )
