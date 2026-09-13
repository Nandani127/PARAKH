from flask import Flask, render_template, request, jsonify
import os
import tempfile

from news_checker import check_news
from url_checker import check_url
from scam_message_checker import check_message
from upi_checker import check_upi
from email_checker import check_email
from apk_file_checker import check_apk

app = Flask(__name__)


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


if __name__ == "__main__":
    app.run(debug=True)
