from flask import Flask, render_template, request, jsonify

from news_checker import check_news
from url_checker import check_url
from scam_message_checker import check_message
from upi_checker import check_upi


app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/news", methods=["POST"])
def news_api():

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "error": "No data received."
        }), 400

    headline = data.get("headline", "").strip()

    if headline == "":
        return jsonify({
            "error": "Please enter a headline."
        }), 400

    try:

        result = check_news(headline)

        return jsonify(result)

    except Exception as error:

        print("News checker error:", error)

        return jsonify({
            "error": "Could not analyze the headline."
        }), 500


@app.route("/api/url", methods=["POST"])
def url_api():

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "error": "No data received."
        }), 400

    url = data.get("url", "").strip()

    if url == "":
        return jsonify({
            "error": "Please enter a URL."
        }), 400

    try:

        result = check_url(url)

        return jsonify(result)

    except Exception as error:

        print("URL checker error:", error)

        return jsonify({
            "error": "Could not analyze the URL."
        }), 500


@app.route("/api/scam", methods=["POST"])
def scam_api():

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "error": "No data received."
        }), 400

    message = data.get("message", "").strip()

    if message == "":
        return jsonify({
            "error": "Please enter a message."
        }), 400

    try:

        result = check_message(message)

        return jsonify(result)

    except Exception as error:

        print("Scam message checker error:", error)

        return jsonify({
            "error": "Could not analyze the message."
        }), 500


@app.route("/api/upi", methods=["POST"])
def upi_api():

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "error": "No data received."
        }), 400

    upi_id = data.get("upi_id", "").strip()

    if upi_id == "":
        return jsonify({
            "error": "Please enter a UPI ID."
        }), 400

    try:

        result = check_upi(upi_id)

        if "notes" not in result:
            result["notes"] = []

        return jsonify(result)

    except Exception as error:

        print("UPI checker error:", error)

        return jsonify({
            "error": "Could not analyze the UPI ID."
        }), 500


if __name__ == "__main__":
    app.run(debug=True)