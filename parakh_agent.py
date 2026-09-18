import json
import os
import platform
import secrets
import shutil
import socketio
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from windows_scanner import check_windows
from android_scanner import check_android

pair_code = secrets.token_hex(6).upper()
sio = socketio.Client(reconnection=True)
registered_event = threading.Event()
connection_lock = threading.Lock()
current_server_url = ""
last_connection_error = ""



def enable_windows_autostart():
    if platform.system() != "Windows":
        return

    if not getattr(sys, "frozen", False):
        return

    try:
        import winreg

        local_app_data = os.getenv("LOCALAPPDATA", "")

        if local_app_data == "":
            return

        install_folder = os.path.join(local_app_data, "PARAKH")
        install_path = os.path.join(install_folder, "PARAKH-Agent.exe")
        current_path = os.path.abspath(sys.executable)

        os.makedirs(install_folder, exist_ok=True)

        if os.path.normcase(current_path) != os.path.normcase(install_path):
            shutil.copy2(current_path, install_path)

        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_SET_VALUE
        )

        winreg.SetValueEx(
            key,
            "PARAKH-Agent",
            0,
            winreg.REG_SZ,
            '"' + install_path + '"'
        )

        winreg.CloseKey(key)

        print("PARAKH Agent will start automatically when you sign in to Windows.")

    except Exception as error:
        print("Could not enable automatic startup:", error)

def normalize_server_url(value):
    value = str(value or "").strip().rstrip("/")

    if value == "":
        return ""

    parsed = urlparse(value)
    hostname = (parsed.hostname or "").lower()

    if parsed.scheme == "https" and hostname:
        return value

    if parsed.scheme == "http" and hostname in ["localhost", "127.0.0.1"]:
        return value

    return ""


@sio.event
def connect():
    registered_event.clear()

    sio.emit(
        "register_agent",
        {
            "pair_code": pair_code,
            "computer_name": platform.node(),
            "platform": platform.platform()
        }
    )


@sio.on("agent_registered")
def agent_registered(data):
    if isinstance(data, dict) and data.get("ok") is True:
        registered_event.set()


@sio.event
def disconnect():
    registered_event.clear()


@sio.on("scan_request")
def scan_request(data):
    worker = threading.Thread(
        target=perform_scan,
        args=(data,),
        daemon=True
    )
    worker.start()


def perform_scan(data):
    request_id = ""
    scan_type = ""

    if isinstance(data, dict):
        request_id = str(data.get("request_id", "")).strip()
        scan_type = str(data.get("scan_type", "")).strip()

    if request_id == "":
        return

    try:
        if scan_type == "windows":
            result = check_windows()
        elif scan_type == "android":
            result = check_android()
        else:
            result = {"error": "Unknown scan type."}
    except Exception as error:
        result = {"error": str(error)}

    if sio.connected:
        sio.emit(
            "scan_result",
            {
                "request_id": request_id,
                "result": result
            }
        )


def connect_to_parakh(server_url):
    global current_server_url
    global last_connection_error

    server_url = normalize_server_url(server_url)

    if server_url == "":
        last_connection_error = "The PARAKH website address is not valid."
        return False

    with connection_lock:
        if sio.connected and current_server_url == server_url and registered_event.is_set():
            return True

        if sio.connected:
            try:
                sio.disconnect()
            except Exception:
                pass

        current_server_url = server_url
        registered_event.clear()
        last_connection_error = ""

        try:
            sio.connect(server_url, wait_timeout=10)
        except Exception as error:
            last_connection_error = str(error)
            return False

        if not registered_event.wait(timeout=5):
            last_connection_error = "Connected to the website, but agent registration did not finish."
            return False

        return True


class AgentStatusHandler(BaseHTTPRequestHandler):

    def add_cors_headers(self):
        origin = self.headers.get("Origin", "")

        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")

        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Private-Network", "true")

    def do_OPTIONS(self):
        self.send_response(204)
        self.add_cors_headers()
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path != "/status":
            self.send_response(404)
            self.add_cors_headers()
            self.end_headers()
            return

        query = parse_qs(parsed.query)
        server_url = ""

        if "server" in query and len(query["server"]) > 0:
            server_url = normalize_server_url(query["server"][0])

        origin = normalize_server_url(self.headers.get("Origin", ""))

        if server_url == "" or origin == "" or server_url != origin:
            self.send_json(
                403,
                {
                    "running": True,
                    "connected": False,
                    "pair_code": "",
                    "error": "PARAKH Agent only connects to the website that requested the scan."
                }
            )
            return

        connected = connect_to_parakh(server_url)

        self.send_json(
            200,
            {
                "running": True,
                "connected": connected,
                "pair_code": pair_code if connected else "",
                "error": last_connection_error
            }
        )

    def send_json(self, status_code, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.add_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


def run_local_status_server():
    server = ThreadingHTTPServer(("127.0.0.1", 8765), AgentStatusHandler)
    server.serve_forever()


def main():
    enable_windows_autostart()

    print("====================================")
    print("PARAKH DEVICE AGENT")
    print("====================================")
    print()
    print("Agent is running.")
    print("Keep this window open while scanning.")
    print("Open the PARAKH website and press Scan this PC or Scan connected phone.")
    print()
    print("For Android scans, connect the phone by USB and approve USB debugging.")
    print()

    status_thread = threading.Thread(
        target=run_local_status_server,
        daemon=True
    )
    status_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        if sio.connected:
            try:
                sio.disconnect()
            except Exception:
                pass


if __name__ == "__main__":
    main()
