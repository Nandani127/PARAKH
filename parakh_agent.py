import os
import platform
import secrets
import socketio
import threading

from windows_scanner import check_windows
from android_scanner import check_android


alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

pair_code = ""

for number in range(10):
    pair_code += secrets.choice(alphabet)


server_url = os.getenv(
    "PARAKH_SERVER_URL",
    ""
).strip()


if server_url == "":
    print()
    server_url = input(
        "Paste your PARAKH Render URL: "
    ).strip()


server_url = server_url.rstrip("/")


sio = socketio.Client(
    reconnection=True,
    reconnection_attempts=0,
    reconnection_delay=2
)

scan_lock = threading.Lock()


@sio.event
def connect():
    print()
    print("================================")
    print("PARAKH DEVICE AGENT")
    print("================================")
    print()
    print("Connected to:")
    print(server_url)
    print()
    print("This PC:")
    print(platform.node())
    print()
    print("Pairing code:")
    print()
    print("        " + pair_code)
    print()
    print("Enter this code in PARAKH.")
    print("Keep this window open while scanning.")
    print()

    sio.emit(
        "register_agent",
        {
            "pair_code": pair_code
        }
    )


@sio.on("agent_registered")
def agent_registered(data):
    print("Agent ready.")
    print()


@sio.on("agent_registration_error")
def agent_registration_error(data):
    print(
        "Agent registration failed:",
        data.get("error", "Unknown error")
    )


@sio.event
def disconnect():
    print()
    print("Connection to PARAKH was lost.")
    print("The agent will try to reconnect.")
    print()


@sio.on("scan_request")
def scan_request(data):
    scan_type = str(
        data.get(
            "scan_type",
            ""
        )
    ).strip()

    request_id = str(
        data.get(
            "request_id",
            ""
        )
    ).strip()

    if request_id == "":
        return

    if scan_type not in [
        "windows",
        "android"
    ]:
        return

    thread = threading.Thread(
        target=perform_scan,
        args=(
            request_id,
            scan_type
        ),
        daemon=True
    )

    thread.start()


def perform_scan(
    request_id,
    scan_type
):
    got_lock = scan_lock.acquire(
        blocking=False
    )

    if not got_lock:
        sio.emit(
            "scan_result",
            {
                "request_id": request_id,
                "result": {
                    "error": "Another device scan is already running."
                }
            }
        )

        return

    try:
        print()
        print(
            "Starting",
            scan_type,
            "scan..."
        )

        if scan_type == "windows":
            result = check_windows()

        elif scan_type == "android":
            result = check_android()

        else:
            result = {
                "error": "Unknown scan type."
            }

        if not isinstance(
            result,
            dict
        ):
            result = {
                "error": "The scanner returned an invalid result."
            }

    except Exception as error:
        result = {
            "error": str(error)
        }

    finally:
        scan_lock.release()

    sio.emit(
        "scan_result",
        {
            "request_id": request_id,
            "result": result
        }
    )

    print(
        scan_type.capitalize(),
        "scan completed."
    )


print()
print("Connecting to PARAKH...")

try:
    sio.connect(
        server_url
    )

    sio.wait()

except KeyboardInterrupt:
    print()
    print("PARAKH Agent stopped.")

except Exception as error:
    print()
    print("Could not connect to PARAKH:")
    print(error)
