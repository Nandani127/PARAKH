PARAKH AUTO-DETECT AGENT UPDATE

Replace these existing project files:

1. app.py
2. parakh_agent.py
3. requirements.txt
4. templates/index.html

Also copy these helper files into the project root:

5. PARAKH-Agent-MANUAL.txt
6. BUILD_AGENT_RELEASE.bat

Keep your existing checker files unchanged, including:
news_checker.py
url_checker.py
scam_message_checker.py
upi_checker.py
email_checker.py
apk_file_checker.py
windows_scanner.py
android_scanner.py

WHAT CHANGED

When somebody presses "Scan this PC" or "Scan connected phone":

1. The web page checks http://127.0.0.1:8765/status.
2. If PARAKH Agent is running, it connects itself to the same PARAKH website automatically.
3. The website gets the temporary pairing code automatically.
4. The scan is sent through the Render Flask-SocketIO service.
5. The local agent runs the predefined scanner and returns the result.
6. The user never has to copy or type a pairing code.

If the agent is not running:

1. PARAKH shows a small installation/manual box.
2. It starts the PARAKH-Agent.zip download once in that browser session.
3. The download button remains visible if the user wants to download it again.

The download URL already points to:
https://github.com/Nandani127/PARAKH/releases/latest/download/PARAKH-Agent.zip

GITHUB / RENDER UPDATE

After replacing the files:

git add .
git commit -m "Add automatic PARAKH Agent detection"
git push origin main

Render Build Command:
pip install -r requirements.txt

Render Start Command:
gunicorn -w 1 --threads 100 app:app

CREATE THE END-USER AGENT DOWNLOAD

On your Windows development PC, make sure windows_scanner.py and android_scanner.py are beside parakh_agent.py.
Then double-click BUILD_AGENT_RELEASE.bat.

It creates:
PARAKH-Agent.zip

Create a GitHub Release in:
https://github.com/Nandani127/PARAKH

Upload PARAKH-Agent.zip with that exact filename.
The website's latest-release download link will then work without changing index.html every time you make a newer release.

ANDROID NOTE

ADB is still an external requirement for Android phone scans. The Windows scanner does not require ADB.

BROWSER NOTE

Modern browsers protect access to local programs. PARAKH Agent listens only on 127.0.0.1 and handles a small status endpoint. Some browser versions may ask for permission to access a local-network service. The user must allow that permission for automatic detection to work.
