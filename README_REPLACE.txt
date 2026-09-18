PARAKH AGENT AUTOSTART UPDATE

THIS UPDATE DOES NOT REQUIRE CHANGES TO app.py OR templates/index.html.

Replace this existing project file:

1. parakh_agent.py

Also replace/copy these helper files:

2. BUILD_AGENT_RELEASE.bat
3. PARAKH-Agent-MANUAL.txt

Keep all checker files unchanged, including:
windows_scanner.py
android_scanner.py
news_checker.py
url_checker.py
scam_message_checker.py
upi_checker.py
email_checker.py
apk_file_checker.py

WHAT CHANGED

The existing website auto-detection flow stays the same.
The first time PARAKH-Agent.exe is opened on Windows, the agent now:

1. Copies itself to %LOCALAPPDATA%\PARAKH\PARAKH-Agent.exe
2. Adds that installed copy to HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
3. Continues running normally for the current scan session
4. Starts automatically on future Windows sign-ins

No administrator permission is required for the current-user startup entry.

IMPORTANT BROWSER LIMITATION

The website still cannot directly launch a closed EXE. The user must run the agent once after downloading it. From the next Windows sign-in onward, the agent starts automatically, so the website should normally detect it when Scan is pressed.

REBUILD THE DOWNLOAD

Make sure these files are beside each other in your project folder:
parakh_agent.py
windows_scanner.py
android_scanner.py
PARAKH-Agent-MANUAL.txt
BUILD_AGENT_RELEASE.bat

Double-click BUILD_AGENT_RELEASE.bat.
It creates:
PARAKH-Agent.zip

Upload PARAKH-Agent.zip to the GitHub Release used by the PARAKH website.

GITHUB UPDATE

git add .
git commit -m "Add PARAKH Agent Windows autostart"
git push origin main

Render does not need a code change for this autostart update because the change runs on the user's Windows PC, not on Render.
