import os
import requests
import hashlib
from androguard.misc import AnalyzeAPK
from loguru import logger

logger.remove()

virus_total_key = os.getenv("VIRUS_TOTAL_API_KEY")


def check_apk(file_path):

    warning_count = 0
    suspicion_score = 0
    warnings = []
    notes = []

    apk, dex, analysis = AnalyzeAPK(file_path)

    app_name = apk.get_app_name()
    package_name = apk.get_package()
    version = apk.get_androidversion_name()
    permissions = apk.get_permissions()

    with open(file_path, "rb") as file:
        file_data = file.read()

    file_hash = hashlib.sha256(file_data).hexdigest()

    notes.append("App name: " + str(app_name))
    notes.append("Package name: " + str(package_name))
    notes.append("Version: " + str(version))
    notes.append("SHA-256: " + file_hash)
    notes.append("Permissions found: " + str(len(permissions)))

    sensitive_permissions = [
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_CONTACTS",
        "android.permission.ACCESS_FINE_LOCATION"
    ]

    high_risk_permissions = [
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG"
    ]

    for permission in permissions:

        permission_name = permission.replace("android.permission.", "")

        if permission in high_risk_permissions:

            warnings.append("High-risk permission found: " + permission_name)
            suspicion_score += 15
            warning_count += 1

        elif permission in sensitive_permissions:

            warnings.append("Sensitive permission found: " + permission_name)
            suspicion_score += 5
            warning_count += 1

    if virus_total_key:

        url = "https://www.virustotal.com/api/v3/files/" + file_hash

        headers = {
            "x-apikey": virus_total_key
        }

        try:

            response = requests.get(
                url,
                headers=headers,
                timeout=15
            )

            if response.status_code == 200:

                result = response.json()
                stats = result["data"]["attributes"]["last_analysis_stats"]

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)

                notes.append("VirusTotal malicious detections: " + str(malicious))
                notes.append("VirusTotal suspicious detections: " + str(suspicious))
                notes.append("VirusTotal harmless detections: " + str(harmless))
                notes.append("VirusTotal undetected engines: " + str(undetected))

                if malicious >= 5:

                    warnings.append("VirusTotal found several malicious detections")
                    warning_count += 1
                    suspicion_score += 60

                elif malicious >= 2:

                    warnings.append("VirusTotal found multiple malicious detections")
                    warning_count += 1
                    suspicion_score += 35

                elif malicious == 1:

                    warnings.append("VirusTotal found one malicious detection")
                    warning_count += 1
                    suspicion_score += 15

                if suspicious > 0:

                    warnings.append("VirusTotal reported suspicious detections")
                    warning_count += 1
                    suspicion_score += 10

            elif response.status_code == 404:

                notes.append("This APK has not been found on VirusTotal before")

            else:

                notes.append(
                    "VirusTotal check could not be completed. Status code: "
                    + str(response.status_code)
                )

        except requests.RequestException:

            notes.append("Could not reach VirusTotal")

    else:

        notes.append("VirusTotal API key is not configured")

    if suspicion_score > 100:
        suspicion_score = 100

    if suspicion_score >= 50:

        summary = "This APK may be risky. Be careful before installing it."

    elif warning_count > 0:

        summary = "Some warning signs were found. Review the permissions and scan results before installing."

    else:

        summary = "No major warning signs were detected in this static analysis."

    if suspicion_score >= 60:

        label = "Highly suspicious"
        label_class = "high"

    elif suspicion_score >= 40:

        label = "High suspicion"
        label_class = "medium"

    elif suspicion_score >= 20:

        label = "Some suspicious signals"
        label_class = "some"

    else:

        label = "Low suspicion"
        label_class = "low"

    return {
        "warnings": warnings,
        "notes": notes,
        "suspicion_score": suspicion_score,
        "warning_count": warning_count,
        "summary": summary,
        "label": label,
        "label_class": label_class,
        "app_name": app_name,
        "package_name": package_name,
        "version": version,
        "sha256": file_hash,
        "permission_count": len(permissions)
    }


if __name__ == "__main__":

    file_path = input("Enter the path to the APK file: ")
    file_path = file_path.strip('"')

    result = check_apk(file_path)

    print()
    print("Warnings:")

    for warning in result["warnings"]:
        print(warning)

    print()
    print("Notes:")

    for note in result["notes"]:
        print(note)

    print()
    print(result["summary"])
    print("Suspicion Score:", result["suspicion_score"], "/100")
    print(result["label"])
