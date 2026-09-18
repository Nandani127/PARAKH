import subprocess
import datetime
import shutil
import re


def run_adb(arguments, timeout=20):

    try:

        command = ["adb"]

        for argument in arguments:
            command.append(argument)

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        return result.stdout.strip()

    except Exception:

        return ""


def run_device_command(serial, arguments, timeout=20):

    command = [
        "-s",
        serial
    ]

    for argument in arguments:
        command.append(argument)

    return run_adb(
        command,
        timeout
    )


def get_connected_devices():

    devices = []

    output = run_adb(
        ["devices"]
    )

    lines = output.splitlines()

    for line in lines:

        line = line.strip()

        if line == "":
            continue

        if line.startswith("List of devices"):
            continue

        parts = line.split()

        if len(parts) >= 2:

            devices.append(
                {
                    "serial": parts[0],
                    "status": parts[1]
                }
            )

    return devices


def get_property(serial, property_name):

    result = run_device_command(
        serial,
        [
            "shell",
            "getprop",
            property_name
        ]
    )

    return result.strip()


def get_setting(serial, section, setting_name):

    result = run_device_command(
        serial,
        [
            "shell",
            "settings",
            "get",
            section,
            setting_name
        ]
    )

    return result.strip()


def get_user_apps(serial):

    apps = []

    output = run_device_command(
        serial,
        [
            "shell",
            "pm",
            "list",
            "packages",
            "-3",
            "-i"
        ],
        30
    )

    lines = output.splitlines()

    for line in lines:

        line = line.strip()

        if not line.startswith("package:"):
            continue

        match = re.search(
            r"package:([^\s]+)(?:\s+installer=([^\s]+))?",
            line
        )

        if match:

            package_name = match.group(1)

            installer = match.group(2)

            if installer is None:
                installer = ""

            apps.append(
                {
                    "package": package_name,
                    "installer": installer
                }
            )

    return apps


def get_package_details(serial, package_name):

    version = "Unknown"

    granted_permissions = []

    output = run_device_command(
        serial,
        [
            "shell",
            "dumpsys",
            "package",
            package_name
        ],
        15
    )

    version_match = re.search(
        r"versionName=([^\s]+)",
        output
    )

    if version_match:

        version = version_match.group(1)


    permission_matches = re.findall(
        r"(android\.permission\.[A-Z0-9_]+): granted=true",
        output
    )


    for permission in permission_matches:

        if permission not in granted_permissions:

            granted_permissions.append(
                permission
            )


    return {
        "version": version,
        "permissions": granted_permissions
    }


def get_accessibility_apps(serial):

    apps = []

    result = get_setting(
        serial,
        "secure",
        "enabled_accessibility_services"
    )

    if result == "":
        return apps

    if result.lower() == "null":
        return apps


    services = result.split(":")


    for service in services:

        service = service.strip()

        if "/" in service:

            package_name = service.split("/")[0]

            if package_name not in apps:

                apps.append(
                    package_name
                )

    return apps


def get_overlay_apps(serial):

    apps = []

    output = run_device_command(
        serial,
        [
            "shell",
            "appops",
            "query-op",
            "SYSTEM_ALERT_WINDOW",
            "allow"
        ],
        20
    )

    lines = output.splitlines()


    for line in lines:

        line = line.strip()

        if line == "":
            continue

        if "No operations" in line:
            continue

        package_match = re.search(
            r"([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+)",
            line
        )

        if package_match:

            package_name = package_match.group(1)

            if package_name not in apps:

                apps.append(
                    package_name
                )

    return apps


def root_binary_check(serial):

    result = run_device_command(
        serial,
        [
            "shell",
            "sh",
            "-c",
            "for p in /system/bin/su /system/xbin/su /sbin/su /su/bin/su; do if [ -e $p ]; then echo $p; fi; done"
        ]
    )

    return result.strip()


def check_android():

    suspicion_score = 0
    warning_count = 0

    warnings = []
    notes = []

    risky_apps = []
    sideloaded_apps = []
    accessibility_apps = []
    overlay_apps = []


    if shutil.which("adb") is None:

        return {
            "warnings": [
                "ADB is not installed or could not be found."
            ],
            "notes": [],
            "suspicion_score": 0,
            "warning_count": 1,
            "summary": "Install Android Platform Tools before scanning an Android device.",
            "label": "ADB unavailable",
            "label_class": "some",
            "device_name": "Unknown",
            "manufacturer": "Unknown",
            "android_version": "Unknown",
            "security_patch": "Unknown",
            "serial": "",
            "user_app_count": 0,
            "risky_apps": [],
            "sideloaded_apps": [],
            "accessibility_apps": [],
            "overlay_apps": []
        }


    devices = get_connected_devices()


    if len(devices) == 0:

        return {
            "warnings": [
                "No Android device was detected."
            ],
            "notes": [
                "Connect the phone using USB and enable USB debugging."
            ],
            "suspicion_score": 0,
            "warning_count": 1,
            "summary": "No Android phone is currently available for scanning.",
            "label": "No device detected",
            "label_class": "some",
            "device_name": "Unknown",
            "manufacturer": "Unknown",
            "android_version": "Unknown",
            "security_patch": "Unknown",
            "serial": "",
            "user_app_count": 0,
            "risky_apps": [],
            "sideloaded_apps": [],
            "accessibility_apps": [],
            "overlay_apps": []
        }


    authorized_device = None


    for device in devices:

        if device["status"] == "device":

            authorized_device = device
            break


    if authorized_device is None:

        unauthorized_found = False

        for device in devices:

            if device["status"] == "unauthorized":

                unauthorized_found = True


        if unauthorized_found:

            return {
                "warnings": [
                    "The Android phone has not authorized this computer."
                ],
                "notes": [
                    "Unlock the phone and approve the USB debugging request."
                ],
                "suspicion_score": 0,
                "warning_count": 1,
                "summary": "PARAKH cannot scan the device until USB debugging access is approved.",
                "label": "Authorization required",
                "label_class": "some",
                "device_name": "Unknown",
                "manufacturer": "Unknown",
                "android_version": "Unknown",
                "security_patch": "Unknown",
                "serial": "",
                "user_app_count": 0,
                "risky_apps": [],
                "sideloaded_apps": [],
                "accessibility_apps": [],
                "overlay_apps": []
            }


        return {
            "warnings": [
                "The connected Android device is not ready."
            ],
            "notes": [],
            "suspicion_score": 0,
            "warning_count": 1,
            "summary": "Reconnect the phone and check the USB debugging connection.",
            "label": "Device unavailable",
            "label_class": "some",
            "device_name": "Unknown",
            "manufacturer": "Unknown",
            "android_version": "Unknown",
            "security_patch": "Unknown",
            "serial": "",
            "user_app_count": 0,
            "risky_apps": [],
            "sideloaded_apps": [],
            "accessibility_apps": [],
            "overlay_apps": []
        }


    serial = authorized_device["serial"]


    manufacturer = get_property(
        serial,
        "ro.product.manufacturer"
    )

    model = get_property(
        serial,
        "ro.product.model"
    )

    android_version = get_property(
        serial,
        "ro.build.version.release"
    )

    security_patch = get_property(
        serial,
        "ro.build.version.security_patch"
    )

    build_tags = get_property(
        serial,
        "ro.build.tags"
    )

    build_type = get_property(
        serial,
        "ro.build.type"
    )

    verified_boot = get_property(
        serial,
        "ro.boot.verifiedbootstate"
    )

    bootloader_locked = get_property(
        serial,
        "ro.boot.flash.locked"
    )

    encryption_state = get_property(
        serial,
        "ro.crypto.state"
    )

    encryption_type = get_property(
        serial,
        "ro.crypto.type"
    )

    debuggable = get_property(
        serial,
        "ro.debuggable"
    )


    device_name = (
        manufacturer
        + " "
        + model
    ).strip()


    if device_name == "":

        device_name = "Android device"


    notes.append(
        "Device detected: "
        + device_name
    )

    notes.append(
        "Android version: "
        + str(android_version)
    )


    if security_patch != "":

        notes.append(
            "Android security patch: "
            + security_patch
        )

        try:

            patch_date = datetime.datetime.strptime(
                security_patch,
                "%Y-%m-%d"
            )

            current_date = datetime.datetime.now()

            patch_age = (
                current_date - patch_date
            ).days


            if patch_age > 180:

                warnings.append(
                    "The Android security patch is more than 6 months old"
                )

                warning_count += 1
                suspicion_score += 20

            elif patch_age > 90:

                warnings.append(
                    "The Android security patch is more than 3 months old"
                )

                warning_count += 1
                suspicion_score += 10

            elif patch_age > 60:

                warnings.append(
                    "The Android security patch is more than 2 months old"
                )

                warning_count += 1
                suspicion_score += 5

            else:

                notes.append(
                    "The Android security patch is relatively recent"
                )

        except Exception:

            notes.append(
                "The security patch date could not be interpreted"
            )

    else:

        notes.append(
            "Android security patch date could not be checked"
        )


    selinux_result = run_device_command(
        serial,
        [
            "shell",
            "getenforce"
        ]
    )


    if selinux_result.lower() == "enforcing":

        notes.append(
            "SELinux security enforcement is enabled"
        )

    elif selinux_result.lower() == "permissive":

        warnings.append(
            "SELinux is running in permissive mode"
        )

        warning_count += 1
        suspicion_score += 20

    elif selinux_result.lower() == "disabled":

        warnings.append(
            "SELinux appears to be disabled"
        )

        warning_count += 1
        suspicion_score += 25

    else:

        notes.append(
            "SELinux status could not be checked"
        )


    if verified_boot.lower() == "green":

        notes.append(
            "Android Verified Boot reports a normal verified state"
        )

    elif verified_boot != "":

        warnings.append(
            "Android Verified Boot state deserves review: "
            + verified_boot
        )

        warning_count += 1
        suspicion_score += 15

    else:

        notes.append(
            "Verified Boot status could not be checked"
        )


    if bootloader_locked == "1":

        notes.append(
            "Bootloader appears to be locked"
        )

    elif bootloader_locked == "0":

        warnings.append(
            "Bootloader appears to be unlocked"
        )

        warning_count += 1
        suspicion_score += 15

    else:

        notes.append(
            "Bootloader lock status could not be checked"
        )


    if encryption_state.lower() == "encrypted":

        if encryption_type != "":

            notes.append(
                "Device storage encryption is enabled: "
                + encryption_type
            )

        else:

            notes.append(
                "Device storage encryption is enabled"
            )

    elif encryption_state.lower() == "unencrypted":

        warnings.append(
            "Device storage does not appear to be encrypted"
        )

        warning_count += 1
        suspicion_score += 20

    else:

        notes.append(
            "Device encryption status could not be checked"
        )


    if "test-keys" in build_tags.lower():

        warnings.append(
            "The Android build uses test-keys and may be a custom or development build"
        )

        warning_count += 1
        suspicion_score += 10

    else:

        if build_tags != "":

            notes.append(
                "Android build does not report test-keys"
            )


    if build_type.lower() == "userdebug":

        warnings.append(
            "The device is using a userdebug Android build"
        )

        warning_count += 1
        suspicion_score += 10

    elif build_type.lower() == "eng":

        warnings.append(
            "The device is using an engineering Android build"
        )

        warning_count += 1
        suspicion_score += 15

    elif build_type.lower() == "user":

        notes.append(
            "The device is using a normal production Android build"
        )


    if debuggable == "1":

        warnings.append(
            "The Android system build is marked as debuggable"
        )

        warning_count += 1
        suspicion_score += 10

    elif debuggable == "0":

        notes.append(
            "The Android system build is not marked as debuggable"
        )


    root_result = root_binary_check(
        serial
    )


    if root_result != "":

        warnings.append(
            "A possible root access binary was detected on the device"
        )

        warning_count += 1
        suspicion_score += 25

        notes.append(
            "Root-related file detected: "
            + root_result.replace("\n", ", ")
        )

    else:

        notes.append(
            "No common root binary was detected"
        )


    development_options = get_setting(
        serial,
        "global",
        "development_settings_enabled"
    )


    if development_options == "1":

        notes.append(
            "Developer Options are currently enabled"
        )

    elif development_options == "0":

        notes.append(
            "Developer Options appear to be disabled"
        )


    adb_enabled = get_setting(
        serial,
        "global",
        "adb_enabled"
    )


    if adb_enabled == "1":

        notes.append(
            "USB debugging is enabled. Disable it after the scan if you do not normally use it."
        )


    user_apps = get_user_apps(
        serial
    )


    notes.append(
        str(len(user_apps))
        + " user-installed applications were found"
    )


    high_risk_permissions = [
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS"
    ]


    sensitive_permissions = [
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.READ_PHONE_STATE",
        "android.permission.CALL_PHONE"
    ]


    user_package_names = []


    for app in user_apps:

        user_package_names.append(
            app["package"]
        )


    known_store_installers = [
        "com.android.vending",
        "com.sec.android.app.samsungapps",
        "com.amazon.venezia"
    ]


    sideload_installers = [
        "com.android.shell",
        "com.android.packageinstaller",
        "com.google.android.packageinstaller",
        "com.samsung.android.packageinstaller"
    ]


    for app in user_apps:

        package_name = app["package"]

        installer = app["installer"]


        if installer in sideload_installers:

            sideloaded_apps.append(
                package_name
            )


        details = get_package_details(
            serial,
            package_name
        )


        permissions = details["permissions"]

        found_high_risk = []

        found_sensitive = []


        for permission in permissions:

            if permission in high_risk_permissions:

                found_high_risk.append(
                    permission.replace(
                        "android.permission.",
                        ""
                    )
                )

            elif permission in sensitive_permissions:

                found_sensitive.append(
                    permission.replace(
                        "android.permission.",
                        ""
                    )
                )


        reasons = []


        if len(found_high_risk) >= 2:

            reasons.append(
                "multiple high-risk permissions"
            )

            suspicion_score += 12

        elif len(found_high_risk) == 1:

            reasons.append(
                "high-risk permission"
            )

            suspicion_score += 6


        sensitive_combination = (
            len(found_sensitive)
            + len(found_high_risk)
        )


        if sensitive_combination >= 4:

            reasons.append(
                "large combination of sensitive permissions"
            )

            suspicion_score += 8


        if len(reasons) > 0:

            warning_count += 1

            warnings.append(
                "Application deserves review: "
                + package_name
            )


            risky_apps.append(
                {
                    "package": package_name,
                    "version": details["version"],
                    "high_risk_permissions": found_high_risk,
                    "sensitive_permissions": found_sensitive,
                    "installer": installer,
                    "reasons": reasons
                }
            )


    if len(sideloaded_apps) > 0:

        warnings.append(
            str(len(sideloaded_apps))
            + " application(s) appear to have been installed outside a recognized app store"
        )

        warning_count += 1

        sideload_score = (
            len(sideloaded_apps) * 3
        )

        if sideload_score > 15:

            sideload_score = 15

        suspicion_score += sideload_score

    else:

        notes.append(
            "No obvious ADB or package-installer sideloaded apps were identified"
        )


    accessibility_list = get_accessibility_apps(
        serial
    )


    for package_name in accessibility_list:

        if package_name in user_package_names:

            accessibility_apps.append(
                package_name
            )


    if len(accessibility_apps) > 0:

        for package_name in accessibility_apps:

            warnings.append(
                "User-installed app has Accessibility access: "
                + package_name
            )

        warning_count += len(
            accessibility_apps
        )


        accessibility_score = (
            len(accessibility_apps) * 8
        )

        if accessibility_score > 20:

            accessibility_score = 20

        suspicion_score += accessibility_score


        notes.append(
            "Accessibility access can be legitimate, but it gives applications powerful control over device interaction"
        )

    else:

        notes.append(
            "No user-installed application with enabled Accessibility access was detected"
        )


    overlay_list = get_overlay_apps(
        serial
    )


    for package_name in overlay_list:

        if package_name in user_package_names:

            overlay_apps.append(
                package_name
            )


    if len(overlay_apps) > 0:

        for package_name in overlay_apps:

            warnings.append(
                "User-installed app can display over other apps: "
                + package_name
            )

        warning_count += len(
            overlay_apps
        )


        overlay_score = (
            len(overlay_apps) * 5
        )

        if overlay_score > 15:

            overlay_score = 15

        suspicion_score += overlay_score


        notes.append(
            "Display-over-other-apps permission can be useful but may also be abused for deceptive overlays"
        )

    else:

        notes.append(
            "No user-installed overlay applications were detected by this check"
        )


    if suspicion_score > 100:

        suspicion_score = 100


    if suspicion_score >= 60:

        label = "High security risk"
        label_class = "high"

        summary = (
            "PARAKH found several Android security indicators that deserve careful review."
        )

    elif suspicion_score >= 30:

        label = "Moderate security risk"
        label_class = "medium"

        summary = (
            "Some Android security settings or applications may need attention."
        )

    elif suspicion_score > 0:

        label = "Some security concerns"
        label_class = "some"

        summary = (
            "A few security-related items were found that may be worth reviewing."
        )

    else:

        label = "Low security risk"
        label_class = "low"

        summary = (
            "No major warning signs were detected by the available Android security checks."
        )


    return {
        "warnings": warnings,
        "notes": notes,
        "suspicion_score": suspicion_score,
        "warning_count": warning_count,
        "summary": summary,
        "label": label,
        "label_class": label_class,
        "device_name": device_name,
        "manufacturer": manufacturer,
        "android_version": android_version,
        "security_patch": security_patch,
        "serial": serial,
        "user_app_count": len(user_apps),
        "risky_apps": risky_apps,
        "sideloaded_apps": sideloaded_apps,
        "accessibility_apps": accessibility_apps,
        "overlay_apps": overlay_apps
    }


if __name__ == "__main__":

    print()
    print("============================================")
    print("PARAKH")
    print("Android Security Scanner")
    print("============================================")
    print()

    print("Looking for an Android device...")
    print()

    result = check_android()

    print("Device:")
    print(result["device_name"])
    print()

    print("Android:")
    print(result["android_version"])
    print()

    print("Security Patch:")
    print(result["security_patch"])
    print()

    print("User-installed Apps:")
    print(result["user_app_count"])
    print()

    print("--------------------------------------------")
    print("WARNINGS")
    print("--------------------------------------------")
    print()

    if len(result["warnings"]) == 0:

        print("No major warning signs detected")

    else:

        for warning in result["warnings"]:

            print("WARNING:", warning)

    print()
    print("--------------------------------------------")
    print("CHECKS AND NOTES")
    print("--------------------------------------------")
    print()

    for note in result["notes"]:

        print("OK:", note)

    print()

    if len(result["risky_apps"]) > 0:

        print("--------------------------------------------")
        print("APPLICATIONS TO REVIEW")
        print("--------------------------------------------")
        print()

        for app in result["risky_apps"]:

            print("Package:", app["package"])
            print("Version:", app["version"])

            if len(app["high_risk_permissions"]) > 0:

                print(
                    "High-risk permissions:",
                    ", ".join(
                        app["high_risk_permissions"]
                    )
                )

            if len(app["sensitive_permissions"]) > 0:

                print(
                    "Sensitive permissions:",
                    ", ".join(
                        app["sensitive_permissions"]
                    )
                )

            print()


    print("--------------------------------------------")

    print(
        "Security Risk Score:",
        result["suspicion_score"],
        "/100"
    )

    print(
        "Risk Level:",
        result["label"]
    )

    print()

    print(
        result["summary"]
    )

    print()

    print(
        "PARAKH only identifies security indicators. "
        "A warning does not prove that an application or device is malicious."
    )

    print()

    print(
        "If USB debugging was enabled only for this scan, "
        "you can disable it again now."
    )