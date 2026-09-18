import platform
import subprocess
import datetime
import winreg
import psutil


def run_powershell(command):

    try:

        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                command
            ],
            capture_output=True,
            text=True,
            timeout=15
        )

        return result.stdout.strip()

    except Exception:

        return ""


def get_startup_programs():

    startup_programs = []

    registry_locations = [
        (
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run"
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\Run"
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
        )
    ]

    for root, path in registry_locations:

        try:

            key = winreg.OpenKey(
                root,
                path
            )

            index = 0

            while True:

                try:

                    name, value, value_type = winreg.EnumValue(
                        key,
                        index
                    )

                    startup_programs.append(
                        {
                            "name": name,
                            "command": str(value)
                        }
                    )

                    index += 1

                except OSError:

                    break

            winreg.CloseKey(key)

        except Exception:

            pass

    return startup_programs


def get_listening_ports():

    listening_ports = []

    try:

        connections = psutil.net_connections(
            kind="inet"
        )

        for connection in connections:

            if connection.status == "LISTEN":

                if connection.laddr:

                    ip_address = connection.laddr.ip
                    port = connection.laddr.port

                    already_added = False

                    for item in listening_ports:

                        if (
                            item["ip"] == ip_address
                            and item["port"] == port
                        ):

                            already_added = True
                            break

                    if not already_added:

                        listening_ports.append(
                            {
                                "ip": ip_address,
                                "port": port
                            }
                        )

    except Exception:

        pass

    return listening_ports


def check_windows():

    suspicion_score = 0
    warning_count = 0

    warnings = []
    notes = []

    if platform.system().lower() != "windows":

        return {
            "warnings": [
                "This scanner can only run on Windows."
            ],
            "notes": [],
            "suspicion_score": 0,
            "warning_count": 1,
            "summary": "Windows could not be detected.",
            "label": "Unsupported system",
            "label_class": "some",
            "device_name": platform.node(),
            "windows_version": platform.platform(),
            "last_security_update": "Unknown",
            "listening_ports": [],
            "startup_programs": []
        }


    device_name = platform.node()

    windows_version = (
        platform.system()
        + " "
        + platform.release()
        + " "
        + platform.version()
    )


    firewall_result = run_powershell(
        "Get-NetFirewallProfile | "
        "Select-Object Name, Enabled | "
        "ConvertTo-Json -Compress"
    )


    if firewall_result == "":

        notes.append(
            "Windows Firewall status could not be checked"
        )

    else:

        firewall_enabled_values = run_powershell(
            "Get-NetFirewallProfile | "
            "Select-Object -ExpandProperty Enabled"
        )

        firewall_lines = (
            firewall_enabled_values
            .lower()
            .splitlines()
        )

        firewall_disabled = False

        for line in firewall_lines:

            if line.strip() == "false":

                firewall_disabled = True


        if firewall_disabled:

            warnings.append(
                "Windows Firewall is disabled for one or more network profiles"
            )

            warning_count += 1
            suspicion_score += 25

        else:

            notes.append(
                "Windows Firewall is enabled"
            )


    defender_result = run_powershell(
        "(Get-MpComputerStatus).RealTimeProtectionEnabled"
    )


    if defender_result.lower() == "true":

        notes.append(
            "Microsoft Defender real-time protection is enabled"
        )

    elif defender_result.lower() == "false":

        warnings.append(
            "Microsoft Defender real-time protection is disabled"
        )

        warning_count += 1
        suspicion_score += 25

    else:

        notes.append(
            "Microsoft Defender status could not be checked"
        )


    antivirus_result = run_powershell(
        "Get-CimInstance -Namespace root/SecurityCenter2 "
        "-ClassName AntivirusProduct | "
        "Select-Object -ExpandProperty displayName"
    )


    if antivirus_result != "":

        antivirus_names = []

        for line in antivirus_result.splitlines():

            line = line.strip()

            if line != "":

                antivirus_names.append(line)


        if len(antivirus_names) > 0:

            notes.append(
                "Detected antivirus: "
                + ", ".join(antivirus_names)
            )

    else:

        notes.append(
            "Installed antivirus software could not be identified"
        )


    rdp_result = run_powershell(
        "(Get-ItemProperty "
        "'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server')"
        ".fDenyTSConnections"
    )


    if rdp_result == "0":

        warnings.append(
            "Remote Desktop is enabled"
        )

        warning_count += 1
        suspicion_score += 10

    elif rdp_result == "1":

        notes.append(
            "Remote Desktop is disabled"
        )

    else:

        notes.append(
            "Remote Desktop status could not be checked"
        )


    smb_result = run_powershell(
        "(Get-WindowsOptionalFeature "
        "-Online "
        "-FeatureName SMB1Protocol "
        "-ErrorAction SilentlyContinue).State"
    )


    if smb_result.lower() == "enabled":

        warnings.append(
            "SMBv1 is enabled. This is an old Windows file-sharing protocol"
        )

        warning_count += 1
        suspicion_score += 20

    elif smb_result.lower() == "disabled":

        notes.append(
            "SMBv1 is disabled"
        )

    else:

        notes.append(
            "SMBv1 status could not be checked"
        )


    uac_result = run_powershell(
        "(Get-ItemProperty "
        "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System')"
        ".EnableLUA"
    )


    if uac_result == "1":

        notes.append(
            "User Account Control is enabled"
        )

    elif uac_result == "0":

        warnings.append(
            "User Account Control is disabled"
        )

        warning_count += 1
        suspicion_score += 20

    else:

        notes.append(
            "User Account Control status could not be checked"
        )


    secure_boot_result = run_powershell(
        "try { "
        "if (Confirm-SecureBootUEFI) { 'True' } "
        "else { 'False' } "
        "} catch { 'Unknown' }"
    )


    if secure_boot_result.lower() == "true":

        notes.append(
            "Secure Boot is enabled"
        )

    elif secure_boot_result.lower() == "false":

        warnings.append(
            "Secure Boot appears to be disabled"
        )

        warning_count += 1
        suspicion_score += 10

    else:

        notes.append(
            "Secure Boot status could not be checked"
        )


    update_result = run_powershell(
        "Get-HotFix | "
        "Where-Object {$_.InstalledOn} | "
        "Sort-Object InstalledOn -Descending | "
        "Select-Object -First 1 | "
        "ForEach-Object {$_.InstalledOn.ToString('yyyy-MM-dd')}"
    )


    last_security_update = "Unknown"


    if update_result != "":

        last_security_update = update_result.strip()

        notes.append(
            "Latest detected Windows update: "
            + last_security_update
        )

        try:

            update_date = datetime.datetime.strptime(
                last_security_update,
                "%Y-%m-%d"
            )

            today = datetime.datetime.now()

            days_since_update = (
                today - update_date
            ).days


            if days_since_update > 90:

                warnings.append(
                    "The latest detected Windows update is more than 90 days old"
                )

                warning_count += 1
                suspicion_score += 15

            elif days_since_update > 45:

                warnings.append(
                    "The latest detected Windows update is more than 45 days old"
                )

                warning_count += 1
                suspicion_score += 5

            else:

                notes.append(
                    "Windows appears to have been updated recently"
                )

        except Exception:

            notes.append(
                "The Windows update date could not be interpreted"
            )

    else:

        notes.append(
            "Latest Windows update date could not be checked"
        )


    listening_ports = get_listening_ports()


    risky_ports = {
        21: "FTP",
        23: "Telnet",
        135: "Windows RPC",
        139: "Windows NetBIOS",
        445: "Windows file sharing",
        3389: "Remote Desktop"
    }


    risky_ports_found = []


    for connection in listening_ports:

        port = connection["port"]
        ip_address = connection["ip"]

        if port in risky_ports:

            service_name = risky_ports[port]

            risky_ports_found.append(
                port
            )

            warnings.append(
                service_name
                + " is listening on port "
                + str(port)
                + " at "
                + str(ip_address)
            )

            warning_count += 1
            suspicion_score += 5


    if len(risky_ports_found) == 0:

        notes.append(
            "No commonly sensitive listening ports were detected"
        )

    else:

        notes.append(
            "A listening port does not automatically mean the computer is vulnerable"
        )


    if len(listening_ports) > 0:

        notes.append(
            str(len(listening_ports))
            + " listening network endpoints were detected"
        )

    else:

        notes.append(
            "No listening network ports were detected"
        )


    startup_programs = get_startup_programs()


    notes.append(
        str(len(startup_programs))
        + " startup programs were found"
    )


    suspicious_startup_words = [
        "temp\\",
        "\\temp",
        "powershell",
        "cmd.exe",
        "wscript",
        "cscript",
        "mshta"
    ]


    for program in startup_programs:

        command_lower = (
            program["command"]
            .lower()
        )

        suspicious_startup = False

        for word in suspicious_startup_words:

            if word in command_lower:

                suspicious_startup = True
                break


        if suspicious_startup:

            warnings.append(
                "Startup item deserves review: "
                + program["name"]
            )

            warning_count += 1
            suspicion_score += 5


    if suspicion_score > 100:

        suspicion_score = 100


    if suspicion_score >= 60:

        label = "High security risk"
        label_class = "high"

        summary = (
            "Several Windows security settings deserve attention. "
            "Review the warnings before ignoring them."
        )

    elif suspicion_score >= 30:

        label = "Moderate security risk"
        label_class = "medium"

        summary = (
            "Some Windows security settings may need attention."
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
            "No major warning signs were detected by these Windows security checks."
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
        "windows_version": windows_version,
        "last_security_update": last_security_update,
        "listening_ports": listening_ports,
        "startup_programs": startup_programs
    }


if __name__ == "__main__":

    print()
    print("============================================")
    print("PARAKH")
    print("Windows Security Scanner")
    print("============================================")
    print()

    print("Scanning this computer...")
    print()

    result = check_windows()

    print("Device:")
    print(result["device_name"])
    print()

    print("Windows:")
    print(result["windows_version"])
    print()

    print("Latest detected update:")
    print(result["last_security_update"])
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

    print(result["summary"])

    print()
    print(
        "PARAKH only checks security indicators. "
        "A warning does not automatically mean the computer is infected or vulnerable."
    )