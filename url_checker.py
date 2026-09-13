import re
import base64
import requests
import os

VIRUS_TOTAL_API_KEY = os.getenv("VIRUS_TOTAL_API_KEY")


def check_url(url):
    suspicion_score = 0
    warning_count = 0
    warnings = []
    notes = []

    url = url.strip()

    if "://" not in url:
        url_for_check = "https://" + url
    else:
        url_for_check = url

    encoded_url = url_for_check.encode()

    url_id = base64.urlsafe_b64encode(encoded_url).decode()

    url_id = url_id.strip("=")

    vt_url = "https://www.virustotal.com/api/v3/urls/" + url_id

    headers = {
        "x-apikey": VIRUS_TOTAL_API_KEY
    }

    try:

        response = requests.get(
            vt_url,
            headers=headers,
            timeout=15
        )

        notes.append(
            "VirusTotal status: "
            + str(response.status_code)
        )

        if response.status_code == 200:

            data = response.json()

            data_part = data["data"]

            attributes = data_part["attributes"]

            stats = attributes["last_analysis_stats"]

            malicious = stats["malicious"]

            suspicious = stats["suspicious"]

            harmless = stats["harmless"]

            undetected = stats["undetected"]

            notes.append(
                "VirusTotal — malicious: "
                + str(malicious)
                + ", suspicious: "
                + str(suspicious)
                + ", harmless: "
                + str(harmless)
                + ", undetected: "
                + str(undetected)
            )

            if malicious > 0:

                if malicious >= 6:

                    suspicion_score += 40

                    warnings.append(
                        "Multiple security engines detected this URL as malicious (+40)"
                    )

                    warning_count += 1

                elif malicious >= 3:

                    suspicion_score += 30

                    warnings.append(
                        "Several security engines detected this URL as malicious (+30)"
                    )

                    warning_count += 1

                elif malicious >= 2:

                    suspicion_score += 10

                    warnings.append(
                        "More than one security engine detected this URL as malicious (+10)"
                    )

                    warning_count += 1

                elif malicious == 1:

                    notes.append(
                        "One security engine flagged this URL, possibly a false positive"
                    )

            elif suspicious > 0:

                warnings.append(
                    "VirusTotal detected suspicious engines: "
                    + str(suspicious)
                )

                if suspicious >= 5:

                    suspicion_score += 25

                elif suspicious >= 2:

                    suspicion_score += 15

                else:

                    suspicion_score += 10

                warning_count += 1

            else:

                notes.append(
                    "VirusTotal detected no malicious or suspicious engines"
                )

        else:

            notes.append(
                "VirusTotal could not find a report for this URL."
            )

    except requests.RequestException:

        notes.append(
            "Could not reach VirusTotal. Local checks still apply."
        )

    if url.startswith("http://"):

        warnings.append(
            "URL explicitly uses HTTP instead of HTTPS (+10)"
        )

        suspicion_score += 10

        warning_count += 1

    else:

        notes.append(
            "URL does not explicitly use HTTP"
        )

    if len(url) > 75:

        warnings.append(
            "The URL is unusually long (+15)"
        )

        suspicion_score += 15

        warning_count += 1

    else:

        notes.append(
            "URL length looks normal"
        )

    if re.search(
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        url
    ):

        warnings.append(
            "IP address detected in URL (+15)"
        )

        suspicion_score += 15

        warning_count += 1

    else:

        notes.append(
            "No IP address detected in URL"
        )

    suspicous_words = [
        "login",
        "password",
        "secure",
        "verify",
        "account",
        "update",
        "KYC",
        "kyc"
    ]

    suspicious_word_found = False

    for word in suspicous_words:

        if word in url.lower():

            suspicious_word_found = True

            warnings.append(
                "Suspicious word detected (+10): "
                + word
            )

            suspicion_score += 10

            warning_count += 1

    if not suspicious_word_found:

        notes.append(
            "No suspicious words detected in URL"
        )

    special_chars = [
        "@",
        "%",
        "=",
        "&"
    ]

    suspicious_char_found = False

    for char in special_chars:

        if char in url:

            suspicious_char_found = True

            warnings.append(
                "Suspicious special characters detected (+5): "
                + char
            )

            suspicion_score += 5

            warning_count += 1

    if not suspicious_char_found:

        notes.append(
            "No suspicious special characters detected"
        )

    suspicious_tlds = [
        ".tk",
        ".top",
        ".xyz",
        ".click",
        ".zip",
        ".mov",
        ".work",
        ".buzz",
        ".gq",
        ".ml",
        ".ga",
        ".cf"
    ]

    suspicious_tld_found = False

    for tld in suspicious_tlds:

        if tld in url.lower():

            suspicious_tld_found = True

            warnings.append(
                "Suspicious TLD detected (+7.5): "
                + tld
            )

            suspicion_score += 7.5

            warning_count += 1

    if not suspicious_tld_found:

        notes.append(
            "No suspicious TLD detected"
        )

    parts = url_for_check.split("/")

    if len(parts) > 2:

        domain = parts[2]

        subdomains = domain.split(".")

        if len(subdomains) > 3:

            warnings.append(
                "Multiple subdomains detected (+10)"
            )

            suspicion_score += 10

            warning_count += 1

        else:

            notes.append(
                "Subdomain count looks normal"
            )

    if suspicion_score > 100:

        suspicion_score = 100

    if warning_count == 0:

        summary = "No warning signs detected"

    else:

        summary = "Warning signs were found. Check the site before entering any details."

    if suspicion_score >= 75:

        label = "Highly suspicious"

        label_class = "high"

    elif suspicion_score >= 55:

        label = "High suspicion"

        label_class = "medium"

    elif suspicion_score >= 35:

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
        "checked": url,
    }


if __name__ == "__main__":

    print("=================================")
    print("PARAKH")
    print("URL checker")
    print("================================")

    print()

    url = input("Enter a URL: ")

    result = check_url(url)

    print()

    print(
        "URL you entered: ",
        result["checked"]
    )

    print()

    for note in result["notes"]:

        print(note)

    print()

    print("⚠️  Warning signs detected:")

    print()

    for warning in result["warnings"]:

        print("⚠️  " + warning)

    print()

    print(result["summary"])

    print(
        "Number of warning signs detected: ",
        result["warning_count"]
    )

    print(
        "Suspicion Score: ",
        result["suspicion_score"],
        "/100"
    )

    print(result["label"])