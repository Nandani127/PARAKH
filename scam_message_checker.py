import re
import base64
import requests
import phonenumbers

from urlextract import URLExtract
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer

api_key = "320561f62938f08b527007b07dd9bec58707bc45e3a36c9d63fbeda23734ac55"


def check_message(message):
    suspicion_score = 0
    warning_count = 0
    warnings = []
    notes = []

    message = message.strip()
    message_lower = message.lower()

    analyzer = SentimentIntensityAnalyzer()

    sentiment = analyzer.polarity_scores(message)

    compound = sentiment["compound"]

    if compound <= -0.5:

        notes.append(
            "Language tone: strong negative / fear-based language detected"
        )

    elif compound >= 0.5:

        notes.append(
            "Language tone: strong emotional / exciting language detected"
        )

    elif compound <= -0.05 or compound >= 0.05:

        notes.append(
            "Language tone: moderate emotional language detected"
        )

    else:

        notes.append(
            "Language tone: mostly neutral language detected"
        )

    urgency_words = [
        "immediately",
        "urgent",
        "hurry",
        "last chance",
        "limited time",
        "act now",
        "expire",
        "expires",
        "within 24 hours",
        "within 12 hours",
        "today only",
        "final warning",
        "last warning",
        "account will be blocked",
        "account blocked",
        "account suspended",
        "will be closed",
        "jaldi",
        "turant",
        "abhi",
        "last date"
    ]

    found_urgency = []

    for word in urgency_words:

        if word in message_lower:
            found_urgency.append(word)

    if found_urgency:

        warnings.append(
            "Urgency language detected (+15): "
            + ", ".join(found_urgency)
        )

        suspicion_score += 15
        warning_count += 1

    else:

        notes.append(
            "No urgency language detected"
        )

    threat_words = [
        "fir",
        "arrest",
        "arrested",
        "police",
        "cyber cell",
        "legal action",
        "court",
        "jail",
        "frozen",
        "penalty",
        "fine",
        "warrant",
        "income tax notice",
        "enforcement",
        "cid",
        "cbi"
    ]

    found_threats = []

    for word in threat_words:

        if word in message_lower:
            found_threats.append(word)

    if found_threats:

        warnings.append(
            "Threat / legal pressure language detected (+20): "
            + ", ".join(found_threats)
        )

        suspicion_score += 20
        warning_count += 1

    else:

        notes.append(
            "No threat or legal-pressure language detected"
        )

    sensitive_words = [
        "otp",
        "pin",
        "cvv",
        "aadhaar",
        "aadhar",
        "pan card",
        "pan number",
        "password",
        "atm pin",
        "net banking",
        "share otp",
        "send otp",
        "verify otp",
        "card number",
        "cvv number"
    ]

    found_sensitive = []

    for word in sensitive_words:

        if word in message_lower:
            found_sensitive.append(word)

    if found_sensitive:

        warnings.append(
            "Request for sensitive details detected (+25): "
            + ", ".join(found_sensitive)
        )

        suspicion_score += 25
        warning_count += 1

    else:

        notes.append(
            "No request for sensitive details detected"
        )

    prize_words = [
        "you have won",
        "you won",
        "lucky winner",
        "lottery",
        "jackpot",
        "congratulations you",
        "prize money",
        "reward points",
        "selected winner",
        "kbc",
        "lucky draw",
        "jeet gaye",
        "aap jeete",
        "cash prize"
    ]

    found_prizes = []

    for word in prize_words:

        if word in message_lower:
            found_prizes.append(word)

    if found_prizes:

        warnings.append(
            "Prize / lottery language detected (+15): "
            + ", ".join(found_prizes)
        )

        suspicion_score += 15
        warning_count += 1

    else:

        notes.append(
            "No prize or lottery language detected"
        )

    payment_words = [
        "upi",
        "send money",
        "transfer money",
        "pay now",
        "paytm",
        "phonepe",
        "google pay",
        "gpay",
        "g pay",
        "bank account",
        "ifsc",
        "qr code",
        "scan and pay",
        "paisa bhejo",
        "payment pending",
        "processing fee",
        "registration fee",
        "refund fee"
    ]

    found_payments = []

    for word in payment_words:

        if word in message_lower:
            found_payments.append(word)

    if found_payments:

        warnings.append(
            "Payment / money request detected (+20): "
            + ", ".join(found_payments)
        )

        suspicion_score += 20
        warning_count += 1

    else:

        notes.append(
            "No payment or money request detected"
        )

    kyc_words = [
        "kyc",
        "update kyc",
        "kyc pending",
        "kyc expired",
        "verify account",
        "update your account",
        "aadhaar linking",
        "re-kyc",
        "rekyc",
        "account verification"
    ]

    found_kyc = []

    for word in kyc_words:

        if word in message_lower:
            found_kyc.append(word)

    if found_kyc:

        warnings.append(
            "KYC / account-update language detected (+15): "
            + ", ".join(found_kyc)
        )

        suspicion_score += 15
        warning_count += 1

    else:

        notes.append(
            "No KYC or account-update language detected"
        )

    govt_words = [
        "income tax",
        "electricity bill",
        "lpg subsidy",
        "pm kisan",
        "pm-kisan",
        "ayushman",
        "epfo",
        "gst notice",
        "ration card",
        "gas subsidy",
        "e-shram",
        "uidai"
    ]

    found_govt = []

    for word in govt_words:

        if word in message_lower:
            found_govt.append(word)

    if found_govt:

        warnings.append(
            "Government / utility impersonation language detected (+15): "
            + ", ".join(found_govt)
        )

        suspicion_score += 15
        warning_count += 1

    else:

        notes.append(
            "No government or utility impersonation language detected"
        )

    job_words = [
        "work from home",
        "part time job",
        "earn from home",
        "earn lakhs",
        "data entry job",
        "registration fee",
        "joining fee",
        "home based job"
    ]

    found_jobs = []

    for word in job_words:

        if word in message_lower:
            found_jobs.append(word)

    if found_jobs:

        warnings.append(
            "Job / work-from-home scam language detected (+10): "
            + ", ".join(found_jobs)
        )

        suspicion_score += 10
        warning_count += 1

    else:

        notes.append(
            "No job or work-from-home scam language detected"
        )

    delivery_words = [
        "courier",
        "parcel",
        "customs duty",
        "delivery failed",
        "pending delivery",
        "package held",
        "consignment"
    ]

    found_delivery = []

    for word in delivery_words:

        if word in message_lower:
            found_delivery.append(word)

    if found_delivery:

        warnings.append(
            "Courier / parcel scam language detected (+10): "
            + ", ".join(found_delivery)
        )

        suspicion_score += 10
        warning_count += 1

    else:

        notes.append(
            "No courier or parcel scam language detected"
        )

    if message.count("!") >= 3 or message.count("?") >= 3:

        warnings.append(
            "Excessive punctuation detected (+5)"
        )

        suspicion_score += 5
        warning_count += 1

    else:

        notes.append(
            "Punctuation use looks normal"
        )

    letters_only = "".join(
        ch for ch in message if ch.isalpha()
    )

    if len(letters_only) >= 8 and message.isupper():

        warnings.append(
            "Entire message is in CAPS (+5)"
        )

        suspicion_score += 5
        warning_count += 1

    else:

        notes.append(
            "Message is not written entirely in capitals"
        )

    indian_numbers = 0
    foreign_numbers = 0

    for match in phonenumbers.PhoneNumberMatcher(
        message,
        "IN"
    ):

        number = match.number

        formatted = phonenumbers.format_number(
            number,
            phonenumbers.PhoneNumberFormat.INTERNATIONAL
        )

        region = phonenumbers.region_code_for_number(
            number
        )

        if region == "IN":

            indian_numbers += 1

            notes.append(
                "Indian number found: "
                + formatted
            )

        else:

            foreign_numbers += 1

            notes.append(
                "Non-Indian number found: "
                + formatted
                + " (region: "
                + str(region)
                + ")"
            )

    if foreign_numbers > 0:

        warnings.append(
            "Foreign phone number in an India-targeted message (+15)"
        )

        suspicion_score += 15
        warning_count += 1

    elif indian_numbers > 0:

        notes.append(
            "Indian number found. Still do not call unknown numbers from unexpected messages."
        )

    else:

        notes.append(
            "No clear phone number found."
        )

    extractor = URLExtract()

    urls = extractor.find_urls(message)

    if not urls:

        notes.append(
            "No links found in the message."
        )

    else:

        notes.append(
            "Links found: "
            + str(len(urls))
        )

        for url in urls:

            notes.append(
                "Checking: "
                + url
            )

            if "://" not in url:

                url_for_check = "https://" + url

            else:

                url_for_check = url

            if url.startswith("http://"):

                warnings.append(
                    "Link uses HTTP instead of HTTPS (+10)"
                )

                suspicion_score += 10
                warning_count += 1

            else:

                notes.append(
                    "Link does not explicitly use HTTP"
                )

            if re.search(
                r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
                url
            ):

                warnings.append(
                    "IP address used instead of a normal website name (+15)"
                )

                suspicion_score += 15
                warning_count += 1

            else:

                notes.append(
                    "Link does not use an IP address"
                )

            short_link_sites = [
                "bit.ly",
                "tinyurl",
                "t.co",
                "rb.gy",
                "cutt.ly"
            ]

            short_link_found = False

            for site in short_link_sites:

                if site in url.lower():

                    short_link_found = True

                    warnings.append(
                        "Shortened link detected (+10): "
                        + site
                    )

                    suspicion_score += 10
                    warning_count += 1

            if not short_link_found:

                notes.append(
                    "Link is not from a known URL shortener"
                )

            suspicious_tlds = [
                ".tk",
                ".top",
                ".xyz",
                ".click",
                ".zip",
                ".mov",
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
                        "Suspicious website ending detected (+10): "
                        + tld
                    )

                    suspicion_score += 10
                    warning_count += 1

            if not suspicious_tld_found:

                notes.append(
                    "Link does not use a suspicious website ending"
                )

            url_id = base64.urlsafe_b64encode(
                url_for_check.encode()
            ).decode().strip("=")

            vt_url = (
                "https://www.virustotal.com/api/v3/urls/"
                + url_id
            )

            headers = {
                "x-apikey": api_key
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

                    stats = data[
                        "data"
                    ][
                        "attributes"
                    ][
                        "last_analysis_stats"
                    ]

                    malicious = stats["malicious"]

                    suspicious = stats["suspicious"]

                    notes.append(
                        "Malicious engines: "
                        + str(malicious)
                        + ", suspicious engines: "
                        + str(suspicious)
                    )

                    if malicious >= 3:

                        warnings.append(
                            "Several security engines marked this link as malicious (+30)"
                        )

                        suspicion_score += 30
                        warning_count += 1

                    elif malicious >= 1:

                        warnings.append(
                            "At least one security engine marked this link as malicious (+15)"
                        )

                        suspicion_score += 15
                        warning_count += 1

                    elif suspicious >= 1:

                        warnings.append(
                            "VirusTotal marked this link as suspicious (+10)"
                        )

                        suspicion_score += 10
                        warning_count += 1

                    else:

                        notes.append(
                            "VirusTotal did not mark this link as malicious"
                        )

                else:

                    notes.append(
                        "VirusTotal has no ready report for this link."
                    )

            except requests.RequestException:

                notes.append(
                    "Could not reach VirusTotal. Local checks still apply."
                )

    if suspicion_score > 100:
        suspicion_score = 100

    if warning_count == 0:

        summary = "No warning signs detected. Still be careful with unexpected messages."

    else:

        summary = "Warning signs were found. Do not share OTP, PIN, or money from this message."

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
        "checked": message,
    }


if __name__ == "__main__":

    print("=================================")
    print("PARAKH")
    print("Scam Message Checker")
    print("=================================")

    print()

    message = input(
        "Enter the message you want to check:\n"
    )

    result = check_message(message)

    print()

    print("Message you entered:")

    print(result["checked"])

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
        "Number of warning signs detected:",
        result["warning_count"]
    )

    print(
        "Suspicion Score:",
        result["suspicion_score"],
        "/100"
    )

    print(result["label"])