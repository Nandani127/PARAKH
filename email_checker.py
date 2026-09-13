from email.utils import parseaddr
from scam_message_checker import check_message


def check_email(sender, subject, body):

    suspicion_score = 0
    warning_count = 0
    warnings = []
    notes = []

    sender = sender.strip()
    subject = subject.strip()
    body = body.strip()

    display_name, email_address = parseaddr(sender)

    if email_address == "":

        warnings.append("Could not find a proper sender email address")
        warning_count += 1
        suspicion_score += 25

    elif "@" not in email_address:

        warnings.append("Sender email address does not look valid")
        warning_count += 1
        suspicion_score += 25

    else:

        parts = email_address.split("@")
        sender_name = parts[0].lower()
        sender_domain = parts[-1].lower()

        notes.append("Sender domain: " + sender_domain)

        free_email_domains = [
            "gmail.com",
            "yahoo.com",
            "outlook.com",
            "hotmail.com",
            "icloud.com",
            "protonmail.com",
            "proton.me"
        ]

        suspicious_tlds = [
            ".xyz",
            ".top",
            ".click",
            ".zip",
            ".work",
            ".buzz",
            ".tk",
            ".gq",
            ".ml",
            ".cf"
        ]

        suspicious_tld_found = False

        for tld in suspicious_tlds:

            if sender_domain.endswith(tld):

                suspicious_tld_found = True
                break

        if suspicious_tld_found:

            warnings.append("Sender uses a suspicious-looking domain ending")
            warning_count += 1
            suspicion_score += 10

        else:

            notes.append("Sender domain ending does not match the suspicious list")

        brand_words = [
            "paypal",
            "amazon",
            "google",
            "microsoft",
            "apple",
            "netflix",
            "instagram",
            "facebook",
            "whatsapp",
            "sbi",
            "hdfc",
            "icici",
            "axis",
            "paytm",
            "phonepe",
            "rbi"
        ]

        sender_identity = sender_name + " " + display_name.lower()
        brand_found = ""

        for brand in brand_words:

            if brand in sender_identity:

                brand_found = brand
                break

        if brand_found != "":

            notes.append("Brand name found in sender: " + brand_found)

            if sender_domain in free_email_domains:

                warnings.append(
                    "Sender claims to be "
                    + brand_found
                    + " but is using a free email service"
                )

                warning_count += 1
                suspicion_score += 20

        if sender_domain in free_email_domains:

            notes.append("Sender is using a free email service")

        if sender_domain.count("-") >= 3:

            warnings.append("Sender domain contains many hyphens")
            warning_count += 1
            suspicion_score += 5

        else:

            notes.append("Sender domain does not contain excessive hyphens")

    email_text = subject + "\n" + body

    message_result = check_message(email_text)

    for warning in message_result.get("warnings", []):
        warnings.append(warning)

    for note in message_result.get("notes", []):
        notes.append(note)

    suspicion_score += message_result.get("suspicion_score", 0)
    warning_count += message_result.get("warning_count", 0)

    if subject == "":
        notes.append("Email has no subject")
    else:
        notes.append("Email subject is present")

    if body == "":

        warnings.append("Email body is empty")
        warning_count += 1

    else:

        notes.append("Email body is present")

    if suspicion_score > 100:
        suspicion_score = 100

    if warning_count == 0:

        summary = "No major warning signs detected. Still be careful with unexpected emails."

    elif suspicion_score >= 55:

        summary = "This email contains several suspicious signs. Do not click links or share personal information without verifying the sender."

    else:

        summary = "Some warning signs were found. Check the sender and content carefully."

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
        "checked": sender,
        "sender": sender,
        "subject": subject,
        "body": body
    }
