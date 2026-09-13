def how_different(word1, word2):

    word1 = word1.lower()

    word2 = word2.lower()

    length_difference = abs(
        len(word1) - len(word2)
    )

    if length_difference > 2:

        return 99

    rows = []

    for i in range(len(word1) + 1):

        row = []

        for j in range(len(word2) + 1):

            row.append(0)

        rows.append(row)

    for i in range(len(word1) + 1):

        rows[i][0] = i

    for j in range(len(word2) + 1):

        rows[0][j] = j

    for i in range(1, len(word1) + 1):

        for j in range(1, len(word2) + 1):

            if word1[i - 1] == word2[j - 1]:

                same = 0

            else:

                same = 1

            rows[i][j] = min(
                rows[i - 1][j] + 1,
                rows[i][j - 1] + 1,
                rows[i - 1][j - 1] + same
            )

    return rows[len(word1)][len(word2)]


def check_upi(upi_id):

    suspicion_score = 0

    warning_count = 0

    warnings = []

    notes = []

    upi_id = upi_id.strip()

    if "@" in upi_id:

        parts = upi_id.split("@")

        name_part = parts[0].strip()

        domain_part = parts[1].strip()

        if name_part == "" or domain_part == "":

            warnings.append(
                "Name or handle is empty"
            )

            warning_count += 1

        else:

            notes.append(
                "Name and handle are present"
            )

        if upi_id.count("@") > 1:

            warnings.append(
                "There is more than one @ in the UPI ID"
            )

            warning_count += 1

            suspicion_score += 60

        else:

            notes.append(
                "Single @ symbol"
            )

        if " " in upi_id:

            warnings.append(
                "There is a space in the UPI ID"
            )

            warning_count += 1

            suspicion_score += 10

        else:

            notes.append(
                "No spaces in the UPI ID"
            )

        extra_punctuation = [
            "!",
            "#",
            "$",
            "%",
            "^",
            "&",
            "*",
            "(",
            ")",
            "+",
            "=",
            "/",
            ",",
            "?",
            "'",
            '"',
            ";",
            ":",
            "~",
            "`"
        ]

        found_punctuation = []

        for letter in upi_id:

            if letter in extra_punctuation:

                if letter not in found_punctuation:

                    found_punctuation.append(
                        letter
                    )

        if found_punctuation:

            warnings.append(
                "Extra punctuation found in the UPI ID: "
                + ", ".join(found_punctuation)
            )

            warning_count += 1

            suspicion_score += 15

        else:

            notes.append(
                "No extra punctuation found"
            )

        punctuation_count = 0

        for letter in name_part:

            if letter == "." or letter == "-":

                punctuation_count += 1

        if punctuation_count > 2:

            warnings.append(
                "Excessive punctuation in the name"
            )

            warning_count += 1

            suspicion_score += 10

        else:

            notes.append(
                "Name punctuation looks normal"
            )

        known_handles = [
            "oksbi",
            "okicici",
            "okaxis",
            "okhdfcbank",
            "okbizaxis",
            "ybl",
            "ibl",
            "axl",
            "paytm",
            "ptaxis",
            "pthdfc",
            "pticici",
            "ptkotak",
            "ptsbi",
            "ptyes",
            "upi",
            "bhim",
            "apl",
            "rapl",
            "yapl",
            "wa",
            "waicici",
            "waaxis",
            "wahdfcbank",
            "wasbi",
            "sbi",
            "icici",
            "hdfcbank",
            "axisbank",
            "kotak",
            "pnb",
            "pnbpay",
            "barodampay",
            "bob",
            "canarabank",
            "cnrb",
            "indianbank",
            "allbank",
            "unionbank",
            "uboi",
            "federal",
            "idbi",
            "idfc",
            "idfcfirst",
            "idfcbank",
            "indus",
            "indie",
            "iob",
            "uco",
            "aubank",
            "bandhan",
            "dlb",
            "dbs",
            "hsbc",
            "citi",
            "citigold",
            "cub",
            "rbl",
            "jkb",
            "kbl",
            "kvb",
            "mahb",
            "scb",
            "cboi",
            "sib",
            "equitas",
            "fino",
            "finopay",
            "finobank",
            "airtel",
            "jio",
            "ippb",
            "postpay",
            "nsdl",
            "sbmpay",
            "freecharge",
            "ikwik",
            "jupiteraxis",
            "abfspay",
            "yesg",
            "inhdfc",
            "credpay",
            "axisb",
            "fi",
            "fibr",
            "lime",
            "niyoicici",
            "slice",
            "sliceaxis",
            "superyes",
            "tapicici",
            "yesbank",
            "yespaychota",
            "fkaxis",
            "zoicici",
            "pz"
        ]

        if domain_part != "":

            domain_lower = domain_part.lower()

            if domain_lower not in known_handles:

                lookalike_found = False

                lookalike_handle = ""

                for handle in known_handles:

                    difference = how_different(
                        domain_lower,
                        handle
                    )

                    if difference >= 1 and difference <= 2:

                        lookalike_found = True

                        lookalike_handle = handle

                        break

                if lookalike_found:

                    warnings.append(
                        "This handle looks similar to a real one: "
                        + lookalike_handle
                    )

                    warning_count += 1

                    suspicion_score += 60

                else:

                    warnings.append(
                        "Unknown domain: "
                        + domain_part
                    )

                    warning_count += 1

                    suspicion_score += 50

            else:

                notes.append(
                    "Known UPI handle: @"
                    + domain_part
                )

        name_lower = name_part.lower()

        scam_words = [
            "kyc",
            "refund",
            "verify",
            "prize",
            "official",
            "support",
            "helpdesk",
            "rbi-support",
            "sbi",
            "hdfc",
            "icici",
            "sbi",
            "rbi"
        ]

        found_scam_words = []

        for word in scam_words:

            if word in name_lower:

                found_scam_words.append(
                    word
                )

        if found_scam_words:

            warnings.append(
                "Scam words found in name: "
                + ", ".join(found_scam_words)
            )

            warning_count += 1

            suspicion_score += 45

        else:

            notes.append(
                "No suspicious words found in name"
            )

    else:

        warnings.append(
            "This is not a valid UPI ID. Please enter a valid UPI ID."
        )

        warning_count += 1

    if suspicion_score > 100:

        suspicion_score = 100

    if suspicion_score >= 50:

        summary = "This UPI ID may be a scam. Please verify before paying."

    elif warning_count > 0:

        summary = "Some warning signs were found. Please check before paying."

    else:

        summary = "No warning signs detected. Still check who you are paying."

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
        "checked": upi_id
    }


if __name__ == "__main__":

    print("====================================")
    print("PARAKH")
    print("UPI ID Checker")
    print("====================================")

    upi_id = input(
        "Enter a UPI ID: "
    )

    result = check_upi(
        upi_id
    )

    print()

    print(
        "The ID you entered:"
    )

    print(
        result["checked"]
    )

    print()

    print(
        "⚠️  Warning signs found: "
    )

    print()

    if result["warnings"]:

        for warning in result["warnings"]:

            print(
                "⚠️  " + warning
            )

    else:

        print(
            "No warning signs detected. Still check who you are paying."
        )

    print()

    print(
        result["summary"]
    )

    print()

    print(
        "Number of warning signs detected: ",
        result["warning_count"]
    )

    print()

    print(
        "Suspicion score: ",
        result["suspicion_score"],
        "/100"
    )

    print()

    print(
        result["label"]
    )