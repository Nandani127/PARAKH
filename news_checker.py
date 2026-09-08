import requests
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer

api_key = "AIzaSyD2H8rjNLt9pQcKFbn8fbGeTNPtRHq_OEM"


def check_news(headline):
    suspicion_score = 0
    warning_count = 0
    warnings = []
    notes = []

    headline = headline.strip()
    headline_lower = headline.lower()

    analyzer = SentimentIntensityAnalyzer()
    sentiment = analyzer.polarity_scores(headline)
    compound = sentiment["compound"]

    if compound >= 0.5 or compound <= -0.5:
        notes.append("Strong emotional language detected")
    elif compound >= 0.05 or compound <= -0.05:
        notes.append("Moderate emotional language detected")
    else:
        notes.append("Mostly neutral language detected")

    if "shocking" in headline_lower or "amazing" in headline_lower or "incredible" in headline_lower or "unbelievable" in headline_lower or "miracle" in headline_lower or "secret" in headline_lower or "you won't believe" in headline_lower or "this will change your life" in headline_lower or "life-changing" in headline_lower or "mind-blowing" in headline_lower or "jaw-dropping" in headline_lower or "game-changer" in headline_lower or "revolutionary" in headline_lower or "groundbreaking" in headline_lower or "once-in-a-lifetime" in headline_lower or "unprecedented" in headline_lower or "extraordinary" in headline_lower or "the shocking truth about" in headline_lower:
        warning_count += 1
        suspicion_score += 15
        warnings.append("Sensational language detected (+15)")
    else:
        notes.append("No sensational language detected")

    if "doctors don't want you to know " in headline_lower or "government doesn't want you to know" in headline_lower or "scientists don't want you to know " in headline_lower or "the secret they don't want you to know" in headline_lower or "the truth they don't want you to know" in headline_lower or "mainstream media won't tell you" in headline_lower:
        warning_count += 1
        suspicion_score += 15
        warnings.append("Conspiracy language detected (+15)")
    else:
        notes.append("No conspiracy language detected")

    if "cure" in headline_lower or "miracle cure" in headline_lower or "cure-all" in headline_lower or "instant cure" in headline_lower or "magical solution" in headline_lower or "miracle solution" in headline_lower or "miracle treatment" in headline_lower or "miracle drug" in headline_lower or "miracle pill" in headline_lower:
        warning_count += 1
        suspicion_score += 15
        warnings.append("Miracle cure language detected (+15)")
    else:
        notes.append("No miracle-cure language detected")

    if "watch before it's taken down" in headline_lower or "share this before it's deleted" in headline_lower or "throw this out immediately" in headline_lower or "delete this immediately" in headline_lower or "share this before it's removed" in headline_lower or "watch this before it's taken down" in headline_lower or "share this before it's taken down" in headline_lower or "watch this before it's deleted" in headline_lower or "share this before it's deleted" in headline_lower or "when you this, you already have" in headline_lower:
        warning_count += 1
        suspicion_score += 15
        warnings.append("Urgent action language detected (+15)")
    else:
        notes.append("No urgent-action language detected")

    if "100% guaranteed" in headline_lower or "100 percent guaranteed" in headline_lower or "100% guarantee" in headline_lower or "100 percent guarantee" in headline_lower:
        warning_count += 1
        suspicion_score += 15
        warnings.append("Extreme certainty detected (+15)")
    else:
        notes.append("No extreme-certainty language detected")

    if "according to" in headline_lower or "experts say" in headline_lower or "scientists claim" in headline_lower or "research" in headline_lower or "study" in headline_lower or "scientists" in headline_lower or "says" in headline_lower:
        notes.append("This headline may be based on research or expert opinions. Please verify the sources before sharing.")
    else:
        notes.append("This headline does not mention research or expert opinions. Please verify the source.")

    if headline.count("?") >= 3 or headline.count("!") >= 3:
        warning_count += 1
        suspicion_score += 2.5
        warnings.append("Excessive use of punctuation marks detected (+2.5)")
    else:
        notes.append("Punctuation use looks normal")

    if headline.isupper():
        suspicion_score += 2.5
        warnings.append("All caps detected (+2.5)")
        warning_count += 1
    else:
        notes.append("Headline is not written entirely in capitals")

    url = "https://factchecktools.googleapis.com/v1alpha1/claims:search"

    params = {
        "query": headline,
        "key": api_key
    }

    try:
        response = requests.get(url, params=params, timeout=15)
        data = response.json()

        if "claims" in data and len(data["claims"]) > 0:
            rating = data["claims"][0]["claimReview"][0]["textualRating"]
            source = data["claims"][0]["claimReview"][0]["publisher"]["name"]
            source_url = data["claims"][0]["claimReview"][0]["url"]

            notes.append("Fact-check result found: " + rating + " (" + source + ")")
            notes.append(source_url)

            if rating.lower() == "false":
                warnings.append("This claim has been rated as false (+20)")
                suspicion_score += 20

        else:
            notes.append("No fact-check result found for this headline. Please verify from reliable sources.")

    except requests.RequestException:
        notes.append("Could not reach the fact-check service. Local checks still apply.")

    if suspicion_score > 100:
        suspicion_score = 100

    if warning_count > 0:
        summary = "This headline may be sensationalized or misleading. Please verify the information before sharing."
    else:
        summary = "No warning signs detected. Still verify the information before sharing."

    if suspicion_score >= 70:
        label = "Highly suspicious"
        label_class = "high"
    elif suspicion_score >= 50:
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
        "checked": headline,
    }


if __name__ == "__main__":
    print("============================================")
    print("Parakh")
    print("News Analyser")
    print("============================================")
    print()

    headline = input("Enter a news headline:")
    result = check_news(headline)

    print()

    for note in result["notes"]:
        print(note)

    print()
    print("⚠️  Warning signs detected:")

    for warning in result["warnings"]:
        print(warning)

    print()
    print(result["summary"])
    print("Number of warning signs detected: ", result["warning_count"])
    print("Suspicion Score: ", result["suspicion_score"], "/100")
    print(result["label"])