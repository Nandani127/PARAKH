import json
import os
import requests

from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
from openai import OpenAI


GOOGLE_FACT_CHECK_API_KEY = os.getenv("GOOGLE_API_KEY")

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def search_news_with_openai(headline):

    prompt = """
Search the web for this news headline:

""" + headline + """

Check if reliable websites or news sources support this headline.

Give the answer only in this JSON format:

{
    "status": "supported",
    "reason": "short reason",
    "confidence": 80
}

The status can only be:

supported
partially_supported
unverified
contradicted

Use supported if reliable sources support the news.

Use partially_supported if only some parts of the headline are supported.

Use unverified if there is not enough information to prove or disprove it.

Use contradicted if reliable sources say the headline is wrong.

Do not call something false only because you cannot find information about it.

Confidence should be a number from 0 to 100.
"""

    response = client.responses.create(
        model="gpt-5.6-luna",

        tools=[
            {
                "type": "web_search"
            }
        ],

        input=prompt
    )

    answer = response.output_text

    try:

        result = json.loads(answer)

        return result

    except:

        result = {
            "status": "unverified",
            "reason": "Could not understand the web search answer",
            "confidence": 0
        }

        return result


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

        notes.append(
            "Strong emotional language detected"
        )

    elif compound >= 0.05 or compound <= -0.05:

        notes.append(
            "Moderate emotional language detected"
        )

    else:

        notes.append(
            "Mostly neutral language detected"
        )


    sensational_words = [
        "shocking",
        "amazing",
        "incredible",
        "unbelievable",
        "miracle",
        "secret",
        "you won't believe",
        "this will change your life",
        "life-changing",
        "mind-blowing",
        "jaw-dropping",
        "game-changer",
        "revolutionary",
        "groundbreaking",
        "once-in-a-lifetime",
        "unprecedented",
        "extraordinary",
        "the shocking truth about"
    ]


    sensational_found = False


    for word in sensational_words:

        if word in headline_lower:

            sensational_found = True


    if sensational_found == True:

        warning_count += 1

        suspicion_score += 15

        warnings.append(
            "Sensational language detected (+15)"
        )

    else:

        notes.append(
            "No sensational language detected"
        )


    conspiracy_words = [
        "doctors don't want you to know ",
        "government doesn't want you to know",
        "scientists don't want you to know ",
        "the secret they don't want you to know",
        "the truth they don't want you to know",
        "mainstream media won't tell you"
    ]


    conspiracy_found = False


    for word in conspiracy_words:

        if word in headline_lower:

            conspiracy_found = True


    if conspiracy_found == True:

        warning_count += 1

        suspicion_score += 15

        warnings.append(
            "Conspiracy language detected (+15)"
        )

    else:

        notes.append(
            "No conspiracy language detected"
        )


    cure_words = [
        "cure",
        "miracle cure",
        "cure-all",
        "instant cure",
        "magical solution",
        "miracle solution",
        "miracle treatment",
        "miracle drug",
        "miracle pill"
    ]


    cure_found = False


    for word in cure_words:

        if word in headline_lower:

            cure_found = True


    if cure_found == True:

        warning_count += 1

        suspicion_score += 15

        warnings.append(
            "Miracle cure language detected (+15)"
        )

    else:

        notes.append(
            "No miracle-cure language detected"
        )


    urgent_words = [
        "watch before it's taken down",
        "share this before it's deleted",
        "throw this out immediately",
        "delete this immediately",
        "share this before it's removed",
        "watch this before it's taken down",
        "share this before it's taken down",
        "watch this before it's deleted",
        "share this before it's deleted",
        "when you this, you already have"
    ]


    urgent_found = False


    for word in urgent_words:

        if word in headline_lower:

            urgent_found = True


    if urgent_found == True:

        warning_count += 1

        suspicion_score += 15

        warnings.append(
            "Urgent action language detected (+15)"
        )

    else:

        notes.append(
            "No urgent-action language detected"
        )


    certainty_words = [
        "100% guaranteed",
        "100 percent guaranteed",
        "100% guarantee",
        "100 percent guarantee"
    ]


    certainty_found = False


    for word in certainty_words:

        if word in headline_lower:

            certainty_found = True


    if certainty_found == True:

        warning_count += 1

        suspicion_score += 15

        warnings.append(
            "Extreme certainty detected (+15)"
        )

    else:

        notes.append(
            "No extreme-certainty language detected"
        )


    research_words = [
        "according to",
        "experts say",
        "scientists claim",
        "research",
        "study",
        "scientists",
        "says"
    ]


    research_found = False


    for word in research_words:

        if word in headline_lower:

            research_found = True


    if research_found == True:

        notes.append(
            "This headline mentions research or experts. Check the original source."
        )

    else:

        notes.append(
            "This headline does not mention research or experts. Check the source."
        )


    if headline.count("?") >= 3 or headline.count("!") >= 3:

        warning_count += 1

        suspicion_score += 2.5

        warnings.append(
            "Too many punctuation marks detected (+2.5)"
        )

    else:

        notes.append(
            "Punctuation use looks normal"
        )


    if headline.isupper():

        suspicion_score += 2.5

        warning_count += 1

        warnings.append(
            "All caps detected (+2.5)"
        )

    else:

        notes.append(
            "Headline is not written fully in capitals"
        )


    url = "https://factchecktools.googleapis.com/v1alpha1/claims:search"


    params = {
        "query": headline,
        "key": GOOGLE_FACT_CHECK_API_KEY
    }


    try:

        response = requests.get(
            url,
            params=params,
            timeout=15
        )


        data = response.json()


        if "claims" in data and len(data["claims"]) > 0:

            claim = data["claims"][0]

            review = claim["claimReview"][0]

            rating = review["textualRating"]

            source = review["publisher"]["name"]

            source_url = review["url"]


            notes.append(
                "Fact check found: "
                + rating
                + " ("
                + source
                + ")"
            )


            notes.append(
                source_url
            )


            if rating.lower() == "false":

                warnings.append(
                    "This claim was rated false (+20)"
                )

                suspicion_score += 20


        else:

            notes.append(
                "No Google fact check was found for this headline."
            )


    except requests.RequestException:

        notes.append(
            "Google Fact Check could not be reached."
        )


    try:

        ai_result = search_news_with_openai(headline)


        ai_status = ai_result["status"]

        ai_reason = ai_result["reason"]

        ai_confidence = ai_result["confidence"]


        if ai_status == "supported":

            notes.append(
                "Web search found reliable support for this headline."
            )

            notes.append(
                "Web search: " + ai_reason
            )


        elif ai_status == "partially_supported":

            warnings.append(
                "Only part of this headline is supported (+10)"
            )

            warning_count += 1

            suspicion_score += 10

            notes.append(
                "Web search: " + ai_reason
            )


        elif ai_status == "unverified":

            warnings.append(
                "Not enough reliable information was found (+20)"
            )

            warning_count += 1

            suspicion_score += 35

            notes.append(
                "Web search: " + ai_reason
            )


        elif ai_status == "contradicted":

            warnings.append(
                "Reliable sources disagree with this headline (+35)"
            )

            warning_count += 1

            suspicion_score += 35

            notes.append(
                "Web search: " + ai_reason
            )


        notes.append(
            "Web search confidence: "
            + str(ai_confidence)
            + "%"
        )


    except Exception as error:

        print(
            "Web search error:",
            error
        )

        notes.append(
            "Web search could not be completed."
        )


    if suspicion_score > 100:

        suspicion_score = 100


    if warning_count > 0:

        summary = "This headline may be misleading. Please check it before sharing."

    else:

        summary = "No warning signs detected. Still check the information before sharing."


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

        "checked": headline
    }


if __name__ == "__main__":

    print("============================================")

    print("PARAKH")

    print("News Analyser")

    print("============================================")

    print()


    headline = input(
        "Enter a news headline: "
    )


    result = check_news(headline)


    print()


    for note in result["notes"]:

        print(note)


    print()

    print(
        "Warning signs detected:"
    )

    print()


    for warning in result["warnings"]:

        print(warning)


    print()

    print(result["summary"])

    print()


    print(
        "Number of warning signs detected:",
        result["warning_count"]
    )


    print(
        "Suspicion Score:",
        result["suspicion_score"],
        "/100"
    )


    print(
        result["label"]
    )