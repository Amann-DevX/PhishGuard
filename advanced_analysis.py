import re
import ipaddress
from urllib.parse import urlparse


# ============================================================
# SUSPICIOUS TLDs
# ============================================================

SUSPICIOUS_TLDS = {
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".top",
    ".xyz",
    ".click",
    ".download",
    ".zip",
    ".review",
    ".country",
    ".stream",
    ".win"
}


# ============================================================
# SUSPICIOUS KEYWORDS
# ============================================================

SUSPICIOUS_WORDS = {

    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "update",
    "secure",
    "security",
    "password",
    "credential",
    "confirm",
    "confirmation",
    "bank",
    "payment",
    "wallet",
    "recover",
    "suspended",
    "unlock",
    "billing",
    "invoice",
    "authenticate"
}


# ============================================================
# URL ANALYSIS
# ============================================================

def analyze_advanced_url(url):

    result = {

        "suspicious_tld": False,

        "tld": "",

        "ip_based": False,

        "excessive_subdomains": False,

        "subdomain_count": 0,

        "suspicious_keywords": [],

        "keyword_count": 0,

        "has_at_symbol": False,

        "has_port": False,

        "long_url": False,

        "url_length": len(url),

        "encoded_characters": 0,

        "hyphen_count": 0,

        "digit_count": 0,

        "risk_points": [],

        "risk_score": 0

    }


    try:

        parsed = urlparse(url)

        hostname = parsed.hostname or ""


        # ----------------------------------------------------
        # TLD
        # ----------------------------------------------------

        parts = hostname.split(".")

        if len(parts) >= 2:

            tld = "." + parts[-1].lower()

            result["tld"] = tld

            if tld in SUSPICIOUS_TLDS:

                result["suspicious_tld"] = True

                result["risk_points"].append(
                    "Suspicious top-level domain"
                )

                result["risk_score"] += 15


        # ----------------------------------------------------
        # IP ADDRESS
        # ----------------------------------------------------

        try:

            ipaddress.ip_address(
                hostname
            )

            result["ip_based"] = True

            result["risk_points"].append(
                "URL uses an IP address instead of a domain"
            )

            result["risk_score"] += 20

        except ValueError:

            pass


        # ----------------------------------------------------
        # SUBDOMAINS
        # ----------------------------------------------------

        if len(parts) > 2:

            result["subdomain_count"] = (
                len(parts) - 2
            )


        if result["subdomain_count"] >= 4:

            result["excessive_subdomains"] = True

            result["risk_points"].append(
                "Excessive number of subdomains"
            )

            result["risk_score"] += 15


        # ----------------------------------------------------
        # SUSPICIOUS WORDS
        # ----------------------------------------------------

        url_lower = url.lower()

        found_words = []


        for word in SUSPICIOUS_WORDS:

            if word in url_lower:

                found_words.append(
                    word
                )


        result["suspicious_keywords"] = (
            sorted(found_words)
        )

        result["keyword_count"] = (
            len(found_words)
        )


        if len(found_words) >= 3:

            result["risk_points"].append(
                "Multiple phishing-related keywords detected"
            )

            result["risk_score"] += 20

        elif len(found_words) > 0:

            result["risk_points"].append(
                "Suspicious security-related keywords detected"
            )

            result["risk_score"] += 5


        # ----------------------------------------------------
        # @ SYMBOL
        # ----------------------------------------------------

        if "@" in url:

            result["has_at_symbol"] = True

            result["risk_points"].append(
                "URL contains @ symbol"
            )

            result["risk_score"] += 15


        # ----------------------------------------------------
        # PORT
        # ----------------------------------------------------

        if parsed.port:

            result["has_port"] = True

            result["risk_points"].append(
                "Non-standard URL port detected"
            )

            result["risk_score"] += 10


        # ----------------------------------------------------
        # LONG URL
        # ----------------------------------------------------

        if len(url) > 150:

            result["long_url"] = True

            result["risk_points"].append(
                "Unusually long URL"
            )

            result["risk_score"] += 10


        # ----------------------------------------------------
        # ENCODED CHARACTERS
        # ----------------------------------------------------

        encoded_count = len(
            re.findall(
                r"%[0-9a-fA-F]{2}",
                url
            )
        )


        result["encoded_characters"] = (
            encoded_count
        )


        if encoded_count >= 5:

            result["risk_points"].append(
                "Large number of encoded characters"
            )

            result["risk_score"] += 10


        # ----------------------------------------------------
        # HYPHENS
        # ----------------------------------------------------

        hyphen_count = hostname.count("-")

        result["hyphen_count"] = (
            hyphen_count
        )


        if hyphen_count >= 3:

            result["risk_points"].append(
                "Multiple hyphens in domain"
            )

            result["risk_score"] += 10


        # ----------------------------------------------------
        # DIGITS
        # ----------------------------------------------------

        digit_count = sum(
            char.isdigit()
            for char in hostname
        )

        result["digit_count"] = (
            digit_count
        )


        if digit_count >= 5:

            result["risk_points"].append(
                "Large number of digits in domain"
            )

            result["risk_score"] += 10


    except Exception as e:

        result["error"] = str(e)


    # --------------------------------------------------------
    # LIMIT SCORE
    # --------------------------------------------------------

    result["risk_score"] = min(
        result["risk_score"],
        100
    )


    return result