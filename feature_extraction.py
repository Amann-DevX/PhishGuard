import re
import math
from urllib.parse import urlparse


SUSPICIOUS_WORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "update",
    "secure",
    "security",
    "confirm",
    "password",
    "bank",
    "payment",
    "wallet",
    "credential",
    "recover",
    "unlock",
    "suspended",
    "limited",
    "urgent",
    "bonus",
    "free",
    "claim",
    "gift"
]


def has_ip_address(url):
    pattern = r'^(?:https?://)?(?:\d{1,3}\.){3}\d{1,3}'
    return int(bool(re.search(pattern, url)))


def count_digits(url):
    return sum(c.isdigit() for c in url)


def count_special_characters(url):
    return sum(not c.isalnum() for c in url)


def count_suspicious_words(url):
    url_lower = url.lower()

    return sum(
        1 for word in SUSPICIOUS_WORDS
        if word in url_lower
    )


def calculate_entropy(text):
    if not text:
        return 0

    probabilities = [
        text.count(char) / len(text)
        for char in set(text)
    ]

    return -sum(
        p * math.log2(p)
        for p in probabilities
    )


def extract_features(url):

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    hostname = parsed.netloc
    path = parsed.path

    features = [

        # URL length
        len(url),

        # Hostname length
        len(hostname),

        # Path length
        len(path),

        # Number of dots
        url.count("."),

        # Number of hyphens
        url.count("-"),

        # Number of underscores
        url.count("_"),

        # Number of slashes
        url.count("/"),

        # Number of question marks
        url.count("?"),

        # Number of equals
        url.count("="),

        # Number of @ symbols
        url.count("@"),

        # Number of &
        url.count("&"),

        # Number of %
        url.count("%"),

        # Number of digits
        count_digits(url),

        # Special characters
        count_special_characters(url),

        # IP address
        has_ip_address(url),

        # HTTPS
        int(parsed.scheme == "https"),

        # Number of subdomains
        max(0, hostname.count(".") - 1),

        # Suspicious words
        count_suspicious_words(url),

        # URL entropy
        calculate_entropy(url)
    ]

    return features