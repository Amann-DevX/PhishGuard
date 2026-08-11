import socket
import ssl
from urllib.parse import urlparse

import dns.resolver


def get_domain(url):
    """
    Extract hostname from a URL.
    """

    try:
        parsed = urlparse(url)

        hostname = parsed.hostname

        if not hostname:
            return None

        return hostname

    except Exception:
        return None


def get_ip_address(hostname):
    """
    Resolve hostname to an IPv4 address.
    """

    try:

        ip = socket.gethostbyname(hostname)

        return {
            "available": True,
            "ip": ip
        }

    except Exception as e:

        return {
            "available": False,
            "ip": None,
            "error": str(e)
        }


def get_dns_records(hostname):
    """
    Retrieve common DNS records.
    """

    result = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "CNAME": []
    }

    record_types = [
        "A",
        "AAAA",
        "MX",
        "NS",
        "CNAME"
    ]

    for record_type in record_types:

        try:

            answers = dns.resolver.resolve(
                hostname,
                record_type,
                lifetime=3
            )

            for answer in answers:

                result[record_type].append(
                    str(answer)
                )

        except Exception:

            result[record_type] = []

    return result


def get_ssl_information(hostname):
    """
    Retrieve SSL/TLS certificate information.

    This performs a TLS handshake only. It does not
    download or execute the website content.
    """

    result = {
        "available": False,
        "valid": False,
        "issuer": None,
        "subject": None,
        "expires": None,
        "tls_version": None,
        "error": None
    }

    context = ssl.create_default_context()

    try:

        with socket.create_connection(
            (hostname, 443),
            timeout=5
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as secure_socket:

                certificate = (
                    secure_socket.getpeercert()
                )

                result["available"] = True

                result["valid"] = True

                result["tls_version"] = (
                    secure_socket.version()
                )

                result["expires"] = (
                    certificate.get(
                        "notAfter"
                    )
                )

                issuer = certificate.get(
                    "issuer",
                    ()
                )

                subject = certificate.get(
                    "subject",
                    ()
                )

                result["issuer"] = (
                    extract_certificate_name(
                        issuer
                    )
                )

                result["subject"] = (
                    extract_certificate_name(
                        subject
                    )
                )

    except ssl.SSLCertVerificationError as e:

        result["error"] = (
            "SSL certificate verification failed."
        )

    except Exception as e:

        result["error"] = str(e)

    return result


def extract_certificate_name(data):
    """
    Extract common certificate name.
    """

    try:

        for group in data:

            for key, value in group:

                if key == "commonName":

                    return value

    except Exception:
        pass

    return None


def analyze_domain(url):
    """
    Perform complete domain intelligence analysis.
    """

    hostname = get_domain(url)

    result = {
        "domain": hostname,
        "ip": None,
        "dns": {
            "A": [],
            "AAAA": [],
            "MX": [],
            "NS": [],
            "CNAME": []
        },
        "ssl": {
            "available": False,
            "valid": False,
            "issuer": None,
            "subject": None,
            "expires": None,
            "tls_version": None,
            "error": None
        }
    }

    if not hostname:
        return result

    # IP information
    ip_result = get_ip_address(hostname)

    result["ip"] = ip_result

    # DNS
    result["dns"] = get_dns_records(
        hostname
    )

    # SSL only makes sense for HTTPS
    parsed = urlparse(url)

    if parsed.scheme.lower() == "https":

        result["ssl"] = get_ssl_information(
            hostname
        )

    return result