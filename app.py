from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    session,
    flash
)

import joblib
import re
import math
import sqlite3

from urllib.parse import urlparse

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from functools import wraps

from feature_extraction import extract_features
from domain_intelligence import analyze_domain
from advanced_analysis import analyze_advanced_url

# ============================================================
# APPLICATION
# ============================================================

app = Flask(__name__)

app.secret_key = "phishguard-change-this-secret-key"

DATABASE = "phishguard.db"

MODEL_PATH = "phishing_model.pkl"


# ============================================================
# LOAD ML MODEL
# ============================================================

try:

    model = joblib.load(MODEL_PATH)

    print("✓ Phishing detection model loaded successfully.")

except Exception as e:

    model = None

    print("✗ Model loading failed:", e)


# ============================================================
# DATABASE
# ============================================================

def get_db():

    connection = sqlite3.connect(
        DATABASE
    )

    connection.row_factory = sqlite3.Row

    return connection


def init_database():

    connection = get_db()

    cursor = connection.cursor()


    # --------------------------------------------------------
    # USERS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT NOT NULL UNIQUE,

            email TEXT NOT NULL UNIQUE,

            password TEXT NOT NULL,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

        )
    """)


    # --------------------------------------------------------
    # SCANS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            url TEXT NOT NULL,

            result TEXT NOT NULL,

            risk_score INTEGER NOT NULL,

            phishing_probability REAL NOT NULL,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY(user_id)
                REFERENCES users(id)

        )
    """)


    connection.commit()

    connection.close()

    print("✓ Database initialized.")


# ============================================================
# LOGIN REQUIRED DECORATOR
# ============================================================

def login_required(function):

    @wraps(function)
    def decorated_function(*args, **kwargs):

        if "user_id" not in session:

            flash(
                "Please login to continue.",
                "warning"
            )

            return redirect(
                url_for("login")
            )

        return function(
            *args,
            **kwargs
        )

    return decorated_function


# ============================================================
# SUSPICIOUS KEYWORDS
# ============================================================

SUSPICIOUS_KEYWORDS = [

    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "confirm",
    "confirmation",
    "password",
    "credential",
    "bank",
    "payment",
    "wallet",
    "suspended",
    "locked",
    "unlock",
    "urgent",
    "alert",
    "claim",
    "reward",
    "prize",
    "free",
    "refund",
    "invoice",
    "authenticate",
    "authentication"

]


# ============================================================
# ENTROPY
# ============================================================

def calculate_entropy(text):

    if not text:

        return 0


    frequency = {}


    for character in text:

        frequency[character] = (
            frequency.get(
                character,
                0
            ) + 1
        )


    entropy = 0

    length = len(text)


    for count in frequency.values():

        probability = count / length

        entropy -= (
            probability *
            math.log2(probability)
        )


    return entropy


# ============================================================
# URL ANALYSIS
# ============================================================

def analyze_url(url):

    indicators = []

    parsed = urlparse(url)

    hostname = parsed.hostname or ""

    path = parsed.path or ""

    query = parsed.query or ""


    # --------------------------------------------------------
    # URL LENGTH
    # --------------------------------------------------------

    url_length = len(url)


    if url_length > 120:

        indicators.append({

            "severity": "danger",

            "title": "Very long URL",

            "description":
                f"The URL contains {url_length} characters."

        })


    elif url_length > 75:

        indicators.append({

            "severity": "warning",

            "title": "Long URL",

            "description":
                f"The URL contains {url_length} characters."

        })


    # --------------------------------------------------------
    # HTTPS
    # --------------------------------------------------------

    https = (
        parsed.scheme.lower()
        == "https"
    )


    if not https:

        indicators.append({

            "severity": "danger",

            "title": "HTTPS is not used",

            "description":
                "The URL uses an unencrypted HTTP connection."

        })


    # --------------------------------------------------------
    # IP ADDRESS
    # --------------------------------------------------------

    ip_pattern = (
        r"^(?:\d{1,3}\.){3}\d{1,3}$"
    )


    has_ip = bool(
        re.match(
            ip_pattern,
            hostname
        )
    )


    if has_ip:

        indicators.append({

            "severity": "danger",

            "title": "IP address detected",

            "description":
                "The URL uses an IP address instead of a normal domain."

        })


    # --------------------------------------------------------
    # @ SYMBOL
    # --------------------------------------------------------

    has_at = "@" in url


    if has_at:

        indicators.append({

            "severity": "danger",

            "title": "@ symbol detected",

            "description":
                "The @ symbol can be used to disguise the destination."

        })


    # --------------------------------------------------------
    # SUBDOMAINS
    # --------------------------------------------------------

    subdomain_count = 0


    if hostname:

        parts = hostname.split(".")


        if len(parts) > 2:

            subdomain_count = (
                len(parts) - 2
            )


    if subdomain_count >= 3:

        indicators.append({

            "severity": "warning",

            "title": "Multiple subdomains",

            "description":
                f"{subdomain_count} subdomains were detected."

        })


    # --------------------------------------------------------
    # SUSPICIOUS WORDS
    # --------------------------------------------------------

    url_lower = url.lower()

    found_keywords = []


    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in url_lower:

            found_keywords.append(
                keyword
            )


    if len(found_keywords) >= 2:

        indicators.append({

            "severity": "danger",

            "title":
                "Multiple suspicious keywords",

            "description":
                "Detected: " +
                ", ".join(found_keywords)

        })


    elif len(found_keywords) == 1:

        indicators.append({

            "severity": "warning",

            "title":
                "Suspicious keyword",

            "description":
                f'Detected keyword: "{found_keywords[0]}"'

        })


    # --------------------------------------------------------
    # SPECIAL CHARACTERS
    # --------------------------------------------------------

    special_chars = len(
        re.findall(
            r"[^a-zA-Z0-9]",
            url
        )
    )


    if special_chars > 25:

        indicators.append({

            "severity": "warning",

            "title":
                "Many special characters",

            "description":
                f"{special_chars} special characters were found."

        })


    # --------------------------------------------------------
    # HYPHENS
    # --------------------------------------------------------

    dash_count = url.count("-")


    if dash_count >= 5:

        indicators.append({

            "severity": "warning",

            "title":
                "Excessive hyphens",

            "description":
                f"The URL contains {dash_count} hyphens."

        })


    # --------------------------------------------------------
    # DOTS
    # --------------------------------------------------------

    dot_count = url.count(".")


    if dot_count >= 6:

        indicators.append({

            "severity": "warning",

            "title":
                "Unusual number of dots",

            "description":
                f"The URL contains {dot_count} dots."

        })


    # --------------------------------------------------------
    # TLD
    # --------------------------------------------------------

    suspicious_tlds = [

        ".xyz",
        ".top",
        ".click",
        ".link",
        ".zip",
        ".mov",
        ".work",
        ".country",
        ".gq",
        ".tk",
        ".ml",
        ".ga",
        ".cf"

    ]


    suspicious_tld = False


    for tld in suspicious_tlds:

        if hostname.lower().endswith(tld):

            suspicious_tld = True


            indicators.append({

                "severity": "warning",

                "title":
                    "Unusual domain extension",

                "description":
                    f"The domain uses the {tld} extension."

            })

            break


    # --------------------------------------------------------
    # PARAMETERS
    # --------------------------------------------------------

    query_parameters = 0


    if query:

        query_parameters = len(
            query.split("&")
        )


    if query_parameters >= 5:

        indicators.append({

            "severity": "warning",

            "title":
                "Many URL parameters",

            "description":
                f"{query_parameters} parameters were detected."

        })


    # --------------------------------------------------------
    # ENTROPY
    # --------------------------------------------------------

    entropy = calculate_entropy(url)


    if entropy > 4.5:

        indicators.append({

            "severity": "warning",

            "title":
                "High URL randomness",

            "description":
                f"URL entropy is {entropy:.2f}."

        })


    # --------------------------------------------------------
    # PATH
    # --------------------------------------------------------

    path_depth = len(

        [
            x
            for x in path.split("/")
            if x
        ]

    )


    if path_depth >= 5:

        indicators.append({

            "severity": "warning",

            "title":
                "Deep URL path",

            "description":
                f"The URL contains {path_depth} path levels."

        })


    # --------------------------------------------------------
    # SECURITY SCORE
    # --------------------------------------------------------

    danger_count = sum(

        1
        for item in indicators
        if item["severity"] == "danger"

    )


    warning_count = sum(

        1
        for item in indicators
        if item["severity"] == "warning"

    )


    security_score = (

        danger_count * 18

        +

        warning_count * 8

    )


    security_score = min(
        security_score,
        100
    )


    return {

        "url_length":
            url_length,

        "https":
            https,

        "hostname":
            hostname,

        "ip_address":
            has_ip,

        "subdomains":
            subdomain_count,

        "suspicious_keywords":
            found_keywords,

        "special_characters":
            special_chars,

        "hyphens":
            dash_count,

        "dots":
            dot_count,

        "suspicious_tld":
            suspicious_tld,

        "query_parameters":
            query_parameters,

        "entropy":
            round(
                entropy,
                2
            ),

        "path_depth":
            path_depth,

        "indicators":
            indicators,

        "security_score":
            security_score

    }


# ============================================================
# PREDICT URL
# ============================================================

def predict_url(url):

    if model is None:

        raise RuntimeError(
            "ML model could not be loaded."
        )


    features = extract_features(
        url
    )


    prediction = model.predict(
        [features]
    )[0]


    probability = 0


    try:

        probabilities = (
            model.predict_proba(
                [features]
            )[0]
        )


        classes = list(
            model.classes_
        )


        if 1 in classes:

            phishing_index = (
                classes.index(1)
            )


            probability = (
                probabilities[
                    phishing_index
                ]
                * 100
            )

        else:

            probability = (
                max(probabilities)
                * 100
            )


    except Exception:

        probability = (

            100
            if prediction == 1
            else 0

        )


    probability = round(
        float(probability),
        2
    )


    analysis = analyze_url(url)

    domain_info = analyze_domain(url)

    advanced_info = analyze_advanced_url(url)

    risk_score = round(

        (
            probability
            * 0.75
        )

        +

        (
            analysis[
                "security_score"
            ]
            * 0.25
        )

    )


    risk_score = min(
        max(
            risk_score,
            0
        ),
        100
    )


    if risk_score >= 70:

        result = "Phishing"

        message = (
            "This URL shows strong "
            "characteristics associated "
            "with phishing."
        )


    elif risk_score >= 40:

        result = "Suspicious"

        message = (
            "This URL contains several "
            "characteristics that require caution."
        )


    else:

        result = "Safe"

        message = (
            "No strong phishing characteristics "
            "were detected."
        )


    return {

    "url": url,

    "result": result,

    "risk_score": risk_score,

    "phishing_probability": probability,

    "message": message,

    "analysis": analysis,

    "domain_intelligence": domain_info,

    "advanced_analysis": advanced_info

}


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    if "user_id" in session:
        return redirect(
            url_for("dashboard")
        )

    return redirect(
        url_for("login")
    )


# ============================================================
# REGISTER
# ============================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )


        if not username or not email or not password:

            flash(
                "All fields are required.",
                "error"
            )

            return redirect(
                url_for("register")
            )


        if len(username) < 3:

            flash(
                "Username must contain at least 3 characters.",
                "error"
            )

            return redirect(
                url_for("register")
            )


        if len(password) < 6:

            flash(
                "Password must contain at least 6 characters.",
                "error"
            )

            return redirect(
                url_for("register")
            )


        connection = get_db()


        existing_user = connection.execute(

            """
            SELECT id
            FROM users
            WHERE username = ?
               OR email = ?
            """,

            (
                username,
                email
            )

        ).fetchone()


        if existing_user:

            connection.close()

            flash(
                "Username or email already exists.",
                "error"
            )

            return redirect(
                url_for("register")
            )


        hashed_password = (
            generate_password_hash(
                password
            )
        )


        connection.execute(

            """
            INSERT INTO users
            (
                username,
                email,
                password
            )
            VALUES (?, ?, ?)
            """,

            (
                username,
                email,
                hashed_password
            )

        )


        connection.commit()

        connection.close()


        flash(
            "Account created successfully. Please login.",
            "success"
        )


        return redirect(
            url_for("login")
        )


    return render_template(
        "register.html"
    )


# ============================================================
# LOGIN
# ============================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )


        connection = get_db()


        user = connection.execute(

            """
            SELECT *
            FROM users
            WHERE email = ?
            """,

            (email,)

        ).fetchone()


        connection.close()


        if (
            user
            and check_password_hash(
                user["password"],
                password
            )
        ):

            session["user_id"] = (
                user["id"]
            )

            session["username"] = (
                user["username"]
            )

            session["email"] = (
                user["email"]
            )


            flash(
                "Welcome back!",
                "success"
            )


            return redirect(
                url_for("dashboard")
            )


        flash(
            "Invalid email or password.",
            "error"
        )


    return render_template(
        "login.html"
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(
        url_for("home")
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
@login_required
def dashboard():

    user_id = session["user_id"]


    connection = get_db()


    total = connection.execute(

        """
        SELECT COUNT(*)
        AS count

        FROM scans

        WHERE user_id = ?
        """,

        (user_id,)

    ).fetchone()["count"]


    safe = connection.execute(

        """
        SELECT COUNT(*)
        AS count

        FROM scans

        WHERE user_id = ?
        AND result = 'Safe'
        """,

        (user_id,)

    ).fetchone()["count"]


    suspicious = connection.execute(

        """
        SELECT COUNT(*)
        AS count

        FROM scans

        WHERE user_id = ?
        AND result = 'Suspicious'
        """,

        (user_id,)

    ).fetchone()["count"]


    phishing = connection.execute(

        """
        SELECT COUNT(*)
        AS count

        FROM scans

        WHERE user_id = ?
        AND result = 'Phishing'
        """,

        (user_id,)

    ).fetchone()["count"]


    recent_scans = connection.execute(

        """
        SELECT *

        FROM scans

        WHERE user_id = ?

        ORDER BY id DESC

        LIMIT 8
        """,

        (user_id,)

    ).fetchall()


    connection.close()


    return render_template(

        "dashboard.html",

        total=total,

        safe=safe,

        suspicious=suspicious,

        phishing=phishing,

        recent_scans=recent_scans

    )


# ============================================================
# HISTORY
# ============================================================

@app.route("/ml-analytics")
@login_required
def ml_analytics():

    try:

        results = joblib.load(
            "model_results.pkl"
        )

    except Exception:

        flash(
            "ML results are not available. Train the models first.",
            "warning"
        )

        return redirect(
            url_for("dashboard")
        )


    best_model = max(

        results,

        key=lambda name:
            results[name]["f1"]

    )


    return render_template(

        "ml_dashboard.html",

        results=results,

        best_model=best_model

    )

@app.route("/history")
@login_required
def history():

    user_id = session["user_id"]


    connection = get_db()


    scans = connection.execute(

        """
        SELECT *

        FROM scans

        WHERE user_id = ?

        ORDER BY id DESC
        """,

        (user_id,)

    ).fetchall()


    connection.close()


    return render_template(

        "history.html",

        scans=scans

    )


# ============================================================
# DELETE HISTORY
# ============================================================

@app.route(
    "/history/delete/<int:scan_id>",
    methods=["POST"]
)
@login_required
def delete_scan(scan_id):

    user_id = session["user_id"]


    connection = get_db()


    connection.execute(

        """
        DELETE FROM scans

        WHERE id = ?

        AND user_id = ?
        """,

        (
            scan_id,
            user_id
        )

    )


    connection.commit()

    connection.close()


    return redirect(
        url_for("history")
    )


# ============================================================
# SCAN
# ============================================================

@app.route(
    "/scan",
    methods=["POST"]
)
def scan():

    try:

        data = request.get_json(
            silent=True
        )


        if not data:

            return jsonify({

                "error":
                    "No JSON data received."

            }), 400


        url = str(

            data.get(
                "url",
                ""
            )

        ).strip()


        if not url:

            return jsonify({

                "error":
                    "Please enter a URL."

            }), 400


        if len(url) > 2048:

            return jsonify({

                "error":
                    "URL is too long."

            }), 400


        if not re.match(

            r"^[a-zA-Z][a-zA-Z0-9+.-]*://",

            url

        ):

            url = "http://" + url


        result = predict_url(
            url
        )


        # ----------------------------------------------------
        # SAVE SCAN FOR LOGGED-IN USER
        # ----------------------------------------------------

        if "user_id" in session:

            connection = get_db()


            connection.execute(

                """
                INSERT INTO scans
                (
                    user_id,
                    url,
                    result,
                    risk_score,
                    phishing_probability
                )

                VALUES (?, ?, ?, ?, ?)
                """,

                (

                    session["user_id"],

                    result["url"],

                    result["result"],

                    result["risk_score"],

                    result[
                        "phishing_probability"
                    ]

                )

            )


            connection.commit()

            connection.close()


        return jsonify(
            result
        )


    except Exception as e:

        print(
            "SCAN ERROR:",
            repr(e)
        )


        return jsonify({

            "error":
                "Unable to analyze URL.",

            "details":
                str(e)

        }), 500


# ============================================================
# API
# ============================================================

@app.route(
    "/api/scan",
    methods=["POST"]
)
def api_scan():

    try:

        data = request.get_json(
            silent=True
        )


        if not data:

            return jsonify({

                "error":
                    "JSON body required."

            }), 400


        url = str(

            data.get(
                "url",
                ""
            )

        ).strip()


        if not url:

            return jsonify({

                "error":
                    "URL is required."

            }), 400


        if not re.match(

            r"^[a-zA-Z][a-zA-Z0-9+.-]*://",

            url

        ):

            url = "http://" + url


        result = predict_url(
            url
        )


        return jsonify(
            result
        )


    except Exception as e:

        return jsonify({

            "error":
                str(e)

        }), 500


# ============================================================
# HEALTH
# ============================================================

@app.route("/health")
def health():

    return jsonify({

        "status":
            "online",

        "model_loaded":
            model is not None,

        "database":
            "connected"

    })


# ============================================================
# START
# ============================================================

init_database()


if __name__ == "__main__":
    import os
    print()

    print(
        "=" * 60
    )

    print(
        "             PHISHGUARD SECURITY ENGINE"
    )

    print(
        "=" * 60
    )

    print(
        "ML Model:       "
        +
        (
            "Loaded"
            if model
            else "ERROR"
        )
    )

    print(
        "URL Analysis:   Active"
    )

    print(
        "Risk Engine:    Active"
    )

    print(
        "Database:       Active"
    )

    print(
        "Authentication:  Active"
    )

    print(
        "Dashboard:       Active"
    )

    print(
        "=" * 60
    )

    print()

    port = int(os.environ.get("PORT", 5000))


    app.run(

        debug=True,

        host="0.0.0.0",

        port=port

    )
   