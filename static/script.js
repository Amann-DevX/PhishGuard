async function scanURL() {

    const input =
        document.getElementById("urlInput");

    const button =
        document.getElementById("scanButton");

    const buttonText =
        document.getElementById("buttonText");

    const loading =
        document.getElementById("loading");

    const result =
        document.getElementById("result");


    const url =
        input.value.trim();


    if (!url) {

        alert("Please enter a URL.");

        input.focus();

        return;

    }


    button.disabled = true;

    buttonText.textContent =
        "Scanning...";

    loading.classList.remove("hidden");

    result.classList.add("hidden");


    try {

        const response =
            await fetch("/scan", {

                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    url: url
                })

            });


        const data =
            await response.json();


        if (!response.ok) {

            throw new Error(
                data.error ||
                "Scan failed."
            );

        }


        showResult(data);


    }

    catch (error) {

        console.error(error);

        alert(error.message);

    }


    loading.classList.add("hidden");

    button.disabled = false;

    buttonText.textContent =
        "Scan URL";
}


/* =====================================================
   SHOW SCAN RESULT
   ===================================================== */

function showResult(data) {

    const result =
        document.getElementById("result");

    const title =
        document.getElementById("resultTitle");

    const message =
        document.getElementById("resultMessage");

    const icon =
        document.getElementById("resultIcon");


    const risk =
        Number(
            data.risk_score || 0
        );


    /* -----------------------------------
       BASIC RESULT
    ----------------------------------- */

    document.getElementById(
        "scoreNumber"
    ).textContent = risk;


    document.getElementById(
        "probability"
    ).textContent =

        Math.round(
            Number(
                data.phishing_probability ||
                0
            )
        ) + "%";


    document.getElementById(
        "progressBar"
    ).style.width =
        risk + "%";


    document.getElementById(
        "scannedURL"
    ).textContent =
        data.url;


    /* -----------------------------------
       RESULT STATUS
    ----------------------------------- */

    if (
        data.result === "Phishing"
    ) {

        icon.textContent = "🚨";

        title.textContent =
            "Phishing Detected";

        message.textContent =
            data.message;

    }

    else if (
        data.result === "Suspicious"
    ) {

        icon.textContent = "⚠️";

        title.textContent =
            "Suspicious URL";

        message.textContent =
            data.message;

    }

    else {

        icon.textContent = "✓";

        title.textContent =
            "URL Appears Safe";

        message.textContent =
            data.message;

    }


    /* -----------------------------------
       SECURITY ANALYSIS
    ----------------------------------- */

    const analysis =
        data.analysis;


    const domain =
        data.domain_intelligence;


    const advanced =
        data.advanced_analysis;


    if (!analysis) {

        console.error(
            "Analysis data missing:",
            data
        );

        return;

    }


    document.getElementById(
        "analysisProtocol"
    ).textContent =

        analysis.https
            ? "HTTPS ✓"
            : "HTTP ⚠";


    document.getElementById(
        "analysisIP"
    ).textContent =

        analysis.ip_address
            ? "Detected 🔴"
            : "Not detected ✓";


    document.getElementById(
        "analysisLength"
    ).textContent =
        analysis.url_length;


    document.getElementById(
        "analysisSubdomains"
    ).textContent =
        analysis.subdomains;


    document.getElementById(
        "analysisKeywords"
    ).textContent =

        analysis.suspicious_keywords.length;


    document.getElementById(
        "analysisSpecial"
    ).textContent =
        analysis.special_characters;


    document.getElementById(
        "analysisEntropy"
    ).textContent =
        analysis.entropy;


    document.getElementById(
        "analysisPath"
    ).textContent =
        analysis.path_depth;


    /* -----------------------------------
       INDICATORS
    ----------------------------------- */

    const indicatorsContainer =
        document.getElementById(
            "indicators"
        );


    indicatorsContainer.innerHTML = "";


    const indicators =
        analysis.indicators || [];


    if (
        indicators.length === 0
    ) {

        indicatorsContainer.innerHTML = `

            <div class="clean-indicator">

                ✓ No major suspicious
                indicators detected.

            </div>

        `;

    }

    else {

        indicators.forEach(
            function(item) {

                const div =
                    document.createElement(
                        "div"
                    );


                div.className =
                    "indicator";


                const icon =
                    item.severity ===
                    "danger"

                        ? "🔴"

                        : "🟠";


                div.innerHTML = `

                    <span>
                        ${icon}
                    </span>

                    <div>

                        <strong>
                            ${escapeHTML(
                                item.title
                            )}
                        </strong>

                        <small>
                            ${escapeHTML(
                                item.description
                            )}
                        </small>

                    </div>

                `;


                indicatorsContainer
                    .appendChild(div);

            }
        );

    }


    /* -----------------------------------
       DOMAIN INTELLIGENCE
    ----------------------------------- */

    renderDomainIntelligence(
        domain
    );


    /* -----------------------------------
       ADVANCED SECURITY ANALYSIS
    ----------------------------------- */

    renderAdvancedAnalysis(
        advanced
    );


    /* -----------------------------------
       SHOW RESULT
    ----------------------------------- */

    result.classList.remove(
        "hidden"
    );


    result.scrollIntoView({

        behavior: "smooth",

        block: "nearest"

    });

}


/* =====================================================
   ESCAPE HTML
   ===================================================== */

function escapeHTML(text) {

    const div =
        document.createElement(
            "div"
        );

    div.textContent = text;

    return div.innerHTML;
}


/* =====================================================
   EXAMPLE URL
   ===================================================== */

function setExample(url) {

    document.getElementById(
        "urlInput"
    ).value = url;

}


/* =====================================================
   ENTER KEY
   ===================================================== */

document
    .getElementById("urlInput")
    .addEventListener(
        "keydown",
        function(event) {

            if (
                event.key === "Enter"
            ) {

                scanURL();

            }

        }
    );


/* =====================================================
   DOMAIN INTELLIGENCE
   ===================================================== */

function renderDomainIntelligence(
    domain
) {

    if (!domain) {
        return;
    }


    /* -----------------------------------
       DOMAIN
    ----------------------------------- */

    document.getElementById(
        "domainName"
    ).textContent =
        domain.domain ||
        "Unknown";


    /* -----------------------------------
       IP
    ----------------------------------- */

    if (
        domain.ip &&
        domain.ip.available
    ) {

        document.getElementById(
            "domainIP"
        ).textContent =
            domain.ip.ip;

    }

    else {

        document.getElementById(
            "domainIP"
        ).textContent =
            "Not resolved";

    }


    /* -----------------------------------
       DNS
    ----------------------------------- */

    const dns =
        domain.dns || {};


    const hasA =
        dns.A &&
        dns.A.length > 0;


    const hasNS =
        dns.NS &&
        dns.NS.length > 0;


    const hasMX =
        dns.MX &&
        dns.MX.length > 0;


    document.getElementById(
        "dnsStatus"
    ).textContent =

        hasA
            ? "Available ✓"
            : "Not found";


    document.getElementById(
        "nsStatus"
    ).textContent =

        hasNS
            ? "Available ✓"
            : "Not found";


    document.getElementById(
        "mxStatus"
    ).textContent =

        hasMX
            ? "Available ✓"
            : "Not found";


    /* -----------------------------------
       SSL
    ----------------------------------- */

    const ssl =
        domain.ssl || {};


    const isHTTPS =
        ssl.available ||

        (
            domain.domain &&

            document
                .getElementById(
                    "analysisProtocol"
                )
                .textContent
                .includes("HTTPS")
        );


    document.getElementById(
        "sslHTTPS"
    ).textContent =

        isHTTPS
            ? "Enabled ✓"
            : "Not available";


    document.getElementById(
        "sslCertificate"
    ).textContent =

        ssl.valid

            ? "Valid ✓"

            : (

                ssl.error

                    ? "Check failed"

                    : "Not checked"

            );


    document.getElementById(
        "tlsVersion"
    ).textContent =

        ssl.tls_version ||
        "Not available";


    document.getElementById(
        "sslIssuer"
    ).textContent =

        ssl.issuer ||
        "Not available";


    document.getElementById(
        "sslExpiry"
    ).textContent =

        ssl.expires ||
        "Not available";

}


/* =====================================================
   PHASE 6
   ADVANCED SECURITY ANALYSIS
   ===================================================== */

function renderAdvancedAnalysis(
    data
) {

    /*
     * If backend did not send
     * advanced_analysis, stop safely.
     */

    if (!data) {

        console.warn(
            "Advanced analysis data missing."
        );

        return;

    }


    /* -----------------------------------
       TLD
    ----------------------------------- */

    const tld =
        document.getElementById(
            "advancedTLD"
        );

    if (tld) {

        tld.textContent =
            data.tld ||
            "Unknown";

    }


    /* -----------------------------------
       IP BASED
    ----------------------------------- */

    const ip =
        document.getElementById(
            "advancedIP"
        );

    if (ip) {

        ip.textContent =

            data.ip_based

                ? "Detected ⚠"

                : "No ✓";

    }


    /* -----------------------------------
       SUBDOMAINS
    ----------------------------------- */

    const subdomains =
        document.getElementById(
            "advancedSubdomains"
        );

    if (subdomains) {

        subdomains.textContent =
            data.subdomain_count ??
            0;

    }


    /* -----------------------------------
       SUSPICIOUS KEYWORDS
    ----------------------------------- */

    const keywords =
        document.getElementById(
            "advancedKeywords"
        );

    if (keywords) {

        keywords.textContent =
            data.keyword_count ??
            0;

    }


    /* -----------------------------------
       @ SYMBOL
    ----------------------------------- */

    const atSymbol =
        document.getElementById(
            "advancedAt"
        );

    if (atSymbol) {

        atSymbol.textContent =

            data.has_at_symbol

                ? "Detected ⚠"

                : "No ✓";

    }


    /* -----------------------------------
       ENCODED CHARACTERS
    ----------------------------------- */

    const encoded =
        document.getElementById(
            "advancedEncoded"
        );

    if (encoded) {

        encoded.textContent =
            data.encoded_characters ??
            0;

    }


    /* -----------------------------------
       HYPHENS
    ----------------------------------- */

    const hyphens =
        document.getElementById(
            "advancedHyphens"
        );

    if (hyphens) {

        hyphens.textContent =
            data.hyphen_count ??
            0;

    }


    /* -----------------------------------
       DIGITS
    ----------------------------------- */

    const digits =
        document.getElementById(
            "advancedDigits"
        );

    if (digits) {

        digits.textContent =
            data.digit_count ??
            0;

    }


    /* -----------------------------------
       RISK INDICATORS
    ----------------------------------- */

    const container =
        document.getElementById(
            "advancedRiskPoints"
        );


    if (!container) {

        console.warn(
            "advancedRiskPoints element not found."
        );

        return;

    }


    const riskPoints =
        data.risk_points || [];


    /* -----------------------------------
       NO RISK INDICATORS
    ----------------------------------- */

    if (
        riskPoints.length === 0
    ) {

        container.innerHTML = `

            <div class="clean-indicator">

                ✓ No additional suspicious
                indicators detected.

            </div>

        `;

        return;

    }


    /* -----------------------------------
       DISPLAY RISK INDICATORS
    ----------------------------------- */

    container.innerHTML = "";


    riskPoints.forEach(
        function(point) {

            const item =
                document.createElement(
                    "div"
                );


            item.className =
                "advanced-risk-point";


            item.innerHTML = `

                <span>
                    ⚠
                </span>

                <strong>
                    ${escapeHTML(point)}
                </strong>

            `;


            container.appendChild(
                item
            );

        }
    );

}