from flask import Flask, render_template, request
import re

app = Flask(__name__)

# PRIVACY NOTE: This application does NOT store, log, or save any user messages or sender emails.
# All analysis is performed in-memory and results are sent directly to the user's browser.
# No database writes, no file logging of user input, no external API calls.
# The app is fully local and stateless â€” each request is independent.


def analyze_text(text):
    """Return a list of heuristic reasons found in the text.

    Reasons (exact strings):
      - "urgent or pressuring language"
      - "asks for sensitive or financial info"
      - "contains link(s)"
      - "references attachments or downloads"
    """
    reasons = []
    if not text:
        return reasons

    s = text.lower()

    # Urgent / pressuring language
    urgent_keywords = [
        "urgent", "immediately", "asap", "act now", "limited time",
        "respond", "required", "do not ignore", "your account will be closed",
        "verify now", "verify your"
    ]
    if any(k in s for k in urgent_keywords):
        reasons.append("urgent or pressuring language")

    # Sensitive / financial info requests
    sensitive_keywords = [
        "password", "passcode", "credit card", "card number", "cvv",
        "social security", "ssn", "account number", "bank account",
        "routing number", "login", "username", "verify identity", "payment",
        "wire transfer", "send money", "pay now"
    ]
    if any(k in s for k in sensitive_keywords):
        reasons.append("asks for sensitive or financial info")

    # Links detection (http(s), www, or obvious domain patterns)
    url_pattern = re.compile(r"https?://|www\.|\b[\w-]+\.(com|net|org|io|bank|ru|info)\b", re.I)
    if url_pattern.search(text):
        reasons.append("contains link(s)")

    # Attachments / downloads
    attachment_keywords = ["attachment", "attached", "download", "open the attachment", "see attached", "invoice attached", ".zip", ".exe", ".pdf"]
    if any(k in s for k in attachment_keywords):
        reasons.append("references attachments or downloads")

    # Ensure unique and consistent ordering
    ordered_reasons = [r for r in [
        "urgent or pressuring language",
        "asks for sensitive or financial info",
        "contains link(s)",
        "references attachments or downloads"
    ] if r in reasons]
    return ordered_reasons


def analyze_sender_email(email: str) -> list:
    """Analyze a sender email and return a list of heuristic reasons.

    Possible returned reasons (exact strings):
      - "Email format looks unusual"
      - "Company-looking name but sent from a free email provider"
      - "Email contains impersonation patterns"
      - "Email has excessive numbers or symbols"
      - "Email uses a high-risk domain extension"
      - "Email uses a medium-risk domain extension"
      - "Email uses an unusual domain extension"
      - "Email domain is not in the safe list"
      - "help_view_sender"
    """
    # If sender blank -> encourage helper
    if not email or not email.strip():
        return ["help_view_sender"]

    reasons = []
    e = email.strip().lower()

    # Basic format check
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", e):
        reasons.append("Email format looks unusual")
        # still include helper if format odd
        reasons.append("help_view_sender")
        # dedupe and return
        return list(dict.fromkeys(reasons))

    local, domain = e.split("@", 1)
    domain = domain.strip()
    local = local.strip()

    free_providers = {
        "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
        "icloud.com", "mail.com", "protonmail.com", "zoho.com", "yandex.com"
    }

    company_keywords = {
        "paypal", "bank", "amazon", "microsoft", "apple", "google",
        "facebook", "billing", "invoice", "support", "account", "service"
    }

    # Free provider but local looks company-like
    if domain in free_providers:
        for kw in company_keywords:
            if kw in local:
                reasons.append("Company-looking name but sent from a free email provider")
                break

    # Impersonation detection (leetspeak)
    brands = ["paypal", "microsoft", "facebook", "google", "amazon"]
    tokens_to_check = [local, domain.split(".")[0]]
    for token in tokens_to_check:
        stripped = re.sub(r"[^a-z]", "", token)
        if stripped:
            for brand in brands:
                if brand in stripped and stripped != token:
                    reasons.append("Email contains impersonation patterns")
                    break
            else:
                continue
            break

    # Excessive numbers or symbols in local part
    digit_count = sum(c.isdigit() for c in local)
    symbol_count = sum(not c.isalnum() for c in local)
    if digit_count >= 3 or symbol_count >= 3:
        reasons.append("Email has excessive numbers or symbols")

    HIGH_RISK_TLDS = [
        ".ru", ".cn", ".tk", ".ml", ".ga", ".cf", ".gq",
        ".work", ".zip", ".review", ".country", ".stream",
        ".download", ".racing", ".date", ".loan", ".accountant",
        ".bid", ".win", ".top", ".xyz", ".click", ".link",
        ".cam", ".bar", ".biz", ".info"
    ]

    MEDIUM_RISK_TLDS = [
        ".co", ".me", ".live", ".site", ".online", ".email",
        ".support", ".help", ".shop", ".store"
    ]

    LOW_RISK_UNUSUAL_TLDS = [
        ".io", ".ai", ".tech", ".cloud", ".app"
    ]

    SAFE_TLDS = [
        ".com", ".org", ".net", ".edu", ".gov",
        ".us", ".ca", ".uk", ".au", ".nz", ".de",
        ".fr", ".jp", ".kr", ".in", ".br"
    ]

    domain_lower = domain.lower()
    matched = False
    for t in HIGH_RISK_TLDS:
        if domain_lower.endswith(t):
            reasons.append("Email uses a high-risk domain extension")
            matched = True
            break
    if not matched:
        for t in MEDIUM_RISK_TLDS:
            if domain_lower.endswith(t):
                reasons.append("Email uses a medium-risk domain extension")
                matched = True
                break
    if not matched:
        for t in LOW_RISK_UNUSUAL_TLDS:
            if domain_lower.endswith(t):
                reasons.append("Email uses an unusual domain extension")
                matched = True
                break

    tld = "." + domain_lower.split(".")[-1]
    if tld not in SAFE_TLDS and all(not domain_lower.endswith(x) for x in (HIGH_RISK_TLDS + MEDIUM_RISK_TLDS + LOW_RISK_UNUSUAL_TLDS)):
        reasons.append("Email domain is not in the safe list")

    # If any sender-email reasons triggered, include helper so user can view real sender
    if reasons:
        reasons.append("help_view_sender")

    # Deduplicate while preserving order
    seen = set()
    ordered = []
    for r in reasons:
        if r not in seen:
            ordered.append(r)
            seen.add(r)
    return ordered


def build_findings(reasons):
    """Convert reason keys into UI-friendly finding dictionaries.

    Uses `generate_solutions()` to retrieve the mapping from reasons to
    user-friendly text, then returns an ordered list of findings.
    Each finding includes: label, risk_level, solution, reassurance, steps.
    """
    mapping = generate_solutions()
    findings = []
    seen = set()
    for r in reasons:
        if r in seen:
            continue
        seen.add(r)
        if r in mapping:
            item = mapping[r].copy()
            findings.append(item)
        else:
            # Fallback for unknown reasons
            findings.append({
                "label": r,
                "risk_level": "low",
                "solution": "This item was flagged by a heuristic check.",
                "reassurance": "You can investigate this in your own time; it's not necessarily urgent.",
                "steps": [
                    "Avoid acting on the item until you confirm it's safe.",
                    "Verify sender or source using trusted contact methods.",
                    "Report or delete if it seems malicious."
                ]
            })
    return findings


def generate_solutions():
    """Return the mapping of reason keys to UI-friendly content.

    Each mapping contains: label, risk_level, solution, reassurance, steps.
    """
    return {
        "urgent or pressuring language": {
            "label": "Pressuring or Urgent Tone",
            "risk_level": "high",
            "solution": "Don't rush: treat urgent requests with skepticism.",
            "reassurance": "It's okay to take a moment â€” most legitimate organizations won't pressure you.",
            "steps": [
                "Pause and don't reply immediately.",
                "Verify the sender via an official website or phone number.",
                "Avoid clicking links or opening attachments from this message."
            ]
        },
        "asks for sensitive or financial info": {
            "label": "Request for Sensitive or Financial Info",
            "risk_level": "high",
            "solution": "Never share passwords, credit card numbers, or SSNs over email or chat.",
            "reassurance": "You can protect yourself â€” legitimate services ask for this only in secure ways.",
            "steps": [
                "Do not provide any requested financial or personal details.",
                "Contact the company using a phone number or website you trust.",
                "If you already shared info, consider contacting your bank or changing passwords."
            ]
        },
        "contains link(s)": {
            "label": "Contains Link(s)",
            "risk_level": "medium",
            "solution": "Links can lead to fake sites; avoid opening them directly.",
            "reassurance": "Not every link is dangerous, but it's smart to be cautious.",
            "steps": [
                "Don't click the link directly from the message.",
                "Hover to inspect the URL or type the known site address yourself.",
                "If unsure, look up the company contact info independently."
            ]
        },
        "references attachments or downloads": {
            "label": "Mentions Attachments or Downloads",
            "risk_level": "medium",
            "solution": "Attachments can contain malware; avoid opening unknown files.",
            "reassurance": "You can ask the sender to confirm before opening anything.",
            "steps": [
                "Don't download or open unexpected attachments.",
                "Ask the sender to confirm via a separate, trusted channel.",
                "Run antivirus scans on files before opening if you must."
            ]
        }
        ,

        # Sender-email reasons
        "Email format looks unusual": {
            "label": "Why this sender might be risky",
            "risk_level": "high",
            "solution": "The sender's address looks malformed or unexpected; treat it with caution.",
            "reassurance": "You can check carefully â€” malformed addresses are often harmless but sometimes used in scams.",
            "steps": [
                "Don't reply or click anything from the sender.",
                "If it claims to be from a company, contact that company using a number or site you know is real.",
                "Delete the message if you didn't expect it."
            ]
        },
        "Company-looking name but sent from a free email provider": {
            "label": "Why this sender might be risky",
            "risk_level": "medium",
            "solution": "Messages that look like they're from a business but come from free email addresses can be suspicious.",
            "reassurance": "Sometimes small businesses use free emails, but it's worth double-checking.",
            "steps": [
                "Don't act on requests until you've confirmed the sender by other means.",
                "Look up the real company's official contact information independently.",
                "If in doubt, contact the company directly before sharing anything."
            ]
        },
        "Email contains impersonation patterns": {
            "label": "Why this sender might be risky",
            "risk_level": "high",
            "solution": "The address appears to mimic a known company by swapping letters for numbers or symbols.",
            "reassurance": "Scammers often try to look legitimate â€” you can spot them by checking closely.",
            "steps": [
                "Do not click links or reply to the message.",
                "Compare the sender address carefully with the official company domain.",
                "Report the message to your email provider or delete it."
            ]
        },
        "Email has excessive numbers or symbols": {
            "label": "Why this sender might be risky",
            "risk_level": "medium",
            "solution": "Addresses with many numbers or strange characters can be throwaway or fraudulent.",
            "reassurance": "Not all odd-looking addresses are harmful, but it's safe to be cautious.",
            "steps": [
                "Avoid interacting with the message until verified.",
                "Check whether the domain looks legitimate using an independent search.",
                "If the message asks for anything important, contact the company another way."
            ]
        },
        "Email uses a high-risk domain extension": {
            "label": "Why this sender might be risky",
            "risk_level": "high",
            "solution": "Some domain extensions are frequently used in scams.",
            "reassurance": "A domain alone doesn't prove malice, but combined with other signs it's concerning.",
            "steps": [
                "Don't click links pointing to that domain.",
                "Search the domain online to see if others reported issues.",
                "When in doubt, contact the claimed sender via a trusted channel."
            ]
        },
        "Email uses a medium-risk domain extension": {
            "label": "Why this sender might be risky",
            "risk_level": "medium",
            "solution": "This extension is sometimes used by questionable sites â€” be cautious.",
            "reassurance": "Many legitimate people use these domains, but extra care is helpful.",
            "steps": [
                "Verify the sender before acting on requests.",
                "Avoid entering personal or financial details linked from this address.",
                "If unsure, look up the business using official resources."
            ]
        },
        "Email uses an unusual domain extension": {
            "label": "Why this sender might be risky",
            "risk_level": "low",
            "solution": "Some modern extensions are uncommon and can look unfamiliar.",
            "reassurance": "This is often harmless, but it's fine to double-check when asked to take action.",
            "steps": [
                "Take a moment to verify the sender if they ask for anything important.",
                "Check the company's official site for contact details.",
                "Keep the message but avoid clicking links until confirmed."
            ]
        },
        "Email domain is not in the safe list": {
            "label": "Why this sender might be risky",
            "risk_level": "medium",
            "solution": "The sender's domain is outside common trusted lists â€” that can increase risk.",
            "reassurance": "This alone isn't proof of fraud, but it's a useful warning sign.",
            "steps": [
                "Don't act on urgent requests without verifying the sender.",
                "Search for the domain or company independently to confirm legitimacy.",
                "If it's unexpected, delete or report the message."
            ]
        },

        "help_view_sender": {
            "label": "How to see the real sender address",
            "risk_level": "low",
            "solution": "Sometimes the name you see in your email app is not the real sender. Here's how to check the actual email address.",
            "reassurance": "You're not expected to know this â€” email apps hide the real address by default.",
            "steps": [
                "Gmail: Tap the sender's name, then choose 'Show details'.",
                "Yahoo Mail: Tap the sender's name and look under 'From'.",
                "iCloud Mail: Tap the arrow next to the sender's name.",
                "Outlook (mobile): Tap the sender's name, then 'View email address'.",
                "Outlook (desktop): Doubleâ€‘click the message and look at the 'From' field."
            ]
        }
    }


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    message = request.form.get("message", "").strip()
    sender = request.form.get("sender", "").strip()
    reasons = analyze_text(message)

    # Run sender-email analysis (optional)
    sender_reasons = analyze_sender_email(sender) if sender is not None else []

    # Merge message reasons and sender reasons (preserve original order)
    merged = reasons + sender_reasons

    # Ensure unique reasons and that 'help_view_sender' appears at most once
    seen = set()
    all_reasons = []
    for r in merged:
        if r not in seen:
            all_reasons.append(r)
            seen.add(r)

    findings = build_findings(all_reasons)

    general_next_steps = [
        "Do not click links or open attachments from suspicious messages.",
        "Verify the sender by contacting the company using official channels.",
        "Report the message to your email provider or IT (if relevant).",
        "If you clicked or shared info, change passwords and contact your bank."
    ]

    return render_template("result.html", message=message, findings=findings, next_steps=general_next_steps)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
