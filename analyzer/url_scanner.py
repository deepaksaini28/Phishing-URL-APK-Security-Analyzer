import ipaddress
import math
import os
import re
from functools import lru_cache
from urllib.parse import urlsplit


SUSPICIOUS_TERMS = {
    "account",
    "auth",
    "bank",
    "billing",
    "confirm",
    "credential",
    "login",
    "password",
    "pay",
    "recover",
    "secure",
    "signin",
    "update",
    "verify",
}


def _entropy(value):
    if not value:
        return 0.0
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in
                (value.count(char) for char in set(value)))


def _normalized_url(value):
    value = value.strip()
    if not value:
        raise ValueError("Enter a URL to scan.")
    candidate = value if "://" in value else "https://" + value
    try:
        parsed = urlsplit(candidate)
        hostname = (parsed.hostname or "").rstrip(".").lower()
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("Enter a valid HTTP or HTTPS URL.") from exc
    if parsed.scheme.lower() not in ("http", "https") or not hostname:
        raise ValueError("Enter a valid HTTP or HTTPS URL.")
    if any(character.isspace() for character in hostname):
        raise ValueError("Enter a valid HTTP or HTTPS URL; the hostname contains whitespace.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing embedded credentials are not accepted.")
    if len(candidate) > 4096:
        raise ValueError("URL is too long (maximum 4,096 characters).")
    try:
        ascii_host = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("The domain name could not be interpreted.") from exc
    return candidate, parsed, ascii_host


@lru_cache(maxsize=1)
def _popular_domains(dataset_dir):
    path = os.path.join(dataset_dir, "top-1m.csv")
    result = set()
    if not os.path.isfile(path):
        return result
    try:
        with open(path, encoding="utf-8-sig", errors="replace") as handle:
            for line in handle:
                cells = line.strip().split(",", 1)
                if len(cells) == 2 and cells[1]:
                    result.add(cells[1].strip().lower())
    except OSError:
        return set()
    return result


@lru_cache(maxsize=4)
def _load_model(model_path, modified_at):
    try:
        import joblib

        return joblib.load(model_path)
    except (OSError, ValueError, ImportError, AttributeError) as exc:
        raise RuntimeError("The local URL model could not be loaded. Check the model artifact and dependencies.") from exc


def _predict_model(url, model_dir):
    model_path = os.path.join(model_dir, "url_model.joblib")
    if not os.path.isfile(model_path):
        return None
    try:
        modified_at = os.stat(model_path).st_mtime_ns
        model = _load_model(model_path, modified_at)
        probabilities = model.predict_proba([url])[0]
        phishing_index = list(model.classes_).index("1")
        return round(float(probabilities[phishing_index]), 4)
    except OSError as exc:
        raise RuntimeError("The local URL model could not be accessed.") from exc
    except (AttributeError, IndexError, ValueError) as exc:
        raise RuntimeError("The local URL model is incompatible with phishing-score inference.") from exc


def analyze_url(value, dataset_dir, model_dir):
    url, parsed, hostname = _normalized_url(value)
    points = 0
    findings = []
    host_parts = hostname.split(".")
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        points += 30
        findings.append(("high", "The hostname is an IP address rather than a domain."))
    if len(url) >= 120:
        points += 15
        findings.append(("medium", "The URL is unusually long."))
    elif len(url) >= 75:
        points += 8
        findings.append(("low", "The URL is longer than typical."))
    if not is_ip:
        if len(host_parts) >= 5:
            points += 12
            findings.append(("medium", "The hostname has several subdomain levels."))
        elif len(host_parts) == 4:
            points += 5
            findings.append(("low", "The hostname has multiple subdomain levels."))
    if "xn--" in hostname:
        points += 18
        findings.append(("medium", "The domain uses punycode encoding."))

    host_terms = set(re.findall(r"[a-z0-9]+", hostname))
    path_terms = set(re.findall(r"[a-z0-9]+", (parsed.path + " " + parsed.query).lower()))
    term_matches = sorted((host_terms | path_terms) & SUSPICIOUS_TERMS)
    if term_matches:
        points += min(24, 8 + 4 * (len(term_matches) - 1))
        findings.append(("medium", "The URL contains credential or account-related terms: "
                         + ", ".join(term_matches) + "."))

    if "@" in url:
        points += 20
        findings.append(("high", "The URL contains an @ character that can obscure its destination."))
    if parsed.scheme.lower() == "http":
        points += 8
        findings.append(("low", "The URL does not use HTTPS."))
    if len(re.findall(r"\d", hostname)) >= 6:
        points += 10
        findings.append(("medium", "The hostname contains an unusual number of digits."))
    if _entropy(hostname) >= 3.7 and len(hostname) >= 18:
        points += 8
        findings.append(("low", "The hostname has high character entropy."))
    if not findings:
        findings.append(("info", "No strong structural warning was identified."))

    popularity_match = hostname in _popular_domains(dataset_dir)
    if popularity_match:
        findings.append(("info", "The domain appears in the supplied top-1m popularity list. "
                         "Popularity is not a safety verdict."))

    model_probability = _predict_model(url, model_dir)
    rule_score = min(points, 100)
    score = rule_score
    if model_probability is not None:
        score = round(0.55 * rule_score + 0.45 * model_probability * 100)
        findings.append(("info", "A locally trained URL model estimates "
                         f"{model_probability:.0%} phishing likelihood; this is not a verdict."))

    risk = "Low" if score < 25 else "Moderate" if score < 55 else "High"
    return {
        "kind": "url",
        "subject": url,
        "risk": risk,
        "score": score,
        "rule_score": rule_score,
        "model_probability": model_probability,
        "domain": hostname,
        "scheme": parsed.scheme.lower(),
        "domain_popularity_match": popularity_match,
        "findings": [{"severity": level, "message": message} for level, message in findings],
        "limitations": [
            "The URL is analyzed locally; the application does not visit it or query live reputation services.",
            "A low-risk result does not establish that a site is legitimate.",
        ],
    }
