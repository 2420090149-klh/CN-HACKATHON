from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, unquote, urlparse

SUSPICIOUS_KEYWORDS = {
    "account",
    "confirm",
    "free",
    "gift",
    "invoice",
    "login",
    "mfa",
    "payment",
    "password",
    "verify",
    "wallet",
}

SHORTENER_HOSTS = {
    "bit.ly",
    "cutt.ly",
    "lnkd.in",
    "ow.ly",
    "rb.gy",
    "t.co",
    "tinyurl.com",
    "url.in",
}

BRAND_IMPERSONATION_PATTERNS = (
    r"paypa1",
    r"g00gle",
    r"micr0soft",
    r"faceb00k",
    r"amaz0n",
)

REDIRECT_PARAM_NAMES = {
    "callback",
    "continue",
    "destination",
    "goto",
    "next",
    "redirect",
    "return",
    "target",
    "url",
}


@dataclass(frozen=True)
class Signal:
    label: str
    severity: str
    detail: str
    points: int


def analyze_url(
    raw_url: str,
    *,
    domain_age_days: int | None = None,
    redirect_hops: int | None = None,
) -> dict[str, Any]:
    normalized = raw_url.strip()
    if not normalized:
        return _result(
            raw_url,
            score=100,
            verdict="Suspicious",
            signals=[
                Signal(
                    label="Missing URL",
                    severity="high",
                    detail="No URL was provided.",
                    points=100,
                )
            ],
        )

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", normalized):
        normalized = f"https://{normalized}"

    parsed = urlparse(normalized)
    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    lower_host = host.lower()
    signals: list[Signal] = []

    if parsed.scheme not in {"http", "https"}:
        signals.append(
            Signal(
                label="Unusual scheme",
                severity="medium",
                detail=f"The URL uses the {parsed.scheme!r} scheme.",
                points=15,
            )
        )

    if not host:
        signals.append(
            Signal(
                label="Missing host",
                severity="high",
                detail="The URL does not include a valid hostname.",
                points=40,
            )
        )

    if host:
        try:
            ipaddress.ip_address(host)
            signals.append(
                Signal(
                    label="IP address host",
                    severity="high",
                    detail="The link uses an IP address instead of a domain name.",
                    points=35,
                )
            )
        except ValueError:
            pass

    if lower_host.startswith("xn--") or ".xn--" in lower_host:
        signals.append(
            Signal(
                label="Punycode domain",
                severity="high",
                detail="The hostname contains punycode, which can hide lookalike characters.",
                points=30,
            )
        )

    if lower_host in SHORTENER_HOSTS:
        signals.append(
            Signal(
                label="URL shortener",
                severity="medium",
                detail="Shortened links hide the final destination.",
                points=20,
            )
        )

    if _subdomain_count(lower_host) >= 3:
        signals.append(
            Signal(
                label="Excessive subdomains",
                severity="medium",
                detail="Too many subdomains can be used to disguise the real site.",
                points=15,
            )
        )

    if len(host) >= 24:
        signals.append(
            Signal(
                label="Long hostname",
                severity="low",
                detail="Very long hostnames are often harder to inspect quickly.",
                points=8,
            )
        )

    if len(path) + len(query) > 80:
        signals.append(
            Signal(
                label="Long path or query",
                severity="medium",
                detail="The path or query string is unusually long.",
                points=10,
            )
        )

    url_text = f"{lower_host}{path}?{query}".lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url_text:
            signals.append(
                Signal(
                    label=f"Contains '{keyword}'",
                    severity="medium",
                    detail=f"The link contains the keyword {keyword!r}.",
                    points=10,
                )
            )

    if any(re.search(pattern, lower_host) for pattern in BRAND_IMPERSONATION_PATTERNS):
        signals.append(
            Signal(
                label="Brand impersonation pattern",
                severity="high",
                detail="The hostname resembles a common brand spoofing pattern.",
                points=30,
            )
        )

    if "@" in normalized:
        signals.append(
            Signal(
                label="Username or @ symbol",
                severity="high",
                detail="An @ symbol can hide the real destination in some URLs.",
                points=25,
            )
        )

    if parsed.scheme == "https" and not host.endswith(tuple([".com", ".org", ".net", ".edu", ".gov"])):
        signals.append(
            Signal(
                label="Unusual top-level domain",
                severity="low",
                detail="The domain does not use a common top-level domain.",
                points=6,
            )
        )

    if any(token in unquote(path).lower() for token in ("login", "verify", "secure", "update")):
        signals.append(
            Signal(
                label="Credential-themed path",
                severity="medium",
                detail="The path suggests a login, verification, or update flow.",
                points=10,
            )
        )

    signals.extend(_redirect_signals(parsed.query, host))

    if domain_age_days is not None:
        if domain_age_days <= 30:
            signals.append(
                Signal(
                    label="Very new domain",
                    severity="high",
                    detail="The domain age is very recent, which is common in short-lived scam campaigns.",
                    points=25,
                )
            )
        elif domain_age_days <= 90:
            signals.append(
                Signal(
                    label="Young domain",
                    severity="medium",
                    detail="The domain was registered recently enough to warrant extra caution.",
                    points=15,
                )
            )
        elif domain_age_days <= 180:
            signals.append(
                Signal(
                    label="Limited domain history",
                    severity="low",
                    detail="The domain is still relatively new compared with established sites.",
                    points=6,
                )
            )

    if redirect_hops is not None:
        if redirect_hops >= 3:
            signals.append(
                Signal(
                    label="Redirect chain",
                    severity="high",
                    detail="The link requires several redirects before reaching the final destination.",
                    points=20,
                )
            )
        elif redirect_hops >= 1:
            signals.append(
                Signal(
                    label="Redirect hop",
                    severity="medium",
                    detail="The link uses at least one redirect hop before the final destination.",
                    points=10,
                )
            )

    score = min(100, sum(signal.points for signal in signals))
    verdict = _verdict(score)

    return _result(raw_url, score=score, verdict=verdict, signals=signals)


def _result(raw_url: str, score: int, verdict: str, signals: list[Signal]) -> dict[str, Any]:
    return {
        "input_url": raw_url,
        "score": score,
        "verdict": verdict,
        "confidence": _confidence_from_score(score),
        "signals": [signal.__dict__ for signal in signals],
    }


def _verdict(score: int) -> str:
    if score >= 70:
        return "Likely phishing"
    if score >= 40:
        return "Suspicious"
    return "Probably safe"


def _confidence_from_score(score: int) -> str:
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def _subdomain_count(host: str) -> int:
    if not host:
        return 0
    parts = host.split(".")
    return max(0, len(parts) - 2)


def _redirect_signals(query: str, host: str) -> list[Signal]:
    signals: list[Signal] = []
    for key, value in parse_qsl(query, keep_blank_values=True):
        normalized_key = key.lower()
        normalized_value = unquote(value).strip()
        if normalized_key not in REDIRECT_PARAM_NAMES:
            continue

        signals.append(
            Signal(
                label="Redirect parameter",
                severity="medium",
                detail=f"The URL includes a {normalized_key!r} parameter.",
                points=8,
            )
        )

        redirect_target = urlparse(normalized_value)
        target_host = redirect_target.hostname or ""
        if target_host and target_host.lower() != host.lower():
            signals.append(
                Signal(
                    label="Open redirect target",
                    severity="high",
                    detail="A redirect parameter points to a different host.",
                    points=18,
                )
            )

    return signals
