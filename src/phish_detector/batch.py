from __future__ import annotations

import csv
import io
from collections.abc import Iterable

from .analyzer import analyze_url


def extract_urls_from_text(text: str) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()

    for raw_part in _split_candidates(text):
        candidate = raw_part.strip().strip('"\'').strip("[](){}").strip()
        if not candidate or candidate.startswith("#") or not _looks_like_url(candidate):
            continue
        if candidate not in seen:
            seen.add(candidate)
            urls.append(candidate)

    return urls


def extract_urls_from_csv_text(text: str) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    rows = list(csv.reader(io.StringIO(text)))
    start_index = 0

    if rows and len(rows) > 1 and not any(_looks_like_url(cell) for cell in rows[0]):
        start_index = 1

    for row in rows[start_index:]:
        for cell in row:
            candidate = cell.strip().strip('"\'').strip("[](){}").strip()
            if not candidate or candidate.startswith("#") or not _looks_like_url(candidate):
                continue
            if candidate not in seen:
                seen.add(candidate)
                urls.append(candidate)

    return urls


def analyze_urls(urls: Iterable[str]) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for index, url in enumerate(urls, start=1):
        result = analyze_url(url)
        result["batch_index"] = index
        results.append(result)
    return results


def summarize_batch(results: Iterable[dict[str, object]]) -> dict[str, int]:
    summary = {"total": 0, "likely_phishing": 0, "suspicious": 0, "probably_safe": 0}
    for result in results:
        summary["total"] += 1
        verdict = str(result.get("verdict", ""))
        if verdict == "Likely phishing":
            summary["likely_phishing"] += 1
        elif verdict == "Suspicious":
            summary["suspicious"] += 1
        else:
            summary["probably_safe"] += 1
    return summary


def _split_candidates(text: str) -> list[str]:
    normalized = text.replace("\r", "\n").replace(";", "\n").replace("\t", "\n")
    parts: list[str] = []
    for line in normalized.split("\n"):
        parts.extend(segment for segment in line.split(",") if segment.strip())
    return parts


def _looks_like_url(text: str) -> bool:
    candidate = text.strip().lower()
    if candidate.startswith(("http://", "https://", "www.")):
        return True
    if " " in candidate:
        return False
    return "." in candidate and len(candidate) >= 4