from phish_detector.batch import analyze_urls, extract_urls_from_csv_text, extract_urls_from_text, summarize_batch


def test_extract_urls_from_text_deduplicates_and_trims():
    urls = extract_urls_from_text(
        """
        https://example.com/login
        bit.ly/secure-login
        https://example.com/login
        # comment
        "https://python.org"
        """
    )

    assert urls == ["https://example.com/login", "bit.ly/secure-login", "https://python.org"]


def test_extract_urls_from_csv_text_reads_cells():
    urls = extract_urls_from_csv_text(
        """
        url,note
        https://example.com/login,primary
        http://185.199.108.153/login,secondary
        """
    )

    assert urls == ["https://example.com/login", "http://185.199.108.153/login"]


def test_batch_analysis_returns_summary_counts():
    results = analyze_urls([
        "https://python.org",
        "https://bit.ly/secure-login",
        "http://185.199.108.153/login",
    ])

    summary = summarize_batch(results)

    assert summary["total"] == 3
    assert summary["likely_phishing"] + summary["suspicious"] >= 1
    assert summary["probably_safe"] >= 1