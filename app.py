from __future__ import annotations

import streamlit as st

from phish_detector import analyze_url
from phish_detector.batch import analyze_urls, extract_urls_from_csv_text, extract_urls_from_text, summarize_batch

st.set_page_config(
    page_title="Phishing Link Detector",
    page_icon="🛡️",
    layout="wide",
)

st.markdown(
    """
    <style>
      .stApp {
        background:
          radial-gradient(circle at top left, rgba(255, 196, 87, 0.16), transparent 30%),
          radial-gradient(circle at top right, rgba(46, 196, 182, 0.15), transparent 28%),
          linear-gradient(180deg, #07111f 0%, #0d1b2a 100%);
        color: #ecf2ff;
      }
      .hero {
        padding: 2rem 0 1rem 0;
      }
      .hero h1 {
        font-size: 3rem;
        line-height: 1.05;
        margin-bottom: 0.5rem;
        color: #f8fbff;
      }
      .hero p {
        max-width: 52rem;
        font-size: 1.05rem;
        color: rgba(236, 242, 255, 0.82);
      }
      .card {
        background: rgba(11, 20, 35, 0.72);
        border: 1px solid rgba(148, 163, 184, 0.18);
        border-radius: 18px;
        padding: 1.2rem 1.25rem;
        box-shadow: 0 18px 45px rgba(2, 8, 23, 0.22);
      }
      .metric {
        font-size: 2rem;
        font-weight: 700;
        color: #ffffff;
      }
      .label {
        letter-spacing: 0.08em;
        text-transform: uppercase;
        font-size: 0.72rem;
        color: rgba(191, 219, 254, 0.78);
      }
      .signal {
        margin: 0.65rem 0;
        padding: 0.85rem 0.95rem;
        border-left: 3px solid #45d483;
        background: rgba(15, 23, 42, 0.55);
        border-radius: 10px;
      }
      .signal.medium { border-left-color: #fbbf24; }
      .signal.high { border-left-color: #fb7185; }
      .stTextInput input,
      .stTextArea textarea {
        background: rgba(255,255,255,0.96) !important;
                color: #07111f !important;
                caret-color: #07111f !important;
        border-radius: 12px !important;
      }
            .stTextInput input::placeholder,
            .stTextArea textarea::placeholder {
                color: rgba(7, 17, 31, 0.5) !important;
            }
      .stButton button {
        background: linear-gradient(135deg, #39d98a, #2dd4bf) !important;
        color: #07111f !important;
        border: none !important;
        border-radius: 12px !important;
        font-weight: 700 !important;
      }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="hero">
      <h1>Phishing Link Detector</h1>
      <p>
        Analyze a single URL or scan a whole list. The detector uses transparent heuristics,
        optional context, and batch-friendly output so suspicious links are easy to review.
      </p>
    </div>
    """,
    unsafe_allow_html=True,
)


def _parse_optional_int(raw_value: str) -> int | None:
    text = raw_value.strip()
    if not text:
        return None
    try:
        value = int(text)
    except ValueError:
        return None
    return value if value >= 0 else None


def _render_analysis(result: dict[str, object]) -> None:
    score = int(result["score"])
    verdict = str(result["verdict"])
    confidence = str(result["confidence"])
    signals = list(result["signals"])

    metric_col1, metric_col2, metric_col3 = st.columns(3)
    metric_col1.markdown(
        f'<div class="card"><div class="label">Risk score</div><div class="metric">{score}/100</div></div>',
        unsafe_allow_html=True,
    )
    metric_col2.markdown(
        f'<div class="card"><div class="label">Verdict</div><div class="metric">{verdict}</div></div>',
        unsafe_allow_html=True,
    )
    metric_col3.markdown(
        f'<div class="card"><div class="label">Confidence</div><div class="metric">{confidence}</div></div>',
        unsafe_allow_html=True,
    )

    st.markdown('<div class="card" style="margin-top: 1rem;">', unsafe_allow_html=True)
    st.subheader("Signals")
    if signals:
        for signal in signals:
            signal_data = dict(signal)
            st.markdown(
                f'<div class="signal {signal_data["severity"]}"><strong>{signal_data["label"]}</strong><br>{signal_data["detail"]}</div>',
                unsafe_allow_html=True,
            )
    else:
        st.success("No strong phishing indicators were detected by the current heuristic set.")
    st.markdown("</div>", unsafe_allow_html=True)


def _collect_batch_urls(pasted_text: str, uploaded_file) -> list[str]:
    urls = extract_urls_from_text(pasted_text)

    if uploaded_file is not None:
        raw_text = uploaded_file.getvalue().decode("utf-8", errors="ignore")
        if uploaded_file.name.lower().endswith(".csv"):
            file_urls = extract_urls_from_csv_text(raw_text)
        else:
            file_urls = extract_urls_from_text(raw_text)
        for url in file_urls:
            if url not in urls:
                urls.append(url)

    return urls


single_tab, batch_tab = st.tabs(["Single URL", "Batch Scan"])

with single_tab:
    with st.form("single_url_form"):
        url = st.text_input("URL to inspect", placeholder="https://example.com/login")

        with st.expander("Optional context", expanded=False):
            domain_age_text = st.text_input(
                "Domain age in days",
                placeholder="Leave blank if unknown",
                help="If you know how long the domain has existed, enter the age in days.",
            )
            redirect_hops_text = st.text_input(
                "Observed redirect hops",
                placeholder="Leave blank if unknown",
                help="Enter how many redirects you observed before the final destination.",
            )

        col_left, col_right = st.columns([1.1, 0.9], gap="large")

        with col_left:
            analyze_clicked = st.form_submit_button("Analyze link", use_container_width=True)

        with col_right:
            st.markdown(
                """
                <div class="card">
                  <div class="label">What it checks</div>
                  <p style="margin-top:0.5rem; color: rgba(236,242,255,0.88);">
                    suspicious keywords, punycode, IP-address hosts, shortened links, redirect patterns,
                    subdomain overload, and optional context such as domain age.
                  </p>
                </div>
                """,
                unsafe_allow_html=True,
            )

    if analyze_clicked:
        domain_age_days = _parse_optional_int(domain_age_text)
        redirect_hops = _parse_optional_int(redirect_hops_text)

        _render_analysis(
            analyze_url(
                url,
                domain_age_days=domain_age_days,
                redirect_hops=redirect_hops,
            )
        )
        st.caption(
            "This tool provides a risk estimate, not a guarantee. Always verify sensitive links before entering credentials."
        )
    else:
        st.info("Enter a URL and click Analyze link to see the risk assessment.")

with batch_tab:
    st.markdown(
        """
        <div class="card">
          <div class="label">Batch scanning</div>
          <p style="margin-top:0.5rem; color: rgba(236,242,255,0.88);">
            Paste one URL per line, or upload a .txt / .csv file. The scanner deduplicates URLs and
            shows the verdict, score, and top signals for each entry.
          </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.form("batch_scan_form"):
        pasted_urls = st.text_area(
            "Paste URLs",
            placeholder="https://example.com\nhttps://bit.ly/secure-login\nhttp://185.199.108.153/login",
            height=180,
        )
        uploaded_file = st.file_uploader("Upload a .txt or .csv file", type=["txt", "csv"])

        batch_clicked = st.form_submit_button("Scan batch", use_container_width=True)

    if batch_clicked:
        batch_urls = _collect_batch_urls(pasted_urls, uploaded_file)

        if not batch_urls:
            st.warning("Add at least one URL in the text area or upload a file.")
        else:
            batch_results = analyze_urls(batch_urls)
            summary = summarize_batch(batch_results)

            summary_col1, summary_col2, summary_col3, summary_col4 = st.columns(4)
            summary_col1.markdown(
                f'<div class="card"><div class="label">Total</div><div class="metric">{summary["total"]}</div></div>',
                unsafe_allow_html=True,
            )
            summary_col2.markdown(
                f'<div class="card"><div class="label">Likely phishing</div><div class="metric">{summary["likely_phishing"]}</div></div>',
                unsafe_allow_html=True,
            )
            summary_col3.markdown(
                f'<div class="card"><div class="label">Suspicious</div><div class="metric">{summary["suspicious"]}</div></div>',
                unsafe_allow_html=True,
            )
            summary_col4.markdown(
                f'<div class="card"><div class="label">Probably safe</div><div class="metric">{summary["probably_safe"]}</div></div>',
                unsafe_allow_html=True,
            )

            table_rows = []
            for result in batch_results:
                signals = list(result["signals"])
                top_signals = ", ".join(signal["label"] for signal in signals[:3]) if signals else "None detected"
                table_rows.append(
                    {
                        "#": result["batch_index"],
                        "URL": result["input_url"],
                        "Score": result["score"],
                        "Verdict": result["verdict"],
                        "Confidence": result["confidence"],
                        "Top signals": top_signals,
                    }
                )

            st.dataframe(table_rows, use_container_width=True, hide_index=True)
    else:
        st.info("Paste URLs or upload a file, then click Scan batch.")