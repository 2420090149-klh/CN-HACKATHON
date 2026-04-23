# Phishing Link Detector

A small Streamlit app that checks one URL or a whole list for common phishing and scam indicators. It gives you a risk score, a plain-English verdict, and the specific signals that influenced the result.

## Features

- Fast heuristic analysis with no training data required
- Clear explanation of suspicious signals
- Modern Streamlit UI for quick manual checks
- Batch scan mode for pasted URLs or uploaded .txt / .csv files
- Testable core logic so you can extend it later with machine learning

## How it works

The detector scores a link using transparent signals such as:

- IP-address hosts
- punycode and lookalike domains
- URL shorteners
- redirect parameters and open-redirect targets
- suspicious keywords like `login`, `verify`, or `password`
- optional domain age and redirect hop context
- long paths, long query strings, and excessive subdomains
- brand-impersonation patterns

## Run it

Install Python 3.10 or newer, then install dependencies:

```bash
pip install -e .
```

Start the app:

```bash
streamlit run app.py
```

Run the tests:

```bash
pytest
```

## Project structure

- `app.py` - Streamlit UI
- `src/phish_detector/batch.py` - batch parsing and summary helpers
- `src/phish_detector/analyzer.py` - URL scoring logic
- `tests/test_analyzer.py` - basic behavior checks
- `tests/test_batch.py` - batch parsing and summary checks

## Notes

This project is a screening tool, not a guarantee. Users should still verify the destination before entering passwords, payment details, or one-time codes.
