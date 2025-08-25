# Phishing Awareness Helper

A minimal Flask web app to teach users about phishing red flags. Users can paste a URL or email headers and receive simple heuristic warnings.

## Setup

1. Create and activate a virtual environment (recommended).
2. Install dependencies:

```
pip install -r requirements.txt
```

## Run

```
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

## Notes

- This app does not send emails or collect credentials. It’s for training only.
- Heuristics are intentionally simple and may produce false positives/negatives.

