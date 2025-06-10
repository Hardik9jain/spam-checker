from flask import Flask, render_template, request, jsonify
import pickle, json, os
from datetime import datetime

app = Flask(__name__, template_folder='ml_templates')

with open("spam_model.pkl", "rb") as f:
    model = pickle.load(f)

with open("vectorizer.pkl", "rb") as f:
    vectorizer = pickle.load(f)

LOG_FILE = "message_log.json"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/checkspam_ml", methods=["POST"])
def checkspam_ml():
    if request.content_type != 'application/json':
        return jsonify({"error": "Unsupported Media Type"}), 415

    data = request.get_json()
    message = data.get("message", "")
    actual_label = data.get("actual", None)

    X_input = vectorizer.transform([message])
    predicted = model.predict(X_input)[0]
    is_spam = bool(predicted)

    entry = {
        "message": message,
        "is_spam": is_spam,
        "categories": [],
        "predicted_label": "spam" if is_spam else "ham",
        "actual_label": actual_label,
        "timestamp": datetime.now().isoformat()
    }

    if actual_label:
        if is_spam and actual_label == "ham":
            entry["evaluation"] = "False Positive"
        elif not is_spam and actual_label == "spam":
            entry["evaluation"] = "False Negative"
        elif is_spam and actual_label == "spam":
            entry["evaluation"] = "True Positive"
        elif not is_spam and actual_label == "ham":
            entry["evaluation"] = "True Negative"

    save_log(entry)

    return jsonify({
        "is_spam": is_spam,
        "message": "🚫 This message looks like spam." if is_spam else "✅ This message looks clean.",
        "evaluation": entry.get("evaluation", None)
    })

@app.route("/evaluation")
def evaluation():
    if not os.path.exists(LOG_FILE):
        return jsonify({})
    with open(LOG_FILE) as f:
        logs = json.load(f)
    counts = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
    for log in logs:
        eval = log.get("evaluation", "")
        if eval == "True Positive":
            counts["TP"] += 1
        elif eval == "True Negative":
            counts["TN"] += 1
        elif eval == "False Positive":
            counts["FP"] += 1
        elif eval == "False Negative":
            counts["FN"] += 1
    return jsonify(counts)

def save_log(entry):
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            try:
                logs = json.load(f)
            except:
                pass
    logs.append(entry)
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=2)

if __name__ == "__main__":
    app.run(port=5001, debug=True)  # different port from main app
