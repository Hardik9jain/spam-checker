from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import json
import os
import pickle
from functools import wraps
from datetime import datetime
from flask_mail import Mail, Message
from dotenv import load_dotenv
from twilio.rest import Client

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# Configure Flask-Mail
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

mail = Mail(app)

# Load ML model and vectorizer
with open("spam_model.pkl", "rb") as f:
    model = pickle.load(f)

with open("vectorizer.pkl", "rb") as f:
    vectorizer = pickle.load(f)

# Twilio credentials
twilio_client = Client(
    os.getenv('TWILIO_ACCOUNT_SID'),
    os.getenv('TWILIO_AUTH_TOKEN')
)
TWILIO_PHONE_NUMBER = os.getenv('TWILIO_PHONE_NUMBER')

LOG_FILE = "message_log.json"

# ----------------- Utilities -----------------

def get_client_ip():
    return request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)

def save_log(entry):
    log = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            try:
                log = json.load(f)
            except json.JSONDecodeError:
                pass
    entry["username"] = session.get("username", "anonymous")
    entry["ip"] = get_client_ip()
    entry["user_agent"] = request.headers.get("User -Agent", "unknown")
    entry["timestamp"] = datetime.now().isoformat()
    log.append(entry)
    with open(LOG_FILE, "w") as f:
        json.dump(log, f, indent=2)

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

# ----------------- Routes -----------------

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        with open("users.json") as f:
            users = json.load(f)
        username = request.form['username']
        password = request.form['password']
        user = next((u for u in users if u['username'] == username and u['password'] == password), None)
        if user:
            session['username'] = username
            session['role'] = user.get('role', 'user')
            return redirect(url_for('admin_dashboard' if session['role'] == 'admin' else 'index'))
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        phone = request.form['phone']

        # Save user
        user_data = {
            'username': username,
            'email': email,
            'password': password,
            'phone': phone
        }

        try:
            with open("users.json", "r+") as f:
                users = json.load(f)
                users.append(user_data)
                f.seek(0)
                json.dump(users, f, indent=2)
        except FileNotFoundError:
            with open("users.json", "w") as f:
                json.dump([user_data], f, indent=2)

        # Send confirmation email
        try:
            msg = Message('Welcome to "SPAM Checker" APP',
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[email])
            msg.body = f'Hi {username}, your registration was successful!'
            mail.send(msg)
        except Exception as e:
            flash(f"Email failed: {str(e)}", "danger")

        # Send confirmation SMS
        try:
            twilio_client.messages.create(
                body=f"Hi {username}, welcome to SPAM Checker APP! Your registration was successful!",
                from_=TWILIO_PHONE_NUMBER,
                to=phone
            )
        except Exception as e:
            flash(f"SMS failed: {str(e)}", "danger")

        flash('Signup successful! Email and SMS confirmation sent.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop("username", None)
    session.pop("role", None)
    return redirect(url_for("login"))

@app.route('/admin')
@login_required
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect(url_for('admin_login'))

    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            logs = json.load(f)
    return render_template("admin_dashboard.html", logs=logs[::-1])

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        with open("users.json") as f:
            users = json.load(f)

        username = request.form['username']
        password = request.form['password']

        user = next((u for u in users if u['username'] == username and u['password'] == password and u.get('role') == 'admin'), None)

        if user:
            session['username'] = username
            session['role'] = 'admin'
            return redirect(url_for('admin_dashboard'))
        return render_template("admin_login.html", error="Invalid admin credentials")

    return render_template("admin_login.html")

@app.route('/index')
@login_required
def index():
    return render_template("index.html")

@app.route('/check-spam', methods=['POST'])
def check_spam():
    data = request.get_json()
    message = data.get('message', '').lower()

    spam_keywords = ["win money", "free", "credit card", "click here", "urgent", "act now", "prize", "lottery", "buy now"]
    is_spam = any(word in message for word in spam_keywords)

    entry = {
        "message": message,
        "is_spam": is_spam,
        "categories": [],
    }
    save_log({
        "message": message,
        "is_spam": is_spam,
        "categories": [],
        "predicted_label": "spam" if is_spam else "ham"
    })

    return jsonify({
        "is_spam": is_spam,
        "message": "🚫 This message looks like spam." if is_spam else "✅ This message looks clean."
    })

@app.route('/check-categories', methods=['POST'])
def check_categories():
    data = request.get_json()
    message = data.get('message', '').lower()

    categories = {
        "Financial Scam": ["bank account", "credit card", "loan", "transfer funds"],
        "Advertisement": ["buy now", "limited offer", "discount", "sale"],
        "Lottery/Prize": ["you won", "claim prize", "lottery", "winner"],
        "Phishing/Urgent": ["urgent", "act now", "verify", "click link"]
    }

    detected = [cat for cat, keywords in categories.items() if any(word in message for word in keywords)]

    log_entry = {
        "message": message,
        "is_spam": False,
        "categories": detected
    }
    save_log({
        "message": message,
        "is_spam": False,
        "categories": detected,
        "predicted_label": "ham"
    })

    return jsonify({
        "categories": detected,
        "message": f"🚫 Spam Categories Detected: {', '.join(detected)}" if detected else "✅ No spam category detected."
    })

@app.route("/logs")
@login_required
def show_logs():
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            logs = json.load(f)
    return render_template("logs.html", logs=logs[::-1])

@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")

@app.route("/contact")
@login_required
def contact_page():
    return render_template("contact.html")

@app.route("/evaluation")
@login_required
def evaluation():
    return render_template("evaluation.html")

@app.route("/api/evaluation")
@login_required
def evaluation_api():
    try:
        if not os.path.exists(LOG_FILE):
            return jsonify({"TP": 0, "TN": 0, "FP": 0, "FN": 0})

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

    except Exception as e:
        print("Error in evaluation route:", e)
        return jsonify({"TP": 0, "TN": 0, "FP": 0, "FN": 0})

@app.route('/dashboard')
@login_required
def dashboard():
    # Load data from JSON file
    with open('message_log.json', 'r') as f:
        data = json.load(f)

    # Filter messages by predicted label
    spam_messages = [msg['message'] for msg in data if msg.get('predicted_label') == 'spam']
    non_spam_messages = [msg['message'] for msg in data if msg.get('predicted_label') == 'ham']

    # Count statistics
    stats = {
        'total': len(data),
        'spam': len(spam_messages),
        'non_spam': len(non_spam_messages)
    }

    return render_template('dashboard.html', stats=stats,
                           spam_messages=spam_messages,
                           non_spam_messages=non_spam_messages)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')

        if not email:
            return render_template("forgot_password.html", error="Please enter your email.")

        if os.path.exists("users.json"):
            with open("users.json", "r") as f:
                users = json.load(f)

            user = next((u for u in users if u['email'] == email), None)

            if user:
                # Generate a simple password reset link (for demo purposes only)
                reset_link = f"http://localhost:5000/reset-password/{user['username']}"
                
                msg = Message("Password Reset Link",
                              sender=app.config['MAIL_USERNAME'],
                              recipients=[email])
                msg.body = f"Hi {user['username']},\n\nClick the link below to reset your password:\n{reset_link}"
                mail.send(msg)

                return render_template("forgot_password.html", success="Password reset link sent to your email.")
            else:
                return render_template("forgot_password.html", error="Email not found.")
    
    return render_template("forgot_password.html")

@app.route('/reset-password/<username>', methods=['GET', 'POST'])
def reset_password(username):
    if request.method == 'POST':
        new_password = request.form.get('password')

        if os.path.exists("users.json"):
            with open("users.json", "r") as f:
                users = json.load(f)

            for u in users:
                if u['username'] == username:
                    u['password'] = new_password
                    break

            with open("users.json", "w") as f:
                json.dump(users, f, indent=2)

            return redirect(url_for('login'))

    return render_template("reset_password.html", username=username)

# ----------------- Run App -----------------
if __name__ == "__main__":
    app.run(debug=True)
