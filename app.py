from bson import ObjectId
from dotenv import load_dotenv
from flask import Flask, render_template, request, send_file, jsonify, redirect, flash, session, url_for
from flask_socketio import SocketIO
from pymongo import MongoClient
from apscheduler.schedulers.background import BackgroundScheduler
from flask_cors import CORS
import requests
from email_alert import send_phishing_alert_email
import pickle
from app_gmail_api import fetch_and_store_emails, get_gmail_service
from werkzeug.utils import secure_filename
from functools import wraps
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
import os
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from oauthlib.oauth2 import WebApplicationClient



load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")  # Required for session management

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

UPLOAD_FOLDER = 'uploads/pcap_files'
REPORT_FOLDER = 'uploads/reports'
ALLOWED_EXTENSIONS = {'pcap'}

REPORT_FOLDER = 'uploads/reports'
PCAP_FOLDER = 'uploads/pcap_files'

app.config['PCAP_FOLDER'] = PCAP_FOLDER
app.config['REPORT_FOLDER'] = REPORT_FOLDER

# Create directories if not exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)    
os.makedirs(PCAP_FOLDER, exist_ok=True)    

socketio = SocketIO(app)
MONGO_URI = os.getenv("MONGO_URI")
# 🔹 Connect to MongoDB
client = MongoClient(MONGO_URI )  # Add your MongoDB URI here if different
db = client["email_db"]
emails_collection = db["emails"]
admins_collection = db["admins"]

# MongoDB Config
app.config["MONGO_URI"] = MONGO_URI

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"  # Redirect to login if not authenticated

# Google OAuth Config
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")

GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
client = WebApplicationClient(GOOGLE_CLIENT_ID)



# 🔹 Load ML Model & Vectorizer
model = pickle.load(open("models/email_model.pkl", "rb"))
vectorizer = pickle.load(open("models/vectorizer.pkl", "rb"))


class User(UserMixin):
    def __init__(self, user):
        self.id = str(user["_id"])
        self.email = user["email"]

    def get_id(self):
        return self.id

# User Loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    if user:
        return User(user)
    return None
# class User(UserMixin):
#     def __init__(self, user):
#         self.id = str(user["_id"])  # Convert ObjectId to string
#         self.email = user["email"]

def admin_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def user_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def analyze_pcap(filepath):
    from scapy.all import rdpcap
    packets = rdpcap(filepath)
    num_packets = len(packets)
    protocols = set(packet.proto for packet in packets if hasattr(packet, 'proto'))
    return {
        'filename': os.path.basename(filepath),
        'num_packets': num_packets,
        'protocols': list(protocols)
    }


def send_email(recipient_email, pdf_path):
    sender_email = os.getenv("SENDER_EMAIL")
    app_password = os.getenv("APP_PASSWORD")# Use the generated app password from Google
    subject = 'Security Analysis Report - [Phishing Incident Response]'

    email_template = f"""
    <html>
    <head></head>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <p>Dear Valued User,</p>

        <p>We have completed the analysis of your submitted network traffic data. Attached to this email is the detailed Security Analysis Report summarizing our findings.</p>

        <p><strong>Key Highlights:</strong></p>
        <ul>
            <li>Identified potential phishing and malicious traffic patterns.</li>
            <li>Packet-level inspection conducted to detect anomalies.</li>
            <li>Recommendations provided for improving your network security posture.</li>
        </ul>

        <p>We encourage you to review the attached report carefully and implement the suggested security measures to safeguard your systems.</p>

        <p>If you have any questions or need further assistance, feel free to contact our security team.</p>

        <p>Best regards,<br>
        <strong>Cybersecurity Analysis Team</strong><br>
        [Your Company Name]</p>
    </body>
    </html>
    """

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject
    msg.attach(MIMEText(email_template, 'html'))

    with open(pdf_path, 'rb') as attachment:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename={os.path.basename(pdf_path)}')
        msg.attach(part)

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(sender_email, app_password)
    text = msg.as_string()
    server.sendmail(sender_email, recipient_email, text)
    server.quit()

def background_email_fetch():
    """Background job to fetch new emails periodically and emit to frontend."""
    new_emails = fetch_and_store_emails()

    if new_emails:
        for email in new_emails:
            socketio.emit("new_email", email)  # Real-time push to frontend



def get_gmail_service():
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)

    # Handle token refresh
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())

    # If no creds or invalid, start OAuth2 flow
    if not creds or not creds.valid:
        return None  # Indicating the user needs authentication

    return build('gmail', 'v1', credentials=creds)


# Home Route (Index Page)
@app.route('/')
# @user_login_required
def home():
    return render_template('index.html')

# Signup Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if mongo.db.users.find_one({"email": email}):
            flash('User already exists', 'error')
            return redirect(url_for('signup'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        mongo.db.users.insert_one({"email": email, "password": hashed_password})

        flash('Signup successful. Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = mongo.db.users.find_one({"email": email})

        if user and bcrypt.check_password_hash(user['password'], password):
            user_obj = User(user)
            login_user(user_obj)

            next_page = request.args.get('next')
            # print("Redirecting to:", next_page or 'home')
            return redirect(next_page or url_for('home'))

        flash('Invalid email or password', 'error')
        return redirect(url_for('login'))

    return render_template('login.html')


# Google OAuth Login
@app.route('/login/google')
def login_google():
    google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=url_for("callback_google", _external=True),
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)

@app.route('/signup/google')
def signup_google():
    google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=url_for("callback_google", _external=True),
        scope=["openid", "email", "profile"],
        )

    return redirect(request_uri)

# Google OAuth Callback
@app.route('/callback/google')
def callback_google():
    code = request.args.get("code")
    google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
    token_endpoint = google_provider_cfg["token_endpoint"]

    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code,
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )
    client.parse_request_body_response(token_response.text)

    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body).json()

    # Add user to MongoDB if not already exists
    user = mongo.db.users.find_one({"email": userinfo_response["email"]})
    if not user:
        mongo.db.users.insert_one({"email": userinfo_response["email"]})

    user = mongo.db.users.find_one({"email": userinfo_response["email"]})
    login_user(User(user))
    return redirect(url_for('home'))

# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/landing")
# @user_login_required
def landing_page():
    return render_template("landing_page.html")
@app.route('/check-auth')
def check_auth():
    """Check if token is valid."""
    service = get_gmail_service()
    if service:
        session["authenticated"] = True
        return jsonify({"authenticated": True})
    return jsonify({"authenticated": False})

@app.route('/authenticate')
def authenticate():
    """Force user authentication and redirect to dashboard."""
    try:
        flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
        creds = flow.run_local_server(port=5003)

        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

        session["authenticated"] = True
        return redirect(url_for('dashboard'))
    except Exception as e:
        return f"Authentication failed: {str(e)}", 403

@app.route('/dashboard')
def dashboard():
    """Show the dashboard if authenticated."""
    if not session.get("authenticated"):
        return redirect(url_for("landing_page"))

    # Fetch emails from MongoDB collection (assuming this part is correct in your original code)
    emails = list(emails_collection.find().sort("date", -1))
    return render_template('dashboard.html', emails=emails)

@app.route("/fetch-emails", methods=["GET"])
def fetch_emails():
    if not session.get("authenticated"):
        return jsonify({"error": "Unauthorized. Please authenticate first."}), 401

    emails = list(emails_collection.find({}, {"_id": 0}).sort("date", -1))
    return jsonify(emails)


@app.route("/postphishing")
# @user_login_required
def postphishing():
    return render_template("postphishing.html")

@app.route('/upload-pcap', methods=['POST'])
def upload_pcap():
    if 'pcap' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['pcap']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)
        return jsonify({'message': 'File uploaded successfully', 'file_path': file_path}), 200

    return jsonify({'error': 'Invalid file format'}), 400



@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin = admins_collection.find_one({'username': username, 'password': password})

        if admin:
            session['admin_logged_in'] = True
            flash('Login Successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid Username or Password', 'danger')

    return render_template('admin_login.html')

# Admin Dashboard Route
@app.route('/admin/dashboard')
@admin_login_required
def index():
    global pcap_details
    pcap_files = os.listdir(app.config['PCAP_FOLDER'])
    pcap_details = [analyze_pcap(os.path.join(app.config['PCAP_FOLDER'], file)) for file in pcap_files]
    return render_template('admin_dashboard.html', pcap_details=pcap_details)


# Logout Route
@app.route('/admin/logout')
@admin_login_required
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('Logged out successfully.', 'info')
    return redirect(url_for('admin_login'))


@app.route('/download/<filename>')
def download_file(filename):
    return send_file(os.path.join(app.config['PCAP_FOLDER'], filename), as_attachment=True)


@app.route('/upload_email_report', methods=['POST'])
def upload_email_report():
    if 'pdf_file' not in request.files or 'email' not in request.form:
        return 'Missing file or email'

    pdf_file = request.files['pdf_file']
    recipient_email = request.form['email']

    if pdf_file.filename == '':
        return 'No selected file'

    filename = secure_filename(pdf_file.filename)
    pdf_path = os.path.join(app.config['REPORT_FOLDER'], filename)
    pdf_file.save(pdf_path)

    send_email(recipient_email, pdf_path)
    return 'Email sent successfully'    
@app.route('/get_phishing_stats')
def get_phishing_stats():
    safe_count = emails_collection.count_documents({'status': 'Safe Email'})
    phishing_count = emails_collection.count_documents({'status': 'Phishing Email'})

    return jsonify({'safe_count': safe_count, 'phishing_count': phishing_count})


@socketio.on('request_stats')
def handle_request_stats():
    try:
        safe_count = emails_collection.count_documents({'status': 'Safe Email'})
        phishing_count = emails_collection.count_documents({'status': 'Phishing Email'})

        socketio.emit('update_stats', {
            'safe_count': safe_count,
            'phishing_count': phishing_count
        })
    except Exception as e:
        socketio.emit('update_stats_error', {'error': str(e)})

@app.route("/analyze-email", methods=["POST"])
def analyze_email():
    data = request.json
    email_id = data.get("message_id")
    email_text = data.get("text", "")
    email_subject = data.get("subject", "No Subject")
    email_from = data.get("from", "Unknown")

    if not email_text:
        return jsonify({"error": "No email content provided"}), 400

    email_vector = vectorizer.transform([email_text])
    prediction = model.predict(email_vector)[0]
    prediction_result = "phishing" if prediction == 1 else "safe"

    # Update email status in the database
    if email_id:
        emails_collection.update_one(
            {"message_id": email_id},
            {"$set": {"status": prediction_result}}
        )

    # If phishing → Send email notification + Real-time socket alert
    if prediction_result == "phishing":
        # 📧 Send Email Notification
        user_email = os.getenv("USER_EMAIL")  # 📧 Replace with the actual user's email
        send_phishing_alert_email(user_email, email_subject, email_from)

        # ⚠️ Emit Real-time Frontend Notification via Socket.IO
        socketio.emit("phishing_alert", {"from": email_from, "subject": email_subject})

    return jsonify({"message_id": email_id, "prediction": prediction_result})


if __name__ == "__main__":
    # 🔹 Start Background Job for Automatic Email Fetching Every 60 Seconds
    scheduler = BackgroundScheduler()
    scheduler.add_job(background_email_fetch, "interval", seconds=60)
    scheduler.start()

    print("🚀 Flask App is running with Real-time Email Fetching and Socket.IO")
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)