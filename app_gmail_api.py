import os
import pickle
import base64
from dotenv import load_dotenv
from pymongo import MongoClient
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from dateutil import parser
from datetime import datetime

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']


load_dotenv()
# 🔹 Connect to MongoDB
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI )
db = client["email_db"]
emails_collection = db["emails"]


def get_gmail_service():
    """Authenticate and return Gmail API service."""
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:
        flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
        creds = flow.run_local_server(port=5003)

        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    service = build('gmail', 'v1', credentials=creds)
    return service


def extract_body(parts):
    """Extract body content from the email parts."""
    for part in parts:
        if part['mimeType'] == 'text/plain':
            body = part['body'].get('data', '')
            body = base64.urlsafe_b64decode(body).decode('utf-8', errors='ignore')
            return body
        elif part['mimeType'] == 'text/html':
            body = part['body'].get('data', '')
            body = base64.urlsafe_b64decode(body).decode('utf-8', errors='ignore')
            return body
        elif 'parts' in part:
            return extract_body(part['parts'])
    return "No body found"


def fetch_and_store_emails():
    """Fetches new emails from Gmail and stores only new ones in MongoDB."""
    service = get_gmail_service()
    results = service.users().messages().list(userId='me', labelIds=['INBOX']).execute()
    messages = results.get('messages', [])

    new_emails = []

    for message in messages:
        msg_id = message['id']

        # 🔹 Skip if email already exists
        if emails_collection.find_one({"message_id": msg_id}):
            continue

        # Fetch complete message details
        msg = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
        email_data = msg['payload']['headers']

        from_email = next((item['value'] for item in email_data if item['name'] == 'From'), 'Unknown Sender')
        subject = next((item['value'] for item in email_data if item['name'] == 'Subject'), 'No Subject')
        date_str = next((item['value'] for item in email_data if item['name'] == 'Date'), 'Unknown Date')

        # 🕒 Convert Date String to Datetime Object
        try:
            date = parser.parse(date_str)
        except Exception as e:
            print(f"❌ Failed to parse date: {date_str}, Error: {e}")
            date = datetime.utcnow()  # Fallback to current time if parsing fails

        body = "No body found"
        if 'parts' in msg['payload']:
            body = extract_body(msg['payload']['parts'])

        email_entry = {
            'message_id': msg_id,
            'from': from_email,
            'subject': subject,
            'date': date,
            'body': body,
            'status': "Pending"
        }

        # 🔹 Store in DB
        emails_collection.insert_one(email_entry)
        new_emails.append(email_entry)
        print(f"✅ New Email Saved: {subject}")

    if not new_emails:
        print("✅ No new emails found.")

    return new_emails


if __name__ == "__main__":
    print("📩 Fetching new emails and storing in MongoDB...")
    new_emails = fetch_and_store_emails()
    print(f"✅ Fetched {len(new_emails)} new emails.")

    # Example: Display emails sorted by date DESCENDING
    print("\n📬 Displaying Emails (Newest First):")
    latest_emails = emails_collection.find().sort("date", -1)
    for email in latest_emails:
        print(f"{email['date']} - {email['subject']} - {email['from']}")
