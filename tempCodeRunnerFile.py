import sqlite3
import pandas as pd
import numpy as np
import re
import streamlit as st
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline
import joblib
from urllib.parse import urlparse
import requests
import hashlib
import nltk
from nltk.corpus import stopwords
import imaplib
import email
from email.header import decode_header
import socket

# Download NLTK stopwords (if not already downloaded)
nltk.download('stopwords')
STOPWORDS = set(stopwords.words("english"))

# --- Database Setup for User Authentication ---
conn = sqlite3.connect("users.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
conn.commit()

def hash_password(password):
    """Hash a password for secure storage."""
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(username, password):
    """Register a new user by inserting into the database."""
    hashed_pw = hash_password(password)
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
    conn.commit()

def login_user(username, password):
    """Check login credentials against the database."""
    hashed_pw = hash_password(password)
    cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed_pw))
    return cursor.fetchone() is not None

# --- Machine Learning Functions for Phishing Detection ---

def clean_email_body(email_body):
    """
    Clean the email body by removing non-alphabetic characters,
    converting to lowercase, and removing stopwords.
    """
    email_body = re.sub(r'[^a-zA-Z\s]', '', email_body)
    email_body = ' '.join([word.lower() for word in email_body.split() if word.lower() not in STOPWORDS])
    return email_body

def extract_url_features(email_body):
    """
    Extract features from URLs in the email body.
    Features include domain length, path length, protocol validity, and HTTP status code.
    """
    urls = re.findall(r'(https?://[^\s]+)', email_body)
    features = []
    for url in urls:
        parsed_url = urlparse(url)
        domain_length = len(parsed_url.netloc)
        path_length = len(parsed_url.path)
        protocol = parsed_url.scheme
        features.append(domain_length)
        features.append(path_length)
        features.append(1 if protocol in ['http', 'https'] else 0)
        try:
            response = requests.get(url, timeout=3)
            features.append(response.status_code)
        except:
            features.append(0)
    return np.mean([f for f in features if isinstance(f, (int, float))]) if features else 0

def train_model(data):
    """
    Train a phishing detection model using email bodies.
    Expects a DataFrame with columns 'email_body' and 'label'.
    Saves the trained model to 'phishing_model.pkl'.
    """
    data['cleaned_body'] = data['email_body'].apply(clean_email_body)
    data['url_features'] = data['email_body'].apply(extract_url_features)
    X = pd.concat([data['cleaned_body'], data['url_features']], axis=1)
    X.columns = ['email_body', 'url_features']
    y = data['label']
    body_vectorizer = CountVectorizer()
    model = make_pipeline(body_vectorizer, MultinomialNB())
    model.fit(X['email_body'], y)
    joblib.dump(model, 'phishing_model.pkl')

def predict_phishing(model, email_body):
    """
    Predict if an email is phishing or safe.
    Returns 'Phishing' if predicted label is 1, else returns 'Safe'.
    """
    cleaned_body = clean_email_body(email_body)
    url_features = extract_url_features(email_body)
    X = pd.DataFrame([[cleaned_body, url_features]], columns=['email_body', 'url_features'])
    prediction = model.predict(X['email_body'])
    return 'Phishing' if prediction[0] == 1 else 'Safe'

# --- Email Fetching and Processing ---

def fetch_emails(email_address, password, limit=10):
    """
    Fetch emails from a Gmail account using IMAP.
    Returns a list of email bodies.
    """
    try:
        # Check internet connectivity
        socket.create_connection(("imap.gmail.com", 993), timeout=5)
    except (socket.error, socket.timeout):
        st.error("No internet connection or unable to reach the email server.")
        return []

    try:
        # Connect to Gmail's IMAP server
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(email_address, password)
        mail.select("inbox")

        # Search for emails
        _, data = mail.search(None, "ALL")
        email_ids = data[0].split()
        emails = []

        # Fetch emails
        for i, email_id in enumerate(email_ids[:limit]):
            _, msg_data = mail.fetch(email_id, "(RFC822)")
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    subject, encoding = decode_header(msg["Subject"])[0]
                    if isinstance(subject, bytes):
                        subject = subject.decode(encoding or "utf-8")
                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            content_type = part.get_content_type()
                            if content_type == "text/plain":
                                body = part.get_payload(decode=True).decode()
                    else:
                        body = msg.get_payload(decode=True).decode()
                    emails.append(body)
        mail.logout()
        return emails
    except imaplib.IMAP4.error as e:
        st.error(f"IMAP Error: {e}")
        if "Invalid credentials" in str(e):
            st.error("Incorrect email credentials. Please check your email address and password.")
            st.write("If you have 2FA enabled, use an App Password instead of your regular password.")
        else:
            st.error("An error occurred while accessing your email account.")
        return []
    except Exception as e:
        st.error(f"An unexpected error occurred: {e}")
        return []

# --- Streamlit Interface ---

def main():
    st.title("AI-Powered Phishing Detection System")

    # Initialize session state variables for login
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
        st.session_state.username = ""

    # Display the login/register UI if the user is not logged in,
    # otherwise display the phishing detection UI.
    if not st.session_state.logged_in:
        login_register_ui()
    else:
        phishing_detection_ui()

def login_register_ui():
    menu = ["Login", "Register"]
    choice = st.sidebar.selectbox("Select an option", menu)

    if choice == "Login":
        st.subheader("Login")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            if login_user(username, password):
                st.session_state.logged_in = True
                st.session_state.username = username
            else:
                st.error("Invalid username or password")

    elif choice == "Register":
        st.subheader("Register")
        new_user = st.text_input("Username")
        new_password = st.text_input("Password", type="password")

        if st.button("Register"):
            register_user(new_user, new_password)
            st.success("Registration successful! You can now log in.")

def phishing_detection_ui():
    st.image("logo.JPEG", width=700)
    
    # Logout button
    if st.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = ""
    
    st.write(f"Welcome, {st.session_state.username}!")
    
    # Attempt to load the trained phishing detection model
    try:
        model = joblib.load('phishing_model.pkl')
        st.write("Model loaded successfully!")
    except:
        st.write("No trained model found. Please train the model first.")

    email_input = st.text_area("Enter the Email Body to Check:", height=200)

    if st.button("Check Phishing"):
        if email_input:
            result = predict_phishing(model, email_input)
            st.write(f"Prediction: {result}")
        else:
            st.write("Please enter an email body for analysis.")

    # Option to train the model using an uploaded CSV file
    st.subheader("Train the Model (Optional)")
    uploaded_file = st.file_uploader("Choose a CSV file with email data", type="csv")
    if uploaded_file is not None:
        data = pd.read_csv(uploaded_file)
        if 'email_body' in data.columns and 'label' in data.columns:
            st.write("Training the model with the uploaded data...")
            train_model(data)
            st.write("Model trained and saved successfully!")

    # Check original emails for spam
    st.subheader("Check Original Emails for Spam")
    email_address = st.text_input("Enter your email address:")
    email_password = st.text_input("Enter your email password:", type="password")
    limit = st.number_input("Number of emails to check:", min_value=1, max_value=100, value=10)

    if st.button("Check Emails"):
        if email_address and email_password:
            emails = fetch_emails(email_address, email_password, limit)
            if emails:
                spam_count = 0
                for i, email_body in enumerate(emails):
                    result = predict_phishing(model, email_body)
                    if result == "Phishing":
                        spam_count += 1
                    st.write(f"Email {i+1}: {result}")
                st.write(f"Total spam/phishing emails: {spam_count}/{len(emails)}")
            else:
                st.write("No emails fetched. Please check your credentials and internet connection.")
        else:
            st.write("Please enter your email address and password.")

if __name__ == '__main__':
    main()