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
import os
import time
from PIL import Image
import base64

# --- Configuration ---
nltk.download('stopwords')
STOPWORDS = set(stopwords.words("english"))

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect("users.db", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users 
                     (id INTEGER PRIMARY KEY, 
                      username TEXT UNIQUE, 
                      password TEXT,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    return conn, cursor

conn, cursor = init_db()

# --- Authentication ---
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(username, password):
    try:
        hashed_pw = hash_password(password)
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                      (username, hashed_pw))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def login_user(username, password):
    hashed_pw = hash_password(password)
    cursor.execute("SELECT * FROM users WHERE username=? AND password=?", 
                 (username, hashed_pw))
    return cursor.fetchone() is not None

# --- ML Core ---
def clean_email_body(email_body):
    if not isinstance(email_body, str):
        return ""
    email_body = re.sub(r'[^a-zA-Z\s]', '', email_body)
    email_body = ' '.join([word.lower() for word in email_body.split() 
                         if word.lower() not in STOPWORDS])
    return email_body

def extract_url_features(email_body):
    if not isinstance(email_body, str):
        return 0
        
    urls = re.findall(r'(https?://[^\s]+)', email_body)
    features = []
    for url in urls[:3]:
        try:
            parsed_url = urlparse(url)
            features.extend([
                len(parsed_url.netloc),
                len(parsed_url.path),
                1 if parsed_url.scheme in ['http', 'https'] else 0,
                200  # Mock status
            ])
        except:
            features.extend([0, 0, 0, 0])
    return np.mean(features) if features else 0

@st.cache_resource
def load_model():
    try:
        return joblib.load('phishing_model.pkl')
    except:
        dummy_data = pd.DataFrame({
            'email_body': ['free money now', 'your account statement'],
            'label': [1, 0]
        })
        model = make_pipeline(CountVectorizer(), MultinomialNB())
        model.fit(dummy_data['email_body'], dummy_data['label'])
        joblib.dump(model, 'phishing_model.pkl')
        return model

def predict_phishing(model, email_body):
    if not email_body or not isinstance(email_body, str):
        return "Invalid input", 0.0
        
    cleaned_body = clean_email_body(email_body)
    proba = model.predict_proba([cleaned_body])[0]
    prediction = model.predict([cleaned_body])[0]
    confidence = max(proba)
    return 'Phishing' if prediction == 1 else 'Safe', confidence

# --- Email Fetching ---
def fetch_emails(email_address, password, limit=5):
    try:
        socket.create_connection(("imap.gmail.com", 993), timeout=5)
    except:
        st.error("Connection error")
        return []

    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(email_address, password)
        mail.select("inbox")

        _, data = mail.search(None, "ALL")
        email_ids = data[0].split()
        emails = []

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
                            if part.get_content_type() == "text/plain":
                                body = part.get_payload(decode=True).decode(errors='ignore')
                    else:
                        body = msg.get_payload(decode=True).decode(errors='ignore')
                    emails.append((subject, body))
        mail.logout()
        return emails
    except Exception as e:
        st.error(f"Error: {str(e)}")
        return []

# --- UI Components ---
def setup_page():
    st.set_page_config(
        page_title="PhishShield AI",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

def show_login():
    st.title("🔐 PhishShield Login")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
        
        if submitted:
            if login_user(username, password):
                st.session_state.logged_in = True
                st.session_state.username = username
                st.rerun()
            else:
                st.error("Invalid credentials")

def show_register():
    st.title("📝 Create Account")
    with st.form("register_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        confirm = st.text_input("Confirm Password", type="password")
        submitted = st.form_submit_button("Register")
        
        if submitted:
            if password == confirm:
                if register_user(username, password):
                    st.success("Account created! Please login")
                else:
                    st.error("Username exists")
            else:
                st.error("Passwords don't match")

def show_dashboard(model):
    st.title(f"🛡️ Welcome, {st.session_state.username}")
    
    # Navigation
    tab1, tab2, tab3 = st.tabs(["Email Analyzer", "Batch Processor", "Account Settings"])
    
    with tab1:
        st.header("📧 Single Email Analysis")
        email_text = st.text_area("Paste email content:", height=250)
        
        if st.button("Analyze", type="primary"):
            if email_text:
                with st.spinner("Analyzing..."):
                    result, confidence = predict_phishing(model, email_text)
                    if result == "Phishing":
                        st.error(f"🚨 Phishing Detected ({confidence:.0%} confidence)")
                        st.markdown("**Recommendations:**")
                        st.markdown("- Do not click any links")
                        st.markdown("- Report to your IT department")
                    else:
                        st.success(f"✅ Safe Email ({confidence:.0%} confidence)")
            else:
                st.warning("Please enter email content")
    
    with tab2:
        st.header("📁 Batch Processing")
        uploaded_file = st.file_uploader("Upload CSV file", type=["csv"])
        
        if uploaded_file:
            df = pd.read_csv(uploaded_file)
            if 'email_body' in df.columns:
                if st.button("Process Batch", type="primary"):
                    progress_bar = st.progress(0)
                    results = []
                    
                    for i, row in df.iterrows():
                        progress_bar.progress((i+1)/len(df))
                        result, _ = predict_phishing(model, row['email_body'])
                        results.append(result)
                    
                    df['prediction'] = results
                    st.dataframe(df)
                    
                    csv = df.to_csv(index=False)
                    st.download_button(
                        "Download Results",
                        data=csv,
                        file_name="phishing_results.csv",
                        mime="text/csv"
                    )
            else:
                st.error("CSV needs 'email_body' column")
    
    with tab3:
        st.header("⚙️ Account Settings")
        if st.button("Logout", type="primary"):
            st.session_state.clear()
            st.rerun()
        
        st.markdown("---")
        st.subheader("Email Integration")
        email = st.text_input("Connect your email")
        password = st.text_input("App password", type="password")
        
        if st.button("Connect Email"):
            if email and password:
                with st.spinner("Fetching emails..."):
                    emails = fetch_emails(email, password, 3)
                    if emails:
                        st.success(f"Connected to {email}")
                        for subject, body in emails:
                            with st.expander(subject[:50] + "..."):
                                result, _ = predict_phishing(model, body)
                                st.write(f"Status: {result}")
                                st.text(body[:200] + "...")
                    else:
                        st.error("Connection failed")

# --- Main App ---
def main():
    setup_page()
    
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
    
    model = load_model()
    
    if not st.session_state.logged_in:
        menu = st.sidebar.radio("Menu", ["Login", "Register"])
        if menu == "Login":
            show_login()
        else:
            show_register()
    else:
        show_dashboard(model)
        
        # Sidebar
        st.sidebar.markdown("---")
        st.sidebar.markdown("### Model Training")
        train_file = st.sidebar.file_uploader("Upload training data", type=["csv"])
        if train_file and st.sidebar.button("Train Model"):
            data = pd.read_csv(train_file)
            if {'email_body', 'label'}.issubset(data.columns):
                with st.spinner("Training..."):
                    pipeline = make_pipeline(CountVectorizer(), MultinomialNB())
                    pipeline.fit(data['email_body'], data['label'])
                    joblib.dump(pipeline, 'phishing_model.pkl')
                    st.sidebar.success("Model updated!")
                    st.session_state.model = pipeline
            else:
                st.sidebar.error("Need 'email_body' and 'label' columns")

if __name__ == '__main__':
    main()