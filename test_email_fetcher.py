import imaplib
import email
from email.header import decode_header
import socket

def fetch_emails(email_address, password, limit=10):
    """
    Fetch emails from a Gmail account using IMAP.
    Returns a list of email bodies.
    """
    try:
        # Check internet connectivity
        socket.create_connection(("imap.gmail.com", 993), timeout=5)
    except (socket.error, socket.timeout):
        print("No internet connection or unable to reach the email server.")
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
        print(f"IMAP Error: {e}")
        if "Invalid credentials" in str(e):
            print("Incorrect email credentials. Please check your email address and password.")
            print("If you have 2FA enabled, use an App Password instead of your regular password.")
        else:
            print("An error occurred while accessing your email account.")
        return []
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return []

# Test the email fetching functionality
if __name__ == '__main__':
    email_address = input("Enter your email address: ")
    password = input("Enter your email password: ")
    limit = int(input("Enter the number of emails to fetch: "))

    emails = fetch_emails(email_address, password, limit)
    if emails:
        print(f"Fetched {len(emails)} emails:")
        for i, email_body in enumerate(emails):
            print(f"\nEmail {i+1}:")
            print(email_body)
    else:
        print("No emails fetched. Please check your credentials and internet connection.")