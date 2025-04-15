import streamlit as st
import json
import os
import hashlib
from cryptography.fernet import Fernet

# Constants
DATA_FILE = "data.json"
KEY_FILE = "secret.key"

# Load or generate encryption key
def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key

# Load encryption key
key = load_or_create_key()
fernet = Fernet(key)

# Load data from JSON
# Load data from JSON safely
def load_data():
    if not os.path.exists(DATA_FILE):
        with open(DATA_FILE, "w") as f:
            json.dump({}, f)
        return {}

    with open(DATA_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            # File exists but is empty or corrupted, reset it
            with open(DATA_FILE, "w") as fw:
                json.dump({}, fw)
            return {}

# Save data to JSON
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# Hash passkey using SHA256
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt the text
def encrypt_data(text):
    return fernet.encrypt(text.encode()).decode()

# Decrypt the text
def decrypt_data(encrypted_text):
    return fernet.decrypt(encrypted_text.encode()).decode()

# Sidebar Navigation
def sidebar():
    st.sidebar.title("🔐 Navigation")
    return st.sidebar.radio("Go to", ["Home", "Insert Data", "Retrieve Data", "Login"])

# Login check
def login_page():
    st.title("🔑 Reauthorization Required")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username == "admin" and password == "password":
            st.session_state["failed_attempts"] = 0
            st.success("Login successful!")
        else:
            st.error("Invalid credentials")

# Home page
def home_page():
    st.title("🔒 Secure Data Storage App")
    st.success("Use the sidebar to insert or retrieve secure data.")

# Insert data
def insert_data():
    st.header("📝 Insert Data")
    username = st.text_input("Enter Unique Identifier (e.g., your name)")
    text = st.text_area("Enter Text to Encrypt")
    passkey = st.text_input("Enter a Secure Passkey", type="password")

    if st.button("Encrypt & Save"):
        if username and text and passkey:
            hashed = hash_passkey(passkey)
            encrypted_text = encrypt_data(text)
            data = load_data()
            data[username] = {"encrypted_text": encrypted_text, "passkey": hashed}
            save_data(data)
            st.success("Data encrypted and saved successfully!")
        else:
            st.warning("Please fill in all fields.")

# Retrieve data
def retrieve_data():
    st.header("🔓 Retrieve Data")
    username = st.text_input("Enter Your Identifier")
    passkey = st.text_input("Enter Your Passkey", type="password")

    if "failed_attempts" not in st.session_state:
        st.session_state["failed_attempts"] = 0

    if username and passkey:
        data = load_data()
        if username in data:
            hashed_input = hash_passkey(passkey)

            if st.session_state["failed_attempts"] >= 3:
                st.warning("Too many failed attempts! Please login.")
                login_page()
                return

            if hashed_input == data[username]["passkey"]:
                decrypted = decrypt_data(data[username]["encrypted_text"])
                st.success("Data Decrypted Successfully:")
                st.code(decrypted)
                st.session_state["failed_attempts"] = 0  # Reset on success
            else:
                st.session_state["failed_attempts"] += 1
                remaining = 3 - st.session_state["failed_attempts"]
                st.error(f"Wrong passkey! Attempts left: {remaining}")
        else:
            st.warning("Username not found.")
    else:
        st.info("Enter both fields to retrieve your data.")

# Main function
def main():
    st.set_page_config(page_title="Secure Data App", page_icon="🛡️", layout="centered")
    page = sidebar()

    if page == "Home":
        home_page()
    elif page == "Insert Data":
        insert_data()
    elif page == "Retrieve Data":
        retrieve_data()
    elif page == "Login":
        login_page()

if __name__ == "__main__":
    main()
