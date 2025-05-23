import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate a key (in production, store this safely)
FERNET_KEY = Fernet.generate_key()
cipher = Fernet(FERNET_KEY)

# In-memory database
stored_data = {}  # Format: {encrypted_text: {"encrypted_text": str, "passkey": hashed_passkey}}
MAX_ATTEMPTS = 3

# Session state for tracking failed attempts
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

# --- Helper Functions ---

def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(data: str, passkey: str) -> str:
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(encrypted_text: str, passkey: str) -> str | None:
    hashed_passkey = hash_passkey(passkey)
    entry = stored_data.get(encrypted_text)

    if entry and entry["passkey"] == hashed_passkey:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        return None

# --- UI Layout ---

st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.radio("Navigation", menu)

# --- Home Page ---
if choice == "Home":
    st.header("🏠 Welcome!")
    st.write("Use this system to **securely store and retrieve sensitive data** using passkeys.")

# --- Store Data Page ---
elif choice == "Store Data":
    st.header("📦 Store New Data")
    user_data = st.text_area("Enter your data:")
    passkey = st.text_input("Enter a passkey:", type="password")

    if st.button("Encrypt & Store"):
        if user_data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_data, passkey)
            stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed}
            st.success("✅ Data encrypted and stored!")
            st.code(encrypted, language="text")
        else:
            st.error("⚠️ Both data and passkey are required.")

# --- Retrieve Data Page ---
elif choice == "Retrieve Data":
    st.header("🔓 Retrieve Data")
    encrypted_input = st.text_area("Paste your encrypted data:")
    passkey_input = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if st.session_state.failed_attempts >= MAX_ATTEMPTS:
            st.warning("🚫 Too many failed attempts! Please login to try again.")
            st.experimental_rerun()

        if encrypted_input and passkey_input:
            result = decrypt_data(encrypted_input, passkey_input)
            if result:
                st.success(f"✅ Decrypted Data: {result}")
            else:
                remaining = MAX_ATTEMPTS - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts left: {remaining}")
                if st.session_state.failed_attempts >= MAX_ATTEMPTS:
                    st.warning("🔒 Locked out. Redirecting to Login...")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required.")

# --- Login Page ---
elif choice == "Login":
    st.header("🔑 Reauthorization Required")
    password = st.text_input("Enter Admin Password:", type="password")

    if st.button("Login"):
        if password == "admin123":  # For demo purposes
            st.session_state.failed_attempts = 0
            st.success("✅ Access restored. You can now try again.")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password.")
