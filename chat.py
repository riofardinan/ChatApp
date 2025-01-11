import streamlit as st
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import firebase_admin
from firebase_admin import credentials, firestore
import base64

# Inisialisasi Firebase
if not firebase_admin._apps:
    firebase_config = st.secrets["firebase"]
    cred = credentials.Certificate(dict(firebase_config))
    firebase_admin.initialize_app(cred)

db = firestore.client()

# Kunci RSA (Public dan Private Key)
PRIVATE_KEY = st.secrets["rsa_keys"]["private_key"]
PUBLIC_KEY = st.secrets["rsa_keys"]["public_key"]

# Load kunci RSA
private_key = serialization.load_pem_private_key(
    PRIVATE_KEY.encode(),
    password=None
)

public_key = serialization.load_pem_public_key(
    PUBLIC_KEY.encode()
)

# Fungsi untuk mengenkripsi pesan
def encrypt_message(message):
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

# Fungsi untuk mendekripsi pesan
def decrypt_message(encrypted_message):
    decrypted = private_key.decrypt(
        base64.b64decode(encrypted_message.encode()),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

# Pop-up for username
if "username" not in st.session_state:
    username = st.text_input("Enter your name to start chat:", key="username_input")
    if username:
        st.session_state["username"] = username
        st.rerun()
else:
    st.title("Chat Room")
    st.success(f"Welcome, {st.session_state['username']}!")

    # Chat interface
    st.header("Chat Messages")
    chat_messages = st.container()

    # Fetch messages from database
    messages = db.collection("messages").stream()
    with chat_messages:
        for msg in messages:
            msg_data = msg.to_dict()
            sender = msg_data["username"]
            encrypted_message = msg_data["message"]
            decrypted_message = decrypt_message(encrypted_message)
            if sender == st.session_state["username"]:
                st.chat_message("user").markdown(f"**{sender}:** {decrypted_message}")
            else:
                st.chat_message("assistant").markdown(f"**{sender}:** {decrypted_message}")

    # Input chat message
    user_message = st.chat_input("Type your message...")
    if user_message:
        encrypted_message = encrypt_message(user_message)
        db.collection("messages").add({"username": st.session_state["username"], "message": encrypted_message})
        st.experimental_rerun()
