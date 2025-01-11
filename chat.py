import streamlit as st
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import firebase_admin
from firebase_admin import credentials, firestore
import base64

# Inisialisasi Firebase
firebase_config = st.secrets["firebase"]  # Simpan konfigurasi Firebase di Streamlit Secrets
cred = credentials.Certificate(dict(firebase_config))
firebase_admin.initialize_app(cred)
db = firestore.client()

# Kunci RSA (Public dan Private Key)
# Pastikan kunci ini disimpan dengan aman
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

# Streamlit UI
st.title("Chatting App with RSA Encryption")

# User harus memasukkan nama terlebih dahulu
username = st.text_input("Enter your name to start chatting:")

if username:
    st.success(f"Welcome, {username}! You can now send messages.")

    # Input pesan
    message = st.text_input("Enter your message:")

    if st.button("Send"):
        if message:
            encrypted_message = encrypt_message(message)  # Enkripsi pesan
            db.collection("messages").add({"username": username, "message": encrypted_message})
            st.success("Message sent!")
        else:
            st.warning("Message cannot be empty!")

    # Menampilkan pesan
    st.header("Chat Messages:")
    messages = db.collection("messages").stream()
    for msg in messages:
        msg_data = msg.to_dict()
        sender = msg_data["username"]
        encrypted_message = msg_data["message"]
        decrypted_message = decrypt_message(encrypted_message)
        st.write(f"**{sender}:** {decrypted_message}")
