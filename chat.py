import firebase_admin
from firebase_admin import credentials, firestore
import streamlit as st

# Ambil konfigurasi dari secrets
firebase_config = st.secrets["firebase"]

# Inisialisasi Firebase menggunakan dictionary
cred = credentials.Certificate(dict(firebase_config))
firebase_admin.initialize_app(cred)

# Koneksi ke Firestore
db = firestore.client()

st.title("Streamlit Firebase Example")

# Input sederhana
message = st.text_input("Enter your message:")
if st.button("Save to Firestore"):
    db.collection("messages").add({"message": message})
    st.success("Message saved!")
