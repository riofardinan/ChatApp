import firebase_admin
from firebase_admin import credentials, firestore
import streamlit as st

# Ambil secrets dari Streamlit
firebase_config = st.secrets["firebase"]

# Inisialisasi Firebase
cred = credentials.Certificate(firebase_config)
firebase_admin.initialize_app(cred)

# Koneksi ke Firestore
db = firestore.client()

st.title("Streamlit Firebase Example")

# Input pesan sederhana
message = st.text_input("Enter a message:")
if st.button("Save to Firestore"):
    db.collection("messages").add({"message": message})
    st.success("Message saved!")
