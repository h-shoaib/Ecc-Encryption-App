### Updated Sender App Code
import streamlit as st
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import requests

# Helper functions
def aes_encrypt(key, plaintext):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, ciphertext, encryptor.tag

def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(public_bytes):
    return serialization.load_pem_public_key(public_bytes)

def derive_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'encryption'
    ).derive(shared_key)
    return derived_key

def encrypt_message(sender_private_key, receiver_public_key, message):
    symmetric_key = derive_shared_key(sender_private_key, receiver_public_key)
    iv, ciphertext, tag = aes_encrypt(symmetric_key, message)
    return iv, ciphertext, tag

# Streamlit Sender App
st.title("ECC Sender Application")

# Generate sender's key pair
if "sender_private_key" not in st.session_state:
    st.session_state.sender_private_key, st.session_state.sender_public_key = generate_key_pair()

# Display sender's public key
st.subheader("Your Public Key (Share this with the Receiver):")
sender_public_key_pem = serialize_public_key(st.session_state.sender_public_key).decode()
st.text_area("Sender Public Key", sender_public_key_pem, height=200)

# Input receiver's public key
receiver_public_key_pem = st.text_area("Paste Receiver's Public Key (PEM format)")

# Input message to encrypt
message = st.text_area("Enter your message:")

if st.button("Encrypt and Send Message"):
    if receiver_public_key_pem and message:
        try:
            receiver_public_key = deserialize_public_key(receiver_public_key_pem.encode('utf-8'))
            iv, ciphertext, tag = encrypt_message(
                st.session_state.sender_private_key, receiver_public_key, message.encode('utf-8')
            )

            # Automatically send data to the receiver app
            receiver_url = "https://msg-ecc-rcv.streamlit.app/receive"
            response = requests.post(receiver_url, json={
                "sender_public_key": sender_public_key_pem,
                "ciphertext": ciphertext.hex(),
                "iv": iv.hex(),
                "tag": tag.hex()
            })

            if response.status_code == 200:
                st.success("Message sent to receiver successfully!")
            else:
                st.error("Failed to send the message to receiver.")

        except Exception as e:
            st.error(f"Error: {e}")
    else:
        st.error("Please provide both the receiver's public key and a message.")
