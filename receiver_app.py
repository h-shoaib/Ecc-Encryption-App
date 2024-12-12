import streamlit as st
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Helper functions
def aes_decrypt(key, iv, ciphertext, tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

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

def decrypt_message(receiver_private_key, sender_public_key, iv, ciphertext, tag):
    symmetric_key = derive_shared_key(receiver_private_key, sender_public_key)
    plaintext = aes_decrypt(symmetric_key, iv, ciphertext, tag)
    return plaintext

# Streamlit Receiver App
st.title("ECC Receiver Application")

# Generate receiver's key pair
if "receiver_private_key" not in st.session_state:
    st.session_state.receiver_private_key, st.session_state.receiver_public_key = generate_key_pair()

# Display receiver's public key
st.subheader("Your Public Key (Share this with the Sender):")
receiver_public_key_pem = serialize_public_key(st.session_state.receiver_public_key).decode()
st.text_area("Receiver Public Key", receiver_public_key_pem, height=200)

# Tabs for manual and automatic decryption
manual_tab, automatic_tab = st.tabs(["Manual Decryption", "Automatic Decryption"])

with manual_tab:
    st.subheader("Manual Decryption")
    sender_public_key_pem = st.text_area("Sender's Public Key (PEM format)")
    iv_hex = st.text_input("IV (Hex)")
    ciphertext_hex = st.text_input("Ciphertext (Hex)")
    tag_hex = st.text_input("Tag (Hex)")

    if st.button("Decrypt Message"):
        if sender_public_key_pem and iv_hex and ciphertext_hex and tag_hex:
            try:
                sender_public_key = deserialize_public_key(sender_public_key_pem.encode('utf-8'))
                plaintext = decrypt_message(
                    st.session_state.receiver_private_key,
                    sender_public_key,
                    bytes.fromhex(iv_hex),
                    bytes.fromhex(ciphertext_hex),
                    bytes.fromhex(tag_hex)
                )
                st.success(f"Decrypted Message: {plaintext.decode('utf-8')}")
            except Exception as e:
                st.error(f"Error: {e}")
        else:
            st.error("All fields are required for decryption.")

with automatic_tab:
    st.subheader("Automatic Decryption")
    st.write("Decrypted messages will appear here when received.")

    # Display decrypted message if available
    if "decrypted_message" in st.session_state:
        st.success(f"Decrypted Message: {st.session_state.decrypted_message}")
