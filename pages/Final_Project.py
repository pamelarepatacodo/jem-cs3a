import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Function to encrypt text using symmetric encryption
def encrypt_text_symmetric(text, key):
    cipher_suite = Fernet(key)
    encrypted_text = cipher_suite.encrypt(text.encode())
    return encrypted_text

# Function to decrypt text using symmetric encryption
def decrypt_text_symmetric(encrypted_text, key):
    cipher_suite = Fernet(key)
    decrypted_text = cipher_suite.decrypt(encrypted_text).decode()
    return decrypted_text

# Function to hash text using hashing function
def hash_text(text, hash_function):
    if hash_function == "MD5":
        hashed_text = hashlib.md5(text.encode()).hexdigest()
    elif hash_function == "SHA-1":
        hashed_text = hashlib.sha1(text.encode()).hexdigest()
    elif hash_function == "SHA-256":
        hashed_text = hashlib.sha256(text.encode()).hexdigest()
    elif hash_function == "SHA-512":
        hashed_text = hashlib.sha512(text.encode()).hexdigest()
    return hashed_text

# Streamlit UI
def main():
    st.title("Applied Cryptography Application")

    # Cryptographic operations
    operation = st.sidebar.selectbox("Select Operation", ["Encrypt", "Decrypt", "Hash"])

    # Text input
    text = st.text_area("Enter Text:")

    if operation == "Encrypt":
        encryption_type = st.selectbox("Select Encryption Algorithm", ["AES", "DES", "RC4"])
        if st.button("Encrypt"):
            key = Fernet.generate_key()
            encrypted_text = encrypt_text_symmetric(text, key)
            st.success("Encrypted Text: " + str(encrypted_text))

    elif operation == "Decrypt":
        key = st.text_input("Enter Key:")
        if st.button("Decrypt"):
            decrypted_text = decrypt_text_symmetric(text.encode(), key.encode())
            st.success("Decrypted Text: " + decrypted_text)

    elif operation == "Hash":
        hash_function = st.selectbox("Select Hashing Algorithm", ["MD5", "SHA-1", "SHA-256", "SHA-512"])
        if st.button("Hash"):
            hashed_text = hash_text(text, hash_function)
            st.success("Hashed Text: " + hashed_text)

if __name__ == "__main__":
    main()
