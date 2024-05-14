import streamlit as st
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import hashlib
import base64

# Function to generate RSA key pair
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return pem_private_key, pem_public_key

# Function to encrypt text using RSA
def encrypt_text_rsa(text, public_key):
    public_key = serialization.load_pem_public_key(public_key, backend=default_backend())
    encrypted_text = public_key.encrypt(
        text.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_text

# Function to decrypt text using RSA
def decrypt_text_rsa(encrypted_text, private_key):
    private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
    decrypted_text = private_key.decrypt(
        encrypted_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()
    return decrypted_text

# Function to generate Fernet key
def generate_fernet_key():
    return Fernet.generate_key()

# Function to encrypt text using Fernet (AES)
def encrypt_text_fernet(text, key):
    fernet = Fernet(key)
    encrypted_text = fernet.encrypt(text.encode())
    return encrypted_text

# Function to decrypt text using Fernet (AES)
def decrypt_text_fernet(encrypted_text, key):
    fernet = Fernet(key)
    decrypted_text = fernet.decrypt(encrypted_text).decode()
    return decrypted_text

# Hashing functions
def hash_text_sha256(text):
    sha256 = hashlib.sha256()
    sha256.update(text.encode())
    return sha256.hexdigest()

def hash_file_sha256(file):
    sha256 = hashlib.sha256()
    sha256.update(file.read())
    return sha256.hexdigest()

# Streamlit UI
def main():
    st.title("Applied Cryptography Application")
    
    operation = st.sidebar.selectbox("Select Operation", ["Encrypt", "Decrypt", "Generate Keys", "Hash Text", "Hash File"])
    
    if operation == "Generate Keys":
        if st.button("Generate RSA Key Pair"):
            private_key, public_key = generate_rsa_keys()
            st.text_area("Private Key:", private_key.decode('utf-8'), height=200)
            st.text_area("Public Key:", public_key.decode('utf-8'), height=200)
        if st.button("Generate Fernet Key"):
            key = generate_fernet_key()
            st.text_area("Fernet Key:", key.decode('utf-8'), height=100)
    
    elif operation == "Encrypt":
        encryption_type = st.selectbox("Select Encryption Algorithm", ["Symmetric (Fernet)", "Asymmetric (RSA)"])
        
        if encryption_type == "Symmetric (Fernet)":
            key = st.text_area("Enter Fernet Key:")
            text = st.text_area("Enter Text to Encrypt:")
            
            if st.button("Encrypt"):
                if key and text:
                    try:
                        encrypted_text = encrypt_text_fernet(text, key.encode('utf-8'))
                        st.text_area("Encrypted Text:", encrypted_text.decode('utf-8'))
                    except Exception as e:
                        st.error(f"Encryption failed: {e}")
                else:
                    st.warning("Please provide both key and text to encrypt.")
        
        elif encryption_type == "Asymmetric (RSA)":
            public_key = st.text_area("Enter Public Key:")
            text = st.text_area("Enter Text to Encrypt:")
            
            if st.button("Encrypt"):
                if public_key and text:
                    try:
                        encrypted_text = encrypt_text_rsa(text, public_key.encode('utf-8'))
                        st.text_area("Encrypted Text:", base64.b64encode(encrypted_text).decode('utf-8'))
                    except Exception as e:
                        st.error(f"Encryption failed: {e}")
                else:
                    st.warning("Please provide both public key and text to encrypt.")
    
    elif operation == "Decrypt":
        decryption_type = st.selectbox("Select Decryption Algorithm", ["Symmetric (Fernet)", "Asymmetric (RSA)"])
        
        if decryption_type == "Symmetric (Fernet)":
            key = st.text_area("Enter Fernet Key:")
            encrypted_text = st.text_area("Enter Encrypted Text:")
            
            if st.button("Decrypt"):
                if key and encrypted_text:
                    try:
                        decrypted_text = decrypt_text_fernet(encrypted_text.encode('utf-8'), key.encode('utf-8'))
                        st.success("Decrypted Text: " + decrypted_text)
                    except Exception as e:
                        st.error(f"Decryption failed: {e}")
                else:
                    st.warning("Please provide both key and encrypted text.")
        
        elif decryption_type == "Asymmetric (RSA)":
            private_key = st.text_area("Enter Private Key:")
            encrypted_text = st.text_area("Enter Encrypted Text:")
            
            if st.button("Decrypt"):
                if private_key and encrypted_text:
                    try:
                        decrypted_text = decrypt_text_rsa(base64.b64decode(encrypted_text), private_key.encode('utf-8'))
                        st.success("Decrypted Text: " + decrypted_text)
                    except Exception as e:
                        st.error(f"Decryption failed: {e}")
                else:
                    st.warning("Please provide both private key and encrypted text.")
    
    elif operation == "Hash Text":
        text = st.text_area("Enter Text to Hash:")
        hash_algorithm = st.selectbox("Select Hash Algorithm", ["SHA-256"])
        
        if st.button("Hash"):
            if text:
                try:
                    if hash_algorithm == "SHA-256":
                        hashed_text = hash_text_sha256(text)
                    st.text_area("Hashed Text:", hashed_text)
                except Exception as e:
                    st.error(f"Hashing failed: {e}")
            else:
                st.warning("Please provide text to hash.")
    
    elif operation == "Hash File":
        file = st.file_uploader("Choose a file")
        hash_algorithm = st.selectbox("Select Hash Algorithm", ["SHA-256"])
        
        if st.button("Hash"):
            if file:
                try:
                    if hash_algorithm == "SHA-256":
                        hashed_file = hash_file_sha256(file)
                    st.text_area("Hashed File:", hashed_file)
                except Exception as e:
                    st.error(f"Hashing failed: {e}")
            else:
                st.warning("Please upload a file to hash.")

if __name__ == "__main__":
    main()
