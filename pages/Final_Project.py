import streamlit as st
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import base64

# AES helper functions
def pad(data):
    length = 16 - (len(data) % 16)
    return data + bytes([length]) * length

def unpad(data):
    return data[:-data[-1]]

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

# Function to encrypt text using AES (manual)
def encrypt_text_aes(text, key):
    if len(key) not in [16, 24, 32]:
        raise ValueError("Key must be 16, 24, or 32 bytes long.")
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(text.encode('utf-8')))
    return base64.b64encode(iv + ct_bytes).decode('utf-8')

# Function to decrypt text using AES (manual)
def decrypt_text_aes(encrypted_text, key):
    if len(key) not in [16, 24, 32]:
        raise ValueError("Key must be 16, 24, or 32 bytes long.")
    encrypted_data = base64.b64decode(encrypted_text)
    iv = encrypted_data[:16]
    ct = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct))
    return pt.decode('utf-8')

# Hashing functions
def hash_text_sha256(text):
    sha256 = hashlib.sha256()
    sha256.update(text.encode())
    return sha256.hexdigest()

def hash_file_sha256(file):
    sha256 = hashlib.sha256()
    sha256.update(file.read())
    return sha256.hexdigest()

def hash_text_md5(text):
    md5 = hashlib.md5()
    md5.update(text.encode())
    return md5.hexdigest()

def hash_file_md5(file):
    md5 = hashlib.md5()
    md5.update(file.read())
    return md5.hexdigest()

def hash_text_sha1(text):
    sha1 = hashlib.sha1()
    sha1.update(text.encode())
    return sha1.hexdigest()

def hash_file_sha1(file):
    sha1 = hashlib.sha1()
    sha1.update(file.read())
    return sha1.hexdigest()

def hash_text_blake2b(text):
    blake2b = hashlib.blake2b()
    blake2b.update(text.encode())
    return blake2b.hexdigest()

def hash_file_blake2b(file):
    blake2b = hashlib.blake2b()
    blake2b.update(file.read())
    return blake2b.hexdigest()

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
        encryption_type = st.selectbox("Select Encryption Algorithm", ["Symmetric (Fernet)", "Symmetric (AES)", "Asymmetric (RSA)"])
        
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
        
        elif encryption_type == "Symmetric (AES)":
            key = st.text_area("Enter AES Key (16, 24, or 32 bytes):")
            text = st.text_area("Enter Text to Encrypt:")
            
            if st.button("Encrypt"):
                if key and text:
                    if len(key) in [16, 24, 32]:
                        try:
                            encrypted_text = encrypt_text_aes(text, key.encode('utf-8'))
                            st.text_area("Encrypted Text:", encrypted_text)
                        except Exception as e:
                            st.error(f"Encryption failed: {e}")
                    else:
                        st.warning("Key must be 16, 24, or 32 bytes long.")
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
        decryption_type = st.selectbox("Select Decryption Algorithm", ["Symmetric (Fernet)", "Symmetric (AES)", "Asymmetric (RSA)"])
        
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
        
        elif decryption_type == "Symmetric (AES)":
            key = st.text_area("Enter AES Key (16, 24, or 32 bytes):")
            encrypted_text = st.text_area("Enter Encrypted Text:")
            
            if st.button("Decrypt"):
                if key and encrypted_text:
                    if len(key) in [16, 24, 32]:
                        try:
                            decrypted_text = decrypt_text_aes(encrypted_text, key.encode('utf-8'))
                            st.success("Decrypted Text: " + decrypted_text)
                        except Exception as e:
                            st.error(f"Decryption failed: {e}")
                    else:
                        st.warning("Key must be 16, 24, or 32 bytes long.")
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
        hash_algorithm = st.selectbox("Select Hash Algorithm", ["SHA-256", "MD5", "SHA-1", "BLAKE2b"])
        
        if st.button("Hash"):
            if text:
                try:
                    if hash_algorithm == "SHA-256":
                        hashed_text = hash_text_sha256(text)
                    elif hash_algorithm == "MD5":
                        hashed_text = hash_text_md5(text)
                    elif hash_algorithm == "SHA-1":
                        hashed_text = hash_text_sha1(text)
                    elif hash_algorithm == "BLAKE2b":
                        hashed_text = hash_text_blake2b(text)
                    st.text_area("Hashed Text:", hashed_text)
                except Exception as e:
                    st.error(f"Hashing failed: {e}")
            else:
                st.warning("Please provide text to hash.")
    
    elif operation == "Hash File":
        file = st.file_uploader("Choose a file")
        hash_algorithm = st.selectbox("Select Hash Algorithm", ["SHA-256", "MD5", "SHA-1", "BLAKE2b"])
        
        if st.button("Hash"):
            if file:
                try:
                    if hash_algorithm == "SHA-256":
                        hashed_file = hash_file_sha256(file)
                    elif hash_algorithm == "MD5":
                        hashed_file = hash_file_md5(file)
                    elif hash_algorithm == "SHA-1":
                        hashed_file = hash_file_sha1(file)
                    elif hash_algorithm == "BLAKE2b":
                        hashed_file = hash_file_blake2b(file)
                    st.text_area("Hashed File:", hashed_file)
                except Exception as e:
                    st.error(f"Hashing failed: {e}")
            else:
                st.warning("Please upload a file to hash.")

if __name__ == "__main__":
    main()
