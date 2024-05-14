import streamlit as st
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Generate private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Generate public key
public_key = private_key.public_key()

# Serialize private key
pem_private_key = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Serialize public key
pem_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Save the keys to variables or write them to files
private_key_str = pem_private_key.decode('utf-8')
public_key_str = pem_public_key.decode('utf-8')

# Print keys (For demonstration purposes, normally you should keep your private key secure)
print("Private Key:")
print(private_key_str)
print("\nPublic Key:")
print(public_key_str)


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

# Function to encrypt text using asymmetric encryption
def encrypt_text_asymmetric(text, public_key):
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

# Function to decrypt text using asymmetric encryption
def decrypt_text_asymmetric(encrypted_text, private_key):
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

# Function to hash a file using hashing function
def hash_file(file_contents, hash_function):
    hash_func = hashlib.new(hash_function)
    hash_func.update(file_contents)
    hashed_file = hash_func.hexdigest()
    return hashed_file

# Streamlit UI
def main():
    st.title("Applied Cryptography Application")

    # Cryptographic operations
    operation = st.sidebar.selectbox("Select Operation", ["Encrypt", "Decrypt", "Hash"])

    # Text input
    text = st.text_area("Enter Text:")

    if operation == "Encrypt":
        encryption_type = st.selectbox("Select Encryption Algorithm", ["AES", "DES", "RC4", "RSA"])
        if encryption_type != "RSA":
            key = Fernet.generate_key()
            if st.button("Encrypt"):
                if text:
                    if encryption_type in ["AES", "DES", "RC4"]:
                        encrypted_text = encrypt_text_symmetric(text, key)
                        st.success("Encrypted Text: " + str(encrypted_text))
                else:
                    st.warning("Please enter text to encrypt.")
        else:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            public_key = key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            if st.button("Encrypt"):
                if text:
                    encrypted_text = encrypt_text_asymmetric(text, public_key)
                    st.success("Encrypted Text: " + str(encrypted_text))
                else:
                    st.warning("Please enter text to encrypt.")

    elif operation == "Decrypt":
        decryption_type = st.selectbox("Select Decryption Algorithm", ["Symmetric (Fernet)", "Asymmetric (RSA)"])
        if decryption_type == "Symmetric (Fernet)":
            key = st.text_input("Enter Key:")
            encrypted_text = st.text_area("Enter Encrypted Text:")
            if st.button("Decrypt"):
                if key and encrypted_text:
                    decrypted_text = decrypt_text_symmetric(encrypted_text.encode(), key.encode())
                    st.success("Decrypted Text: " + decrypted_text)
                else:
                    st.warning("Please provide both key and encrypted text.")
        else:
            private_key = st.text_area("Enter Private Key:")
            encrypted_text = st.text_area("Enter Encrypted Text:")
            if st.button("Decrypt"):
                if private_key and encrypted_text:
                    decrypted_text = decrypt_text_asymmetric(encrypted_text.encode(), private_key.encode())
                    st.success("Decrypted Text: " + decrypted_text)
                else:
                    st.warning("Please provide both private key and encrypted text.")

    elif operation == "Hash":
        hash_function = st.selectbox("Select Hashing Algorithm", ["MD5", "SHA-1", "SHA-256", "SHA-512"])
        if st.button("Hash"):
            if text:
                hashed_text = hash_text(text, hash_function)
                st.success("Hashed Text: " + hashed_text)
            else:
                st.warning("Please enter text to hash.")

if __name__ == "__main__":
    main()
