import os
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Configuration
PASSWORD = "JusticeScottStadler21895!$"

def generate_and_encrypt_secret_key(password):
    secure_random_key = secrets.token_bytes(32)  # 256-bit key
    salt = secrets.token_bytes(16)  # Generate a random salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Length of the derived key (AES key size)
        salt=salt,
        iterations=100000,  # Recommended number of iterations
        backend=default_backend()
    )
    key = kdf.derive(password.encode())  # Derive a key from the password
    
    # Generate a random nonce (12 bytes)
    nonce = os.urandom(12)
    
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(secure_random_key) + encryptor.finalize()
    return salt, nonce, ciphertext, encryptor.tag

def decrypt_key(encrypted_key, password, salt, nonce, tag):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Length of the derived key (AES key size)
        salt=salt,
        iterations=100000,  # Same number of iterations used for encryption
        backend=default_backend()
    )
    key = kdf.derive(password.encode())  # Derive a key from the password
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_key = decryptor.update(encrypted_key) + decryptor.finalize()
    return decrypted_key

# Generate and encrypt the secret key
salt, nonce, ciphertext, tag = generate_and_encrypt_secret_key(PASSWORD)

# Decrypt the key on application startup
decrypted_key = decrypt_key(ciphertext, PASSWORD, salt, nonce, tag)
