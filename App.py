import os
import secrets
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Configuration
PASSWORD = "JusticeScottStadler21895!$"

# Function to generate and encrypt the secret key using AES-GCM mode
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

# Function to decrypt the secret key using AES-GCM mode
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

# Flask Application Setup
app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = decrypted_key  # Use the decrypted key for JWT
jwt = JWTManager(app)

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    # Validate username and password (e.g., check against database)
    if username == 'example' and password == 'password':
        # Generate access token
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"message": "Invalid username or password"}), 401

# Protected endpoint example
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

# File Management Endpoints

@app.route('/create_file', methods=['POST'])
@jwt_required()
def create_file():
    file_path = request.json.get('file_path')
    content = request.json.get('content', '')
    try:
        with open(file_path, 'w') as file:
            file.write(content)
        return jsonify({"message": f"File {file_path} created successfully."}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/read_file', methods=['GET'])
@jwt_required()
def read_file():
    file_path = request.args.get('file_path')
    try:
        with open(file_path, 'r') as file:
            content = file.read()
        return jsonify({"content": content}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/update_file', methods=['PUT'])
@jwt_required()
def update_file():
    file_path = request.json.get('file_path')
    content = request.json.get('content', '')
    try:
        with open(file_path, 'a') as file:
            file.write(content)
        return jsonify({"message": f"File {file_path} updated successfully."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/delete_file', methods=['DELETE'])
@jwt_required()
def delete_file():
    file_path = request.json.get('file_path')
    try:
        os.remove(file_path)
        return jsonify({"message": f"File {file_path} deleted successfully."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/create_folder', methods=['POST'])
@jwt_required()
def create_folder():
    folder_path = request.json.get('folder_path')
    try:
        os.makedirs(folder_path, exist_ok=True)
        return jsonify({"message": f"Folder {folder_path} created successfully."}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/delete_folder', methods=['DELETE'])
@jwt_required()
def delete_folder():
    folder_path = request.json.get('folder_path')
    try:
        os.rmdir(folder_path)
        return jsonify({"message": f"Folder {folder_path} deleted successfully."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Web Information Retrieval Endpoint

@app.route('/fetch_url', methods=['GET'])
@jwt_required()
def fetch_url():
    url = request.args.get('url')
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors
        return jsonify({"content": response.text}), 200
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
