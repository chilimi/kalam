from flask import Flask, render_template, request, redirect, url_for
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import binascii

app = Flask(_name_)

# Encrypt function
def encrypt_message(message, key):
    iv = os.urandom(16)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return iv, ciphertext
# Decrypt function
def decrypt_message(iv, ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()
    return message.decode()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        key = os.urandom(32)  # Random 32-byte key for AES-256
        message = request.form['message']
        iv, ciphertext = encrypt_message(message, key)
        encrypted_message = binascii.hexlify(iv + ciphertext).decode()
        return render_template('index.html', encrypted_message=encrypted_message, key=binascii.hexlify(key).decode())
    return render_template('index.html')
@app.route('/decrypt', methods=['POST'])
def decrypt():
    key = binascii.unhexlify(request.form['key'])
    encrypted_message = binascii.unhexlify(request.form['encrypted_message'])
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    decrypted_message = decrypt_message(iv, ciphertext, key)
    return render_template('index.html', decrypted_message=decrypted_message)

if _name_ == '_main_':
    app.run(debug=True)
