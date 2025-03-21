import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt(key, plaintext):
    # Generate a random 12-byte nonce (IV for GCM)
    nonce = os.urandom(12)
    # Create a Cipher object using the key and nonce with GCM mode
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    # Encrypt the plaintext (no padding needed for GCM)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    # Return the nonce, ciphertext, and authentication tag
    return nonce + encryptor.tag + ciphertext

def decrypt(key, ciphertext):
    # Extract the nonce and authentication tag from the beginning of the ciphertext
    nonce = ciphertext[:12]
    tag = ciphertext[12:28]  # GCM tag is 16 bytes
    actual_ciphertext = ciphertext[28:]
    # Create a Cipher object using the key, nonce and tag with GCM mode
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    # Decrypt the ciphertext and verify the authentication tag
    plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
    return plaintext

# DUMMY TEST
key = b'0123456789abcdef0123456789abcdef'  # 32 bytes key
message = b'Hello there!'

# Print the key
print("Key:", key.hex())

# Encrypt the message and print the result
encrypted_message = encrypt(key, message)
print("Encrypted message:", encrypted_message.hex())

# Decrypt the message and print the result
decrypted_message = decrypt(key, encrypted_message)
print("Decrypted message:", decrypted_message.decode())