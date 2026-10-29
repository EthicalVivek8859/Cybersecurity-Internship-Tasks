import bcrypt
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

print("--- 1. AES-256-GCM Encryption & Decryption ---")

# AES-256 ke liye ek 256-bit (32 bytes) ki random key generate karna
key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)

# GCM mode ke liye 96-bit (12 bytes) ka ek random IV (Nonce) generate karna
nonce = os.urandom(12)

# Jo message hume encrypt karna hai (bytes format mein)
message = b"Yeh ek secret message hai Task 05 ke liye!"
print(f"Original Message: {message.decode('utf-8')}")

# Data ko encrypt karna (Authenticated Encryption)
ciphertext = aesgcm.encrypt(nonce, message, None)
print(f"Encrypted Data (Hex): {ciphertext.hex()}")

# Data ko wapas decrypt karna
decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
print(f"Decrypted Message: {decrypted_data.decode('utf-8')}\n")
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

print("--- 2. RSA Key Pairs & Signature Verification ---")

# 2048-bit RSA private key generate karna
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Private key se public key nikalna
public_key = private_key.public_key()

# Message ko sign karna
message = b"Yeh ek sensitive data hai jise sign karna hai."
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
print(f"Digital Signature (Hex): {signature.hex()}")

# Signature ko verify karna
try:
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Verification Successful: Signature valid hai!\n")
except Exception as e:
    print(f"Verification Failed: {e}\n")
   
print("--- 3. Bcrypt Password Hashing ---")

# Ek simple password string
password = b"MySecurePassword123!"

# Salt generate karna
salt = bcrypt.gensalt(rounds=12)

# Password ko hash karna
hashed_password = bcrypt.hashpw(password, salt)
print(f"Hashed Password (Bytes): {hashed_password.decode('utf-8')}")

# Password ko verify karna
check = bcrypt.checkpw(password, hashed_password)
print(f"Password Match Status: {check}\n")