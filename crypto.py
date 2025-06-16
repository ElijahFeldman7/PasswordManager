# crypto.py
import os
import json
from typing import Union
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

ITERATIONS = 600_000
KEY_LENGTH = 32  
SALT_LENGTH = 16
NONCE_LENGTH = 12 

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend() 
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt(data_dict: dict, key: bytes) -> bytes:
    """
    Serializes, then encrypts data using AES-256-GCM.
    A new nonce is generated for each encryption.
    The nonce is prepended to the ciphertext.
    """
    nonce = os.urandom(NONCE_LENGTH)
    plaintext_bytes = json.dumps(data_dict, indent=2).encode('utf-8')
    ciphertext = AESGCM(key).encrypt(nonce, plaintext_bytes, None)
    return nonce + ciphertext

def decrypt(encrypted_data: bytes, key: bytes) -> Union[dict, None]:
    if len(encrypted_data) < NONCE_LENGTH:
        return None

    nonce = encrypted_data[:NONCE_LENGTH]
    ciphertext = encrypted_data[NONCE_LENGTH:]

    try:
        decrypted_bytes = AESGCM(key).decrypt(nonce, ciphertext, None)
        return json.loads(decrypted_bytes)
    except InvalidTag:
        return None
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None