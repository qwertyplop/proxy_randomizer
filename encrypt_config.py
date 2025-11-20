import json
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_key(password: str, salt: bytes) -> bytes:
    """Derives a 32-byte key from the password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(input_path, output_path, password):
    if not os.path.exists(input_path):
        print(f"❌ Input file not found: {input_path}")
        return

    with open(input_path, "rb") as f:
        data = f.read()

    # Generate a random salt
    salt = os.urandom(16)
    key = generate_key(password, salt)
    f = Fernet(key)
    
    encrypted_data = f.encrypt(data)

    # We prepend the salt to the encrypted file so we can use it for decryption
    with open(output_path, "wb") as f:
        f.write(salt + encrypted_data)

    print(f"✅ Encrypted {input_path} -> {output_path}")
    print(f"🔑 Password used: {password}")

if __name__ == "__main__":
    print("--- FunTimeRouter Config Encrypter ---")
    password = input("Enter encryption password: ").strip()
    if password:
        encrypt_file("providers.json", "providers.enc", password)
    else:
        print("❌ Password cannot be empty.")

