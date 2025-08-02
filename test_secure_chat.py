import hashlib
from cryptography.fernet import Fernet

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def test_password_hashing():
    pw1 = "secret123"
    pw2 = "secret123"
    assert hash_password(pw1) == hash_password(pw2)

def test_password_mismatch():
    assert hash_password("pass1") != hash_password("pass2")

def test_encryption_decryption():
    key = Fernet.generate_key()
    f = Fernet(key)
    msg = "Test message"
    enc = f.encrypt(msg.encode())
    dec = f.decrypt(enc).decode()
    assert msg == dec
