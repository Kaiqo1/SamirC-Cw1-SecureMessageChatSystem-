import unittest
import hashlib
import json
import os
from cryptography.fernet import Fernet

# -------------------- Utility Functions from App --------------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def save_data(file, data):
    with open(file, 'w') as f:
        json.dump(data, f)

def load_data(file):
    return json.load(open(file)) if os.path.exists(file) else {}

# -------------------- Paths --------------------
USERS_FILE = 'users.json'
KEYS_FILE = 'keys.json'
MESSAGES_FILE = 'messages.json'

# -------------------- Test Cases --------------------
class TestSecureChat(unittest.TestCase):

    def setUp(self):
        # Sample test data
        self.username = "testuser"
        self.password = "testpass"
        self.hashed = hash_password(self.password)

        self.key = Fernet.generate_key()
        self.fernet = Fernet(self.key)

        # Reset test data
        save_data(USERS_FILE, {})
        save_data(KEYS_FILE, {})
        save_data(MESSAGES_FILE, {})

    def test_hash_password(self):
        hashed1 = hash_password("abc123")
        hashed2 = hash_password("abc123")
        hashed3 = hash_password("different")
        self.assertEqual(hashed1, hashed2)
        self.assertNotEqual(hashed1, hashed3)

    def test_fernet_encrypt_decrypt(self):
        message = "Secret message"
        encrypted = self.fernet.encrypt(message.encode())
        decrypted = self.fernet.decrypt(encrypted).decode()
        self.assertEqual(message, decrypted)

    def test_register_user(self):
        # Simulate registration
        users = load_data(USERS_FILE)
        keys = load_data(KEYS_FILE)

        users[self.username] = self.hashed
        keys[self.username] = self.key.decode()

        save_data(USERS_FILE, users)
        save_data(KEYS_FILE, keys)

        # Reload and check
        loaded_users = load_data(USERS_FILE)
        loaded_keys = load_data(KEYS_FILE)

        self.assertIn(self.username, loaded_users)
        self.assertEqual(loaded_users[self.username], self.hashed)
        self.assertEqual(loaded_keys[self.username], self.key.decode())

    def test_login_success(self):
        users = {self.username: self.hashed}
        save_data(USERS_FILE, users)

        loaded = load_data(USERS_FILE)
        result = loaded.get(self.username) == hash_password(self.password)
        self.assertTrue(result)

    def test_login_fail_wrong_password(self):
        users = {self.username: self.hashed}
        save_data(USERS_FILE, users)

        wrong_password = "wrong123"
        loaded = load_data(USERS_FILE)
        result = loaded.get(self.username) == hash_password(wrong_password)
        self.assertFalse(result)

    def test_login_fail_unregistered_user(self):
        loaded = load_data(USERS_FILE)
        result = "unknown_user" in loaded
        self.assertFalse(result)

# -------------------- Run Tests --------------------
if __name__ == '__main__':
    unittest.main()
