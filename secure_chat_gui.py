import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet
import hashlib, json, base64, os
from datetime import datetime

# -------------------- File Paths --------------------
USERS_FILE = 'users.json'
KEYS_FILE = 'keys.json'
MESSAGES_FILE = 'messages.json'
LOGS_DIR = 'logs'

# Create logs directory if it doesn't exist
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR)

# -------------------- Load / Save Data --------------------
def load_data(file):
    return json.load(open(file)) if os.path.exists(file) else {}

def save_data(file, data):
    with open(file, 'w') as f:
        json.dump(data, f)

user_db = load_data(USERS_FILE)
user_keys_raw = load_data(KEYS_FILE)
user_messages = load_data(MESSAGES_FILE)
user_keys = {user: base64.b64decode(key.encode()) for user, key in user_keys_raw.items()}

# -------------------- Hashing --------------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# -------------------- Functions --------------------
def register():
    username = entry_user.get()
    password = entry_pass.get()
    if not username or not password:
        messagebox.showerror("Error", "Username or password cannot be empty.")
        return
    if username in user_db:
        messagebox.showerror("Error", "User already exists.")
        return

    user_db[username] = hash_password(password)
    key = Fernet.generate_key()
    user_keys[username] = key
    user_messages[username] = []

    save_data(USERS_FILE, user_db)
    encoded_keys = {user: base64.b64encode(k).decode() for user, k in user_keys.items()}
    save_data(KEYS_FILE, encoded_keys)
    save_data(MESSAGES_FILE, user_messages)

    messagebox.showinfo("Success", "Registration successful!")

def login():
    global current_user
    username = entry_user.get()
    password = entry_pass.get()

    if username not in user_db:
        messagebox.showerror("Login Failed", f"User '{username}' is not registered.\nPlease register first.")
        return

    if user_db[username] == hash_password(password):
        current_user = username
        user_label.config(text=f"🔐 Logged in as: {current_user}")
        entry_user.delete(0, tk.END)
        entry_pass.delete(0, tk.END)
        login_frame.pack_forget()
        chat_frame.pack(padx=10, pady=10)
        user_label.pack(pady=(10, 0))
        update_messages()
        messagebox.showinfo("Login Success", f"Welcome, {username}!")
    else:
        messagebox.showerror("Login Failed", "Incorrect password.")

def send_message():
    message = message_entry.get()
    if not message:
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"[{timestamp}] {message}"

    fernet = Fernet(user_keys[current_user])
    encrypted = fernet.encrypt(full_message.encode())
    user_messages[current_user].append(encrypted.decode())

    save_data(MESSAGES_FILE, user_messages)
    save_to_log_file(current_user, encrypted.decode())
    message_entry.delete(0, tk.END)
    update_messages()

def update_messages():
    msg_box.delete(1.0, tk.END)
    fernet = Fernet(user_keys[current_user])
    for msg in user_messages[current_user]:
        try:
            decrypted = fernet.decrypt(msg.encode()).decode()
            msg_box.insert(tk.END, f"🗨️ {decrypted}\n")
        except:
            msg_box.insert(tk.END, "❌ [Decryption failed]\n")

def save_to_log_file(user, encrypted_msg):
    date_str = datetime.now().strftime("%Y-%m-%d")
    log_filename = os.path.join(LOGS_DIR, f"{user}_{date_str}.json")

    logs = []
    if os.path.exists(log_filename):
        logs = load_data(log_filename)

    logs.append(encrypted_msg)
    save_data(log_filename, logs)

def logout():
    global current_user
    current_user = None
    chat_frame.pack_forget()
    user_label.pack_forget()
    login_frame.pack(padx=20, pady=20)

# -------------------- GUI Setup --------------------
root = tk.Tk()
root.title("🔐 Secure Chat Messaging System")
root.geometry("600x500")
root.resizable(False, False)

current_user = None

# -------------------- Fonts & Styles --------------------
FONT_HEADER = ("Helvetica", 14, "bold")
FONT_NORMAL = ("Helvetica", 11)

# -------------------- Login/Register Frame --------------------
login_frame = tk.Frame(root)

tk.Label(login_frame, text="Welcome to Secure Chat", font=FONT_HEADER).grid(row=0, column=0, columnspan=2, pady=(10, 15))

tk.Label(login_frame, text="Username:", font=FONT_NORMAL).grid(row=1, column=0, sticky="e")
entry_user = tk.Entry(login_frame, width=30)
entry_user.grid(row=1, column=1, pady=5)

tk.Label(login_frame, text="Password:", font=FONT_NORMAL).grid(row=2, column=0, sticky="e")
entry_pass = tk.Entry(login_frame, width=30, show="*")
entry_pass.grid(row=2, column=1, pady=5)

tk.Button(login_frame, text="Register", width=15, command=register).grid(row=3, column=0, pady=10)
tk.Button(login_frame, text="Login", width=15, command=login).grid(row=3, column=1, pady=10)

login_frame.pack(padx=20, pady=20)

# -------------------- Chat Frame --------------------
chat_frame = tk.Frame(root)
user_label = tk.Label(root, text="", font=("Helvetica", 10, "italic"), fg="blue")

message_entry = tk.Entry(chat_frame, width=50)
message_entry.grid(row=0, column=0, padx=5, pady=5, sticky="w")

tk.Button(chat_frame, text="Send", width=12, command=send_message).grid(row=0, column=1, padx=5, pady=5)

msg_box = tk.Text(chat_frame, height=18, width=68, wrap=tk.WORD, state='normal')
msg_box.grid(row=1, column=0, columnspan=2, pady=10)

tk.Button(chat_frame, text="🔙 Logout", command=logout, fg="white", bg="red").grid(row=2, column=1, sticky="e", padx=10, pady=(5, 15))

# -------------------- Run the App --------------------
root.mainloop()
