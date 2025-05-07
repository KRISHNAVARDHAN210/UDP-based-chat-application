import socket
import threading
import base64
import hmac
import hashlib

# PySide6 imports for GUI
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QTextEdit, QLineEdit, QPushButton, QLabel
)
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QInputDialog

# Import cryptographic utility functions
from crypto_utls import (
    generate_rsa_keypair, encrypt_with_aes, decrypt_with_aes, decrypt_with_rsa
)

# Server configuration
SERVER_IP = '127.0.0.1'
SERVER_PORT = 1234
BUFFER_SIZE = 4096
MAX_RETRIES = 3

# Global cryptographic keys
aes_key = None
private_key = None

# Generate HMAC for a message using the given key
def generate_hmac(key, message):
    return hmac.new(key, message, hashlib.sha256).hexdigest()

# Verify the HMAC of a received message
def verify_hmac(key, message, received_hmac):
    expected_hmac = hmac.new(key, message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_hmac, received_hmac)

# Attempt to send a UDP packet with retries for reliability
def reliable_send(sock, data, address):
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            sock.sendto(data, address)
            return True
        except Exception as e:
            print(f"[Retry {attempt}] Send failed: {e}")
    print("[Send Failure] Max retries reached. Message not sent.")
    return False

# Main chat client class with GUI
class ChatClient(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure UDP Chat")
        self.setGeometry(100, 100, 500, 400)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.username = ""

        self.init_ui()
        self.initialize_crypto()
        self.start_receiver_thread()

    # Set up the UI components
    def init_ui(self):
        layout = QVBoxLayout()

        self.status_label = QLabel("Enter your username to begin.")
        layout.addWidget(self.status_label)

        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        layout.addWidget(self.chat_display)

        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("Enter message here...")
        self.input_field.returnPressed.connect(self.send_message)
        layout.addWidget(self.input_field)

        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)
        layout.addWidget(self.send_button)

        self.setLayout(layout)

        # Prompt for username
        self.username, ok = QInputDialog.getText(self, "Username", "Enter your username:")
        if not self.username:
            self.username = "anonymous"

        self.status_label.setText(f"Username: {self.username}")

    # Generate RSA keypair and send public key to server
    def initialize_crypto(self):
        global private_key
        private_key, public_key = generate_rsa_keypair()
        reliable_send(self.sock, base64.b64encode(public_key), (SERVER_IP, SERVER_PORT))
        self.append_chat("[Client] Public key sent to server.")

    # Append a message to the chat window
    def append_chat(self, message):
        self.chat_display.append(message)

    # Send a message using AES encryption and HMAC
    def send_message(self):
        global aes_key
        msg = self.input_field.text()
        if not msg:
            return

        if not aes_key:
            self.append_chat("[Waiting for AES key exchange to complete...]")
            return

        # Encrypt and authenticate the message
        full_message = f"{self.username}: {msg}".encode()
        iv, encrypted_msg = encrypt_with_aes(aes_key, full_message)
        hmac_payload = f"{iv}:{encrypted_msg}".encode()
        tag = generate_hmac(aes_key, hmac_payload)
        combined = f"{iv}:{encrypted_msg}:{tag}".encode()

        reliable_send(self.sock, combined, (SERVER_IP, SERVER_PORT))
        self.append_chat(f"[You] {msg}")
        self.input_field.clear()

    # Start a background thread to listen for incoming messages
    def start_receiver_thread(self):
        threading.Thread(target=self.receive_messages, daemon=True).start()

    # Receive and decrypt messages from the server
    def receive_messages(self):
        global aes_key
        while True:
            try:
                data, _ = self.sock.recvfrom(BUFFER_SIZE)
                if aes_key is None:
                    # Handle initial AES key exchange (encrypted with RSA)
                    encrypted_aes_key = base64.b64decode(data)
                    aes_key = decrypt_with_rsa(private_key, encrypted_aes_key)
                    self.append_chat("[Client] AES key received and decrypted.")
                else:
                    # Decrypt and verify received message
                    try:
                        decoded = data.decode()
                        parts = decoded.split(":", 2)
                        if len(parts) != 3:
                            raise ValueError("Invalid message format")
                        iv_str, ct_str, received_hmac = parts
                        hmac_payload = f"{iv_str}:{ct_str}".encode()
                        if not verify_hmac(aes_key, hmac_payload, received_hmac):
                            self.append_chat("[HMAC Verification Failed]")
                            continue

                        decrypted_message = decrypt_with_aes(aes_key, iv_str, ct_str)
                        self.append_chat(f"[Received] {decrypted_message.decode()}")
                    except Exception as e:
                        self.append_chat(f"[Decryption Error] {e}")
            except Exception as e:
                self.append_chat(f"[Receive Error] {e}")

# Launch the application
def main():
    app = QApplication([])
    window = ChatClient()
    window.show()
    app.exec()

if __name__ == "__main__":
    main()
