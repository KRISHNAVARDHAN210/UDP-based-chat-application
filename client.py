"""
Secure UDP Chat Client with GUI (PySide6).

This client:
- Uses RSA to exchange a symmetric AES key with the server.
- Sends and receives AES-encrypted, HMAC-authenticated messages.
- Displays a Qt-based GUI for interactive chatting.

Modules used:
- PySide6 for GUI
- socket + threading for communication
- crypto_utls for encryption primitives
"""

__all__ = [
    "generate_hmac",
    "verify_hmac",
    "reliable_send",
    "ChatClient",
    "main"
]
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
    """
    Generate an HMAC using SHA-256.

    Args:
        key (bytes): The AES key used for HMAC.
        message (bytes): The message to authenticate.

    Returns:
        str: Hex-encoded HMAC string.
    """
    return hmac.new(key, message, hashlib.sha256).hexdigest()

# Verify the HMAC of a received message
def verify_hmac(key, message, received_hmac):
    """
    Verify that an HMAC matches the expected value.

    Args:
        key (bytes): The shared AES key.
        message (bytes): The original message.
        received_hmac (str): The received HMAC.

    Returns:
        bool: True if HMAC matches, else False.
    """
    expected_hmac = hmac.new(key, message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_hmac, received_hmac)

# Attempt to send a UDP packet with retries for reliability
def reliable_send(sock, data, address):
    """
    Send a message over UDP with retry attempts.

    Args:
        sock (socket.socket): The UDP socket.
        data (bytes): The message to send.
        address (tuple): The server's (IP, port) address.

    Returns:
        bool: True if successful, False if retries exceeded.
    """
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
    """
    GUI-based UDP Chat Client that handles encryption, messaging, and GUI updates.
    """
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
        """
        Initialize the GUI layout and widgets.
        """
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
        """
        Generate RSA keys and initiate AES key exchange with the server.
        """
        global private_key
        private_key, public_key = generate_rsa_keypair()
        reliable_send(self.sock, base64.b64encode(public_key), (SERVER_IP, SERVER_PORT))
        self.append_chat("[Client] Public key sent to server.")

    # Append a message to the chat window
    def append_chat(self, message):
        """
        Append a message to the chat display.

        Args:
            message (str): The message to show.
        """
        self.chat_display.append(message)

    # Send a message using AES encryption and HMAC
    def send_message(self):
        """
        Encrypt and send a chat message to the server.
        """
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
        """
        Start a background thread to listen for messages.
        """
        threading.Thread(target=self.receive_messages, daemon=True).start()

    # Receive and decrypt messages from the server
    def receive_messages(self):
        """
        Continuously receive, decrypt, and verify messages from the server.
        """
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
    """
    Launch the Qt application and run the chat client.
    """
    app = QApplication([])
    window = ChatClient()
    window.show()
    app.exec()

if __name__ == "__main__":
    main()
