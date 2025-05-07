import socket
import base64
import hmac
import hashlib

# Import cryptographic utility functions
from crypto_utls import (
    generate_aes_key, encrypt_with_aes, decrypt_with_aes,
    generate_rsa_keypair, encrypt_with_rsa, decrypt_with_rsa
)

# Server configuration
SERVER_IP = '0.0.0.0'  # Listen on all network interfaces
SERVER_PORT = 1234
BUFFER_SIZE = 4096

# State management
clients = {}  # Maps client address to AES key
client_public_keys = {}  # Maps client address to their RSA public key
client_hmac_keys = {}  # Maps client address to HMAC key (same as AES key)

# HMAC generation using SHA-256
def generate_hmac(key, message):
    return hmac.new(key, message, hashlib.sha256).hexdigest()

# HMAC verification using constant-time comparison
def verify_hmac(key, message, received_hmac):
    expected_hmac = hmac.new(key, message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_hmac, received_hmac)

# Main loop to handle incoming packets from clients
def handle_client(sock):
    while True:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)

            # First message: treat it as a public RSA key registration
            if addr not in clients:
                try:
                    # Decode and validate the public key
                    public_key = base64.b64decode(data)
                    _ = encrypt_with_rsa(public_key, b'test')  # Validation
                except Exception as e:
                    print(f"[Key Format Error from {addr}] {e}")
                    continue

                # Generate a unique AES key for this client
                aes_key = generate_aes_key()
                clients[addr] = aes_key
                client_public_keys[addr] = public_key
                client_hmac_keys[addr] = aes_key

                # Encrypt AES key with the client's RSA public key
                encrypted_aes_key = encrypt_with_rsa(public_key, aes_key)
                sock.sendto(base64.b64encode(encrypted_aes_key), addr)
                print(f"[Server] AES key sent to {addr}")

            # If client already registered, process their secure message
            else:
                aes_key = clients[addr]
                hmac_key = client_hmac_keys[addr]

                try:
                    decoded = data.decode()

                    if ":" not in decoded:
                        raise ValueError("Invalid message format (missing colon)")

                    parts = decoded.split(":", 2)
                    if len(parts) != 3:
                        raise ValueError("Invalid message format (expecting iv:ct:hmac)")

                    iv_str, ct_str, received_hmac = parts

                    # Verify message authenticity
                    hmac_payload = f"{iv_str}:{ct_str}".encode()
                    if not verify_hmac(hmac_key, hmac_payload, received_hmac):
                        print(f"[HMAC Verification Failed from {addr}]")
                        continue

                    # Decrypt the message with the client's AES key
                    decrypted_msg = decrypt_with_aes(aes_key, iv_str, ct_str)

                except Exception as e:
                    print(f"[Decryption Error] {e}")
                    continue

                # Print the decrypted message to server terminal
                print(f"[{addr}] {decrypted_msg.decode()}")

                # Relay the message to all other clients (end-to-end encrypted)
                broadcast_encrypted(sock, addr, decrypted_msg)

        except Exception as e:
            print(f"[Handle Client Error] {e}")

# Broadcast a message securely to all other clients
def broadcast_encrypted(sock, sender_addr, message):
    for addr, aes_key in clients.items():
        if addr != sender_addr:
            try:
                # Encrypt the message with the recipient's AES key
                iv, encrypted_message = encrypt_with_aes(aes_key, message)
                hmac_key = client_hmac_keys[addr]

                # Generate HMAC for integrity/authentication
                hmac_payload = f"{iv}:{encrypted_message}".encode()
                tag = generate_hmac(hmac_key, hmac_payload)

                # Format and send the message
                combined = f"{iv}:{encrypted_message}:{tag}".encode()
                sock.sendto(combined, addr)

            except Exception as e:
                print(f"[Broadcast Error] {e}")

# Start the UDP server
def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SERVER_IP, SERVER_PORT))
    print(f"[Server started on {SERVER_IP}:{SERVER_PORT}]")
    handle_client(sock)

# Entry point
if __name__ == "__main__":
    main()