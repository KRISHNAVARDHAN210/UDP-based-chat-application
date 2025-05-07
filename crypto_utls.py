__all__ = [
    "generate_rsa_keypair",
    "encrypt_with_rsa",
    "decrypt_with_rsa",
    "generate_aes_key",
    "encrypt_with_aes",
    "decrypt_with_aes"
]
"""
Cryptographic utilities for secure communication.

This module provides functions for generating RSA key pairs,
encrypting/decrypting messages with RSA and AES, and handling base64 encoding.
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64


def generate_rsa_keypair():
    """
    Generate a new RSA key pair.

    Returns:
        tuple: A tuple containing the private key and public key as byte strings.
    """
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def encrypt_with_rsa(public_key_bytes, message_bytes):
    """
    Encrypt data using an RSA public key.

    Args:
        public_key_bytes (bytes): The RSA public key in bytes.
        message_bytes (bytes): The plaintext message to encrypt.

    Returns:
        bytes: The encrypted message.
    """
    pub_key = RSA.import_key(public_key_bytes)
    cipher_rsa = PKCS1_OAEP.new(pub_key)
    return cipher_rsa.encrypt(message_bytes)


def decrypt_with_rsa(private_key_bytes, ciphertext_bytes):
    """
    Decrypt data using an RSA private key.

    Args:
        private_key_bytes (bytes): The RSA private key in bytes.
        ciphertext_bytes (bytes): The encrypted message.

    Returns:
        bytes: The decrypted plaintext message.
    """
    priv_key = RSA.import_key(private_key_bytes)
    cipher_rsa = PKCS1_OAEP.new(priv_key)
    return cipher_rsa.decrypt(ciphertext_bytes)


def generate_aes_key():
    """
    Generate a new 128-bit AES key.

    Returns:
        bytes: A 16-byte AES key.
    """
    return get_random_bytes(16)


def encrypt_with_aes(key, plaintext_bytes):
    """
    Encrypt data using AES in CBC mode.

    Args:
        key (bytes): The AES encryption key (16 bytes).
        plaintext_bytes (bytes): The plaintext message.

    Returns:
        tuple: A tuple containing the IV and ciphertext as base64-encoded strings.
    """
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext_bytes, AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct


def decrypt_with_aes(key, iv, ct):
    """
    Decrypt AES-encrypted data using CBC mode.

    Args:
        key (bytes): The AES decryption key (16 bytes).
        iv (str): Base64-encoded initialization vector.
        ct (str): Base64-encoded ciphertext.

    Returns:
        bytes: The decrypted plaintext.
    """
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt
