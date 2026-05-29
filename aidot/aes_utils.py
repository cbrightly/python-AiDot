from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES-ECB encrypt with raw key bytes (used for LAN discovery / TCP:10000)."""
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()


def aes_decrypt(ciphertext: bytes, key: bytes) -> str:
    """AES-ECB decrypt with raw key bytes; returns UTF-8 string."""
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
    return plaintext.decode("utf-8")


def _str_key_32(key_str: str) -> bytes:
    """Zero-pad a string key to 32 bytes (AESUtils.get32Key from Leedarson SDK)."""
    raw = key_str.encode("utf-8")
    return raw[:32].ljust(32, b"\x00")


def aes_ecb_encrypt_str_key(plaintext: bytes, key_str: str) -> bytes:
    """AES-256/ECB/PKCS7 encrypt; key is a string zero-padded to 32 bytes."""
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(_str_key_32(key_str)), modes.ECB(), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


def aes_ecb_decrypt_str_key(ciphertext: bytes, key_str: str) -> bytes:
    """AES-256/ECB/PKCS7 decrypt; key is a string zero-padded to 32 bytes."""
    cipher = Cipher(algorithms.AES(_str_key_32(key_str)), modes.ECB(), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()
