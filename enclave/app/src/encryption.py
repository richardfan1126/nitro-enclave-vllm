import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from Crypto.Cipher import AES

class Encryption:
    def __init__(self):
        """Constructor - generates new X25519 key pair"""
        self.priv_key = X25519PrivateKey.generate()
        self.pub_key = self.priv_key.public_key()

    def get_pub_key_bytes(self) -> bytes:
        """Get public key as bytes"""
        return self.pub_key.public_bytes_raw()

    def get_session_key(self, client_pub_key_b64: str) -> bytes:
        """Generate session key using ECDH"""
        client_pub_key_bytes = base64.b64decode(client_pub_key_b64)
        
        if len(client_pub_key_bytes) != 32:
            raise ValueError("Invalid client public key length")
        
        client_pub_key = X25519PublicKey.from_public_bytes(client_pub_key_bytes)
        session_key = self.priv_key.exchange(client_pub_key)
        
        return session_key

    @staticmethod
    def decrypt(encrypted_payload: str, session_key: bytes) -> str:
        """Decrypt payload using AES-GCM"""
        parts = encrypted_payload.split(":")
        if len(parts) != 3:
            raise ValueError("Invalid encrypted payload format")
        
        nonce_b64, ciphertext_b64, digest_b64 = parts
        
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        digest = base64.b64decode(digest_b64)
        
        try:
            cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce = nonce)
            decrypted_bytes = cipher_aes.decrypt_and_verify(ciphertext, digest)
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Failed to decrypt: {str(e)}")

    @staticmethod
    def encrypt(plaintext: str, session_key: bytes) -> str:
        """Encrypt plaintext using AES-GCM"""
        nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
        
        aesgcm = AESGCM(session_key)
        
        try:
            ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
            
            ciphertext_b64 = base64.b64encode(ciphertext).decode()
            nonce_b64 = base64.b64encode(nonce).decode()
            
            return f"{nonce_b64}:{ciphertext_b64}"
        except Exception as e:
            raise ValueError(f"Failed to encrypt: {str(e)}")