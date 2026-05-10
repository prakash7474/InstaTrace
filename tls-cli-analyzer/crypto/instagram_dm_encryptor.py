from __future__ import annotations

import base64
import json
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass
class EncryptedDM:
    payload_json: str
    nonce_b64: str
    ciphertext_b64: str
    decrypted_message_text: Optional[str]


class InstagramDMEncryptor:
    """Educational AES-256-GCM encrypt/decrypt for an Instagram-like DM payload.

    NOTE:
    - This does NOT decrypt real Instagram traffic.
    - It only provides a utility to create an IG-style JSON payload and encrypt/decrypt it locally.
    """

    def __init__(self, key_size: int = 256, key: Optional[bytes] = None) -> None:
        self.key_size = key_size

        if key is not None:
            if len(key) not in (32,):
                # For AES-256-GCM the key must be 32 bytes.
                raise ValueError("Invalid key length for AES-256-GCM; expected 32 bytes")
            self.key = key
        else:
            # Generate a random 32-byte (256-bit) key for AES-256-GCM
            self.key = AESGCM.generate_key(bit_length=self.key_size)

    @staticmethod
    def create_ig_payload(text: str) -> bytes:
        payload: Dict[str, Any] = {
            "message_id": str(uuid.uuid4()),
            "type": "generic",
            "timestamp": str(int(time.time())),
            "message_text": text,
            "client_context": str(uuid.uuid4()),
        }
        return json.dumps(payload).encode("utf-8")

    def encrypt(self, plaintext: bytes) -> Tuple[bytes, bytes]:
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        aesgcm = AESGCM(self.key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce, ciphertext

    def decrypt(self, nonce: bytes, ciphertext: bytes) -> Optional[bytes]:
        aesgcm = AESGCM(self.key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, None)
        except Exception:
            return None

    def full_process(self, message_text: str, verify: bool = True) -> EncryptedDM:
        payload_bytes = self.create_ig_payload(message_text)
        payload_json = payload_bytes.decode("utf-8")

        nonce, ciphertext = self.encrypt(payload_bytes)

        decrypted_message_text: Optional[str] = None
        if verify:
            decrypted_bytes = self.decrypt(nonce, ciphertext)
            if decrypted_bytes is not None:
                try:
                    decrypted_json = json.loads(decrypted_bytes.decode("utf-8"))
                    decrypted_message_text = decrypted_json.get("message_text")
                except Exception:
                    decrypted_message_text = None

        return EncryptedDM(
            payload_json=payload_json,
            nonce_b64=base64.b64encode(nonce).decode("ascii"),
            ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
            decrypted_message_text=decrypted_message_text,
        )

