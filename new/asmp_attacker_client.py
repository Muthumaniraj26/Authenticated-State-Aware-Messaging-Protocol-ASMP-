# ==============================================================================
# PROJECT: AUTHENTICATED STATE-AWARE MESSAGING PROTOCOL (ASMP)
# AUTHOR:  Muthumani Raj
# COLLEGE: AAA College of Engineering and Technology
# PLACE:   Sivakasi, Tamil Nadu
# DATE:    15-October-2025
# ==============================================================================

# asmp_attacker_client.py
# Description: An advanced attacker client for ASMP.
# This version is designed to specifically test the AI Anomaly Detection layer.
# It sends a message with a PERFECTLY VALID signature but a SUBTLE ANOMALOUS payload.

import asyncio
import json
import time
import os
import uuid
import struct
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# --- Configuration ---
HOST = '127.0.0.1' # Must match the server's IP
PORT = 8888
DEVICE_ID = "DEVICE-001" # Pretend to be a legitimate device

# --- SHARED SECRET FOR PROTOTYPE ---
SECRET_PASSPHRASE = "MyASMPUltraSecureKeyPhrase"
SHARED_AES_KEY = hashlib.sha256(SECRET_PASSPHRASE.encode('utf-8')).digest()

class ASMPAttackerClient:
    def __init__(self, device_id):
        self.device_id = device_id
        device_num = self.device_id.split('-')[-1]
        self.private_key_file = f"device_{device_num}_private_key.pem"
        self.private_key = None
        self.reader = None
        self.writer = None
        self.session_id = None
        self.message_id = 999 # Use a high message ID to avoid replay errors
        self.aes_key = SHARED_AES_KEY

    # (Helper functions for networking, crypto, and encryption)
    async def read_msg(self):
        len_header = await self.reader.readexactly(4)
        msg_len = struct.unpack('>I', len_header)[0]
        data = await self.reader.readexactly(msg_len)
        return data

    async def write_msg(self, message):
        encoded_message = message.encode()
        len_header = struct.pack('>I', len(encoded_message))
        self.writer.write(len_header + encoded_message)
        await self.writer.drain()

    def load_private_key(self):
        if not os.path.exists(self.private_key_file):
            print(f"[ERROR] Private key file '{self.private_key_file}' not found.")
            return False
        with open(self.private_key_file, "rb") as f:
            self.private_key = serialization.load_pem_private_key(f.read(), password=None)
        return True

    def sign(self, data):
        return self.private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    def encrypt_payload(self, data):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext, iv

    async def connect_and_handshake(self):
        try:
            self.reader, self.writer = await asyncio.open_connection(HOST, PORT)
            print(f"Connected to server at {HOST}:{PORT}")
            
            nonce = str(uuid.uuid4())
            signature = self.sign(nonce.encode())
            handshake_msg = f"{self.device_id}:{nonce}:{signature.hex()}"
            await self.write_msg(handshake_msg)
            
            response = await self.read_msg()
            self.session_id = response.decode().strip()
            
            if self.session_id:
                print(f"[Handshake] Legitimate handshake successful. Session ID: {self.session_id[:8]}")
                return True
            return False
        except Exception as e:
            print(f"[Connection] Failed to connect or handshake: {e}")
            return False

    async def run_attack(self):
        """The main logic for the attack."""
        if not self.load_private_key(): return

        if await self.connect_and_handshake():
            print("\n--- Preparing Smart Attack: Compromised Insider ---")
            print("Objective: Send a plausible but anomalous payload with a valid signature.")
            
            # --- CHANGE APPLIED HERE ---
            # The temperature is changed to 27.0, a value that is meaningful
            # but should be detected as a statistical anomaly by the AI.
            anomalous_payload = {"temperature": 27.0, "humidity": 50.0}
            payload_json_string = json.dumps(anomalous_payload)
            ciphertext, iv = self.encrypt_payload(payload_json_string)
            
            header = {
                "session_id": self.session_id,
                "message_id": self.message_id,
                "timestamp": int(time.time()),
                "type": "DATA",
                "iv_hex": iv.hex()
            }
            header_json = json.dumps(header, separators=(',', ':'))
            
            payload_hex = ciphertext.hex()
            
            message_to_sign = f"{header_json}:{payload_hex}".encode()
            signature = self.sign(message_to_sign)
            
            message_frame = f"{header_json}:{payload_hex}:{signature.hex()}"
            
            print(f"-> Sending MALICIOUS DATA (MsgID: {self.message_id}): {anomalous_payload}")
            print("   (Note: The signature for this message is cryptographically valid)")
            
            try:
                await self.write_msg(message_frame)
                print("   Waiting for server to respond or close the connection...")
                # Try to read data. If the server closes the connection, this will fail.
                data = await self.reader.read(100) 
                if not data:
                    print("[Attack SUCCESS] The server closed the connection as a defense, as expected.")
            except (asyncio.IncompleteReadError, ConnectionResetError):
                print("[Attack SUCCESS] The server closed the connection as a defense, as expected.")
            except Exception as e:
                print(f"[Attack] An unexpected error occurred: {e}")

        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()
        print("\n--- Attack complete. ---")


if __name__ == '__main__':
    client = ASMPAttackerClient(DEVICE_ID)
    try:
        print(f"--- ASMP Attacker Client ({DEVICE_ID}) starting ---")
        asyncio.run(client.run_attack())
    except KeyboardInterrupt:
        print("\n--- ASMP Attacker Client shutting down ---")

