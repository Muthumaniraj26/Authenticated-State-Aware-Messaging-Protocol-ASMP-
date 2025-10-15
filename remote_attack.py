# attacker_client.py
# Description: Simulates a compromised IoT device that successfully authenticates 
# but then tries to violate the ASMP rules (Replay or Tampering).

import asyncio
import json
import time
import os
import random
import uuid
import sys
import hashlib

# --- Cryptography Imports ---
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# --- Attack Configuration ---
# Set the type of attack to run: "REPLAY" or "TAMPER"
ATTACK_MODE = "REPLAY" 

# --- Connection Configuration (Set these to match your network) ---
SERVER_HOST = '172.16.71.181' 
SERVER_PORT = 8888
DEVICE_ID = "DEVICE-001"  # Must use a dedicated device ID for the attacker
PRIVATE_KEY_FILE = "device_001_private_key.pem" # Must use the corresponding key file

# --- Protocol Configuration ---
DATA_INTERVAL = 3  # seconds

# --- SHARED SECRET FOR PROTOTYPE CONFIDENTIALITY FIX ---
SECRET_PASSPHRASE = "MyASMPUltraSecureKeyPhrase" 
SHARED_AES_KEY = hashlib.sha256(SECRET_PASSPHRASE.encode('utf-8')).digest()

class AttackerClient:
    def __init__(self, device_id, private_key_file, attack_mode):
        self.reader = None
        self.writer = None
        self.session_id = None
        self.message_id = 0
        self.device_id = device_id
        self.attack_mode = attack_mode
        self.private_key = self.load_private_key(private_key_file)
        self.aes_key = SHARED_AES_KEY 
        print(f"[{self.device_id}] [DEBUG] Attack Mode: {self.attack_mode}")

    # --- Standard ASMP Methods (Copied from Client) ---
    def load_private_key(self, filename):
        if not os.path.exists(filename):
            print(f"[ERROR] Private key file '{filename}' not found. Please run util_generate_keys.py first.")
            exit(1)
        with open(filename, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    def sign_data(self, data):
        return self.private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    def encrypt_payload(self, data: bytes) -> tuple[bytes, bytes]:
        iv = os.urandom(16) 
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext, iv

    async def connect(self):
        try:
            self.reader, self.writer = await asyncio.open_connection(SERVER_HOST, SERVER_PORT)
            return await self.perform_handshake()
        except ConnectionRefusedError:
            print("[ERROR] Connection refused. Is the server running?")
            return False
        except Exception as e:
            print(f"[ERROR] Could not connect to server: {e}")
            return False

    async def perform_handshake(self):
        # Authenticates with the correct key (initial trust established)
        nonce = str(uuid.uuid4())
        signature = self.sign_data(nonce.encode())
        request = f"{self.device_id}:{nonce}:{signature.hex()}\n"
        self.writer.write(request.encode())
        await self.writer.drain()
        try:
            data = await self.reader.readuntil(b'\n')
            self.session_id = data.decode().strip()
            if self.session_id:
                print(f"[Handshake] Success. Session ID: {self.session_id[:8]}. Now commencing attack.")
                return True
            return False
        except asyncio.IncompleteReadError:
            return False

    async def send_message_secure(self, message_type, payload):
        """Sends a standard, secure ASMP frame. Used for the initial message."""
        self.message_id += 1
        payload_json = json.dumps(payload, separators=(',', ':')).encode('utf-8')
        encrypted_payload, iv = self.encrypt_payload(payload_json)

        header = {
            "session_id": self.session_id,
            "message_id": self.message_id,
            "timestamp": int(time.time()),
            "message_type": 1 if message_type == "DATA" else 2,
            "encrypted": True,
            "iv_hex": iv.hex()
        }
        
        header_json = json.dumps(header, separators=(',', ':'))
        message_to_sign = f"{header_json}:{encrypted_payload.hex()}".encode('utf-8')
        signature = self.sign_data(message_to_sign)
        self.last_frame = f"{header_json}:{encrypted_payload.hex()}:{signature.hex()}\n".encode('utf-8')
        
        print(f"-> Sending secure message (MsgID: {self.message_id}).")
        self.writer.write(self.last_frame)
        await self.writer.drain()


    async def send_attack_message(self, last_frame_bytes):
        """Modifies and sends the attack message based on the mode."""
        
        # --- ATTACK MODE: REPLAY ---
        if self.attack_mode == "REPLAY":
            print(f"!!! ATTACK: Replaying MsgID {self.message_id} multiple times...")
            # Send the exact same, validly signed frame repeatedly
            for i in range(3):
                # The server should close connection after the first repeat (i=0)
                if i > 0:
                    print(f"   [Replay attempt {i+1}]: Expected server connection close.")
                try:
                    self.writer.write(last_frame_bytes)
                    await self.writer.drain()
                except ConnectionResetError:
                    print(f"   [Replay attempt {i+1}]: Connection was successfully closed by server.")
                    return # Exit the loop immediately after the server closes connection
                await asyncio.sleep(0.5)
        
        # --- ATTACK MODE: DATA TAMPERING ---
        elif self.attack_mode == "TAMPER":
            # The Attacker needs to modify the encrypted payload (the hex part) 
            # without generating a new signature (as the private key is assumed secure)
            parts = last_frame_bytes.decode('utf-8').strip().rsplit(':', 2)
            header_json, encrypted_payload_hex, signature_hex = parts

            # Simulate tampering: changing a single character in the encrypted payload
            tampered_payload_hex = encrypted_payload_hex[:-1] + ('A' if encrypted_payload_hex[-1] != 'A' else 'B')
            
            # The malicious frame is constructed using the OLD signature
            tampered_frame = f"{header_json}:{tampered_payload_hex}:{signature_hex}\n".encode('utf-8')
            
            print(f"!!! ATTACK: Tampering with Encrypted Data and reusing signature...")
            try:
                self.writer.write(tampered_frame)
                await self.writer.drain()
            except ConnectionResetError:
                print("   [Tamper Attempt]: Connection was successfully closed by server after invalid signature.")
                return


    async def run(self):
        """Main attack sequence."""
        if not await self.connect():
            return
        
        try:
            # 1. Send one legitimate message to establish a baseline
            initial_payload = {"status": "Starting attack sequence", "mode": self.attack_mode}
            await self.send_message_secure("DATA", initial_payload)
            
            # 2. Execute the attack
            if hasattr(self, 'last_frame'):
                await self.send_attack_message(self.last_frame)
                
            # Keep connection open briefly to allow server to process failure
            print("Attacker finished attack and waiting for final server close...")
            await asyncio.sleep(5) 
        
        except (ConnectionResetError, asyncio.IncompleteReadError):
            print("Server successfully closed connection due to security violation.")
        except Exception as e:
            print(f"[ERROR] An unexpected error occurred in attack loop: {e}")
        finally:
            print("Closing connection.")
            if self.writer:
                # Suppress the ConnectionAbortedError often seen on remote disconnect.
                try:
                    self.writer.close()
                    await self.writer.wait_closed()
                except (ConnectionAbortedError, ConnectionResetError):
                    pass

        
if __name__ == '__main__':
    # We are using hardcoded values here for the demo simplicity, but they are defined at the top.
    attacker = AttackerClient(DEVICE_ID, PRIVATE_KEY_FILE, ATTACK_MODE)
    try:
        asyncio.run(attacker.run())
    except KeyboardInterrupt:
        print("\n--- Attacker shutting down ---")
