# asmp_client.py
# Description: A client application that simulates an IoT device using the ASMP protocol.
# Now includes AES-256 encryption and reflects the architecture needed for HSM key storage.

import asyncio
import json
import time
import os
import random
import uuid

# --- Cryptography Imports for Authentication and Encryption ---
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# --- New Import for Robust Key Derivation ---
import hashlib

# --- Configuration ---
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 8888
DEVICE_ID = "DEVICE-001"
PRIVATE_KEY_FILE = "device_001_private_key.pem"
DATA_INTERVAL = 5  # seconds
HEARTBEAT_INTERVAL = 30 # seconds

# --- SHARED SECRET FOR PROTOTYPE CONFIDENTIALITY FIX ---
# NOTE: In a production system, this key MUST be established via a secure 
# key exchange (like ECDH) during the handshake and never hardcoded.
# FIX: Use SHA-256 to guarantee a 32-byte (256-bit) key for AES.
SECRET_PASSPHRASE = "MyASMPUltraSecureKeyPhrase" 
SHARED_AES_KEY = hashlib.sha256(SECRET_PASSPHRASE.encode('utf-8')).digest()

class ASMPClient:
    def __init__(self):
        self.reader = None
        self.writer = None
        self.session_id = None
        self.message_id = 0
        
        # [KEY MANAGEMENT ABSTRACTION]
        # In the prototype, we load the key from a file for simulation convenience.
        self.private_key = self.load_private_key(PRIVATE_KEY_FILE)
        
        # [CONFIDENTIALITY FIX] Use the derived SHA-256 key
        self.aes_key = SHARED_AES_KEY 
        print(f"[{DEVICE_ID}] [DEBUG] Using derived SHA-256 AES key (32-byte) for prototype encryption.")


    def load_private_key(self, filename):
        """
        [KEY MANAGEMENT ABSTRACTION] 
        In production, this function would return a hardware key handle (HSM/TPM).
        """
        if not os.path.exists(filename):
            print(f"[ERROR] Private key file '{filename}' not found. Please run util_generate_keys.py first.")
            exit(1)
        with open(filename, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    def sign_data(self, data):
        """
        [KEY MANAGEMENT ABSTRACTION] 
        In production, this would call the HSM/TPM signing function.
        """
        return self.private_key.sign(
            data,
            ec.ECDSA(hashes.SHA256())
        )

    def encrypt_payload(self, data: bytes) -> tuple[bytes, bytes]:
        """[CONFIDENTIALITY] Encrypts data using AES-256-CBC and returns ciphertext and IV."""
        # Generate a unique Initialization Vector (IV) for every message
        iv = os.urandom(16) 
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Add PKCS7 padding before encryption
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext, iv

    async def connect(self):
        """Connects to the server and performs the handshake."""
        print(f"--- ASMP Client ({DEVICE_ID}) starting ---")
        try:
            # FIX: The actual connection attempt is here. If this fails, the server is offline.
            self.reader, self.writer = await asyncio.open_connection(SERVER_HOST, SERVER_PORT)
            print(f"Connected to server at {SERVER_HOST}:{SERVER_PORT}")
            return await self.perform_handshake()
        except ConnectionRefusedError:
            print("[ERROR] Connection refused. Is the server running?")
            return False
        except Exception as e:
            print(f"[ERROR] Could not connect to server: {e}")
            return False

    async def perform_handshake(self):
        """Performs the ASMP Identity-First Handshake."""
        print("[Handshake] Performing handshake (Authenticating with ECDSA signature)...")
        # Nonce for handshake is signed
        nonce = str(uuid.uuid4())
        signature = self.sign_data(nonce.encode())
        
        # Format: <Device_ID>:<Nonce>:<Signature_in_hex>
        request = f"{DEVICE_ID}:{nonce}:{signature.hex()}\n"
        
        self.writer.write(request.encode())
        await self.writer.drain()

        # Wait for REGISTER_RESPONSE
        try:
            data = await self.reader.readuntil(b'\n')
            self.session_id = data.decode().strip()
            
            if self.session_id:
                print(f"[Handshake] Handshake successful. Received Session ID: {self.session_id[:8]}")
                return True
            else:
                print("[Handshake] Handshake failed. Server did not provide a Session ID.")
                return False
        except asyncio.IncompleteReadError:
            print("[Handshake] Handshake failed. Connection closed by server before response.")
            return False


    async def send_message(self, message_type, payload):
        """Constructs and sends a secure ASMP message frame (Authenticated and Encrypted)."""
        self.message_id += 1
        
        # --- A. Encrypt the Payload ---
        payload_json = json.dumps(payload, separators=(',', ':')).encode('utf-8')
        encrypted_payload, iv = self.encrypt_payload(payload_json)

        # --- B. Create the Header with new encryption metadata ---
        header = {
            "session_id": self.session_id,
            "message_id": self.message_id, # Anti-Replay Counter
            "timestamp": int(time.time()),
            "message_type": 1 if message_type == "DATA" else 2,
            "encrypted": True,
            "iv_hex": iv.hex()
        }
        
        header_json = json.dumps(header, separators=(',', ':'))
        
        # --- C. Atomic Message Attestation (Sign the Header + Encrypted Payload) ---
        message_to_sign = f"{header_json}:{encrypted_payload.hex()}".encode('utf-8')
        signature = self.sign_data(message_to_sign)
        
        # --- D. Assemble the final ASMP Frame ---
        # Frame Format: Header(JSON):EncryptedPayload(HEX):Signature(HEX)
        frame = f"{header_json}:{encrypted_payload.hex()}:{signature.hex()}\n"
        
        print(f"-> Sending {message_type} (MsgID: {self.message_id}) [Encrypted]")
        self.writer.write(frame.encode('utf-8'))
        await self.writer.drain()

    async def run(self):
        """Main loop to connect and send data."""
        if not await self.connect():
            return
        
        now = time.time()
        last_data_time = now
        last_heartbeat_time = now

        # Send an initial data message right after connecting
        initial_payload = {
            "temperature": round(random.uniform(20.0, 25.0), 2),
            "humidity": round(random.uniform(40.0, 60.0), 2)
        }
        await self.send_message("DATA", initial_payload)

        try:
            while True:
                now = time.time()
                # Send sensor data periodically
                if now - last_data_time >= DATA_INTERVAL:
                    payload = {
                        "temperature": round(random.uniform(20.0, 25.0), 2),
                        "humidity": round(random.uniform(40.0, 60.0), 2)
                    }
                    await self.send_message("DATA", payload)
                    last_data_time = now

                # Send heartbeat periodically
                if now - last_heartbeat_time >= HEARTBEAT_INTERVAL:
                    # Heartbeat payload is also encrypted and signed
                    await self.send_message("HEARTBEAT", {"status": "OK", "uptime_s": int(now - last_data_time)})
                    last_heartbeat_time = now
                
                await asyncio.sleep(1)
        except (ConnectionResetError, asyncio.IncompleteReadError, ConnectionAbortedError):
            print("[Connection] Connection to server lost.")
        except Exception as e:
            print(f"[ERROR] An unexpected error occurred in client loop: {e}")
        finally:
            print("Closing connection.")
            if self.writer:
                # Added conditional check to suppress the ConnectionAbortedError 
                # that often occurs on cleanup after the server forces a disconnect.
                try:
                    self.writer.close()
                    await self.writer.wait_closed()
                except ConnectionAbortedError:
                    pass


if __name__ == '__main__':
    client = ASMPClient()
    try:
        asyncio.run(client.run())
    except KeyboardInterrupt:
        print("\n--- ASMP Client shutting down ---")
