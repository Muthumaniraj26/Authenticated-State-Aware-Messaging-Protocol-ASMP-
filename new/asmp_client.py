
import asyncio
import json
import time
import os
import uuid
import random
import sys
import struct # Used for message framing
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import hashlib

# --- Configuration ---
HOST = '127.0.0.1' # CHANGE THIS to the server's IP address for real network tests
PORT = 8888
DATA_INTERVAL = 5 # seconds
HEARTBEAT_INTERVAL = 30 # seconds

# --- SHARED SECRET FOR PROTOTYPE ---
SECRET_PASSPHRASE = "MyASMPUltraSecureKeyPhrase"
SHARED_AES_KEY = hashlib.sha256(SECRET_PASSPHRASE.encode('utf-8')).digest()

class ASMPClient:
    def __init__(self, device_id):
        self.device_id = device_id
        # Handle different device IDs passed from command line
        device_num = self.device_id.split('-')[-1]
        self.private_key_file = f"device_{device_num}_private_key.pem"
        self.private_key = None
        self.reader = None
        self.writer = None
        self.session_id = None
        self.message_id = 0
        self.aes_key = SHARED_AES_KEY

    async def read_msg(self):
        """Reads a length-prefixed message from the reader."""
        len_header = await self.reader.readexactly(4)
        msg_len = struct.unpack('>I', len_header)[0]
        data = await self.reader.readexactly(msg_len)
        return data

    async def write_msg(self, message):
        """Writes a length-prefixed message to the writer."""
        encoded_message = message.encode()
        len_header = struct.pack('>I', len(encoded_message))
        self.writer.write(len_header + encoded_message)
        await self.writer.drain()

    def load_private_key(self):
        """Loads the device's private key from a PEM file."""
        if not os.path.exists(self.private_key_file):
            print(f"[ERROR] Private key file '{self.private_key_file}' not found for device {self.device_id}.")
            return False
        with open(self.private_key_file, "rb") as f:
            self.private_key = serialization.load_pem_private_key(f.read(), password=None)
        return True

    def sign(self, data):
        """Signs data with the device's private key."""
        return self.private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    def encrypt_payload(self, data):
        """Encrypts a payload using AES-256-CBC."""
        iv = os.urandom(16) # Generate a random IV for each message
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext, iv

    async def connect(self):
        """Connects to the server and performs the handshake."""
        try:
            self.reader, self.writer = await asyncio.open_connection(HOST, PORT)
            print(f"Connected to server at {HOST}:{PORT}")
            return await self.perform_handshake()
        except Exception as e:
            print(f"[Connection] Failed to connect to server: {e}")
            return False

    async def perform_handshake(self):
        """Performs the ASMP handshake to establish a trusted session."""
        print("[Handshake] Performing handshake...")
        try:
            nonce = str(uuid.uuid4())
            signature = self.sign(nonce.encode())
            
            handshake_msg = f"{self.device_id}:{nonce}:{signature.hex()}"
            await self.write_msg(handshake_msg) # Use robust write
            
            response = await self.read_msg() # Use robust read
            self.session_id = response.decode().strip()
            
            if self.session_id:
                print(f"[Handshake] Handshake successful. Received Session ID: {self.session_id[:8]}")
                return True
            else:
                print("[Handshake] Handshake failed: Server returned empty session ID.")
                return False
        except (asyncio.IncompleteReadError, ConnectionResetError):
             print("[Handshake] Handshake failed. Connection closed by server before response.")
             return False
        except Exception as e:
            print(f"[Handshake] Handshake failed. {e}")
            return False

    async def send_message(self, msg_type, payload):
        """Constructs, encrypts, signs, and sends an ASMP message."""
        self.message_id += 1
        
        payload_json_string = json.dumps(payload)
        ciphertext, iv = self.encrypt_payload(payload_json_string)
        
        header = {
            "session_id": self.session_id,
            "message_id": self.message_id,
            "timestamp": int(time.time()),
            "type": msg_type,
            "iv_hex": iv.hex() # Include IV in the header
        }
        header_json = json.dumps(header, separators=(',', ':'))
        
        payload_hex = ciphertext.hex()
        
        message_to_sign = f"{header_json}:{payload_hex}".encode()
        signature = self.sign(message_to_sign)
        
        message_frame = f"{header_json}:{payload_hex}:{signature.hex()}"
        
        try:
            await self.write_msg(message_frame)
            print(f"-> Sending {msg_type} (MsgID: {self.message_id}): {payload}")
            return True
        except Exception as e:
            print(f"[Connection] Failed to send message: {e}")
            return False

    async def run(self):
        """The main loop for the client."""
        if not self.load_private_key(): return
        
        if await self.connect():
            last_data_time = time.time()
            last_heartbeat_time = time.time()

            try:
                while True:
                    now = time.time()
                    if now - last_data_time >= DATA_INTERVAL:
                        temp = round(random.uniform(20.0, 25.0), 2)
                        humidity = round(random.uniform(40.0, 60.0), 2)
                        payload = {"temperature": temp, "humidity": humidity}
                        if not await self.send_message("DATA", payload): break
                        last_data_time = now

                    if now - last_heartbeat_time >= HEARTBEAT_INTERVAL:
                        if not await self.send_message("HEARTBEAT", {"status": "OK"}): break
                        last_heartbeat_time = now
                    
                    await asyncio.sleep(1)
            except (asyncio.IncompleteReadError, ConnectionResetError):
                print("[Connection] Connection to server lost.")
            finally:
                if self.writer:
                    self.writer.close()
                    await self.writer.wait_closed()
        
        print("Closing connection.")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python asmp_client.py <DEVICE_ID>")
        print("Example: python asmp_client.py DEVICE-001")
        sys.exit(1)
    
    client_device_id = sys.argv[1]
    client = ASMPClient(client_device_id)
    
    try:
        print(f"--- ASMP Client ({client_device_id}) starting ---")
        asyncio.run(client.run())
    except KeyboardInterrupt:
        print(f"\n--- ASMP Client ({client_device_id}) shutting down ---")

