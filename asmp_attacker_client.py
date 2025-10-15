# asmp_attacker_client.py
# Description: A special version of the ASMP client that performs a
# man-in-the-middle attack on itself to test the ASMP server's security.
# It correctly signs a normal message, but then tampers with the payload
# *after* signing, before sending it.

import asyncio
import json
import random
import time
import os
import uuid
import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

# --- Configuration ---
HOST = '127.0.0.1'
PORT = 8888 # The port for the SECURE ASMP server
DEVICE_ID = "DEVICE-001" # We will use a legitimate device's keys

class ASMPAttackerClient:
    def __init__(self, device_id):
        self.device_id = device_id
        self.prefix = f"device_{device_id.split('-')[1]}"
        self.private_key = self.load_private_key()
        self.session_id = None
        self.message_id = 0
        self.reader = None
        self.writer = None

    def load_private_key(self):
        key_file = f"{self.prefix}_private_key.pem"
        with open(key_file, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    async def connect_and_handshake(self):
        try:
            self.reader, self.writer = await asyncio.open_connection(HOST, PORT)
        except ConnectionRefusedError:
            print(f"[ERROR] Connection refused. Is the asmp_server.py running?")
            return False
            
        nonce = str(uuid.uuid4())
        signature = self.private_key.sign(nonce.encode(), ec.ECDSA(hashes.SHA256()))
        handshake_message = f"{self.device_id}:{nonce}:{signature.hex()}\n"
        self.writer.write(handshake_message.encode())
        await self.writer.drain()
        response = await self.reader.readuntil(b'\n')
        self.session_id = response.decode().strip()
        return True

    async def send_tampered_message(self):
        """Creates a valid signature, then tampers with the data."""
        self.message_id += 1
        
        # 1. Create a legitimate payload
        legit_payload = {"temperature": 22.5, "humidity": 45.8}
        legit_payload_json = json.dumps(legit_payload)
        legit_payload_hex = legit_payload_json.encode().hex()
        
        header = {
            "session_id": self.session_id,
            "message_id": self.message_id,
            "timestamp": int(time.time()),
            "message_type": "DATA"
        }
        header_json = json.dumps(header, separators=(',', ':'))

        # 2. Create a valid signature for the LEGITIMATE message
        message_to_sign = f"{header_json}:{legit_payload_hex}".encode()
        signature = self.private_key.sign(message_to_sign, ec.ECDSA(hashes.SHA256()))

        # 3. THE ATTACK: Create a fake payload AFTER signing
        fake_payload = {"temperature": 999.0, "humidity": 50.0} # DANGEROUS VALUE
        fake_payload_json = json.dumps(fake_payload)
        fake_payload_hex = fake_payload_json.encode().hex()
        
        # 4. Assemble and send the tampered message
        # The header and signature are for the legit payload, but the payload is fake.
        # The ASMP server's signature check should fail.
        tampered_message = f"{header_json}:{fake_payload_hex}:{signature.hex()}\n"
        
        print("--- ASMP Attacker Client ---")
        print(f"Handshake successful with Session ID: {self.session_id[:8]}")
        print(f"Sending TAMPERED message with fake temperature: 999.0")
        
        self.writer.write(tampered_message.encode())
        await self.writer.drain()
        print("Tampered message sent. The server should reject it.")

        self.writer.close()
        await self.writer.wait_closed()

    async def run(self):
        if await self.connect_and_handshake():
            await self.send_tampered_message()

if __name__ == '__main__':
    client = ASMPAttackerClient(DEVICE_ID)
    asyncio.run(client.run())
