# ==============================================================================
# PROJECT: AUTHENTICATED STATE-AWARE MESSAGING PROTOCOL (ASMP)
# AUTHOR:  Muthumani Raj
# COLLEGE: AAA College of Engineering and Technology
# PLACE:   Sivakasi, Tamil Nadu
# DATE:    15-October-2025
# ==============================================================================

# asmp_server.py
# Description: The final, production-ready version of the ASMP Gateway.
# This version is resilient against common network errors and includes all features:
# AI anomaly detection, AES encryption, and clear, color-coded console monitoring.

import asyncio
import json
import time
import os
import uuid
import socket
import struct
import numpy as np
import hashlib
import tempfile
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# --- Configuration ---
HOST = '0.0.0.0'
PORT = 8888
TRUSTED_DEVICES_FILE = "trusted_devices.json"
STATE_FILE = "asmp_state.json"
HEARTBEAT_TIMEOUT = 40
AI_TRAINING_SAMPLES = 10
AI_ANOMALY_THRESHOLD = 3.0

# --- ANSI Color Codes for Terminal Output ---
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BLUE = '\033[94m'
GRAY = '\033[90m'
RESET = '\033[0m'

# --- SHARED SECRET FOR PROTOTYPE ---
SECRET_PASSPHRASE = "MyASMPUltraSecureKeyPhrase"
SHARED_AES_KEY = hashlib.sha256(SECRET_PASSPHRASE.encode('utf-8')).digest()

# --- In-memory storage ---
sessions = {}
device_registry = {}

# --- AI Anomaly Detection Logic ---
def train_model(history):
    temps = [reading['temperature'] for reading in history if 'temperature' in reading]
    if len(temps) < 2: return None
    mean, std_dev = np.mean(temps), np.std(temps)
    if std_dev == 0: std_dev = 0.1
    print(f"{BLUE}[AI INFO] Training complete. Model: mean={mean:.2f}, std_dev={std_dev:.2f}{RESET}")
    return {"mean": mean, "std_dev": std_dev}

def is_anomaly(model, reading):
    if not model or 'temperature' not in reading: return False
    temp = reading['temperature']
    deviation = abs(temp - model["mean"]) / model["std_dev"]
    if deviation > AI_ANOMALY_THRESHOLD:
        print(f"{RED}[AI ALERT] Anomaly detected! Deviation: {deviation:.2f} > Threshold: {AI_ANOMALY_THRESHOLD}{RESET}")
        return True
    return False

# --- ASMP Protocol & Utility Logic ---
def load_public_key(device_id):
    public_key_pem = device_registry.get(device_id)
    if not public_key_pem: return None
    return serialization.load_pem_public_key(public_key_pem.encode())

def verify_signature(public_key, signature, data):
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

def decrypt_payload(ciphertext, iv, key):
    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        return data.decode()
    except Exception as e:
        raise ValueError(f"DECRYPTION FAILED: {e}")

def get_session_key(session_id):
    return SHARED_AES_KEY

def write_session_state(sessions_data):
    visual_state = {}
    for session_id, s in sessions_data.items():
        visual_state[session_id] = {k: v for k, v in s.items() if k not in ['aes_key', 'history', 'model']}
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, dir='.') as tmp_file:
            json.dump(visual_state, tmp_file, indent=4)
        os.replace(tmp_file.name, STATE_FILE)
    except Exception as e:
        print(f"{YELLOW}[State Writer WARNING] Failed to write state file: {e}{RESET}")
        if 'tmp_file' in locals() and os.path.exists(tmp_file.name):
            os.remove(tmp_file.name)

def print_session_status():
    if not sessions:
        print("\n--- ASMP REAL-TIME SESSION MONITORING ---\nNo active sessions.")
        return
    headers = ["ID", "DEVICE ID", "STATE", "LAST MSG", "LAST SEEN"]
    table_data = []
    for session_id, s in sessions.items():
        state_color = {"ACTIVE": GREEN, "TAMPERED": RED, "HEARTBEAT_MISSED": RED, "DISCONNECTED": GRAY}.get(s.get('state'), YELLOW)
        reset_color = RESET
        last_seen_str = time.strftime('%H:%M:%S', time.localtime(s.get('last_seen', 0)))
        table_data.append([
            session_id[:8], s.get('device_id'), f"{state_color}{s.get('state')}{reset_color}",
            s.get('last_message_id', 0), last_seen_str
        ])
    def get_display_len(s):
        s = str(s)
        for color_code in [GREEN, YELLOW, RED, BLUE, GRAY, RESET]: s = s.replace(color_code, '')
        return len(s)
    col_widths = [len(h) for h in headers]
    for row in table_data:
        for i, item in enumerate(row): col_widths[i] = max(col_widths[i], get_display_len(item))
    print("\n--- ASMP REAL-TIME SESSION MONITORING ---")
    print(" | ".join(h.ljust(w) for h, w in zip(headers, col_widths)))
    print("-" * (sum(col_widths) + len(col_widths) * 3))
    for row in table_data:
        row_items = []
        for i, item in enumerate(row):
            item_str, display_len = str(item), get_display_len(item)
            padding = " " * (col_widths[i] - display_len)
            row_items.append(f"{item_str}{padding}")
        print(" | ".join(row_items))

async def read_msg(reader):
    len_header = await reader.readexactly(4)
    if not len_header: return None
    msg_len = struct.unpack('>I', len_header)[0]
    if msg_len > 1024 * 10: raise ValueError("Message size too large.")
    data = await reader.readexactly(msg_len)
    return data

async def handle_connection(reader, writer):
    addr = writer.get_extra_info('peername')
    print(f"\n{BLUE}[INFO] New connection from {addr}. Awaiting handshake...{RESET}")
    session_id = None
    
    try:
        handshake_data = await read_msg(reader)
        if not handshake_data: return
        handshake_parts = handshake_data.decode().strip().split(':')
        
        if len(handshake_parts) != 3: return
        device_id, nonce, signature_hex = handshake_parts
        public_key = load_public_key(device_id)
        if not public_key: return
        signature = bytes.fromhex(signature_hex)
        if not verify_signature(public_key, signature, nonce.encode()): return

        session_id = str(uuid.uuid4())
        sessions[session_id] = {
            "device_id": device_id, "addr": addr, "state": "ACTIVE",
            "last_message_id": 0, "last_seen": time.time(), "last_payload": "N/A",
            "aes_key": get_session_key(session_id),
            "history": [], "model": None, "is_trained": False
        }
        
        writer.write(struct.pack('>I', len(session_id)) + session_id.encode())
        await writer.drain()
        print_session_status()

        while True:
            data = await asyncio.wait_for(read_msg(reader), timeout=HEARTBEAT_TIMEOUT)
            if not data: break
            
            message = data.decode().strip()
            parts = message.rsplit(':', 2)
            
            if len(parts) != 3:
                sessions[session_id]['state'] = 'TAMPERED'; break

            header_json, payload_hex, signature_hex = parts
            header = json.loads(header_json)
            message_to_sign = f"{header_json}:{payload_hex}".encode()
            signature = bytes.fromhex(signature_hex)
            session = sessions.get(header['session_id'])
            
            if not session or session['state'] != 'ACTIVE': break
            if not verify_signature(public_key, signature, message_to_sign):
                session['state'] = 'TAMPERED'
                print(f"{RED}[ATTACK DETECTED] Invalid Signature from {device_id}. Connection terminated.{RESET}")
                break
            if header['message_id'] <= session['last_message_id']:
                session['state'] = 'TAMPERED'
                print(f"{RED}[ATTACK DETECTED] Replay Attack from {device_id}. Connection terminated.{RESET}")
                break
            
            encrypted_payload = bytes.fromhex(payload_hex)
            iv = bytes.fromhex(header.get("iv_hex"))
            aes_key = session['aes_key']
            payload_json_string = decrypt_payload(encrypted_payload, iv, aes_key)
            payload = json.loads(payload_json_string)

            if header['type'] == 'DATA':
                if not session['is_trained']:
                    session['history'].append(payload)
                    if len(session['history']) >= AI_TRAINING_SAMPLES:
                        session['model'] = train_model(session['history'])
                        session['is_trained'] = True
                else:
                    if is_anomaly(session['model'], payload):
                        session['state'] = 'TAMPERED'
                        print(f"{RED}[AI DEFENSE] Statistical anomaly detected from {device_id}. This is a potential insider attack. Connection terminated.{RESET}")
                        break
            
            session['last_message_id'] = header['message_id']
            session['last_seen'] = time.time()
            session['last_payload'] = payload_json_string
            write_session_state(sessions)
            print_session_status()

    except (asyncio.IncompleteReadError, ConnectionResetError, ValueError) as e:
        print(f"{GRAY}[INFO] Client {addr} disconnected cleanly ({type(e).__name__}).{RESET}")
    except asyncio.TimeoutError:
        if session_id and session_id in sessions: sessions[session_id]['state'] = 'HEARTBEAT_MISSED'
    except Exception as e:
        if session_id and session_id in sessions: sessions[session_id]['state'] = 'TAMPERED'
        print(f"{YELLOW}[WARNING][Session {session_id[:8]}] A minor network issue occurred: {e}{RESET}")
    finally:
        if session_id and session_id in sessions:
            if sessions[session_id]['state'] == 'ACTIVE':
                sessions[session_id]['state'] = 'DISCONNECTED'
            print_session_status()
            write_session_state(sessions)
            await asyncio.sleep(0.5)
            del sessions[session_id]
        
        print_session_status()
        if writer:
            writer.close()
            await writer.wait_closed()

async def main():
    global device_registry
    if not os.path.exists(TRUSTED_DEVICES_FILE):
        print(f"{RED}[SETUP INCOMPLETE] The '{TRUSTED_DEVICES_FILE}' file is missing. Please run the key generation script first.{RESET}")
        return
    with open(TRUSTED_DEVICES_FILE, 'r') as f:
        device_registry = json.load(f)
    print(f"{BLUE}[INFO] Loaded {len(device_registry)} trusted devices.{RESET}")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    
    server = await asyncio.start_server(handle_connection, sock=sock)
    addrs = ', '.join(str(s.getsockname()) for s in server.sockets)
    print(f'--- ASMP Server (AI-Powered) started on {addrs} ---')
    
    write_session_state({})
    print_session_status()
    await server.serve_forever()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"\n{RED}[CRITICAL] The server has stopped unexpectedly: {e}{RESET}")
    finally:
        print("\n--- ASMP Server shutting down ---")

