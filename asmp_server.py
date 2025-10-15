# asmp_server.py
# Description: ASMP Gateway, Zero-Trust Verifier, and Stateful Session Manager.

import asyncio
import json
import time
import os
import uuid
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import socket
import hashlib
import tempfile # NEW: For reliable file writing

# --- Configuration ---
HOST = '0.0.0.0'
PORT = 8888
TRUSTED_DEVICES_FILE = "trusted_devices.json"
HEARTBEAT_TIMEOUT = 40
STATE_FILE = "asmp_state.json"

# --- SHARED SECRET FOR PROTOTYPE CONFIDENTIALITY FIX ---
# NOTE: In a production system, this key MUST be established via a secure 
# key exchange (like ECDH) during the handshake and never hardcoded.
SECRET_PASSPHRASE = "MyASMPUltraSecureKeyPhrase" 
SHARED_AES_KEY = hashlib.sha256(SECRET_PASSPHRASE.encode('utf-8')).digest() 

# --- In-memory storage ---
sessions = {}
device_registry = {}

# --- Utility Functions (Cryptographic & State Management) ---

def load_public_key(device_id):
    """Loads a public key for a given device ID from the registry."""
    public_key_pem = device_registry.get(device_id)
    if not public_key_pem:
        return None
    return serialization.load_pem_public_key(public_key_pem.encode())

def verify_signature(public_key, signature, data):
    """Verifies a signature against the data using the public key."""
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

def decrypt_payload(ciphertext, iv, key):
    """Decrypts AES-256-CBC ciphertext."""
    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        return data.decode()
    except Exception as e:
        # Catch decryption/padding errors (indicates tampering or key mismatch)
        raise ValueError(f"DECRYPTION FAILED (Integrity/Confidentiality breach): {e}")

def get_session_key(session_id):
    """Retrieves the shared static key for the prototype."""
    # In a real system, this would retrieve the ECDH-derived key for the session.
    return SHARED_AES_KEY

# NEW: Function to perform atomic, reliable file writing
def write_session_state(sessions_data):
    """Writes the current sessions dictionary to the state file atomically."""
    # Create a clean dictionary suitable for JSON serialization and visualization
    visual_state = {}
    for session_id, s in sessions_data.items():
        # Only expose safe, relevant data for the monitor
        visual_state[session_id] = {
            "device_id": s.get("device_id"),
            "state": s.get("state"),
            "last_message_id": s.get("last_message_id"),
            "last_seen": s.get("last_seen"),
            "last_payload": s.get("last_payload", "N/A")
        }
    
    # Use a temporary file and rename to ensure atomic write
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, dir='.') as tmp_file:
            json.dump(visual_state, tmp_file, indent=4)
        os.replace(tmp_file.name, STATE_FILE)
    except Exception as e:
        print(f"[State Writer ERROR] Failed to write state file: {e}")
        if os.path.exists(tmp_file.name):
            os.remove(tmp_file.name) # Clean up partial temp file

def print_session_status():
    """Prints the current status of all sessions to the console."""
    if not sessions:
        print("\n--- ASMP REAL-TIME SESSION MONITORING ---")
        print("No active sessions.")
        return

    # Prepare data for console table
    table_data = []
    headers = ["ID", "DEVICE ID", "STATE", "LAST MSG", "LAST SEEN"]

    for session_id, s in sessions.items():
        state_color = ""
        if s['state'] == 'ACTIVE':
            state_color = "\033[92m" # Green
        elif s['state'] == 'TAMPERED' or s['state'] == 'HEARTBEAT_MISSED':
            state_color = "\033[91m" # Red
        else:
            state_color = "\033[93m" # Yellow

        reset_color = "\033[0m"

        last_seen_str = time.strftime('%H:%M:%S', time.localtime(s['last_seen']))
        
        table_data.append([
            session_id[:8],
            s['device_id'],
            f"{state_color}{s['state']}{reset_color}",
            s['last_message_id'],
            last_seen_str
        ])
    
    # Simple table print for console
    col_widths = [len(h) for h in headers]
    for row in table_data:
        for i, item in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(item).replace('\033[92m', '').replace('\033[91m', '').replace('\033[93m', '').replace('\033[0m', '')))

    print("\n--- ASMP REAL-TIME SESSION MONITORING ---")
    print(" | ".join(h.ljust(w) for h, w in zip(headers, col_widths)))
    print("-" * (sum(col_widths) + len(col_widths) * 3))

    for row in table_data:
        row_str = " | ".join(str(item).ljust(col_widths[i] + (len(str(item)) - len(row[i])) if isinstance(row[i], str) and '\033' in row[i] else col_widths[i]) for i, item in enumerate(row))
        print(row_str)


async def handle_connection(reader, writer):
    """Handles a single client connection."""
    addr = writer.get_extra_info('peername')
    print(f"\n[Connection] New connection from {addr}. Awaiting handshake...")
    session_id = None
    
    try:
        # --- 1. Handshake Phase ---
        handshake_data = await reader.readuntil(b'\n')
        
        handshake_parts = handshake_data.decode().strip().split(':')
        
        if len(handshake_parts) != 3:
            return

        device_id, nonce, signature_hex = handshake_parts
        public_key = load_public_key(device_id)
        
        if not public_key:
            return

        signature = bytes.fromhex(signature_hex)
        if not verify_signature(public_key, signature, nonce.encode()):
            return

        # Handshake successful
        session_id = str(uuid.uuid4())
        sessions[session_id] = {
            "device_id": device_id,
            "addr": addr,
            "state": "ACTIVE",
            "last_message_id": 0,
            "last_seen": time.time(),
            "last_payload": "N/A" # Initialized payload
        }
        sessions[session_id]["aes_key"] = get_session_key(session_id)
        
        writer.write(f"{session_id}\n".encode())
        await writer.drain()

        # Update state file after successful handshake
        write_session_state(sessions)
        print_session_status()

        # --- 2. Main Message Loop ---
        while True:
            try:
                data = await asyncio.wait_for(reader.readuntil(b'\n'), timeout=HEARTBEAT_TIMEOUT)
                message = data.decode().strip()
                parts = message.rsplit(':', 2)
                
                if len(parts) != 3:
                    sessions[session_id]['state'] = 'TAMPERED'
                    break

                header_json, payload_hex, signature_hex = parts
                
                try:
                    header = json.loads(header_json)
                except json.JSONDecodeError:
                    sessions[session_id]['state'] = 'TAMPERED'
                    break

                message_to_sign = f"{header_json}:{payload_hex}".encode()
                signature = bytes.fromhex(signature_hex)
                session = sessions.get(header['session_id'])
                
                if not session or session['state'] != 'ACTIVE':
                    # If session is inactive (e.g., missed heartbeat), don't process data
                    break
                
                if not verify_signature(public_key, signature, message_to_sign):
                    session['state'] = 'TAMPERED'
                    break
                
                if header['message_id'] <= session['last_message_id']:
                    session['state'] = 'TAMPERED'
                    break
                
                # Decrypt the payload
                encrypted_payload = bytes.fromhex(payload_hex)
                iv = bytes.fromhex(header.get("iv_hex"))
                aes_key = session['aes_key']
                
                payload_json_string = decrypt_payload(encrypted_payload, iv, aes_key)
                
                # --- FIX APPLIED HERE ---
                # Update session state after successful verification
                session['last_message_id'] = header['message_id']
                session['last_seen'] = time.time()
                # Store the decoded JSON string for the dashboard
                session['last_payload'] = payload_json_string
                # --- END FIX ---


            except asyncio.TimeoutError:
                sessions[session_id]['state'] = 'HEARTBEAT_MISSED'
                break
            except (asyncio.IncompleteReadError, ConnectionResetError):
                break
            except ValueError: # Catch decryption/padding/integrity errors
                sessions[session_id]['state'] = 'TAMPERED'
                break
            except Exception:
                sessions[session_id]['state'] = 'TAMPERED'
                break
            
            finally:
                write_session_state(sessions)
                print_session_status()

    finally:
        # Update state to DISCONNECTED/TAMPERED/MISSED before removal
        if session_id and session_id in sessions:
            if sessions[session_id]['state'] == 'ACTIVE':
                 sessions[session_id]['state'] = 'DISCONNECTED' # Clean disconnect
            
            write_session_state(sessions)
            
            # Remove from sessions after a brief pause for the dashboard to catch the last state
            await asyncio.sleep(0.5) 
            del sessions[session_id]

async def main():
    global device_registry
    if not os.path.exists(TRUSTED_DEVICES_FILE):
        print(f"[ERROR] Trusted devices file '{TRUSTED_DEVICES_FILE}' not found.")
        return

    with open(TRUSTED_DEVICES_FILE, 'r') as f:
        device_registry = json.load(f)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    
    server = await asyncio.start_server(handle_connection, sock=sock)
    addrs = ', '.join(str(s.getsockname()) for s in server.sockets)
    print(f'--- ASMP Server started on {addrs} ---')

    # Initial empty state file dump
    write_session_state({})
    
    await server.serve_forever()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n--- ASMP Server shutting down ---")
    except Exception as e:
        print(f"\n[FATAL SERVER ERROR] The server has crashed: {e}")
