# util_generate_keys.py
# Description: A utility script to generate the necessary cryptographic keys
# for both the server and the simulated IoT devices. It also creates the
# trusted device registry file used by the server.

import os
import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# --- Configuration ---
SERVER_KEY_PREFIX = "server"
DEVICES = {
    "DEVICE-001": "device_001"
}
TRUSTED_DEVICES_FILE = "trusted_devices.json"

def generate_keys_and_get_public_pem(prefix):
    """Generates an ECDSA private/public key pair and returns the public key PEM."""
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()

    # Serialize and save private key
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(f"{prefix}_private_key.pem", "wb") as f:
        f.write(pem_private)
    print(f"Private key saved to {prefix}_private_key.pem")

    # Serialize and save public key
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(f"{prefix}_public_key.pem", "wb") as f:
        f.write(pem_public)
    print(f"Public key saved to {prefix}_public_key.pem")
    
    return pem_public.decode('utf-8')

def create_trusted_registry(device_public_keys):
    """Creates the trusted device registry file from the provided public keys."""
    print("\n[3] Creating Trusted Device Registry...")
    
    with open(TRUSTED_DEVICES_FILE, 'w') as f:
        json.dump(device_public_keys, f, indent=4)
    print(f"Trusted device registry saved to {TRUSTED_DEVICES_FILE}")


if __name__ == '__main__':
    print("--- Generating Keys for ASMP Prototype ---")
    
    # This will hold the public keys for the trusted device registry
    device_public_keys_registry = {}

    print("\n[1] Generating Server Keys...")
    generate_keys_and_get_public_pem(SERVER_KEY_PREFIX)
    print("Server keys generated successfully.")

    print("\n[2] Generating Keys for Devices...")
    for device_id, prefix in DEVICES.items():
        print(f"--- Generating for '{device_id}' ---")
        public_pem = generate_keys_and_get_public_pem(prefix)
        device_public_keys_registry[device_id] = public_pem
        print(f"Device '{device_id}' keys generated successfully.")

    # Create the JSON file with the public keys we just generated
    create_trusted_registry(device_public_keys_registry)

    print("\n--- Key Generation and Registry Creation Complete ---")
    print("Next steps:")
    print("1. Start the asmp_server.py.")
    print("2. Run the asmp_client.py.")
