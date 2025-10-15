# standard_client.py
# Description: A client that sends deliberately corrupted data to the insecure
# standard_server.py to demonstrate how easily it can be fooled.

import asyncio

HOST = '127.0.0.1' # Connect to the local machine
PORT = 9999      # The port for the insecure server

async def send_attack():
    """Connects and sends a single malicious message."""
    try:
        reader, writer = await asyncio.open_connection(HOST, PORT)
        
        device_id = "DEVICE-ATTACKER"
        # The attacker changes the temperature to a dangerous, fake value.
        corrupted_payload = '{"temperature": 999.0, "humidity": 50.0}' 
        
        message = f"DEVICE_ID={device_id}:{corrupted_payload}\n"
        
        print(f"--- Standard Client (Attacker) ---")
        print(f"Connecting to insecure server at {HOST}:{PORT}")
        print(f"Sending corrupted data: {corrupted_payload}")
        
        writer.write(message.encode())
        await writer.drain()
        
        print("Corrupted data sent. Closing connection.")
        writer.close()
        await writer.wait_closed()

    except ConnectionRefusedError:
        print(f"[ERROR] Connection refused. Is the standard_server.py running?")

if __name__ == '__main__':
    asyncio.run(send_attack())
