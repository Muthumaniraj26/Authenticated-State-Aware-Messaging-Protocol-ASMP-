# standard_client_normal.py
# Description: A simple, normal client that connects to the insecure standard server.
# It sends a legitimate, non-malicious message to show how a normal interaction works.

import asyncio
import random

HOST = '127.0.0.1'
PORT = 9999
DEVICE_ID = "DEVICE-NORMAL"

async def run_client():
    """Connects to the standard server and sends a normal message."""
    print(f"--- Standard Client ({DEVICE_ID}) ---")
    try:
        reader, writer = await asyncio.open_connection(HOST, PORT)
        print(f"Connecting to insecure server at {HOST}:{PORT}")

        # --- Create a Normal, Non-Malicious Payload ---
        temp = round(random.uniform(20.0, 25.0), 2)
        humidity = round(random.uniform(40.0, 60.0), 2)
        payload = f'{{"temperature": {temp}, "humidity": {humidity}}}'
        
        message = f"DEVICE_ID={DEVICE_ID}:{payload}\n"
        
        print(f"Sending normal data: {payload}")
        writer.write(message.encode())
        await writer.drain()
        
        print("Normal data sent. Closing connection.")

    except ConnectionRefusedError:
        print("[ERROR] Connection refused. Is the standard_server.py running?")
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {e}")
    finally:
        if 'writer' in locals() and writer:
            writer.close()
            await writer.wait_closed()

if __name__ == '__main__':
    asyncio.run(run_client())
