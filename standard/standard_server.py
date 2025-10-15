# standard_server.py
# Description: An insecure server that does not perform cryptographic validation.
# This version is intentionally simple to highlight the vulnerabilities that ASMP solves.
# This version includes color-coded output for better readability.

import asyncio
import socket

# --- Configuration ---
HOST = '0.0.0.0' # Listen on all network interfaces
PORT = 9999

# --- ANSI Color Codes for Terminal Output ---
GREEN = '\033[92m'
YELLOW = '\033[93m'
RESET = '\033[0m'

async def handle_connection(reader, writer):
    """Handles a single client connection for the standard, insecure server."""
    addr = writer.get_extra_info('peername')
    # Use GREEN for successful connection
    print(f"{GREEN}[Standard Server] New connection from {addr}{RESET}")
    
    try:
        while True:
            # STEP 1: The server receives the raw data.
            data = await reader.readuntil(b'\n')
            
            # Decode with an error handler to be robust
            message = data.decode('utf-8', errors='ignore').strip()

            # If the message is empty after decoding/stripping, the client has disconnected.
            if not message:
                break
            
            # STEP 2: The server IMMEDIATELY processes the data by printing it.
            # It blindly accepts whatever it receives.
            # Use YELLOW for received data
            print(f"{YELLOW}[Standard Server] DATA RECEIVED: {message}{RESET}")

    except (asyncio.IncompleteReadError, ConnectionResetError):
        # This block is entered when the client closes the connection.
        print(f"[Standard Server] Client {addr} disconnected.")
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred with client {addr}: {e}")
    finally:
        print(f"[Standard Server] Closing connection from {addr}")
        if writer:
            writer.close()
            await writer.wait_closed()

async def main():
    """Main function to start the insecure server."""
    # Create a socket and set SO_REUSEADDR to allow fast restarts
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))

    server = await asyncio.start_server(handle_connection, sock=sock)

    addrs = ', '.join(str(s.getsockname()) for s in server.sockets)
    print(f'--- Standard Server (Insecure) started on {addrs} ---')
    
    try:
        await server.serve_forever()
    except asyncio.CancelledError:
        pass
    finally:
        server.close()
        await server.wait_closed()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    finally:
        print("\n--- Standard Server shutting down ---")

