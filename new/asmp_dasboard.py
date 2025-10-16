# asmp_dashboard.py
# Description: WebSocket server that reads the ASMP session state file and pushes 
# real-time updates to the browser dashboard.

import asyncio
import json
import time
import os
import aiohttp.web
import websockets

STATE_FILE = "asmp_state.json"
WEB_HOST = '0.0.0.0'
WEB_PORT = 8080
WS_PORT = 8081 # Separate port for WebSocket

# Set to keep track of all active WebSocket connections
websocket_connections = set()

async def register_websocket(websocket, path):
    """
    Registers a new WebSocket connection.
    Includes 'path' argument as required by the websockets library, 
    but only the websocket object is used here.
    """
    websocket_connections.add(websocket)
    try:
        # Keep the connection open until closed by client or error
        await websocket.wait_closed()
    finally:
        websocket_connections.remove(websocket)

# --- START OF FIX ---
# Define a simple wrapper to ensure the handler is called correctly, 
# even if the path isn't strictly needed for the single endpoint.
# This fixes the "missing 1 required positional argument: 'path'" TypeError.
async def websocket_handler_wrapper(websocket, path):
    await register_websocket(websocket, path)
# --- END OF FIX ---


async def state_pusher():
    """Reads the state file periodically and pushes updates to all connected clients."""
    last_modified = 0
    print(f"[Pusher] Starting state pusher loop.")
    while True:
        await asyncio.sleep(1) # Check state file every second
        
        # Ensure file exists before trying to read metadata
        if not os.path.exists(STATE_FILE):
            continue

        try:
            current_modified = os.path.getmtime(STATE_FILE)
            
            # Check if the file has been modified since the last check
            if current_modified > last_modified:
                with open(STATE_FILE, 'r') as f:
                    state_data = f.read()
                
                if websocket_connections:
                    print(f"[Pusher] Sending update to {len(websocket_connections)} client(s)")
                    print(f"[Pusher] Data: {state_data[:200]}")  # show first 200 chars
                    await asyncio.gather(*[ws.send(state_data) for ws in websocket_connections])

                
        except json.JSONDecodeError:
            # This is expected if the server writes the file partially
            print("[Pusher ERROR] Cannot decode state file (Partial Write detected). Skipping.")
        except FileNotFoundError:
            continue
        except Exception as e:
            print(f"[Pusher ERROR] An unexpected error occurred: {e}")

async def index_handler(request):
    """Handles requests for the main dashboard HTML file."""
    # NOTE: This requires index.html to be in the same directory.
    try:
        with open('index.html', 'r') as f:
            content = f.read()
        return aiohttp.web.Response(text=content, content_type='text/html')
    except FileNotFoundError:
        return aiohttp.web.Response(text="Error: index.html not found.", status=404)

async def start_websocket_server():
    """Starts the standalone WebSocket server."""
    print(f"[WebSocket] Starting WS server on ws://{WEB_HOST}:{WS_PORT}")
    
    # FIX: Use the explicit wrapper function for maximum compatibility.
    websocket_server = websockets.serve(
        websocket_handler_wrapper, # Using the new wrapper function
        WEB_HOST, 
        WS_PORT
    )
    await websocket_server
    await asyncio.Future() # Runs forever

async def start_web_server():
    """Starts the HTTP server for serving the index.html file."""
    app = aiohttp.web.Application()
    app.router.add_get('/', index_handler)
    runner = aiohttp.web.AppRunner(app)
    await runner.setup()
    site = aiohttp.web.TCPSite(runner, WEB_HOST, WEB_PORT)
    await site.start()
    print(f"[Web] HTTP server started on http://127.0.0.1:{WEB_PORT}")

async def main():
    # Start the state pusher in the background
    asyncio.create_task(state_pusher())
    
    # Start the HTTP server and the WebSocket server concurrently
    await asyncio.gather(start_web_server(), start_websocket_server())

if __name__ == '__main__':
    print("--- ASMP Real-Time Dashboard Starting ---")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n--- Dashboard shutting down ---")
