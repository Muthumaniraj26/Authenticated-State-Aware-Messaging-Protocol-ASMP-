Step 1: Setup - Create the Cryptographic Identities
This is Phase 1 from your roadmap. It only needs to be done once.

Open a terminal in your project directory (D:\Authenticated State-Aware Messaging Protocol (ASMP)).

Delete old keys: To ensure a clean start, delete any existing .pem files and the trusted_devices.json file.

Run the key generator: Execute the utility script to create the new, perfectly matched keys and the server's identity registry.

Bash

python util_generate_keys.py
You will see it create keys for all your devices and the crucial trusted_devices.json file.

Step 2: Start the Server
This begins Phase 2 from your roadmap.

In the same terminal, start your AI-powered asmp_server.py.

Leave this terminal window open. It is your central monitoring station. You will see it load the trusted devices and wait for connections.

Bash

python asmp_server.py
Step 3: Train the AI (Simulate Normal Operation)
This demonstrates Phase 3 of your roadmap and prepares the final defense layer from Phase 4.

Open a second terminal window.

Run the normal client (asmp_client.py) to simulate a legitimate device sending good data.

Bash

python asmp_client.py DEVICE-001
Watch the server's terminal. You will see the client connect and start sending data. After about 10 messages, you will see the crucial log message:
[AI INFO] Training complete.

Once the AI is trained, you can stop the normal client by pressing Ctrl+C in its terminal.

Step 4: Demonstrate the Smart Attack (Prove the AI Defense)
This is the final and most powerful part of your demonstration, showing the "Attack Scenario" from your roadmap's visualization.

Open a third terminal window.

Run the attacker client (asmp_attacker_client.py). This simulates a compromised insider sending malicious data ("temperature": 27.0) with a valid signature.

Bash

python asmp_attacker_client.py
Observe the Attacker's Terminal: You will see the attacker's log confirming that the server detected the attack and closed the connection:
[Attack SUCCESS] The server closed the connection as a defense, as expected.

Observe the Server's Terminal: This is the most important result. You will see the server's multi-layered defense in action:

It will log a successful handshake (as the signature is valid).

It will then immediately log the [AI ALERT] Anomaly detected!

Finally, it will log the security action: [AI DEFENSE]... Connection terminated.

The final monitoring table will show the attacker's session state as TAMPERED.
