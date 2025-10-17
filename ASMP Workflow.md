#ASMP Workflow Roadmap: A Top-to-End Explanation
This document provides a complete roadmap of how the Authenticated State-Aware Messaging Protocol (ASMP) works, from the initial connection to the final, AI-powered security checks.

Phase 1: Foundation & Identity Provisioning (Before Connection)
This is the critical preparation phase that establishes the "root of trust" for the entire system before any network communication begins.

Cryptographic Identity Generation (util_generate_keys.py):

Using Elliptic Curve Cryptography, a unique and mathematically linked public/private key pair is generated for every device.

The private key (the secret) is stored securely on the IoT device itself. This key represents the device's unforgeable identity.

The corresponding public key is collected into the trusted_devices.json file. This file acts as the server's central, authoritative identity registry.

Server Initialization (asmp_server.py):

The server starts and "arms itself with knowledge" by loading the trusted_devices.json identity registry into memory. The server now knows the public identity of every legitimate device it is allowed to communicate with.

It opens a TCP socket on port 8888, establishing its presence on the network and beginning to listen for incoming connections.

Client Initialization (asmp_client.py):

The client application starts on the IoT device.

It retrieves its secret identity by loading its unique private key from its .pem file into memory.

Phase 2: The Zero-Trust Handshake (Prove Your Identity)
This phase embodies the "zero-trust" principle. The server does not trust any device by default and forces the client to prove its identity before granting access.

Connection & Challenge: The client connects to the server's IP address and port. To prove it is not an imposter, the client generates a random, one-time-use string (a "nonce").

Presenting Credentials: The client uses its private key to create a cryptographic signature of the nonce. It then sends its Device_ID, the original nonce, and the signature to the server. This is the client presenting its "digital passport."

Rigorous Verification: The server acts as a gatekeeper. It receives the request and performs a rigorous cryptographic check:

It looks up the public key for the claimed Device_ID in its identity registry.

It uses this public key to verify if the signature is mathematically valid for the nonce.

The Security Decision:

If the signature is valid, the server has mathematical proof of the device's identity. It creates a new, stateful, and secure session, sending a unique Session_ID back to the client to authorize communication.

If the signature is invalid, the server immediately terminates the connection. An imposter attack is blocked.

Phase 3: The Secure Message Lifecycle (The Promise)
Once trust is established, every message sent must uphold that trust. This phase ensures every piece of data is individually secured.

Data Creation & Confidentiality: The client reads its sensor data (e.g., {"temperature": 25.0}). To ensure privacy from outsiders, it uses the shared AES key to encrypt this payload into unreadable ciphertext.

Signing (The Tamper-Proof Seal): The client assembles the full message frame, including the encrypted data and other metadata (like the message_id). It then uses its private key to create a signature for this entire message. This signature is a cryptographic promise that the message content is authentic and has not been changed.

Transmission: The client sends the complete, verifiable package—the signed and encrypted message—to the server over the network.

Phase 4: Server-Side Verification (The Defense-in-Depth)
This is where the multi-layered defense of ASMP comes into play. For every single message, the server performs the following checks in order:

Cryptographic Verification:

Signature Check: The server first verifies the message's signature. If it doesn't match the content, it means the message was tampered with in transit. A tamperer is blocked.

Replay Check: The server checks the message_id. If it has already seen this ID for this session, it knows this is an old message being replayed. A replayer is blocked.

Decryption: Only after the message is proven to be authentic does the server use the SHARED_AES_KEY to decrypt the payload and see the actual data.

AI Anomaly Detection (The Final Layer):

Training: If the AI is not yet trained for this device, it stores the trusted data. After 10 samples, it builds a statistical model of the device's "normal" behavior.

Active Defense: If the AI is trained, it analyzes the decrypted data. It checks if the new data is a statistical anomaly (e.g., a temperature of 27.0 when the normal is 25.0 ± 0.1). If it is, the server knows this is a potential insider attack. A smart attacker is blocked.

Acceptance: Only if a message passes all of these checks is it finally accepted as trustworthy and logged as [DATA RECEIVED].

Roadmap Visualization
This diagram shows the complete journey of both a normal message and an attack message through the ASMP system.

sequenceDiagram
    participant Client
    participant Server

    %% --- Phase 1 & 2: Handshake ---
    Client->>Server: 1. Connect
    Client->>Server: 2. Handshake Request (with Signature)
    Server-->>Server: 3. Verify Signature
    alt Signature is VALID
        Server->>Client: 4. Acknowledge with Session_ID
    else Signature is INVALID
        Server->>Client: 5. Terminate Connection (Attack Blocked)
    end

    %% --- Phase 3 & 4: Normal Data ---
    loop Normal Operation
        Client-->>Client: 6. Create & Encrypt Data
        Client-->>Client: 7. Sign Message
        Client->>Server: 8. Send Secure Message
        Server-->>Server: 9. Verify Signature & Replay Check
        Server-->>Server: 10. Decrypt Data
        Server-->>Server: 11. AI Anomaly Check (passes)
        Server-->>Server: 12. ACCEPT DATA
    end

    %% --- Attack Scenario ---
    participant Attacker
    Note over Attacker: (Has stolen private key)
    Attacker->>Server: 13. Send Malicious Message (Valid Signature, Anomalous Data)
    Server-->>Server: 14. Verify Signature (passes)
    Server-->>Server: 15. Decrypt Data
    Server-->>Server: 16. AI Anomaly Check (FAILS!)
    Server->>Attacker: 17. Terminate Connection (Attack Blocked)

