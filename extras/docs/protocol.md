# 📡 Protocol Details

## Packet Structure

Each packet contains the following components:

- **Version** 🔢: Protocol version (currently 1)
- **Type** 📋: Packet type (ANNOUNCE, MESSAGE, etc.)
- **TTL** ⏰: Time-to-live for relay prevention
- **Timestamp** 🕐: Unix timestamp in milliseconds
- **Flags** 🚩: Compression, encryption, and routing flags
- **Sender ID** 🆔: Unique identifier of the sender
- **Recipient ID** 📬: Target recipient (optional)
- **Payload** 📦: Compressed and encrypted message data
- **Signature** ✍️: Ed25519 signature for authenticity

### Packet Header Format

```
┌─────────┬─────────┬─────────┬─────────┬─────────┬─────────┬─────────┐
│ Version │  Type   │   TTL   │         Timestamp          │  Flags  │
│  (1B)   │  (1B)   │  (1B)   │         (8B)              │  (1B)   │
└─────────┴─────────┴─────────┴─────────┴─────────┴─────────┴─────────┘
```

### Packet Types

| Type | Value | Description |
|------|-------|-------------|
| ANNOUNCE | 0x01 | Broadcast device presence and status |
| MESSAGE | 0x02 | Chat messages with content and metadata |
| KEYEXCHANGE | 0x03 | Cryptographic key exchange for secure communication |
| LEAVE | 0x04 | Notify peers when disconnecting |
| CHANNEL_ANNOUNCE | 0x05 | Join/leave channel notifications |
| FRAGMENT_START | 0x06 | Start of fragmented message |
| FRAGMENT_DATA | 0x07 | Fragment data |
| FRAGMENT_END | 0x08 | End of fragmented message |
| DELIVERY_REQUEST | 0x09 | Request delivery confirmation |
| DELIVERY_CONFIRM | 0x0A | Confirm message delivery |

### Flags

| Bit | Flag | Description |
|-----|------|-------------|
| 0 | COMPRESSED | Payload is compressed with LZ4 |
| 1 | ENCRYPTED | Payload is encrypted |
| 2 | FRAGMENTED | Message is part of a fragmented sequence |
| 3 | RELAY | Message should be relayed to other peers |
| 4-7 | RESERVED | Reserved for future use |

## Security 🔐

### Ed25519 Signatures

All messages are cryptographically signed using Ed25519, providing:

- **Message Authenticity** ✅: Verifies the message came from the claimed sender
- **Integrity Protection** 🛡️: Prevents message tampering during transmission
- **Non-repudiation** 📝: Sender cannot deny sending the message

### Key Exchange Process

1. **Key Generation** 🔑: Each device generates a unique Ed25519 key pair
2. **Public Key Broadcast** 📢: Devices announce their public keys via ANNOUNCE packets
3. **Key Verification** ✅: Received public keys are verified and stored
4. **Message Signing** ✍️: All outgoing messages are signed with the private key
5. **Signature Verification** 🔍: All incoming messages are verified using the sender's public key

### Security Features

- **Replay Attack Prevention** 🚫: Timestamps and TTL prevent message replay
- **Man-in-the-Middle Protection** 🛡️: Ed25519 signatures prevent message interception
- **Key Rotation** 🔄: Support for periodic key updates (future feature)
- **Forward Secrecy** 🔒: Each session uses unique keys (future feature)

## Compression 📦

### LZ4 Algorithm

Bitchat uses LZ4 compression for efficient data transmission:

- **Fast Compression** ⚡: LZ4 provides excellent compression speed
- **Low CPU Usage** 💻: Minimal impact on device performance
- **Good Compression Ratio** 📊: Typically 2-3x compression for text messages
- **Streaming Support** 🌊: Supports streaming compression for large messages

### Compression Strategy

1. **Size Threshold** 📏: Messages smaller than 64 bytes are not compressed
2. **Automatic Detection** 🤖: Compression is applied automatically when beneficial
3. **Compression Flag** 🚩: The COMPRESSED flag indicates compressed payloads
4. **Fallback** 🔄: If compression fails, message is sent uncompressed

### Compression Performance

| Message Type | Original Size | Compressed Size | Compression Ratio |
|--------------|---------------|-----------------|-------------------|
| Short text | 50 bytes | 50 bytes | 1.0x (no compression) |
| Medium text | 200 bytes | 120 bytes | 1.7x |
| Long text | 1000 bytes | 450 bytes | 2.2x |
| Binary data | 500 bytes | 480 bytes | 1.04x |

## Message Flow 📤📥

### Outgoing Message Process

1. **Message Creation** ✏️: User creates a message
2. **Channel Assignment** 📢: Message is assigned to a channel
3. **Compression** 📦: Message is compressed if beneficial
4. **Packet Creation** 📄: Packet is created with metadata
5. **Signing** ✍️: Packet is signed with Ed25519
6. **Transmission** 📡: Packet is sent via BLE
7. **Relay** 🔄: Connected peers relay the message

### Incoming Message Process

1. **Reception** 📥: Packet is received via BLE
2. **Validation** ✅: Packet structure and signature are verified
3. **Decompression** 📦: Payload is decompressed if needed
4. **Channel Routing** 📢: Message is routed to appropriate channel
5. **Display** 💬: Message is displayed to user
6. **Relay** 🔄: Message is relayed to other connected peers

## Error Handling 🚨

### Packet Validation

- **Version Check** 🔢: Ensures protocol compatibility
- **Signature Verification** ✍️: Validates message authenticity
- **TTL Check** ⏰: Prevents infinite message loops
- **Size Limits** 📏: Enforces maximum packet size (16KB)
- **Timestamp Validation** 🕐: Rejects old messages (5-minute window)

### Recovery Mechanisms

- **Retransmission** 🔄: Failed messages are retransmitted (up to 3 attempts)
- **Fragment Recovery** 📄: Missing fragments trigger retransmission requests
- **Connection Recovery** 🔌: Automatic reconnection on connection loss
- **Key Refresh** 🔑: Automatic key refresh on security errors
