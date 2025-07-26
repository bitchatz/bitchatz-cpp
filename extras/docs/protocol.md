# 📡 Protocol Details

## Packet Structure

Each packet contains the following components:

- **Version** 🔢: Protocol version (currently 1)
- **Type** 📋: Packet type (ANNOUNCE, MESSAGE, etc.)
- **TTL** ⏰: Time-to-live for relay prevention
- **Timestamp** 🕐: Unix timestamp in milliseconds
- **Flags** 🚩: Compression, encryption, and routing flags
- **Payload Length** 📏: Length of the payload in bytes
- **Sender ID** 🆔: Unique identifier of the sender
- **Recipient ID** 📬: Target recipient (optional)
- **Payload** 📦: Compressed and encrypted message data
- **Signature** ✍️: Ed25519 signature for authenticity

### Packet Header Format

```
┌─────────┬─────────┬─────────┬─────────┬─────────┬─────────┬─────────┬─────────┐
│ Version │  Type   │   TTL   │         Timestamp          │  Flags  │PayloadLen│
│  (1B)   │  (1B)   │  (1B)   │         (8B)              │  (1B)   │   (2B)   │
└─────────┴─────────┴─────────┴─────────┴─────────┴─────────┴─────────┴─────────┘
```

### Packet Types

| Type | Value | Description |
|------|-------|-------------|
| ANNOUNCE | 0x01 | Broadcast device presence and status |
| KEY_EXCHANGE | 0x02 | Cryptographic key exchange for secure communication |
| LEAVE | 0x03 | Notify peers when disconnecting |
| MESSAGE | 0x04 | Chat messages with content and metadata |
| FRAGMENT_START | 0x05 | Start of fragmented message |
| FRAGMENT_CONTINUE | 0x06 | Fragment data |
| FRAGMENT_END | 0x07 | End of fragmented message |
| CHANNEL_ANNOUNCE | 0x08 | Join/leave channel notifications |
| DELIVERY_ACK | 0x0A | Confirm message delivery |
| DELIVERY_STATUS_REQUEST | 0x0B | Request delivery confirmation |
| READ_RECEIPT | 0x0C | Confirm message read |

### Noise Protocol Messages

| Type | Value | Description |
|------|-------|-------------|
| NOISE_HANDSHAKE_INIT | 0x10 | Noise protocol handshake initiation |
| NOISE_HANDSHAKE_RESP | 0x11 | Noise protocol handshake response |
| NOISE_ENCRYPTED | 0x12 | Encrypted message using Noise protocol |
| NOISE_IDENTITY_ANNOUNCE | 0x13 | Announce Noise protocol identity |
| CHANNEL_KEY_VERIFY_REQUEST | 0x14 | Request channel key verification |
| CHANNEL_KEY_VERIFY_RESPONSE | 0x15 | Response to channel key verification |
| CHANNEL_PASSWORD_UPDATE | 0x16 | Update channel password |
| CHANNEL_METADATA | 0x17 | Channel metadata information |

### Protocol Version Negotiation

| Type | Value | Description |
|------|-------|-------------|
| VERSION_HELLO | 0x20 | Protocol version negotiation initiation |
| VERSION_ACK | 0x21 | Protocol version negotiation acknowledgment |

### Flags

| Bit | Flag | Description |
|-----|------|-------------|
| 0 | HAS_RECIPIENT | Packet has a specific recipient |
| 1 | HAS_SIGNATURE | Packet is cryptographically signed |
| 2 | IS_COMPRESSED | Payload is compressed with LZ4 |
| 3-7 | RESERVED | Reserved for future use |

## Security 🔐

### Ed25519 Signatures

All messages are cryptographically signed using Ed25519, providing:

- **Message Authenticity** ✅: Verifies the message came from the claimed sender
- **Integrity Protection** 🛡️: Prevents message tampering during transmission
- **Non-repudiation** 📝: Sender cannot deny sending the message

### Noise Protocol Integration

Bitchat implements the Noise protocol for advanced security features:

- **Forward Secrecy** 🔒: Each session uses unique ephemeral keys
- **Perfect Forward Secrecy** 🛡️: Compromised keys don't affect past communications
- **Identity Hiding** 🕵️: Optional identity protection
- **Key Confirmation** ✅: Mutual key verification

### Key Exchange Process

1. **Key Generation** 🔑: Each device generates a unique Ed25519 key pair
2. **Public Key Broadcast** 📢: Devices announce their public keys via ANNOUNCE packets
3. **Noise Handshake** 🤝: Establish secure session using Noise protocol
4. **Key Verification** ✅: Received public keys are verified and stored
5. **Message Signing** ✍️: All outgoing messages are signed with the private key
6. **Signature Verification** 🔍: All incoming messages are verified using the sender's public key

### Security Features

- **Replay Attack Prevention** 🚫: Timestamps and TTL prevent message replay
- **Man-in-the-Middle Protection** 🛡️: Ed25519 signatures and Noise protocol prevent message interception
- **Key Rotation** 🔄: Support for periodic key updates
- **Forward Secrecy** 🔒: Each session uses unique keys via Noise protocol
- **Channel Security** 🔐: Encrypted channels with password protection

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
3. **Compression Flag** 🚩: The IS_COMPRESSED flag indicates compressed payloads
4. **Fallback** 🔄: If compression fails, message is sent uncompressed

### Compression Performance

| Message Type | Original Size | Compressed Size | Compression Ratio |
|--------------|---------------|-----------------|-------------------|
| Short text | 50 bytes | 50 bytes | 1.0x (no compression) |
| Medium text | 200 bytes | 120 bytes | 1.7x |
| Long text | 1000 bytes | 450 bytes | 2.2x |

## Message Types

### Chat Messages

Chat messages support various features:

- **Public Messages** 📢: Broadcast to all peers in the channel
- **Private Messages** 🔒: Direct messages to specific recipients
- **Relay Messages** 🔄: Messages relayed from other peers
- **Mentions** @: User mentions with notifications
- **Channel Support** 📺: Messages can be channel-specific

### Message Metadata

Each message includes:

- **Unique ID** 🆔: UUID for message identification
- **Sender Information** 👤: Sender nickname and peer ID
- **Timestamp** 🕐: Message creation time
- **Channel** 📺: Target channel (if applicable)
- **Encryption Status** 🔐: Whether content is encrypted
- **Mentions** @: List of mentioned users

## Fragmentation

### Large Message Support

For messages that exceed Bluetooth packet size limits:

1. **FRAGMENT_START** 📦: Indicates the beginning of a fragmented message
2. **FRAGMENT_CONTINUE** 📦: Contains fragment data
3. **FRAGMENT_END** 📦: Indicates the end of a fragmented message

### Fragmentation Strategy

- **Automatic Fragmentation** 🤖: Large messages are automatically fragmented
- **Reassembly** 🔧: Receiving end reassembles fragments
- **Error Recovery** 🔄: Missing fragments trigger retransmission requests
- **Timeout Handling** ⏰: Stale fragments are cleaned up

## Delivery Confirmation

### Delivery Status

Bitchat supports message delivery confirmation:

- **DELIVERY_STATUS_REQUEST** 📨: Request delivery status for a message
- **DELIVERY_ACK** ✅: Confirm message delivery
- **READ_RECEIPT** 👁️: Confirm message has been read

### Reliability Features

- **Automatic Retransmission** 🔄: Failed messages are retransmitted
- **Delivery Tracking** 📊: Track delivery status of sent messages
- **Timeout Handling** ⏰: Messages expire after a configurable timeout
- **Duplicate Detection** 🔍: Prevent duplicate message processing
