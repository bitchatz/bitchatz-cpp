# 🏗️ Architecture

## How Bitchat Works

Bitchat creates a decentralized mesh network where devices communicate directly via Bluetooth Low Energy. Here's how the system operates:

### Core Architecture

1. **Mesh Networking** 🔗: Each device acts as both a sender and relay, forwarding messages to extend the network range
2. **BLE Transport** 📡: Uses Bluetooth Low Energy for device discovery and data transmission
3. **Cryptographic Security** 🔐: Ed25519 signatures ensure message authenticity and prevent tampering
4. **Data Compression** 📦: LZ4 compression reduces bandwidth usage and improves transmission speed
5. **Channel-based Communication** 💬: Users can join different channels for organized conversations

### Protocol Flow

1. **Discovery** 🔍: Devices continuously scan for and advertise their presence
2. **Connection** 🤝: When devices are in range, they establish BLE connections
3. **Key Exchange** 🔑: Devices exchange cryptographic keys for secure communication
4. **Message Transmission** 📤: Messages are encrypted, compressed, and sent as binary packets
5. **Relay** 🔄: Connected devices automatically relay messages to extend network coverage
6. **TTL Management** ⏰: Each packet has a Time-To-Live counter to prevent infinite loops

### Packet Types

- **ANNOUNCE** 📢: Broadcast device presence and status
- **MESSAGE** 💬: Chat messages with content and metadata
- **KEYEXCHANGE** 🔑: Cryptographic key exchange for secure communication
- **LEAVE** 👋: Notify peers when disconnecting
- **CHANNEL_ANNOUNCE** 📢: Join/leave channel notifications
- **FRAGMENT_*** 📄: Large message fragmentation support
- **DELIVERY_*** ✅: Message delivery confirmation system

## Project Structure

```
bitchat-cpp/
├── include/                   # Public headers
│   ├── bitchat/               # Core library headers
│   │   ├── core/              # Main application logic
│   │   │   └── bitchat_manager.h
│   │   ├── crypto/            # Cryptography and security
│   │   │   └── crypto_manager.h
│   │   ├── compression/       # Data compression (LZ4)
│   │   │   └── compression_manager.h
│   │   ├── protocol/          # Network protocol and packet handling
│   │   │   ├── packet.h
│   │   │   └── packet_serializer.h
│   │   └── platform/          # Platform abstraction layer
│   │       ├── bluetooth_interface.h
│   │       └── bluetooth_factory.h
│   └── platforms/             # Platform-specific headers
│       └── apple/             # macOS/iOS CoreBluetooth
│           └── bluetooth.h
├── src/                       # Implementation files
│   ├── bitchat/               # Core library implementation
│   │   ├── core/              # Core implementation
│   │   │   └── bitchat_manager.cpp
│   │   ├── crypto/            # Crypto implementation
│   │   │   └── crypto_manager.cpp
│   │   ├── compression/       # Compression implementation
│   │   │   └── compression_manager.cpp
│   │   ├── protocol/          # Protocol implementation
│   │   │   ├── packet_serializer.cpp
│   │   │   └── packet_utils.cpp
│   │   └── platform/          # Platform factory
│   └── platforms/             # Platform-specific implementations
│       └── apple/             # macOS/iOS CoreBluetooth
│           └── bluetooth.mm
├── cmake/                     # CMake utilities
│   └── CPM.cmake              # CPM dependency manager
├── main.cpp                   # Application entry point
├── CMakeLists.txt             # Build configuration
```

## Key Components

### Core Classes

- **BitchatManager** 🎮: Main orchestrator that manages the entire application lifecycle
- **BluetoothInterface** 📱: Abstract interface for platform-specific Bluetooth implementations
- **CryptoManager** 🔐: Handles encryption, signatures, and key management using OpenSSL
- **CompressionManager** 📦: LZ4 compression for efficient data transmission
- **PacketSerializer** 📄: Binary serialization/deserialization of network packets

### Platform Abstraction

The Bluetooth functionality is abstracted through the `BluetoothInterface` class, allowing different implementations for each platform:

- **Apple** 🍎: Uses CoreBluetooth framework (implemented)
- **Windows** 🪟: Will use Windows Bluetooth APIs (TODO)
- **Linux** 🐧: Will use BlueZ (TODO)
