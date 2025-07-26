# 🛠️ Development Guide

## Getting Started

### Prerequisites

- **CMake 3.20+** 📦: Build system
- **C++20 Compiler** 🔧: Modern C++ features required
- **OpenSSL** 🔐: Cryptography library
- **Platform Bluetooth APIs** 📱: CoreBluetooth (Apple), Windows Bluetooth, BlueZ (Linux)

### Building from Source

#### macOS

```bash
# Install dependencies
brew install cmake openssl

# Build
mkdir build && cd build
cmake ..
make

# Run
./bin/bitchat
```

#### Linux

```bash
# Install dependencies
sudo apt-get install pkg-config cmake libssl-dev libbluetooth-dev

# Build
mkdir build && cd build
cmake ..
make

# Run
./bin/bitchat
```

#### Windows

```bash
# Install dependencies (using vcpkg)
vcpkg install openssl

# Build
mkdir build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=[path_to_vcpkg]/scripts/buildsystems/vcpkg.cmake
cmake --build . --config Release

# Run
.\bin\Release\bitchat.exe
```

### Development Environment Setup

#### macOS

```bash
# Install dependencies
brew install cmake openssl

# Clone and setup
git clone https://github.com/bitchatz/bitchat-cpp.git
cd bitchat-cpp
mkdir build && cd build
cmake ..
make
```

#### Linux

```bash
# Install dependencies
sudo apt-get install pkg-config cmake libssl-dev libbluetooth-dev

# Clone and setup
git clone https://github.com/bitchatz/bitchat-cpp.git
cd bitchat-cpp
mkdir build && cd build
cmake ..
make
```

#### Windows

```bash
# Install dependencies (using vcpkg)
vcpkg install openssl

# Clone and setup
git clone https://github.com/bitchatz/bitchat-cpp.git
cd bitchat-cpp
mkdir build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=[path_to_vcpkg]/scripts/buildsystems/vcpkg.cmake
cmake --build . --config Release
```

## Code Style Guidelines

### C++ Standards

- **C++20 Features** 🚀: Use modern C++ features where appropriate
- **RAII Principles** 🏗️: Resource Acquisition Is Initialization
- **Smart Pointers** 🧠: Use `std::shared_ptr` for memory management
- **Exception Safety** 🛡️: Provide strong exception guarantees

### Naming Conventions

```cpp
// Classes: PascalCase
class BitchatManager { };

// Methods: camelCase
void sendMessage(const std::string& message);
bool initialize();

// Variables: camelCase
PacketReceivedCallback packetReceivedCallback;

// Constants: UPPER_SNAKE_CASE
const int MAX_PACKET_SIZE = 16384;

// Namespaces: snake_case
namespace bitchat { }

// Acronyms (UUID, ID, etc.): keep as is
std::string peripheralID;
```

### File Organization

```
include/bitchat/
├── core/           # Core application logic (BitchatManager, BitchatData)
├── services/       # Service layer (CryptoService, MessageService, etc.)
├── noise/          # Noise protocol implementation
├── protocol/       # Network protocol (Packet, PacketSerializer)
├── platform/       # Platform abstraction (BluetoothInterface)
├── ui/             # User interface (ConsoleUI, DummyUI)
├── runners/        # Background runners (BluetoothAnnounceRunner, CleanupRunner)
├── helpers/        # Utility helpers (CompressionHelper, DateTimeHelper)
├── identity/       # Identity management
└── compression/    # Data compression utilities

src/bitchat/
├── core/           # Core implementation
├── services/       # Service implementations
├── noise/          # Noise protocol implementation
├── protocol/       # Protocol implementation
├── ui/             # UI implementations
├── runners/        # Runner implementations
├── helpers/        # Helper implementations
├── identity/       # Identity implementation
└── compression/    # Compression implementation

src/platforms/
├── apple/          # macOS/iOS platform implementation
└── linux/          # Linux platform implementation
```

### Error Handling

```cpp
// Use exceptions for exceptional cases
if (!bluetooth_available()) {
    throw std::runtime_error("Bluetooth not available");
}

// Use return codes for expected failures
enum class Result {
    Success,
    ConnectionFailed,
    Timeout
};

Result connectToPeer(const std::string& peerID);
```

## Adding a New Platform

### Step 1: Create Platform Directory

```bash
mkdir -p src/platforms/your_platform
mkdir -p include/platforms/your_platform
```

### Step 2: Implement BluetoothInterface

Create `src/platforms/your_platform/bluetooth.cpp`:

```cpp
#include "bitchat/platform/bluetooth_interface.h"
#include "platforms/your_platform/bluetooth.h"

class YourPlatformBluetooth : public bitchat::IBluetoothNetwork {
public:
    YourPlatformBluetooth() = default;
    ~YourPlatformBluetooth() override = default;

    bool initialize() override {
        // Platform-specific initialization
        return true;
    }

    bool start() override {
        // Start BLE advertising and scanning
        return true;
    }

    void stop() override {
        // Stop all Bluetooth operations
    }

    bool sendPacket(const bitchat::BitchatPacket& packet) override {
        // Send packet to all connected peers
        return true;
    }

    bool sendPacketToPeer(const bitchat::BitchatPacket& packet, const std::string& peerID) override {
        // Send packet to specific peer
        return true;
    }

    bool isReady() const override {
        // Check if Bluetooth is ready
        return true;
    }

    void setPeerConnectedCallback(bitchat::PeerConnectedCallback callback) override {
        // Set peer connected callback
    }

    void setPeerDisconnectedCallback(bitchat::PeerDisconnectedCallback callback) override {
        // Set peer disconnected callback
    }

    void setPacketReceivedCallback(bitchat::PacketReceivedCallback callback) override {
        // Set packet received callback
    }

    size_t getConnectedPeersCount() const override {
        // Return connected peers count
        return 0;
    }
};
```

### Step 3: Create Platform Header

Create `include/platforms/your_platform/bluetooth.h`:

```cpp
#pragma once

#include "bitchat/platform/bluetooth_interface.h"

namespace bitchat {
namespace platforms {
namespace your_platform {

class Bluetooth : public IBluetoothNetwork {
    // Implementation details
};

} // namespace your_platform
} // namespace platforms
} // namespace bitchat
```

### Step 4: Update Factory

Update `src/platforms/bluetooth_factory.cpp`:

```cpp
#include "bitchat/platform/bluetooth_factory.h"
#include "platforms/your_platform/bluetooth.h"

std::shared_ptr<bitchat::IBluetoothNetwork>
bitchat::BluetoothFactory::createBluetoothInterface() {
    #ifdef YOUR_PLATFORM_DEFINE
        return std::make_shared<platforms::your_platform::Bluetooth>();
    #elif defined(APPLE)
        return std::make_shared<platforms::apple::Bluetooth>();
    #elif defined(LINUX)
        return std::make_shared<platforms::linux::Bluetooth>();
    #else
        throw std::runtime_error("No Bluetooth implementation available for this platform");
    #endif
}
```

### Step 5: Update CMakeLists.txt

Add platform-specific configuration:

```cmake
# Platform-specific settings
if(YOUR_PLATFORM)
    add_definitions(-DYOUR_PLATFORM_DEFINE)
    find_package(YourBluetoothLibrary REQUIRED)
    target_link_libraries(bitchat PRIVATE YourBluetoothLibrary::YourBluetoothLibrary)
endif()
```

## Testing

### Unit Tests

```cpp
#include <gtest/gtest.h>
#include "bitchat/core/bitchat_manager.h"

class BitchatManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        manager = std::make_shared<bitchat::BitchatManager>();
    }

    void TearDown() override {
        manager.reset();
    }

    std::shared_ptr<bitchat::BitchatManager> manager;
};

TEST_F(BitchatManagerTest, InitializeSuccessfully) {
    EXPECT_TRUE(manager->initialize());
}

TEST_F(BitchatManagerTest, SendMessage) {
    manager->initialize();
    EXPECT_TRUE(manager->sendMessage("Hello, world!"));
}
```

### Integration Tests

```cpp
TEST_F(IntegrationTest, PeerDiscovery) {
    auto manager1 = std::make_shared<bitchat::BitchatManager>();
    auto manager2 = std::make_shared<bitchat::BitchatManager>();

    manager1->initialize();
    manager2->initialize();

    // Wait for discovery
    std::this_thread::sleep_for(std::chrono::seconds(5));

    auto peers1 = manager1->getDiscoveredPeers();
    auto peers2 = manager2->getDiscoveredPeers();

    EXPECT_FALSE(peers1.empty());
    EXPECT_FALSE(peers2.empty());
}
```

## Debugging

### Logging

Bitchat uses spdlog for logging:

```cpp
#include <spdlog/spdlog.h>

// Different log levels
spdlog::info("Application started");
spdlog::warn("Connection quality is poor");
spdlog::error("Failed to send message: {}", error_message);
spdlog::debug("Packet received: {} bytes", packet_size);
```

### Debug Build

```bash
mkdir build-debug && cd build-debug
cmake .. -DCMAKE_BUILD_TYPE=Debug
make
```

### Common Debug Scenarios

1. **Bluetooth Connection Issues** 🔌
   - Check platform permissions
   - Verify Bluetooth is enabled
   - Monitor system logs

2. **Message Delivery Problems** 📨
   - Check packet serialization
   - Verify signature generation
   - Monitor network traffic

3. **Performance Issues** ⚡
   - Profile compression performance
   - Monitor memory usage
   - Check thread utilization

## Performance Optimization

### Memory Management

```cpp
// Use move semantics
std::vector<uint8_t> data = std::move(compressed_data);

// Avoid unnecessary copies
const auto& peers = manager.getConnectedPeers();

// Use reserve for known sizes
std::vector<uint8_t> buffer;
buffer.reserve(expected_size);
```

### Thread Safety

```cpp
class ThreadSafeManager {
private:
    mutable std::mutex mutex;
    std::vector<PeerInfo> peers;

public:
    void addPeer(const PeerInfo& peer) {
        std::lock_guard<std::mutex> lock(mutex);
        peers.push_back(peer);
    }

    std::vector<PeerInfo> getPeers() const {
        std::lock_guard<std::mutex> lock(mutex);

        // Return copy for thread safety
        return peers;
    }
};
```

### Network Optimization

- **Batch Operations** 📦: Group multiple operations
- **Connection Pooling** 🔗: Reuse connections when possible
- **Compression** 📦: Use LZ4 for large messages
- **Caching** 💾: Cache frequently accessed data

## Contributing

### Pull Request Process

1. **Fork the Repository** 🍴
2. **Create Feature Branch** 🌿: `git checkout -b feature/amazing-feature`
3. **Make Changes** ✏️: Follow code style guidelines
4. **Add Tests** 🧪: Include unit and integration tests
5. **Update Documentation** 📚: Update relevant docs
6. **Submit PR** 📤: Create pull request with description

### Commit Messages

Use conventional commit format:

```
feat: add Windows Bluetooth support
fix: resolve memory leak in packet serializer
docs: update usage guide with new commands
test: add unit tests for crypto service
```

### Code Review Checklist

- [ ] **Code Style** ✅: Follows project conventions
- [ ] **Tests** 🧪: Includes appropriate tests
- [ ] **Documentation** 📚: Updated documentation
- [ ] **Performance** ⚡: No performance regressions
- [ ] **Security** 🔐: No security vulnerabilities
- [ ] **Platform Support** 🖥️: Works on target platforms

## 📋 TODO

- [x] macOS Bluetooth implementation
- [ ] Windows Bluetooth implementation
- [ ] Linux Bluetooth implementation
- [x] Unit tests and integration tests
- [x] CI/CD pipeline
- [ ] Performance optimizations
- [x] Message encryption (end-to-end)
- [ ] File sharing support
- [ ] Group chat features
- [ ] Offline message storage
