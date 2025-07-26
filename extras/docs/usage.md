# 💬 Usage Guide

## Getting Started

The Bitchat application provides a simple command-line interface for real-time messaging over Bluetooth Low Energy with end-to-end encryption. Here's how to get started:

### Starting the Application

```bash
# Build and run
mkdir build && cd build
cmake ..
make
./bin/bitchat
```

### Initial Setup

When you first start Bitchat, you'll see:

```
=== Bitchat Terminal Client ===
Connected! Type /help for commands.
Peer ID: 550e8400-e29b-41d4-a716-446655440000
Nickname: User_12345
```

- **Peer ID** 🆔: Your unique device identifier
- **Nickname** 👤: Your display name (auto-generated, can be changed)

## Commands Reference

### Basic Commands

| Command | Description | Example |
|---------|-------------|---------|
| `/help` | Show available commands | `/help` |
| `/exit` | Exit the application | `/exit` |
| `/clear` | Clear the terminal screen | `/clear` |
| `/status` | Show current status | `/status` |

### Channel Management

| Command | Description | Example |
|---------|-------------|---------|
| `/j #channel` | Join a specific channel | `/j #random` |
| `/leave` | Leave current channel | `/leave` |
| `/channels` | List available channels | `/channels` |

### User Management

| Command | Description | Example |
|---------|-------------|---------|
| `/nick NICKNAME` | Change your nickname | `/nick Alice` |
| `/w` | Show people online in current channel | `/w` |
| `/peers` | Show all discovered peers | `/peers` |

### Messaging

| Command | Description | Example |
|---------|-------------|---------|
| `message` | Send message to current channel | `Hello, world!` |
| `/w USER message` | Send private message | `/w Bob Hi there!` |
| `/me action` | Send action message | `/me waves hello` |

## Example Session

Here's a typical Bitchat session:

```
=== Bitchat Terminal Client ===
Connected! Type /help for commands.
Peer ID: 550e8400-e29b-41d4-a716-446655440000
Nickname: User_12345

> /help
Available commands:
/j #channel    - Join channel
/nick NICK     - Change nickname
/w             - Show people online in current channel
/clear         - Clear screen
/help          - Show this help
/exit          - Exit
Message        - Send message to current channel

> /j #random
Joined channel: #random

> /nick Alice
Nickname changed to: Alice

> Hello, world!
[14:30:15] You: Hello, world!
[14:30:16] Bob: Hi Alice!

> /w
People online:
- Alice (you) (channel: #random)
- Bob (channel: #random) (RSSI: -45 dBm)
- Charlie (channel: #help) (RSSI: -67 dBm)

> /me waves hello
[14:30:20] * Alice waves hello
```

## Features

### Real-time Messaging 💬

- **Instant Delivery** ⚡: Messages are delivered immediately to nearby devices
- **Channel Support** 📢: Join different channels for organized conversations
- **Private Messages** 🔒: Send direct messages to specific users
- **Action Messages** 🎭: Use `/me` for roleplay and actions
- **Message Encryption** 🔐: All messages are encrypted using Noise protocol

### Peer Discovery 🔍

- **Automatic Discovery** 🤖: Automatically find nearby Bitchat users
- **Signal Strength** 📶: View RSSI values to gauge connection quality
- **Online Status** 🟢: See who's currently online and in which channels
- **Real-time Updates** 🔄: Peer list updates automatically

### Mesh Networking 🔗

- **Extended Range** 📡: Messages are relayed through connected devices
- **Automatic Relay** 🔄: No manual configuration required
- **TTL Protection** ⏰: Prevents infinite message loops
- **Network Resilience** 🛡️: Network continues even if some devices disconnect

### Security Features 🔐

- **End-to-End Encryption** 🔒: All messages are encrypted using Noise protocol
- **Message Signing** ✍️: All messages are cryptographically signed with Ed25519
- **Identity Verification** ✅: Verify message authenticity
- **Forward Secrecy** 🛡️: Each session uses unique ephemeral keys
- **Perfect Forward Secrecy** 🔐: Compromised keys don't affect past communications
- **Privacy** 🔒: No central server stores your messages

### Advanced Security

- **Noise Protocol** 🤝: Industry-standard cryptographic protocol
- **Key Exchange** 🔑: Secure key establishment with mutual verification
- **Session Management** 📋: Automatic session creation and management
- **Channel Security** 🔐: Encrypted channels with optional password protection

## Best Practices

### Getting the Best Experience

1. **Stay in Range** 📶: Keep devices within Bluetooth range (typically 10-30 meters)
2. **Join Popular Channels** 📢: Use common channel names like `#random`, `#help`, `#chat`
3. **Use Clear Nicknames** 👤: Choose recognizable nicknames
4. **Monitor Signal Strength** 📊: Use `/w` to check connection quality
5. **Be Patient** ⏳: Allow time for peer discovery and message relay
6. **Trust the Encryption** 🔐: All communications are automatically encrypted

### Troubleshooting

| Issue | Solution |
|-------|----------|
| No peers visible | Ensure Bluetooth is enabled and other devices are running Bitchat |
| Messages not sending | Check signal strength with `/w` command |
| App not connecting | Restart the application and check Bluetooth permissions |
| High latency | Move closer to other devices or check for interference |
| Encryption errors | Restart the application to establish new secure sessions |

### Channel Etiquette

- **Use Appropriate Channels** 📢: Join relevant channels for your topic
- **Be Respectful** 🤝: Treat other users with courtesy
- **Avoid Spam** 🚫: Don't send excessive messages
- **Help New Users** 💡: Guide newcomers with `/help` and tips
- **Respect Privacy** 🔒: Remember that messages are encrypted but visible to nearby devices

## Advanced Usage

### Network Diagnostics

```bash
# Check network status
/status

# View detailed peer information
/peers

# Monitor connection quality
# Look for RSSI values in peer list
```

### Security Information

- **Session Establishment** 🤝: Secure sessions are automatically established when peers connect
- **Key Verification** ✅: Public keys are exchanged and verified during handshake
- **Encryption Status** 🔐: All messages are automatically encrypted
- **Session Management** 📋: Sessions are automatically managed and rekeyed as needed

### Performance Tips

- **Close Other Bluetooth Apps** 📱: Reduce interference from other BLE applications
- **Optimize Device Placement** 📍: Position devices for better signal reception
- **Use Short Messages** 📝: Shorter messages transmit faster
- **Monitor Battery** 🔋: BLE scanning can use significant power
- **Trust the Encryption** 🔐: Don't worry about encryption overhead - it's optimized

### Customization

- **Nickname Management** 👤: Use memorable, unique nicknames
- **Channel Organization** 📂: Create topic-specific channels
- **Message Style** ✨: Use emojis and formatting for better communication
- **Security Awareness** 🔐: Understand that your messages are secure but visible to nearby devices
