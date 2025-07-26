# 🔧 Troubleshooting Guide

## Common Issues and Solutions

### Build Issues

#### CMake Version Too Old

**Problem**: `CMake 3.20 or higher is required`

**Solution**:
```bash
# macOS
brew install cmake

# Ubuntu/Debian
sudo apt-get update
sudo apt-get install cmake

# Windows
# Download from https://cmake.org/download/
```

#### Missing OpenSSL

**Problem**: `Could not find OpenSSL`

**Solution**:
```bash
# macOS
brew install openssl

# Ubuntu/Debian
sudo apt-get install libssl-dev

# Windows (with vcpkg)
vcpkg install openssl
```

#### Compiler Not Supporting C++20

**Problem**: `C++20 features not supported`

**Solution**:
```bash
# Update GCC (Linux)
sudo apt-get install g++-11

# Update Clang (macOS)
brew install llvm

# Windows: Use Visual Studio 2019 or later
```

#### Missing Dependencies

**Problem**: Build fails due to missing libraries

**Solution**:
```bash
# Install all required dependencies
# macOS
brew install cmake openssl

# Ubuntu/Debian
sudo apt-get install pkg-config cmake libssl-dev libbluetooth-dev

# Windows (with vcpkg)
vcpkg install openssl
```

### Runtime Issues

#### Bluetooth Not Working

**Problem**: Application fails to initialize Bluetooth

**Symptoms**:
- "Bluetooth not available" error
- No peer discovery
- Connection failures

**Solutions**:

1. **Check Bluetooth Status**:
   ```bash
   # macOS
   system_profiler SPBluetoothDataType

   # Linux
   bluetoothctl show

   # Windows
   # Check Device Manager > Bluetooth
   ```

2. **Enable Bluetooth**:
   - macOS: System Preferences > Bluetooth
   - Linux: `sudo systemctl start bluetooth`
   - Windows: Settings > Devices > Bluetooth

3. **Check Permissions**:
   - macOS: System Preferences > Security & Privacy > Privacy > Bluetooth
   - Linux: Ensure user is in `bluetooth` group
   - Windows: Allow app through firewall

#### No Peers Visible

**Problem**: No other devices appear in peer list

**Solutions**:

1. **Verify Other Devices**:
   - Ensure other devices are running Bitchat
   - Check that devices are within Bluetooth range (10-30 meters)
   - Verify Bluetooth is enabled on all devices

2. **Check Signal Strength**:
   ```bash
   # Use /w command to see RSSI values
   /w
   ```

3. **Restart Discovery**:
   ```bash
   # Restart the application
   /exit
   # Then restart
   ```

4. **Check for Interference**:
   - Move away from WiFi routers
   - Close other Bluetooth applications
   - Check for physical obstacles

#### Messages Not Sending

**Problem**: Messages appear to send but aren't received

**Solutions**:

1. **Check Connection Quality**:
   ```bash
   /w
   # Look for RSSI values above -70 dBm
   ```

2. **Verify Channel Membership**:
   ```bash
   # Ensure you're in the same channel as recipients
   /j #random
   ```

3. **Check Message Size**:
   - Large messages may fail to transmit
   - Try shorter messages first

4. **Restart Connections**:
   ```bash
   /exit
   # Restart application
   ```

#### High Latency

**Problem**: Messages take a long time to deliver

**Solutions**:

1. **Improve Signal Quality**:
   - Move devices closer together
   - Remove physical obstacles
   - Reduce interference from other devices

2. **Check Network Load**:
   - Fewer connected peers = lower latency
   - Consider disconnecting from distant peers

3. **Optimize Message Size**:
   - Use shorter messages
   - Avoid sending large files

### Security and Encryption Issues

#### Noise Protocol Handshake Failures

**Problem**: Secure sessions fail to establish

**Symptoms**:
- "Noise handshake failed" errors
- Messages not being encrypted
- Connection timeouts during handshake

**Solutions**:

1. **Restart Application**:
   ```bash
   /exit
   # Restart to clear session state
   ```

2. **Check Key Generation**:
   - Ensure CryptoService initialized properly
   - Check for key file permissions

3. **Verify Protocol Compatibility**:
   - Ensure all devices are running compatible versions
   - Check for protocol version mismatches

#### Encryption Errors

**Problem**: Messages fail to encrypt or decrypt

**Solutions**:

1. **Clear Session State**:
   ```bash
   /exit
   # Restart to establish new sessions
   ```

2. **Check Key Integrity**:
   - Verify key files are not corrupted
   - Regenerate keys if necessary

3. **Monitor Session Status**:
   - Check if sessions are properly established
   - Look for session timeout errors

#### Signature Verification Failures

**Problem**: Message signatures fail to verify

**Solutions**:

1. **Check Clock Synchronization**:
   - Ensure device clocks are reasonably synchronized
   - Check for timestamp validation errors

2. **Verify Key Exchange**:
   - Ensure public keys were properly exchanged
   - Check for key verification errors

3. **Restart Secure Sessions**:
   ```bash
   /exit
   # Restart to re-establish secure sessions
   ```

### Platform-Specific Issues

#### macOS Issues

**Problem**: CoreBluetooth permissions denied

**Solution**:
1. Go to System Preferences > Security & Privacy > Privacy > Bluetooth
2. Add your terminal application (Terminal.app or iTerm2)
3. Restart the application

**Problem**: Bluetooth not available in terminal

**Solution**:
```bash
# Check if Bluetooth is enabled
system_profiler SPBluetoothDataType | grep "State:"
# Should show "State: On"

# Reset Bluetooth if needed
sudo pkill bluetoothd
```

#### Linux Issues

**Problem**: BlueZ not installed or outdated

**Solution**:
```bash
# Install BlueZ
sudo apt-get install bluez bluez-tools

# Start Bluetooth service
sudo systemctl start bluetooth
sudo systemctl enable bluetooth

# Add user to bluetooth group
sudo usermod -a -G bluetooth $USER
# Log out and back in
```

**Problem**: Permission denied for Bluetooth

**Solution**:
```bash
# Check if user is in bluetooth group
groups $USER

# Add to group if not present
sudo usermod -a -G bluetooth $USER

# Check Bluetooth service status
sudo systemctl status bluetooth
```

#### Windows Issues

**Problem**: Windows Bluetooth APIs not available

**Solution**:
1. Ensure Windows 10 version 1803 or later
2. Update Bluetooth drivers
3. Enable Bluetooth in Device Manager

**Problem**: Application blocked by firewall

**Solution**:
1. Windows Security > Firewall & network protection
2. Allow app through firewall
3. Check antivirus software settings

### Performance Issues

#### High CPU Usage

**Problem**: Application uses excessive CPU

**Solutions**:

1. **Reduce Scan Frequency**:
   - Modify scan intervals in code
   - Use less aggressive discovery

2. **Optimize Compression**:
   - Disable compression for short messages
   - Use faster compression settings

3. **Limit Peer Connections**:
   - Reduce maximum number of simultaneous connections
   - Disconnect from distant peers

4. **Monitor Service Performance**:
   - Check NoiseService session management
   - Monitor CryptoService operations

#### High Memory Usage

**Problem**: Application uses excessive memory

**Solutions**:

1. **Clear Message History**:
   ```bash
   /clear
   ```

2. **Restart Application**:
   ```bash
   /exit
   # Restart to clear memory
   ```

3. **Check for Memory Leaks**:
   - Use debug build for profiling
   - Monitor memory usage over time
   - Check service memory usage

#### Battery Drain

**Problem**: Application drains device battery quickly

**Solutions**:

1. **Reduce Scan Power**:
   - Increase scan intervals
   - Use lower power scanning modes

2. **Optimize Transmission**:
   - Send fewer messages
   - Use shorter messages
   - Batch multiple messages

3. **Close When Not in Use**:
   ```bash
   /exit
   # Close application when not chatting
   ```

4. **Monitor Encryption Overhead**:
   - Noise protocol operations are optimized
   - Session caching reduces repeated handshakes

### Debug Information

#### Enable Debug Logging

```bash
# Set environment variable for debug output
export BITCHAT_LOG_LEVEL=debug

# Run application
./bin/bitchat
```

#### Common Log Messages

```
[INFO] Bluetooth initialized successfully
[INFO] CryptoService initialized
[INFO] NoiseService initialized
[WARN] Connection quality poor: -75 dBm
[ERROR] Failed to send message: Connection timeout
[DEBUG] Packet received: 256 bytes from peer 12345
[DEBUG] Noise handshake completed with peer 12345
[DEBUG] Message encrypted successfully
```

#### Network Diagnostics

```bash
# Check peer status
/w

# View all discovered peers
/peers

# Check application status
/status

# Monitor connection quality
# Look for RSSI values in output
```

#### Security Diagnostics

```bash
# Check if sessions are established
# Look for Noise handshake messages in debug logs

# Monitor encryption status
# Check for encryption/decryption errors in logs

# Verify key exchange
# Look for key exchange completion messages
```

### Getting Help

#### Before Asking for Help

1. **Check This Guide** 📖: Look for your issue in this troubleshooting guide
2. **Enable Debug Logging** 🔍: Set `BITCHAT_LOG_LEVEL=debug`
3. **Gather Information** 📋:
   - Platform and version
   - Error messages
   - Debug logs
   - Steps to reproduce
   - Security-related errors

#### Reporting Issues

When reporting issues, include:

- **Platform**: macOS/Linux/Windows version
- **Bitchat Version**: Git commit hash or version
- **Error Messages**: Complete error output
- **Steps to Reproduce**: Detailed steps
- **Expected vs Actual Behavior**: What you expected vs what happened
- **Debug Logs**: Output with debug logging enabled
- **Security Context**: Any encryption or authentication errors

#### Community Support

- **GitHub Issues**: Report bugs and feature requests
- **Discussions**: Ask questions and share solutions
- **Documentation**: Check the docs folder for detailed guides
