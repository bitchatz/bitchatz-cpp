#pragma once

#include "bitchat/platform/bluetooth_interface.h"
#include "bitchat/protocol/packet.h"
#include <atomic>
#include <memory>
#include <string>
#include <thread>

namespace bitchat
{

// Forward declarations
class BluetoothInterface;

// BluetoothAnnounceRunner: Handles periodic announce packet sending
class BluetoothAnnounceRunner
{
public:
    BluetoothAnnounceRunner();
    ~BluetoothAnnounceRunner();

    // Set the Bluetooth interface
    void setBluetoothInterface(std::shared_ptr<BluetoothInterface> bluetooth);

    // Set the local peer ID
    void setLocalPeerID(const std::string &peerID);

    // Set the nickname for announce packets
    void setNickname(const std::string &nickname);

    // Start the announce loop
    bool start();

    // Stop the announce loop
    void stop();

    // Check if the runner is running
    bool isRunning() const;

private:
    // Bluetooth interface
    std::shared_ptr<BluetoothInterface> bluetoothInterface;

    // Network state
    std::string localPeerID;
    std::string nickname;

    // Threading
    std::atomic<bool> shouldExit;
    std::atomic<bool> running;
    std::thread runnerThread;

    // Internal methods
    void runnerLoop();

    // Constants
    static constexpr int ANNOUNCE_INTERVAL = 15; // seconds
};

} // namespace bitchat
