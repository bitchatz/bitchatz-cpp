#pragma once

#include "bitchat/core/constants.h"
#include "bitchat/platform/bluetooth_interface.h"
#include "bitchat/protocol/packet.h"
#include <atomic>
#include <memory>
#include <string>
#include <thread>

namespace bitchat
{

// Forward declarations
class IBluetoothNetwork;

// BluetoothAnnounceRunner: Handles periodic announce packet sending
class BluetoothAnnounceRunner
{
public:
    BluetoothAnnounceRunner();
    virtual ~BluetoothAnnounceRunner();

    // Set the Bluetooth interface
    virtual void setBluetoothNetworkInterface(std::shared_ptr<IBluetoothNetwork> bluetoothNetwork);

    // Start the announce loop
    virtual bool start();

    // Stop the announce loop
    virtual void stop();

    // Check if the runner is running
    virtual bool isRunning() const;

private:
    // Bluetooth interface
    std::shared_ptr<IBluetoothNetwork> bluetoothNetworkInterface;

    // Threading
    std::atomic<bool> shouldExit;
    std::atomic<bool> running;
    std::thread runnerThread;

    // Internal methods
    virtual void runnerLoop();
};

} // namespace bitchat
