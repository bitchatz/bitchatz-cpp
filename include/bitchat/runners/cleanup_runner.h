#pragma once

#include "bitchat/core/network_manager.h"
#include <atomic>
#include <memory>
#include <thread>

namespace bitchat
{

// Forward declarations
class NetworkManager;

// CleanupRunner: Handles periodic cleanup of stale peers
class CleanupRunner
{
public:
    CleanupRunner();
    ~CleanupRunner();

    // Set the network manager
    void setNetworkManager(std::shared_ptr<NetworkManager> networkManager);

    // Start the cleanup loop
    bool start();

    // Stop the cleanup loop
    void stop();

    // Check if the runner is running
    bool isRunning() const;

private:
    // Network manager reference
    std::shared_ptr<NetworkManager> networkManager;

    // Threading
    std::atomic<bool> shouldExit;
    std::atomic<bool> running;
    std::thread runnerThread;

    // Internal methods
    void runnerLoop();

    // Constants
    static constexpr int CLEANUP_INTERVAL = 30; // seconds
    static constexpr int PEER_TIMEOUT = 180;    // seconds
};

} // namespace bitchat
