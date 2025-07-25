#pragma once

#include "bitchat/services/network_service.h"
#include <atomic>
#include <memory>
#include <thread>

namespace bitchat
{

// Forward declarations
class NetworkService;

// CleanupRunner: Handles periodic cleanup of stale peers
class CleanupRunner
{
public:
    CleanupRunner();
    ~CleanupRunner();

    // Set the network service
    void setNetworkService(std::shared_ptr<NetworkService> networkService);

    // Start the cleanup loop
    bool start();

    // Stop the cleanup loop
    void stop();

    // Check if the runner is running
    bool isRunning() const;

private:
    // Network service reference
    std::shared_ptr<NetworkService> networkService;

    // Threading
    std::atomic<bool> shouldExit;
    std::atomic<bool> running;
    std::thread runnerThread;

    // Internal methods
    void runnerLoop();

    // Constants
    static constexpr int CLEANUP_INTERVAL = 30; // seconds
};

} // namespace bitchat
