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
    virtual ~CleanupRunner();

    // Initialize the cleanup runner
    virtual bool initialize(std::shared_ptr<NetworkService> networkService);

    // Start the cleanup loop
    virtual bool start();

    // Stop the cleanup loop
    virtual void stop();

    // Check if the runner is running
    virtual bool isRunning() const;

private:
    // Network service reference
    std::shared_ptr<NetworkService> networkService;

    // Threading
    std::atomic<bool> shouldExit;
    std::atomic<bool> running;
    std::thread runnerThread;

    // Internal methods
    virtual void runnerLoop();

    // Constants
    static constexpr int CLEANUP_INTERVAL = 30; // seconds
};

} // namespace bitchat
