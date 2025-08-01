#include "bitchat/runners/cleanup_runner.h"
#include "bitchat/core/bitchat_data.h"
#include "bitchat/core/constants.h"
#include <chrono>
#include <spdlog/spdlog.h>

namespace bitchat
{

CleanupRunner::CleanupRunner()
    : shouldExit(false)
    , running(false)
{
    // Pass
}

CleanupRunner::~CleanupRunner()
{
    stop();
}

bool CleanupRunner::initialize(std::shared_ptr<NetworkService> networkService)
{
    this->networkService = networkService;

    spdlog::info("CleanupRunner initialized");

    return true;
}

bool CleanupRunner::start()
{
    if (!networkService)
    {
        spdlog::error("CleanupRunner: Cannot start without NetworkService");
        return false;
    }

    if (running.load())
    {
        spdlog::warn("CleanupRunner: Already running");
        return true;
    }

    shouldExit = false;
    running = true;

    // Start background thread
    runnerThread = std::thread(&CleanupRunner::runnerLoop, this);

    spdlog::info("CleanupRunner started");

    return true;
}

void CleanupRunner::stop()
{
    shouldExit = true;
    running = false;

    if (runnerThread.joinable())
    {
        runnerThread.join();
    }

    spdlog::info("CleanupRunner stopped");
}

bool CleanupRunner::isRunning() const
{
    return running.load();
}

void CleanupRunner::runnerLoop()
{
    spdlog::info("CleanupRunner: Runner loop started");

    while (!shouldExit)
    {
        try
        {
            BitchatData::shared()->cleanupStalePeers();

            std::this_thread::sleep_for(std::chrono::seconds(CLEANUP_INTERVAL));
        }
        catch (const std::exception &e)
        {
            spdlog::error("Error in cleanup loop: {}", e.what());
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

} // namespace bitchat
