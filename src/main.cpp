#include "bitchat/core/bitchat_manager.h"
#include "bitchat/helpers/user_interface_helper.h"
#include "bitchat/platform/bluetooth_factory.h"
#include "bitchat/platform/bluetooth_interface.h"
#include "bitchat/runners/bluetooth_announce_runner.h"
#include "bitchat/runners/cleanup_runner.h"
#include "bitchat/services/crypto_service.h"
#include "bitchat/services/message_service.h"
#include "bitchat/services/network_service.h"
#include "bitchat/services/noise_service.h"
#include "bitchat/ui/console_ui.h"
#include <chrono>
#include <ctime>
#include <iostream>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/spdlog.h>
#include <string>
#include <thread>

using namespace bitchat;

int main()
{
    // Initialize spdlog with file sink only (no console output)
    auto fileSink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>("bitchat.log", 1024 * 1024 * 5, 3);

    // Configure for faster writing
    fileSink->set_level(spdlog::level::debug);
    fileSink->set_pattern("[%H:%M:%S] %v");

    auto logger = std::make_shared<spdlog::logger>("bitchat", fileSink);
    logger->set_level(spdlog::level::debug);

    // Flush on every log message
    logger->flush_on(spdlog::level::debug);

    spdlog::set_default_logger(logger);

    // Create bluetooth network interface
    auto bluetoothNetworkInterface = createBluetoothNetworkInterface();

    // Create services
    auto networkService = std::make_shared<bitchat::NetworkService>();
    auto messageService = std::make_shared<bitchat::MessageService>();
    auto cryptoService = std::make_shared<bitchat::CryptoService>();
    auto noiseService = std::make_shared<bitchat::NoiseService>();

    // Create runners
    auto bluetoothAnnounceRunner = std::make_shared<bitchat::BluetoothAnnounceRunner>();
    auto cleanupRunner = std::make_shared<bitchat::CleanupRunner>();

    // Create UI
    auto consoleUserInterface = std::make_shared<bitchat::ConsoleUserInterface>();

    // Create and initialize manager
    auto manager = BitchatManager::shared();

    // Initialize manager
    if (!BitchatManager::shared()->initialize(consoleUserInterface, bluetoothNetworkInterface, networkService, messageService, cryptoService, noiseService, bluetoothAnnounceRunner, cleanupRunner))
    {
        spdlog::error("Failed to initialize BitchatManager");
        return EXIT_FAILURE;
    }

    // Start manager
    if (!BitchatManager::shared()->start())
    {
        spdlog::error("Failed to start BitchatManager");
        return EXIT_FAILURE;
    }

    // Start user interface
    BitchatManager::shared()->getUserInterface()->start();

    // Stop manager
    BitchatManager::shared()->stop();

    return EXIT_SUCCESS;
}
