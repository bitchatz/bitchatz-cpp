#include "bitchat/core/bitchat_manager.h"
#include "bitchat/platform/bluetooth_factory.h"
#include "bitchat/platform/bluetooth_interface.h"
#include "bitchat/runners/bluetooth_announce_runner.h"
#include "bitchat/runners/cleanup_runner.h"
#include "bitchat/services/crypto_service.h"
#include "bitchat/services/message_service.h"
#include "bitchat/services/network_service.h"
#include "bitchat/services/noise_service.h"
#include <chrono>
#include <ctime>
#include <iostream>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/spdlog.h>
#include <string>
#include <thread>

// clang-format off
#ifdef BITCHAT_GUI_CONSOLE
    #include "bitchat/ui/console_ui.h"
#elif defined(BITCHAT_GUI_DUMMY)
    #include "bitchat/ui/dummy_ui.h"
#endif
// clang-format on

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

    // clang-format off
    // Create UI
    #ifdef BITCHAT_GUI_CONSOLE
        auto userInterface = std::make_shared<bitchat::ConsoleUserInterface>();
    #elif defined(BITCHAT_GUI_DUMMY)
        auto userInterface = std::make_shared<bitchat::DummyUserInterface>();
    #else
        #error "No valid BITCHAT_GUI macro defined"
    #endif
    // clang-format on

    // Create and initialize manager
    auto manager = std::make_shared<BitchatManager>();

    // Initialize manager
    if (!manager->initialize(userInterface, bluetoothNetworkInterface, networkService, messageService, cryptoService, noiseService, bluetoothAnnounceRunner, cleanupRunner))
    {
        spdlog::error("Failed to initialize BitchatManager");
        return EXIT_FAILURE;
    }

    // Start manager
    if (!manager->start())
    {
        spdlog::error("Failed to start BitchatManager");
        return EXIT_FAILURE;
    }

    // Start user interface
    manager->getUserInterface()->start();

    // Stop manager
    manager->stop();

    return EXIT_SUCCESS;
}
