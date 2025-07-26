#include "bitchat/core/bitchat_manager.h"
#include "bitchat/core/bitchat_data.h"
#include "bitchat/helpers/datetime_helper.h"
#include "bitchat/helpers/protocol_helper.h"
#include "bitchat/helpers/string_helper.h"
#include "bitchat/platform/bluetooth_factory.h"
#include "bitchat/protocol/packet.h"
#include "bitchat/runners/bluetooth_announce_runner.h"
#include "bitchat/runners/cleanup_runner.h"
#include <iostream>
#include <openssl/evp.h>
#include <spdlog/spdlog.h>

namespace bitchat
{

std::shared_ptr<BitchatManager> BitchatManager::instance = nullptr;

std::shared_ptr<BitchatManager> BitchatManager::shared()
{
    if (!instance)
    {
        instance = std::make_shared<BitchatManager>();
    }

    return instance;
}

BitchatManager::BitchatManager()
{
    // Pass
}

BitchatManager::~BitchatManager()
{
    // Pass
}

bool BitchatManager::initialize(
    std::shared_ptr<IUserInterface> userInterface,
    std::shared_ptr<IBluetoothNetwork> bluetoothNetworkInterface,
    std::shared_ptr<NetworkService> networkService,
    std::shared_ptr<MessageService> messageService,
    std::shared_ptr<CryptoService> cryptoService,
    std::shared_ptr<NoiseService> noiseService,
    std::shared_ptr<BluetoothAnnounceRunner> announceRunner,
    std::shared_ptr<CleanupRunner> cleanupRunner)
{
    // Store interfaces
    this->userInterface = userInterface;
    this->bluetoothNetworkInterface = bluetoothNetworkInterface;

    // Store services
    this->networkService = networkService;
    this->messageService = messageService;
    this->cryptoService = cryptoService;
    this->noiseService = noiseService;

    // Store runners
    this->announceRunner = announceRunner;
    this->cleanupRunner = cleanupRunner;

    // Generate local peer ID
    std::string localPeerID = StringHelper::randomPeerID();
    spdlog::info("Generated local peer ID: {}", localPeerID);

    // Set peer ID
    BitchatData::shared()->setPeerID(localPeerID);

    // Initialize services
    if (!networkService->initialize(bluetoothNetworkInterface, announceRunner, cleanupRunner))
    {
        spdlog::error("Failed to initialize NetworkService");
        return false;
    }

    if (!cryptoService->initialize())
    {
        spdlog::error("Failed to initialize CryptoService");
        return false;
    }

    // Initialize UI with message service
    if (!userInterface->initialize(messageService))
    {
        spdlog::error("Failed to initialize UserInterface");
        return false;
    }

    if (!messageService->initialize(networkService, cryptoService, noiseService))
    {
        spdlog::error("Failed to initialize MessageService");
        return false;
    }

    spdlog::info("BitchatManager initialized successfully");

    return true;
}

bool BitchatManager::start()
{
    // Start network service
    if (!networkService->start())
    {
        spdlog::error("Failed to start NetworkService");
        return false;
    }

    // Send initial identity announce
    messageService->startIdentityAnnounce();

    return true;
}

void BitchatManager::stop()
{
    // Stop network service
    if (networkService)
    {
        networkService->stop();
    }

    // Stop user interface
    if (userInterface)
    {
        userInterface->stop();
    }
}

bool BitchatManager::sendMessage(const std::string &content)
{
    if (!messageService)
    {
        return false;
    }

    return messageService->sendMessage(content);
}

bool BitchatManager::sendPrivateMessage(const std::string &content, const std::string &recipientNickname)
{
    if (!messageService)
    {
        return false;
    }

    return messageService->sendPrivateMessage(content, recipientNickname);
}

void BitchatManager::joinChannel(const std::string &channel)
{
    if (messageService)
    {
        messageService->joinChannel(channel);
    }
}

void BitchatManager::leaveChannel()
{
    if (messageService)
    {
        messageService->leaveChannel();
    }
}

void BitchatManager::changeNickname(const std::string &nickname)
{
    BitchatData::shared()->setNickname(nickname);
}

std::shared_ptr<IUserInterface> BitchatManager::getUserInterface() const
{
    return userInterface;
}

std::shared_ptr<NetworkService> BitchatManager::getNetworkService() const
{
    return networkService;
}

std::shared_ptr<MessageService> BitchatManager::getMessageService() const
{
    return messageService;
}

std::shared_ptr<CryptoService> BitchatManager::getCryptoService() const
{
    return cryptoService;
}

std::shared_ptr<NoiseService> BitchatManager::getNoiseService() const
{
    return noiseService;
}

#ifdef UNIT_TEST
void BitchatManager::resetInstance()
{
    instance.reset();
}
#endif

} // namespace bitchat
