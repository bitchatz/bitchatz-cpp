#include "bitchat/core/bitchat_manager.h"
#include "bitchat/core/bitchat_data.h"
#include "bitchat/helpers/datetime_helper.h"
#include "bitchat/helpers/protocol_helper.h"
#include "bitchat/helpers/string_helper.h"
#include "bitchat/platform/bluetooth_factory.h"
#include "bitchat/protocol/packet.h"
#include "bitchat/runners/bluetooth_announce_runner.h"
#include "bitchat/runners/cleanup_runner.h"
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
    spdlog::debug("BitchatManager constructor called");
}

BitchatManager::~BitchatManager()
{
    spdlog::debug("BitchatManager destructor called");
    stop();
}

bool BitchatManager::initialize(
    std::shared_ptr<NetworkService> networkService,
    std::shared_ptr<MessageService> messageService,
    std::shared_ptr<CryptoService> cryptoService,
    std::shared_ptr<NoiseService> noiseService,
    std::shared_ptr<BluetoothAnnounceRunner> announceRunner,
    std::shared_ptr<CleanupRunner> cleanupRunner)
{
    if (BitchatData::shared()->isInitialized())
    {
        spdlog::warn("BitchatManager already initialized");
        return true;
    }

    // Store services
    this->networkService = networkService;
    this->messageService = messageService;
    this->cryptoService = cryptoService;
    this->noiseService = noiseService;

    // Store runners
    this->announceRunner = announceRunner;
    this->cleanupRunner = cleanupRunner;

    try
    {
        // Generate local peer ID
        std::string localPeerID = StringHelper::randomPeerID();
        spdlog::info("Generated local peer ID: {}", localPeerID);

        // Set peer ID
        BitchatData::shared()->setPeerID(localPeerID);

        // Create Bluetooth interface
        bluetoothInterface = createBluetoothInterface();

        if (!bluetoothInterface)
        {
            spdlog::error("Failed to create Bluetooth interface");
            return false;
        }

        // Initialize services
        if (!networkService->initialize(bluetoothInterface, announceRunner, cleanupRunner))
        {
            spdlog::error("Failed to initialize NetworkService");
            return false;
        }

        if (!cryptoService->initialize())
        {
            spdlog::error("Failed to initialize CryptoService");
            return false;
        }

        // Generate or load key pair
        if (!cryptoService->generateOrLoadKeyPair("bitchat-pk.pem"))
        {
            spdlog::error("Failed to generate or load key pair");
            return false;
        }

        if (!messageService->initialize(networkService, cryptoService, noiseService))
        {
            spdlog::error("Failed to initialize MessageService");
            return false;
        }

        // Send initial identity announce
        messageService->startIdentityAnnounce();

        // Set up callbacks
        setupCallbacks();

        // Set initialization state
        BitchatData::shared()->setInitialized(true);
        spdlog::info("BitchatManager initialized successfully");

        return true;
    }
    catch (const std::exception &e)
    {
        spdlog::error("Exception during initialization: {}", e.what());
        return false;
    }
}

bool BitchatManager::start()
{
    if (!BitchatData::shared()->isInitialized())
    {
        spdlog::error("BitchatManager not initialized");
        return false;
    }

    if (BitchatData::shared()->isStarted())
    {
        spdlog::warn("BitchatManager already started");
        return true;
    }

    try
    {
        if (!networkService->start())
        {
            spdlog::error("Failed to start NetworkService");
            return false;
        }

        // Set started state
        BitchatData::shared()->setStarted(true);
        spdlog::info("BitchatManager started successfully");

        return true;
    }
    catch (const std::exception &e)
    {
        spdlog::error("Exception during start: {}", e.what());
        return false;
    }
}

void BitchatManager::stop()
{
    if (!BitchatData::shared()->isStarted())
    {
        return;
    }

    try
    {
        networkService->stop();
        BitchatData::shared()->setStarted(false);

        spdlog::info("BitchatManager stopped");
    }
    catch (const std::exception &e)
    {
        spdlog::error("Exception during stop: {}", e.what());
    }
}

bool BitchatManager::sendMessage(const std::string &content)
{
    if (!isReady())
    {
        spdlog::error("BitchatManager not ready");
        return false;
    }

    return messageService->sendMessage(content);
}

bool BitchatManager::sendPrivateMessage(const std::string &content, const std::string &recipientNickname)
{
    if (!isReady())
    {
        spdlog::error("BitchatManager not ready");
        return false;
    }

    return messageService->sendPrivateMessage(content, recipientNickname);
}

void BitchatManager::joinChannel(const std::string &channel)
{
    BitchatData::shared()->setCurrentChannel(channel);

    if (messageService)
    {
        messageService->joinChannel(channel);
    }
}

void BitchatManager::leaveChannel()
{
    BitchatData::shared()->setCurrentChannel("");

    if (messageService)
    {
        messageService->leaveChannel();
    }
}

void BitchatManager::changeNickname(const std::string &nickname)
{
    BitchatData::shared()->setNickname(nickname);
}

bool BitchatManager::isReady() const
{
    return BitchatData::shared()->isReady() && networkService && messageService && networkService->isReady() && messageService->isReady();
}

void BitchatManager::setMessageCallback(MessageCallback callback)
{
    messageCallback = callback;
}

void BitchatManager::setPeerJoinedCallback(PeerJoinedCallback callback)
{
    peerJoinedCallback = callback;
}

void BitchatManager::setPeerLeftCallback(PeerLeftCallback callback)
{
    peerLeftCallback = callback;
}

void BitchatManager::setPeerConnectedCallback(PeerConnectedCallback callback)
{
    peerConnectedCallback = callback;
}

void BitchatManager::setPeerDisconnectedCallback(PeerDisconnectedCallback callback)
{
    peerDisconnectedCallback = callback;
}

void BitchatManager::setStatusCallback(StatusCallback callback)
{
    statusCallback = callback;
}

void BitchatManager::setChannelJoinedCallback(ChannelJoinedCallback callback)
{
    channelJoinedCallback = callback;
}

void BitchatManager::setChannelLeftCallback(ChannelLeftCallback callback)
{
    channelLeftCallback = callback;
}

void BitchatManager::setupCallbacks()
{
    // Set up network manager callbacks

    // clang-format off
    networkService->setPeerConnectedCallback([this](const std::string &peripheralID) {
        onPeerConnected(peripheralID);
    });
    // clang-format on

    // clang-format off
    networkService->setPeerDisconnectedCallback([this](const std::string &peripheralID) {
        onPeerDisconnected(peripheralID);
    });
    // clang-format on

    // Set up message manager callbacks

    // clang-format off
    messageService->setMessageReceivedCallback([this](const BitchatMessage &message) {
        onMessageReceived(message);
    });
    // clang-format on

    // clang-format off
    messageService->setChannelJoinedCallback([this](const std::string &channel) {
        onChannelJoined(channel);
    });
    // clang-format on

    // clang-format off
    messageService->setChannelLeftCallback([this](const std::string &channel) {
        onChannelLeft(channel);
    });
    // clang-format on

    // clang-format off
    messageService->setPeerJoinedCallback([this](const std::string &peerID, const std::string &nickname) {
        onPeerJoined(peerID, nickname);
    });
    // clang-format on

    // clang-format off
    messageService->setPeerLeftCallback([this](const std::string &peerID, const std::string &nickname) {
        onPeerLeft(peerID, nickname);
    });
    // clang-format on
}

void BitchatManager::onMessageReceived(const BitchatMessage &message)
{
    if (messageCallback)
    {
        messageCallback(message);
    }
}

void BitchatManager::onPeerJoined(const std::string &peerID, const std::string &nickname)
{
    if (peerJoinedCallback)
    {
        peerJoinedCallback(peerID, nickname);
    }
}

void BitchatManager::onPeerLeft(const std::string &peerID, const std::string &nickname)
{
    if (peerLeftCallback)
    {
        peerLeftCallback(peerID, nickname);
    }
}

void BitchatManager::onPeerConnected(const std::string &peripheralID)
{
    if (peerConnectedCallback)
    {
        peerConnectedCallback(peripheralID);
    }
}

void BitchatManager::onPeerDisconnected(const std::string &peripheralID)
{
    // Remove peer from data store
    auto peers = BitchatData::shared()->getPeers();

    for (const auto &peer : peers)
    {
        if (peer.getPeripheralID() == peripheralID)
        {
            std::string peerID = peer.getPeerID();
            std::string nickname = peer.getNickname();
            BitchatData::shared()->removePeer(peerID);

            onPeerLeft(peerID, nickname);

            break;
        }
    }

    // Notify callback
    if (peerDisconnectedCallback)
    {
        peerDisconnectedCallback(peripheralID);
    }
}

void BitchatManager::onStatusUpdate(const std::string &status)
{
    if (statusCallback)
    {
        statusCallback(status);
    }
}

void BitchatManager::onChannelJoined(const std::string &channel)
{
    if (channelJoinedCallback)
    {
        channelJoinedCallback(channel);
    }
}

void BitchatManager::onChannelLeft(const std::string &channel)
{
    if (channelLeftCallback)
    {
        channelLeftCallback(channel);
    }
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

} // namespace bitchat
