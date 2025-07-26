#pragma once

#include "bitchat/core/bitchat_data.h"
#include "bitchat/helpers/compression_helper.h"
#include "bitchat/platform/bluetooth_interface.h"
#include "bitchat/protocol/packet.h"
#include "bitchat/services/crypto_service.h"
#include "bitchat/services/message_service.h"
#include "bitchat/services/network_service.h"
#include "bitchat/services/noise_service.h"
#include "bitchat/ui/ui_interface.h"
#include <memory>

namespace bitchat
{

// Forward declarations
class BluetoothAnnounceRunner;
class CleanupRunner;
class IUserInterface;
class MessageService;

// BitchatManager: Main orchestrator that coordinates all components
class BitchatManager : public std::enable_shared_from_this<BitchatManager>
{
public:
    BitchatManager();
    ~BitchatManager();

    // Initialize the manager
    bool initialize(
        std::shared_ptr<IUserInterface> userInterface,
        std::shared_ptr<IBluetoothNetwork> bluetoothNetworkInterface,
        std::shared_ptr<NetworkService> networkService,
        std::shared_ptr<MessageService> messageService,
        std::shared_ptr<CryptoService> cryptoService,
        std::shared_ptr<NoiseService> noiseService,
        std::shared_ptr<BluetoothAnnounceRunner> announceRunner,
        std::shared_ptr<CleanupRunner> cleanupRunner);

    // Start the manager
    bool start();

    // Stop the manager
    void stop();

    // Message operations
    bool sendMessage(const std::string &content);
    bool sendPrivateMessage(const std::string &content, const std::string &recipientNickname);

    // Channel operations
    void joinChannel(const std::string &channel);
    void leaveChannel();

    // Nickname operations
    void changeNickname(const std::string &nickname);

    // Service getters
    std::shared_ptr<IUserInterface> getUserInterface() const;
    std::shared_ptr<NetworkService> getNetworkService() const;
    std::shared_ptr<MessageService> getMessageService() const;
    std::shared_ptr<CryptoService> getCryptoService() const;
    std::shared_ptr<NoiseService> getNoiseService() const;

private:
    // Bluetooth interface
    std::shared_ptr<IBluetoothNetwork> bluetoothNetworkInterface;

    // Core services
    std::shared_ptr<IUserInterface> userInterface;
    std::shared_ptr<NetworkService> networkService;
    std::shared_ptr<MessageService> messageService;
    std::shared_ptr<CryptoService> cryptoService;
    std::shared_ptr<NoiseService> noiseService;

    // Runners
    std::shared_ptr<BluetoothAnnounceRunner> announceRunner;
    std::shared_ptr<CleanupRunner> cleanupRunner;
};

} // namespace bitchat
