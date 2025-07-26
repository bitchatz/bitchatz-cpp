#pragma once

#include "bitchat/ui/ui_interface.h"
#include <memory>
#include <string>

namespace bitchat
{

// Forward declarations
class MessageService;

// DummyUserInterface: Dummy user interface implementation
class DummyUserInterface : public IUserInterface
{
public:
    DummyUserInterface();
    ~DummyUserInterface() = default;

    // Initialize the UI with message service
    bool initialize(std::shared_ptr<BitchatManager> manager, std::shared_ptr<MessageService> messageService) override;

    // Message event callbacks
    void onMessageReceived(const BitchatMessage &message) override;
    void onPeerJoined(const std::string &peerID, const std::string &nickname) override;
    void onPeerLeft(const std::string &peerID, const std::string &nickname) override;
    void onPeerConnected(const std::string &peripheralID) override;
    void onPeerDisconnected(const std::string &peripheralID) override;
    void onChannelJoined(const std::string &channel) override;
    void onChannelLeft(const std::string &channel) override;
    void onStatusUpdate(const std::string &status) override;

    // Display methods
    void showPeers() override;
    void showStatus() override;
    void showHelp() override;
    void clearChat() override;
    void showWelcome() override;

    // Chat output methods
    void showChatMessage(const std::string &message) override;
    void showChatMessageInfo(const std::string &message) override;
    void showChatMessageWarn(const std::string &message) override;
    void showChatMessageError(const std::string &message) override;
    void showChatMessageSuccess(const std::string &message) override;

    // Control methods
    void start() override;
    void stop() override;
};

} // namespace bitchat
