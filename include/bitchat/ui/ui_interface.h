#pragma once

#include "bitchat/protocol/packet.h"
#include "bitchat/services/message_service.h"
#include <functional>
#include <memory>
#include <string>

namespace bitchat
{

// Forward declarations
class MessageService;

// IUserInterface: Defines the contract for all UI implementations
class IUserInterface
{
public:
    virtual ~IUserInterface() = default;

    // Initialize the UI with message service
    virtual bool initialize(std::shared_ptr<MessageService> messageService) = 0;

    // Message event callbacks
    virtual void onMessageReceived(const BitchatMessage &message) = 0;
    virtual void onPeerJoined(const std::string &peerID, const std::string &nickname) = 0;
    virtual void onPeerLeft(const std::string &peerID, const std::string &nickname) = 0;
    virtual void onPeerConnected(const std::string &peripheralID) = 0;
    virtual void onPeerDisconnected(const std::string &peripheralID) = 0;
    virtual void onChannelJoined(const std::string &channel) = 0;
    virtual void onChannelLeft(const std::string &channel) = 0;
    virtual void onStatusUpdate(const std::string &status) = 0;

    // Display methods
    virtual void showPeers() = 0;
    virtual void showStatus() = 0;
    virtual void showHelp() = 0;
    virtual void clearChat() = 0;
    virtual void showWelcome() = 0;

    // Chat output methods
    virtual void showChatMessage(const std::string &message) = 0;
    virtual void showChatMessageInfo(const std::string &message) = 0;
    virtual void showChatMessageWarn(const std::string &message) = 0;
    virtual void showChatMessageError(const std::string &message) = 0;
    virtual void showChatMessageSuccess(const std::string &message) = 0;

    // Control methods
    virtual void start() = 0;
    virtual void stop() = 0;
};

} // namespace bitchat
