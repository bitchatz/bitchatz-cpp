#include "bitchat/ui/dummy_ui.h"

namespace bitchat
{

DummyUserInterface::DummyUserInterface()
{
    // Pass
}

bool DummyUserInterface::initialize([[maybe_unused]] std::shared_ptr<MessageService> messageService)
{
    return true;
}

void DummyUserInterface::onMessageReceived([[maybe_unused]] const BitchatMessage &message)
{
    // Pass
}

void DummyUserInterface::onPeerJoined([[maybe_unused]] const std::string &peerID, [[maybe_unused]] const std::string &nickname)
{
    // Pass
}

void DummyUserInterface::onPeerLeft([[maybe_unused]] const std::string &peerID, [[maybe_unused]] const std::string &nickname)
{
    // Pass
}

void DummyUserInterface::onPeerConnected([[maybe_unused]] const std::string &peripheralID)
{
    // Pass
}

void DummyUserInterface::onPeerDisconnected([[maybe_unused]] const std::string &peripheralID)
{
    // Pass
}

void DummyUserInterface::onChannelJoined([[maybe_unused]] const std::string &channel)
{
    // Pass
}

void DummyUserInterface::onChannelLeft([[maybe_unused]] const std::string &channel)
{
    // Pass
}

void DummyUserInterface::onStatusUpdate([[maybe_unused]] const std::string &status)
{
    // Pass
}

void DummyUserInterface::showPeers()
{
    // Pass
}

void DummyUserInterface::showStatus()
{
    // Pass
}

void DummyUserInterface::showHelp()
{
    // Pass
}

void DummyUserInterface::clearChat()
{
    // Pass
}

void DummyUserInterface::showWelcome()
{
    // Pass
}

void DummyUserInterface::start()
{
    // Pass
}

void DummyUserInterface::stop()
{
    // Pass
}

// Chat output method implementations
void DummyUserInterface::showChatMessage([[maybe_unused]] const std::string &message)
{
    // Pass
}

void DummyUserInterface::showChatMessageInfo([[maybe_unused]] const std::string &message)
{
    // Pass
}

void DummyUserInterface::showChatMessageWarn([[maybe_unused]] const std::string &message)
{
    // Pass
}

void DummyUserInterface::showChatMessageError([[maybe_unused]] const std::string &message)
{
    // Pass
}

void DummyUserInterface::showChatMessageSuccess([[maybe_unused]] const std::string &message)
{
    // Pass
}

} // namespace bitchat
