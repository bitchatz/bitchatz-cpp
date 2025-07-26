#include "bitchat/ui/console_ui.h"
#include "bitchat/core/bitchat_data.h"
#include "bitchat/core/bitchat_manager.h"
#include <chrono>
#include <iostream>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <thread>

namespace bitchat
{

ConsoleUserInterface::ConsoleUserInterface()
    : initialized(false)
{
    // Pass
}

bool ConsoleUserInterface::initialize(std::shared_ptr<MessageService> messageService)
{
    if (initialized)
    {
        return true;
    }

    initialized = true;

    if (!messageService)
    {
        spdlog::error("ConsoleUserInterface: Cannot initialize with null message service");
        return false;
    }

    this->messageService = messageService;

    // Set up callbacks to route all events through ConsoleUserInterface
    // clang-format off
    messageService->setMessageReceivedCallback([this](const BitchatMessage &message) {
        onMessageReceived(message);
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

    // Create a colored console sink for chat messages
    auto consoleSink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();

    // No prefix, just the message
    consoleSink->set_pattern("%v");

    // Create the chat logger
    logger = std::make_shared<spdlog::logger>("chat", consoleSink);
    logger->set_level(spdlog::level::debug);

    spdlog::info("ConsoleUserInterface initialized");

    return true;
}

void ConsoleUserInterface::onMessageReceived(const BitchatMessage &message)
{
    spdlog::debug("onMessageReceived callback called - Sender: {}, Content: {}, Channel: {}", message.getSender(), message.getContent(), message.getChannel());
    showChatMessage(fmt::format("[{}] {}: {}", getChatPrefix(), message.getSender(), message.getContent()));
}

void ConsoleUserInterface::onPeerJoined([[maybe_unused]] const std::string &peerID, const std::string &nickname)
{
    showChatMessageInfo(fmt::format("[{}] *** {} joined ***", getChatPrefix(), nickname));
}

void ConsoleUserInterface::onPeerLeft([[maybe_unused]] const std::string &peerID, const std::string &nickname)
{
    showChatMessageInfo(fmt::format("[{}] *** {} left ***", getChatPrefix(), nickname));
}

void ConsoleUserInterface::onPeerConnected(const std::string &peripheralID)
{
    showChatMessageInfo(fmt::format("[{}] *** {} connected ***", getChatPrefix(), peripheralID));
}

void ConsoleUserInterface::onPeerDisconnected(const std::string &peripheralID)
{
    showChatMessageInfo(fmt::format("[{}] *** {} disconnected ***", getChatPrefix(), peripheralID));
}

void ConsoleUserInterface::onChannelJoined(const std::string &channel)
{
    showChatMessageSuccess(fmt::format("[{}] *** Joined channel: {} ***", getChatPrefix(), channel));
}

void ConsoleUserInterface::onChannelLeft(const std::string &channel)
{
    showChatMessageInfo(fmt::format("[{}] *** Left channel: {} ***", getChatPrefix(), channel));
}

void ConsoleUserInterface::onStatusUpdate(const std::string &status)
{
    showChatMessageInfo(fmt::format("Status: {}", status));
}

void ConsoleUserInterface::showPeers()
{
    auto peers = BitchatData::shared()->getPeers();
    showChatMessage("People online:");

    time_t now = time(nullptr);
    bool found = false;

    for (const auto &peer : peers)
    {
        // Show all peers that have been seen recently (within 3 minutes)
        if ((now - peer.getLastSeen()) < 180)
        {
            std::string peerInfo = "- " + peer.getNickname();

            // Check if this is us (by comparing peer ID)
            if (peer.getPeerID() == BitchatData::shared()->getPeerID())
            {
                peerInfo += " (you)";
            }

            if (!peer.getChannel().empty())
            {
                peerInfo += " (channel: " + peer.getChannel() + ")";
            }

            if (peer.getRSSI() > -100)
            {
                peerInfo += " (RSSI: " + std::to_string(peer.getRSSI()) + " dBm)";
            }

            showChatMessage(peerInfo);

            found = true;
        }
    }

    if (!found)
    {
        showChatMessageInfo("No one online at the moment");
    }
}

void ConsoleUserInterface::showStatus()
{
    std::string currentChannel = BitchatData::shared()->getCurrentChannel();

    if (currentChannel.empty())
    {
        showChatMessageInfo("Status: Not in any channel");
    }
    else
    {
        showChatMessageInfo(fmt::format("Status: In channel '{}'", currentChannel));
    }
}

void ConsoleUserInterface::showHelp()
{
    showChatMessage("Available commands:");
    showChatMessage("/j #channel    - Join channel");
    showChatMessage("/nick NICK     - Change nickname");
    showChatMessage("/w             - Show people online in current channel");
    showChatMessage("/status        - Show current channel status");
    showChatMessage("/clear         - Clear screen");
    showChatMessage("/help          - Show this help");
    showChatMessage("/exit          - Exit");
    showChatMessage("Message        - Send message to current channel");
    showChatMessage("");
    showChatMessage("Note: You can send messages without joining a channel (default chat)");
    showChatMessage("");
}

void ConsoleUserInterface::clearChat()
{
#ifdef _WIN32
    [[maybe_unused]] auto ignored = system("clear");
#else
    // https://student.cs.uwaterloo.ca/~cs452/terminal.html
    std::cout << "\033[2J\033[H";
#endif
}

void ConsoleUserInterface::showWelcome()
{
    showChatMessageInfo("=== Bitchat Terminal Client ===");
    showChatMessageInfo(fmt::format("Peer ID: {}", BitchatData::shared()->getPeerID()));
    showChatMessageInfo(fmt::format("Nickname: {}", BitchatData::shared()->getNickname()));
    showChatMessageInfo("Connected! Type /help for commands.");
}

void ConsoleUserInterface::start()
{
    if (!initialized)
    {
        return;
    }

    // Show welcome message
    showWelcome();

    // Start chat loop
    std::string line;

    while (true)
    {
        if (std::getline(std::cin, line))
        {
            if (line == "/exit")
            {
                break;
            }
            else if (line == "/help")
            {
                BitchatManager::shared()->getUserInterface()->showHelp();
            }
            else if (line.rfind("/j ", 0) == 0)
            {
                std::string channel = line.substr(3);
                BitchatManager::shared()->joinChannel(channel);

                showChatMessageSuccess(fmt::format("Joined channel: {}", channel));
            }
            else if (line == "/j")
            {
                BitchatManager::shared()->joinChannel("");
                showChatMessageSuccess("Joined main chat");
            }
            else if (line.rfind("/nick ", 0) == 0)
            {
                std::string nickname = line.substr(6);
                BitchatManager::shared()->changeNickname(nickname);
                showChatMessageSuccess(fmt::format("Nickname changed to: {}", nickname));
            }
            else if (line == "/w")
            {
                showPeers();
            }
            else if (line == "/status")
            {
                showStatus();
            }
            else if (line == "/clear")
            {
                clearChat();
            }
            else if (line[0] == '/')
            {
                showChatMessageWarn("Unknown command, type /help for available commands");
            }
            else if (line.empty())
            {
                // Do nothing
            }
            else
            {
                // Send message
                if (BitchatManager::shared()->sendMessage(line))
                {
                    showChatMessage(fmt::format("{} You: {}", getChatPrefix(), line));
                }
                else
                {
                    showChatMessageError("Failed to send message");
                }
            }
        }

        // Small delay to prevent busy waiting
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void ConsoleUserInterface::stop()
{
    showChatMessageInfo("Shutdown");
    logger->flush();
}

// Chat output method implementations
void ConsoleUserInterface::showChatMessage(const std::string &message)
{
    if (!initialized)
    {
        return;
    }

    logger->info(message);
}

void ConsoleUserInterface::showChatMessageInfo(const std::string &message)
{
    if (!initialized)
    {
        return;
    }

    logger->info(message);
}

void ConsoleUserInterface::showChatMessageWarn(const std::string &message)
{
    if (!initialized)
    {
        return;
    }

    logger->warn(message);
}

void ConsoleUserInterface::showChatMessageError(const std::string &message)
{
    if (!initialized)
    {
        return;
    }

    logger->error(message);
}

void ConsoleUserInterface::showChatMessageSuccess(const std::string &message)
{
    if (!initialized)
    {
        return;
    }

    logger->info(message);
}

std::string ConsoleUserInterface::getChatPrefix()
{
    time_t now = time(nullptr);
    char timebuf[10];
    std::tm *tinfo = std::localtime(&now);
    std::strftime(timebuf, sizeof(timebuf), "%H:%M", tinfo);
    return fmt::format("[{}]", timebuf);
}

} // namespace bitchat
