#include "bitchat/core/bitchat_manager.h"
#include "bitchat/helpers/chat_helper.h"
#include <chrono>
#include <iostream>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/spdlog.h>
#include <string>
#include <thread>

using namespace bitchat;

// Global manager instance
std::unique_ptr<bitchat::BitchatManager> manager;

// Callback functions for UI updates
void onMessageReceived(const BitchatMessage &message)
{
    spdlog::debug("onMessageReceived callback called - Sender: {}, Content: {}, Channel: {}", message.getSender(), message.getContent(), message.getChannel());

    // Format timestamp
    time_t timestamp = message.getTimestamp() / 1000;
    char timebuf[10];
    std::tm *tinfo = std::localtime(&timestamp);
    std::strftime(timebuf, sizeof(timebuf), "%H:%M", tinfo);

    // Display message using ChatHelper
    ChatHelper::show("[{}] {}: {}", timebuf, message.getSender(), message.getContent());
}

void onPeerJoined(const std::string & /*peerID*/, const std::string &nickname)
{
    ChatHelper::info("*** {} joined ***", nickname);
}

void onPeerLeft(const std::string & /*peerID*/, const std::string &nickname)
{
    ChatHelper::info("*** {} left ***", nickname);
}

void onStatusUpdate(const std::string &status)
{
    spdlog::info("Status: {}", status);
}

void showOnlinePeers()
{
    if (!manager)
        return;

    auto peers = manager->getOnlinePeers();
    ChatHelper::info("\nPeople online:");

    time_t now = time(nullptr);
    bool found = false;

    for (const auto &[peerID, peer] : peers)
    {
        // Show all peers that have been seen recently (within 3 minutes)
        if ((now - peer.getLastSeen()) < 180)
        {
            std::string peerInfo = "- " + peer.getNickname();

            // Check if this is us (by comparing peer ID)
            if (peerID == manager->getPeerID())
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
            ChatHelper::info(peerInfo);
            found = true;
        }
    }

    if (!found)
    {
        ChatHelper::info("No one online at the moment.");
    }
}

void showStatus()
{
    if (!manager)
    {
        return;
    }

    std::string currentChannel = manager->getCurrentChannel();
    if (currentChannel.empty())
    {
        ChatHelper::info("Current channel: main (default chat)");
    }
    else
    {
        ChatHelper::info("Current channel: {}", currentChannel);
    }
}

void showHelp()
{
    ChatHelper::info("\nAvailable commands:");
    ChatHelper::info("/j #channel    - Join channel");
    ChatHelper::info("/nick NICK     - Change nickname");
    ChatHelper::info("/w             - Show people online in current channel");
    ChatHelper::info("/status        - Show current channel status");
    ChatHelper::info("/clear         - Clear screen");
    ChatHelper::info("/help          - Show this help");
    ChatHelper::info("/exit          - Exit");
    ChatHelper::info("Message        - Send message to current channel");
    ChatHelper::info("");
    ChatHelper::info("Note: You can send messages without joining a channel (default chat)");
    ChatHelper::info("");
}

void clearScreen()
{
#ifdef _WIN32
    [[maybe_unused]] auto ignored = system("clear");
#else
    // https://student.cs.uwaterloo.ca/~cs452/terminal.html
    std::cout << "\033[2J\033[H";
#endif
}

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
    spdlog::set_pattern("[%H:%M:%S] %v");

    spdlog::info("=== Bitchat Terminal Client ===");

    // Create and initialize manager
    manager = std::make_unique<bitchat::BitchatManager>();

    // Set callbacks
    manager->setMessageCallback(onMessageReceived);
    manager->setPeerJoinedCallback(onPeerJoined);
    manager->setPeerLeftCallback(onPeerLeft);
    manager->setStatusCallback(onStatusUpdate);

    // Initialize
    if (!manager->initialize())
    {
        spdlog::error("Failed to initialize BitchatManager");
        return 1;
    }

    // Start
    if (!manager->start())
    {
        spdlog::error("Failed to start BitchatManager");
        return 1;
    }

    // Initialize ChatHelper for console output
    ChatHelper::initialize();

    ChatHelper::info("=== Bitchat Terminal Client ===");
    ChatHelper::info("Peer ID: {}", manager->getPeerID());
    ChatHelper::info("Nickname: {}", manager->getNickname());
    ChatHelper::info("Connected! Type /help for commands.");

    // Main command loop
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
                showHelp();
            }
            else if (line.rfind("/j ", 0) == 0)
            {
                std::string channel = line.substr(3);
                manager->joinChannel(channel);
                ChatHelper::success("Joined channel: {}", channel);
            }
            else if (line == "/j")
            {
                manager->joinChannel("");
                ChatHelper::success("Joined main chat");
            }
            else if (line.rfind("/nick ", 0) == 0)
            {
                std::string nickname = line.substr(6);
                manager->setNickname(nickname);
                ChatHelper::success("Nickname changed to: {}", nickname);
            }
            else if (line == "/w")
            {
                showOnlinePeers();
            }
            else if (line == "/status")
            {
                showStatus();
            }
            else if (line == "/clear")
            {
                clearScreen();
            }
            else if (line[0] == '/')
            {
                ChatHelper::warn("Unknown command. Type /help for available commands.");
            }
            else if (line.empty())
            {
                // Do nothing
            }
            else
            {
                // Send message
                if (manager->sendMessage(line))
                {
                    time_t now = time(nullptr);
                    char timebuf[10];
                    std::tm *tinfo = std::localtime(&now);
                    std::strftime(timebuf, sizeof(timebuf), "%H:%M", tinfo);
                    ChatHelper::show("[{}] You: {}", timebuf, line);
                }
                else
                {
                    ChatHelper::error("Failed to send message");
                }
            }
        }

        // Small delay to prevent busy waiting
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Cleanup
    manager->stop();
    manager.reset();

    ChatHelper::shutdown();

    return 0;
}
