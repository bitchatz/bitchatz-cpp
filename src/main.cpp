#include "bitchat/core/bitchat_manager.h"
#include <chrono>
#include <iostream>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <string>
#include <thread>

// Global manager instance
std::unique_ptr<bitchat::BitchatManager> manager;

// Callback functions for UI updates
void onMessageReceived(const bitchat::BitchatMessage &message)
{
    spdlog::debug("onMessageReceived callback called - Sender: {}, Content: {}, Channel: {}", message.getSender(), message.getContent(), message.getChannel());

    // Format timestamp
    time_t timestamp = message.getTimestamp() / 1000;
    char timebuf[10];
    std::tm *tinfo = std::localtime(&timestamp);
    std::strftime(timebuf, sizeof(timebuf), "%H:%M", tinfo);

    // Display message
    spdlog::info("[{}] {}: {}", timebuf, message.getSender(), message.getContent());
}

void onPeerJoined(const std::string & /*peerId*/, const std::string &nickname)
{
    spdlog::info("*** {} joined ***", nickname);
}

void onPeerLeft(const std::string & /*peerId*/, const std::string &nickname)
{
    spdlog::info("*** {} left ***", nickname);
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
    spdlog::info("\nPeople online:");

    time_t now = time(nullptr);
    bool found = false;

    for (const auto &[peerId, peer] : peers)
    {
        // Show all peers that have been seen recently (within 3 minutes)
        if ((now - peer.getLastSeen()) < 180)
        {
            std::string peerInfo = "- " + peer.getNick();

            // Check if this is us (by comparing peer ID)
            if (peerId == manager->getPeerId())
            {
                peerInfo += " (you)";
            }

            if (!peer.getCanal().empty())
            {
                peerInfo += " (channel: " + peer.getCanal() + ")";
            }
            if (peer.getRSSI() > -100)
            {
                peerInfo += " (RSSI: " + std::to_string(peer.getRSSI()) + " dBm)";
            }
            spdlog::info(peerInfo);
            found = true;
        }
    }

    if (!found)
    {
        spdlog::info("No one online at the moment.");
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
        spdlog::info("Current channel: main (default chat)");
    }
    else
    {
        spdlog::info("Current channel: {}", currentChannel);
    }
}

void showHelp()
{
    spdlog::info("\nAvailable commands:");
    spdlog::info("/j #channel    - Join channel");
    spdlog::info("/nick NICK     - Change nickname");
    spdlog::info("/w             - Show people online in current channel");
    spdlog::info("/status        - Show current channel status");
    spdlog::info("/clear         - Clear screen");
    spdlog::info("/help          - Show this help");
    spdlog::info("/exit          - Exit");
    spdlog::info("Message        - Send message to current channel");
    spdlog::info("");
    spdlog::info("Note: You can send messages without joining a channel (default chat)");
    spdlog::info("");
}

void clearScreen()
{
#ifdef _WIN32
    [[maybe_unused]] auto ignored = system("clear");
#else
    std::cout << "\033[2J\033[H"; // student.cs.uwaterloo.ca/~cs452/terminal.html
#endif
}

int main()
{
    // Initialize spdlog
    auto consoleSink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    auto logger = std::make_shared<spdlog::logger>("bitchat", consoleSink);
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

    spdlog::info("Connected! Type /help for commands.");
    spdlog::info("Peer ID: {}", manager->getPeerId());
    spdlog::info("Nickname: {}", manager->getNickname());
    spdlog::info("You can send messages without joining a channel or use /j #channel to join one");

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
                spdlog::info("Joined channel: {}", channel);
            }
            else if (line == "/j")
            {
                manager->joinChannel("");
                spdlog::info("Joined main chat");
            }
            else if (line.rfind("/nick ", 0) == 0)
            {
                std::string nickname = line.substr(6);
                manager->setNickname(nickname);
                spdlog::info("Nickname changed to: {}", nickname);
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
            else if (line.empty())
            {
                // Do nothing
            }
            else if (line[0] == '/')
            {
                spdlog::warn("Unknown command. Type /help for available commands.");
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
                    spdlog::info("[{}] You: {}", timebuf, line);
                }
                else
                {
                    spdlog::error("Failed to send message");
                }
            }
        }

        // Small delay to prevent busy waiting
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Cleanup
    manager->stop();
    manager.reset();

    spdlog::info("Disconnected.");
    return 0;
}
