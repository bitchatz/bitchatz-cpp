#include "bitchat/core/bitchat_manager.h"
#include "bitchat/helpers/chat_helper.h"
#include "bitchat/runners/bluetooth_announce_runner.h"
#include "bitchat/runners/cleanup_runner.h"
#include "bitchat/services/crypto_service.h"
#include "bitchat/services/message_service.h"
#include "bitchat/services/network_service.h"
#include "bitchat/services/noise_service.h"
#include <chrono>
#include <iostream>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/spdlog.h>
#include <string>
#include <thread>

using namespace bitchat;

// Callback functions for UI updates
void onMessageReceived(const BitchatMessage &message)
{
    spdlog::debug("onMessageReceived callback called - Sender: {}, Content: {}, Channel: {}", message.getSender(), message.getContent(), message.getChannel());
    ChatHelper::show("{} {}: {}", ChatHelper::getChatPrefix(), message.getSender(), message.getContent());
}

void onPeerJoined(const std::string & /*peerID*/, const std::string &nickname)
{
    ChatHelper::info("{} *** {} joined ***", ChatHelper::getChatPrefix(), nickname);
}

void onPeerLeft(const std::string & /*peerID*/, const std::string &nickname)
{
    ChatHelper::info("{} *** {} left ***", ChatHelper::getChatPrefix(), nickname);
}

void onPeerConnected(const std::string &peripheralID)
{
    ChatHelper::info("{} *** {} connected ***", ChatHelper::getChatPrefix(), peripheralID);
}

void onPeerDisconnected(const std::string &peripheralID)
{
    ChatHelper::info("{} *** {} disconnected ***", ChatHelper::getChatPrefix(), peripheralID);
}

void onChannelJoined(const std::string &channel)
{
    ChatHelper::success("{} *** Joined channel: {} ***", ChatHelper::getChatPrefix(), channel);
}

void onChannelLeft(const std::string &channel)
{
    ChatHelper::info("{} *** Left channel: {} ***", ChatHelper::getChatPrefix(), channel);
}

void onStatusUpdate(const std::string &status)
{
    spdlog::info("Status: {}", status);
}

void showOnlinePeers()
{
    auto peers = BitchatData::shared()->getPeers();
    ChatHelper::info("\nPeople online:");

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
    std::string currentChannel = BitchatData::shared()->getCurrentChannel();

    if (currentChannel.empty())
    {
        ChatHelper::info("Status: Not in any channel");
    }
    else
    {
        ChatHelper::info("Status: In channel '{}'", currentChannel);
    }

    ChatHelper::info("Ready: {}", BitchatData::shared()->isReady() ? "Yes" : "No");
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

    // Create services
    auto networkService = std::make_shared<bitchat::NetworkService>();
    auto messageService = std::make_shared<bitchat::MessageService>();
    auto cryptoService = std::make_shared<bitchat::CryptoService>();
    auto noiseService = std::make_shared<bitchat::NoiseService>();

    // Create runners
    auto bluetoothAnnounceRunner = std::make_shared<bitchat::BluetoothAnnounceRunner>();
    auto cleanupRunner = std::make_shared<bitchat::CleanupRunner>();

    // Create and initialize manager
    auto manager = BitchatManager::shared();

    // Set callbacks
    BitchatManager::shared()->setMessageCallback(onMessageReceived);
    BitchatManager::shared()->setPeerJoinedCallback(onPeerJoined);
    BitchatManager::shared()->setPeerLeftCallback(onPeerLeft);
    BitchatManager::shared()->setPeerConnectedCallback(onPeerConnected);
    BitchatManager::shared()->setPeerDisconnectedCallback(onPeerDisconnected);
    BitchatManager::shared()->setChannelJoinedCallback(onChannelJoined);
    BitchatManager::shared()->setChannelLeftCallback(onChannelLeft);
    BitchatManager::shared()->setStatusCallback(onStatusUpdate);

    // Initialize with services and runners
    if (!BitchatManager::shared()->initialize(networkService, messageService, cryptoService, noiseService, bluetoothAnnounceRunner, cleanupRunner))
    {
        spdlog::error("Failed to initialize BitchatManager");
        return 1;
    }

    // Start
    if (!BitchatManager::shared()->start())
    {
        spdlog::error("Failed to start BitchatManager");
        return 1;
    }

    // Initialize ChatHelper for console output
    ChatHelper::initialize();

    ChatHelper::info("=== Bitchat Terminal Client ===");
    ChatHelper::info("Peer ID: {}", BitchatData::shared()->getPeerID());
    ChatHelper::info("Nickname: {}", BitchatData::shared()->getNickname());
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
                BitchatManager::shared()->joinChannel(channel);
                ChatHelper::success("Joined channel: {}", channel);
            }
            else if (line == "/j")
            {
                BitchatManager::shared()->joinChannel("");
                ChatHelper::success("Joined main chat");
            }
            else if (line.rfind("/nick ", 0) == 0)
            {
                std::string nickname = line.substr(6);
                BitchatManager::shared()->changeNickname(nickname);
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
                if (BitchatManager::shared()->sendMessage(line))
                {
                    ChatHelper::show("{} You: {}", ChatHelper::getChatPrefix(), line);
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
    BitchatManager::shared()->stop();

    ChatHelper::shutdown();

    return 0;
}
