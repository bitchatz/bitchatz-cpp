#include "bitchat/core/bitchat_manager.h"
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

// Global manager instance
std::unique_ptr<bitchat::BitchatManager> g_manager;

// Callback functions for UI updates
void onMessageReceived(const bitchat::BitchatMessage& message) {
    // Format timestamp
    time_t timestamp = message.timestamp / 1000;
    char timebuf[10];
    std::tm* tinfo = std::localtime(&timestamp);
    std::strftime(timebuf, sizeof(timebuf), "%H:%M", tinfo);
    
    // Display message
    spdlog::info("[{}] {}: {}", timebuf, message.sender, message.content);
}

void onPeerJoined(const std::string& /*peerId*/, const std::string& nickname) {
    spdlog::info("*** {} joined ***", nickname);
}

void onPeerLeft(const std::string& /*peerId*/, const std::string& nickname) {
    spdlog::info("*** {} left ***", nickname);
}

void onStatusUpdate(const std::string& status) {
    spdlog::info("Status: {}", status);
}

void showOnlinePeers() {
    if (!g_manager) return;
    
    auto peers = g_manager->getOnlinePeers();
    spdlog::info("\nPeople online:");
    
    time_t now = time(nullptr);
    bool found = false;
    
    for (const auto& [peerId, peer] : peers) {
        // Show all peers that have been seen recently (within 3 minutes)
        if ((now - peer.lastSeen) < 180) {
            std::string peerInfo = "- " + peer.nick;
            
            // Check if this is us (by comparing peer ID)
            if (peerId == g_manager->getPeerId()) {
                peerInfo += " (you)";
            }
            
            if (!peer.canal.empty()) {
                peerInfo += " (channel: " + peer.canal + ")";
            }
            if (peer.rssi > -100) {
                peerInfo += " (RSSI: " + std::to_string(peer.rssi) + " dBm)";
            }
            spdlog::info(peerInfo);
            found = true;
        }
    }
    
    if (!found) {
        spdlog::info("No one online at the moment.");
    }
}

void showHelp() {
    spdlog::info("\nAvailable commands:");
    spdlog::info("/j #channel    - Join channel");
    spdlog::info("/nick NICK     - Change nickname");
    spdlog::info("/w             - Show people online in current channel");
    spdlog::info("/clear         - Clear screen");
    spdlog::info("/help          - Show this help");
    spdlog::info("/exit          - Exit");
    spdlog::info("Message        - Send message to current channel");
    spdlog::info("");
}

void clearScreen() {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

int main() {
    // Initialize spdlog
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    auto logger = std::make_shared<spdlog::logger>("bitchat", console_sink);
    spdlog::set_default_logger(logger);
    spdlog::set_pattern("[%H:%M:%S] %v");
    
    spdlog::info("=== Bitchat Terminal Client ===");
    
    // Create and initialize manager
    g_manager = std::make_unique<bitchat::BitchatManager>();
    
    // Set callbacks
    g_manager->setMessageCallback(onMessageReceived);
    g_manager->setPeerJoinedCallback(onPeerJoined);
    g_manager->setPeerLeftCallback(onPeerLeft);
    g_manager->setStatusCallback(onStatusUpdate);
    
    // Initialize
    if (!g_manager->initialize()) {
        spdlog::error("Failed to initialize BitchatManager");
        return 1;
    }
    
    // Start
    if (!g_manager->start()) {
        spdlog::error("Failed to start BitchatManager");
        return 1;
    }
    
    spdlog::info("Connected! Type /help for commands.");
    spdlog::info("Peer ID: {}", g_manager->getPeerId());
    spdlog::info("Nickname: {}", g_manager->getNickname());
    
    // Main command loop
    std::string line;
    while (true) {
        if (std::getline(std::cin, line)) {
            if (line == "/exit") {
                break;
            } else if (line == "/help") {
                showHelp();
            } else if (line.rfind("/j ", 0) == 0) {
                std::string channel = line.substr(3);
                g_manager->joinChannel(channel);
                spdlog::info("Joined channel: {}", channel);
            } else if (line == "/j") {
                g_manager->joinChannel("#general");
                spdlog::info("Joined general chat");
            } else if (line.rfind("/nick ", 0) == 0) {
                std::string nickname = line.substr(6);
                g_manager->setNickname(nickname);
                spdlog::info("Nickname changed to: {}", nickname);
            } else if (line == "/w") {
                showOnlinePeers();
            } else if (line == "/clear") {
                clearScreen();
            } else if (line.empty()) {
                // Do nothing
            } else if (line[0] == '/') {
                spdlog::warn("Unknown command. Type /help for available commands.");
            } else {
                // Send message
                if (g_manager->sendMessage(line)) {
                    time_t now = time(nullptr);
                    char timebuf[10];
                    std::tm* tinfo = std::localtime(&now);
                    std::strftime(timebuf, sizeof(timebuf), "%H:%M", tinfo);
                    spdlog::info("[{}] You: {}", timebuf, line);
                } else {
                    spdlog::error("Failed to send message");
                }
            }
        }
        
        // Small delay to prevent busy waiting
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    // Cleanup
    g_manager->stop();
    g_manager.reset();
    
    spdlog::info("Disconnected.");
    return 0;
} 