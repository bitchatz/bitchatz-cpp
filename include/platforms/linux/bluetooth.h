#pragma once

#include "bitchat/platform/bluetooth_interface.h"
#include <string>
#include <functional>
#include <vector>
#include <thread>
#include <atomic>
#include <map>
#include <mutex>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

namespace bitchat {

class LinuxBluetooth : public BluetoothInterface {
public:
    LinuxBluetooth();
    ~LinuxBluetooth() override;

    bool initialize() override;
    bool start() override;
    void stop() override;
    bool sendPacket(const BitchatPacket& packet) override;
    bool sendPacketToPeer(const BitchatPacket& packet, const std::string& peerId) override;
    bool isReady() const override;
    std::string getLocalPeerId() const override;
    void setPeerDisconnectedCallback(PeerDisconnectedCallback callback) override;
    void setPacketReceivedCallback(PacketReceivedCallback callback) override;
    size_t getConnectedPeersCount() const override;

private:
    void scan_thread_func();
    void reader_thread_func(const std::string& device_id, int socket);
    void accept_thread_func();

    int dev_id_;
    int hci_socket_;
    int rfcomm_socket_;
    std::string local_peer_id_;

    std::thread scan_thread_;
    std::thread accept_thread_;
    std::atomic<bool> stop_threads_;

    PacketReceivedCallback packet_received_callback_;
    PeerDisconnectedCallback peer_disconnected_callback_;

    std::map<std::string, int> connected_sockets_;
    mutable std::mutex sockets_mutex_;
    std::shared_ptr<spdlog::logger> logger_;
};

} // namespace bitchat