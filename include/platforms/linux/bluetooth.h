#pragma once

#include "bitchat/platform/bluetooth_interface.h"
#include <atomic>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace bitchat
{

class LinuxBluetoothNetwork : public IBluetoothNetwork
{
public:
    LinuxBluetoothNetwork();
    ~LinuxBluetoothNetwork() override;

    bool initialize() override;
    bool start() override;
    void stop() override;
    bool sendPacket(const BitchatPacket &packet) override;
    bool sendPacketToPeer(const BitchatPacket &packet, const std::string &peerID) override;
    bool isReady() const override;

    void setPeerConnectedCallback(PeerConnectedCallback callback) override;
    void setPeerDisconnectedCallback(PeerDisconnectedCallback callback) override;
    void setPacketReceivedCallback(PacketReceivedCallback callback) override;
    size_t getConnectedPeersCount() const override;

private:
    void scanThreadFunc();
    void readerThreadFunc(const std::string &deviceID, int socket);
    void acceptThreadFunc();

    int deviceID;
    int hciSocket;
    int rfcommSocket;

    std::thread scanThread;
    std::thread acceptThread;
    std::atomic<bool> stopThreads;

    PacketReceivedCallback packetReceivedCallback;
    PeerConnectedCallback peerConnectedCallback;
    PeerDisconnectedCallback peerDisconnectedCallback;

    std::map<std::string, int> connectedSockets;
    std::mutex socketsMutex;
};

} // namespace bitchat
