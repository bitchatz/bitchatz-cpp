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

class LinuxBluetooth : public BluetoothInterface
{
public:
    LinuxBluetooth();
    ~LinuxBluetooth() override;

    bool initialize() override;
    bool start() override;
    void stop() override;
    bool sendPacket(const BitchatPacket &packet) override;
    bool sendPacketToPeer(const BitchatPacket &packet, const std::string &peerId) override;
    bool isReady() const override;
    std::string getLocalPeerId() const override;
    void setPeerDisconnectedCallback(PeerDisconnectedCallback callback) override;
    void setPacketReceivedCallback(PacketReceivedCallback callback) override;
    size_t getConnectedPeersCount() const override;

private:
    void scanThreadFunc();
    void readerThreadFunc(const std::string &deviceId, int socket);
    void acceptThreadFunc();

    int deviceId;
    int hciSocket;
    int rfcommSocket;
    std::string localPeerId;

    std::thread scanThread;
    std::thread acceptThread;
    std::atomic<bool> stopThreads;

    PacketReceivedCallback packetReceivedCallback;
    PeerDisconnectedCallback peerDisconnectedCallback;

    std::map<std::string, int> connectedSockets;
    mutable std::mutex socketsMutex;
};

} // namespace bitchat
