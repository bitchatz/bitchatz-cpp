#include "platforms/linux/bluetooth.h"
#include "bitchat/protocol/packet.h"
#include "bitchat/protocol/packet_serializer.h"
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <chrono>
#include <iostream>
#include <spdlog/spdlog.h>
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>

namespace bitchat
{

LinuxBluetooth::LinuxBluetooth()
    : deviceId(-1)
    , hciSocket(-1)
    , rfcommSocket(-1)
    , stopThreads(false)
{
    deviceId = hci_get_route(nullptr);
    if (deviceId < 0)
    {
        spdlog::error("No Bluetooth adapter found");
        throw std::runtime_error("No Bluetooth adapter found");
    }

    hciSocket = hci_open_dev(deviceId);
    if (hciSocket < 0)
    {
        spdlog::error("Failed to open HCI socket");
        throw std::runtime_error("Failed to open HCI socket");
    }

    bdaddr_t bdaddr;
    hci_read_bd_addr(hciSocket, &bdaddr, 1000);
    char addr[19];
    ba2str(&bdaddr, addr);
    localPeerId = addr;
    spdlog::info("Local Bluetooth adapter address: {}", localPeerId);
}

LinuxBluetooth::~LinuxBluetooth()
{
    stop();

    if (hciSocket >= 0)
    {
        close(hciSocket);
        spdlog::info("Closed HCI socket.");
    }

    if (rfcommSocket >= 0)
    {
        close(rfcommSocket);
        spdlog::info("Closed RFCOMM socket.");
    }
}

bool LinuxBluetooth::initialize()
{
    spdlog::info("LinuxBluetooth initialized.");
    return true;
}

bool LinuxBluetooth::start()
{
    stopThreads = false;
    scanThread = std::thread(&LinuxBluetooth::scanThreadFunc, this);
    acceptThread = std::thread(&LinuxBluetooth::acceptThreadFunc, this);
    spdlog::info("Bluetooth scanning and acceptance threads started.");

    return true;
}

void LinuxBluetooth::stop()
{
    stopThreads = true;
    spdlog::info("Stopping Bluetooth threads...");

    if (scanThread.joinable())
    {
        scanThread.join();
    }

    if (acceptThread.joinable())
    {
        acceptThread.join();
    }

    std::lock_guard<std::mutex> lock(socketsMutex);
    for (auto const &[key, val] : connectedSockets)
    {
        close(val);
        spdlog::info("Closed socket for peer: {}", key);
    }

    connectedSockets.clear();
    spdlog::info("Bluetooth threads stopped and sockets closed.");
}

bool LinuxBluetooth::sendPacket(const BitchatPacket &packet)
{
    PacketSerializer serializer;
    std::vector<uint8_t> data = serializer.serializePacket(packet);
    std::lock_guard<std::mutex> lock(socketsMutex);

    if (connectedSockets.empty())
    {
        spdlog::warn("No connected peers to send packet to.");
        return false;
    }

    for (auto const &[key, val] : connectedSockets)
    {
        if (write(val, data.data(), data.size()) < 0)
        {
            spdlog::error("Failed to write to socket for peer {}: {}", key, strerror(errno));
            return false;
        }

        spdlog::debug("Sent packet to peer: {}", key);
    }

    return true;
}

bool LinuxBluetooth::sendPacketToPeer(const BitchatPacket &packet, const std::string &peerId)
{
    PacketSerializer serializer;
    std::vector<uint8_t> data = serializer.serializePacket(packet);
    std::lock_guard<std::mutex> lock(socketsMutex);
    auto it = connectedSockets.find(peerId);

    if (it != connectedSockets.end())
    {
        if (write(it->second, data.data(), data.size()) < 0)
        {
            spdlog::error("Failed to write to socket for peer {}: {}", peerId, strerror(errno));
            return false;
        }
        spdlog::debug("Sent packet to specific peer: {}", peerId);
        return true;
    }

    spdlog::warn("Peer {} not found in connected sockets.", peerId);

    return false;
}

bool LinuxBluetooth::isReady() const
{
    return deviceId >= 0 && hciSocket >= 0;
}

std::string LinuxBluetooth::getLocalPeerId() const
{
    return localPeerId;
}

void LinuxBluetooth::setPeerDisconnectedCallback(PeerDisconnectedCallback callback)
{
    peerDisconnectedCallback = callback;
}

void LinuxBluetooth::setPacketReceivedCallback(PacketReceivedCallback callback)
{
    packetReceivedCallback = callback;
}

size_t LinuxBluetooth::getConnectedPeersCount() const
{
    std::lock_guard<std::mutex> lock(socketsMutex);
    return connectedSockets.size();
}

void LinuxBluetooth::scanThreadFunc()
{
    inquiry_info *ii = new inquiry_info[255];
    int maxRsp = 255;
    int numRsp{};
    int flags = IREQ_CACHE_FLUSH;
    char addr[19] = {0};

    spdlog::info("Bluetooth scan thread started.");

    while (!stopThreads)
    {
        numRsp = hci_inquiry(deviceId, 8, maxRsp, nullptr, &ii, flags);

        if (numRsp < 0)
        {
            spdlog::error("HCI inquiry failed: {}", strerror(errno));
            break;
        }

        for (int i = 0; i < numRsp; i++)
        {
            ba2str(&(ii[i].bdaddr), addr);
            std::string deviceId = addr;

            {
                std::lock_guard<std::mutex> lock(socketsMutex);
                if (connectedSockets.find(deviceId) != connectedSockets.end())
                {
                    spdlog::debug("Device {} is already connected, skipping.", deviceId);
                    continue;
                }
            }

            struct sockaddr_rc sockAddr;
            memset(&sockAddr, 0, sizeof(sockAddr));
            int s = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);

            if (s < 0)
            {
                spdlog::error("Failed to create RFCOMM socket: {}", strerror(errno));
                continue;
            }

            sockAddr.rc_family = AF_BLUETOOTH;
            sockAddr.rc_channel = (uint8_t)1;
            str2ba(addr, &sockAddr.rc_bdaddr);

            if (connect(s, (struct sockaddr *)&sockAddr, sizeof(sockAddr)) == 0)
            {
                std::lock_guard<std::mutex> lock(socketsMutex);
                connectedSockets[deviceId] = s;
                spdlog::info("Connected to device: {}", deviceId);
                std::thread(&LinuxBluetooth::readerThreadFunc, this, deviceId, s).detach();
            }
            else
            {
                spdlog::warn("Failed to connect to device {}: {}", deviceId, strerror(errno));
                close(s);
            }
        }

        // Scan every 10 seconds
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }

    spdlog::info("Bluetooth scan thread stopped.");

    delete[] ii;
}

void LinuxBluetooth::acceptThreadFunc()
{
    struct sockaddr_rc locAddr, remAddr;
    memset(&locAddr, 0, sizeof(locAddr));
    memset(&remAddr, 0, sizeof(remAddr));
    char buf[256] = {0};
    int client;
    socklen_t opt = sizeof(remAddr);

    rfcommSocket = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
    if (rfcommSocket < 0)
    {
        spdlog::error("Failed to create RFCOMM socket for accepting connections: {}", strerror(errno));
        return;
    }

    locAddr.rc_family = AF_BLUETOOTH;
    bdaddr_t anyBdaddr = {0}; // Initialize to all zeros
    bacpy(&locAddr.rc_bdaddr, &anyBdaddr);
    locAddr.rc_channel = (uint8_t)1;

    if (bind(rfcommSocket, (struct sockaddr *)&locAddr, sizeof(locAddr)) < 0)
    {
        spdlog::error("Failed to bind RFCOMM socket: {}", strerror(errno));
        close(rfcommSocket);
        rfcommSocket = -1;
        return;
    }

    // Listen for incoming connections on channel 1
    listen(rfcommSocket, 1);
    spdlog::info("Listening for incoming Bluetooth connections on channel 1.");

    while (!stopThreads)
    {
        client = accept(rfcommSocket, (struct sockaddr *)&remAddr, &opt);
        if (client < 0)
        {
            if (errno == EINTR)
            {
                // Interrupted system call, e.g., by signal
                continue;
            }

            spdlog::error("Failed to accept connection: {}", strerror(errno));
            continue;
        }

        ba2str(&remAddr.rc_bdaddr, buf);
        std::string deviceId = buf;

        std::lock_guard<std::mutex> lock(socketsMutex);
        connectedSockets[deviceId] = client;
        spdlog::info("Accepted connection from device: {}", deviceId);
        std::thread(&LinuxBluetooth::readerThreadFunc, this, deviceId, client).detach();
    }

    spdlog::info("Bluetooth accept thread stopped.");
}

void LinuxBluetooth::readerThreadFunc(const std::string &deviceId, int socket)
{
    char buf[4096];
    ssize_t bytesRead;

    spdlog::info("Reader thread started for device: {}", deviceId);

    while ((bytesRead = read(socket, buf, sizeof(buf))) > 0)
    {
        if (packetReceivedCallback)
        {
            std::vector<uint8_t> data(buf, buf + bytesRead);
            PacketSerializer serializer;
            BitchatPacket packet = serializer.deserializePacket(data);
            packetReceivedCallback(packet);
            spdlog::debug("Received packet from device: {}", deviceId);
        }
    }

    if (bytesRead == 0)
    {
        spdlog::info("Device {} disconnected gracefully.", deviceId);
    }
    else if (bytesRead < 0)
    {
        spdlog::error("Failed to read from device {}: {}", deviceId, strerror(errno));
    }

    if (peerDisconnectedCallback)
    {
        peerDisconnectedCallback(deviceId);
        spdlog::info("Peer disconnected callback invoked for device: {}", deviceId);
    }

    std::lock_guard<std::mutex> lock(socketsMutex);
    connectedSockets.erase(deviceId);
    close(socket);
    spdlog::info("Reader thread for device {} finished. Socket closed and removed from map.", deviceId);
}

} // namespace bitchat
