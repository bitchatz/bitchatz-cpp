#include "platforms/linux/bluetooth.h"
#include "bitchat/protocol/packet.h"
#include "bitchat/protocol/packet_serializer.h"
#include <algorithm>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <chrono>
#include <cstring>
#include <iostream>
#include <spdlog/spdlog.h>
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>

namespace bitchat
{

LinuxBluetooth::LinuxBluetooth()
    : deviceID(-1)
    , hciSocket(-1)
    , rfcommSocket(-1)
    , stopThreads(false)
    , packetReceivedCallback(nullptr)
    , peerDisconnectedCallback(nullptr)
{
    deviceID = hci_get_route(nullptr);

    if (deviceID < 0)
    {
        spdlog::error("No Bluetooth adapter found");
        throw std::runtime_error("No Bluetooth adapter found");
    }

    hciSocket = hci_open_dev(deviceID);
    if (hciSocket < 0)
    {
        spdlog::error("Failed to open HCI socket");
        throw std::runtime_error("Failed to open HCI socket");
    }

    bdaddr_t bdAddr;
    hci_read_bd_addr(hciSocket, &bdAddr, 1000);
    char addr[19];
    ba2str(&bdAddr, addr);

    spdlog::info("Bluetooth adapter address: {}", addr);
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

    bool sentToAny = false;
    for (auto const &[key, val] : connectedSockets)
    {
        if (write(val, data.data(), data.size()) < 0)
        {
            spdlog::error("Failed to write to socket for peer {}: {}", key, strerror(errno));
            // Don't return false here, try to send to other peers
            continue;
        }

        spdlog::debug("Sent packet to peer: {}", key);
        sentToAny = true;
    }

    return sentToAny;
}

bool LinuxBluetooth::sendPacketToPeer(const BitchatPacket &packet, const std::string &peerID)
{
    PacketSerializer serializer;
    std::vector<uint8_t> data = serializer.serializePacket(packet);
    std::lock_guard<std::mutex> lock(socketsMutex);
    auto it = connectedSockets.find(peerID);

    if (it != connectedSockets.end())
    {
        if (write(it->second, data.data(), data.size()) < 0)
        {
            spdlog::error("Failed to write to socket for peer {}: {}", peerID, strerror(errno));
            return false;
        }
        spdlog::debug("Sent packet to specific peer: {}", peerID);
        return true;
    }

    spdlog::warn("Peer {} not found in connected sockets.", peerID);

    return false;
}

bool LinuxBluetooth::isReady() const
{
    return deviceID >= 0 && hciSocket >= 0;
}

std::string LinuxBluetooth::getLocalPeerID() const
{
    return localPeerID;
}

void LinuxBluetooth::setLocalPeerID(const std::string &peerID)
{
    localPeerID = peerID;
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
    std::lock_guard<std::mutex> lock(const_cast<std::mutex &>(socketsMutex));
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
        numRsp = hci_inquiry(deviceID, 8, maxRsp, nullptr, &ii, flags);

        if (numRsp < 0)
        {
            spdlog::error("HCI inquiry failed: {}", strerror(errno));
            break;
        }

        for (int i = 0; i < numRsp; i++)
        {
            ba2str(&(ii[i].bdaddr), addr);
            std::string deviceID = addr;

            {
                std::lock_guard<std::mutex> lock(socketsMutex);
                if (connectedSockets.find(deviceID) != connectedSockets.end())
                {
                    spdlog::debug("Device {} is already connected, skipping.", deviceID);
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
                connectedSockets[deviceID] = s;
                spdlog::info("Connected to device: {}", deviceID);
                std::thread(&LinuxBluetooth::readerThreadFunc, this, deviceID, s).detach();
            }
            else
            {
                spdlog::warn("Failed to connect to device {}: {}", deviceID, strerror(errno));
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
        std::string deviceID = buf;

        std::lock_guard<std::mutex> lock(socketsMutex);
        connectedSockets[deviceID] = client;
        spdlog::info("Accepted connection from device: {}", deviceID);
        std::thread(&LinuxBluetooth::readerThreadFunc, this, deviceID, client).detach();
    }

    spdlog::info("Bluetooth accept thread stopped.");
}

void LinuxBluetooth::readerThreadFunc(const std::string &deviceID, int socket)
{
    char buf[4096];
    ssize_t bytesRead;
    std::vector<uint8_t> accumulatedData;
    PacketSerializer serializer;
    const size_t maxPacketSize = 65536; // 64KB max packet size

    spdlog::info("Reader thread started for device: {}", deviceID);

    while ((bytesRead = read(socket, buf, sizeof(buf))) > 0)
    {
        // Add received data to accumulated buffer
        accumulatedData.insert(accumulatedData.end(), buf, buf + bytesRead);

        // Process complete packets from accumulated data
        while (accumulatedData.size() >= 21) // Minimum packet size (header + senderID)
        {
            // Read payload length from the packet header (offset 12-13)
            uint16_t payloadLength = (accumulatedData[12] << 8) | accumulatedData[13];
            uint8_t flags = accumulatedData[11]; // flags byte

            // Calculate total expected packet size
            size_t expectedSize = 21; // header + senderID
            if (flags & FLAG_HAS_RECIPIENT)
            {
                expectedSize += 8; // recipientID
            }
            expectedSize += payloadLength; // payload
            if (flags & FLAG_HAS_SIGNATURE)
            {
                expectedSize += 64; // signature
            }

            // Check for invalid or too large packets
            if (expectedSize > maxPacketSize || payloadLength > maxPacketSize - 21)
            {
                spdlog::error("Invalid or too large packet from device: {} (size: {})", deviceID, expectedSize);
                accumulatedData.clear();
                break;
            }

            // Check if we have enough data for the complete packet
            if (accumulatedData.size() < expectedSize)
            {
                // Not enough data for complete packet, wait for more
                break;
            }

            // Try to deserialize the packet
            try
            {
                BitchatPacket packet = serializer.deserializePacket(accumulatedData);

                // Validate the packet
                if (packet.getVersion() == 0 || packet.getVersion() > 1)
                {
                    spdlog::warn("Invalid packet version {} from device: {}", packet.getVersion(), deviceID);
                    accumulatedData.erase(accumulatedData.begin());
                    continue;
                }

                if (packetReceivedCallback)
                {
                    packetReceivedCallback(packet);
                    spdlog::debug("Received packet from device: {}", deviceID);
                }

                // Remove the consumed packet from accumulated data
                accumulatedData.erase(accumulatedData.begin(), accumulatedData.begin() + expectedSize);
            }
            catch (const std::exception &e)
            {
                spdlog::error("Failed to deserialize packet from device {}: {}", deviceID, e.what());
                // Remove one byte and try again
                accumulatedData.erase(accumulatedData.begin());
            }
        }
    }

    if (bytesRead == 0)
    {
        spdlog::info("Device {} disconnected gracefully.", deviceID);
    }
    else if (bytesRead < 0)
    {
        spdlog::error("Failed to read from device {}: {}", deviceID, strerror(errno));
    }

    // Notify about disconnection
    if (peerDisconnectedCallback)
    {
        peerDisconnectedCallback(deviceID);
        spdlog::info("Peer disconnected callback invoked for device: {}", deviceID);
    }

    // Clean up socket
    std::lock_guard<std::mutex> lock(socketsMutex);
    connectedSockets.erase(deviceID);
    close(socket);
    spdlog::info("Reader thread for device {} finished. Socket closed and removed from map.", deviceID);
}

} // namespace bitchat
