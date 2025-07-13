#include "platforms/linux/bluetooth.h"
#include "bitchat/protocol/packet.h"
#include "bitchat/protocol/packet_serializer.h"
#include <iostream>
#include <stdexcept>
#include <unistd.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/rfcomm.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <chrono>

namespace bitchat {

LinuxBluetooth::LinuxBluetooth() : dev_id_(-1), hci_socket_(-1), rfcomm_socket_(-1), stop_threads_(false) {
    logger_ = spdlog::stdout_color_mt("linux_bluetooth");
    logger_->set_level(spdlog::level::debug);

    dev_id_ = hci_get_route(nullptr);
    if (dev_id_ < 0) {
        logger_->error("No Bluetooth adapter found");
        throw std::runtime_error("No Bluetooth adapter found");
    }

    hci_socket_ = hci_open_dev(dev_id_);
    if (hci_socket_ < 0) {
        logger_->error("Failed to open HCI socket");
        throw std::runtime_error("Failed to open HCI socket");
    }

    bdaddr_t bdaddr;
    hci_read_bd_addr(hci_socket_, &bdaddr, 1000);
    char addr[19];
    ba2str(&bdaddr, addr);
    local_peer_id_ = addr;
    logger_->info("Local Bluetooth adapter address: {}", local_peer_id_);
}

LinuxBluetooth::~LinuxBluetooth() {
    stop();
    if (hci_socket_ >= 0) {
        close(hci_socket_);
        logger_->info("Closed HCI socket.");
    }
    if (rfcomm_socket_ >= 0) {
        close(rfcomm_socket_);
        logger_->info("Closed RFCOMM socket.");
    }
}

bool LinuxBluetooth::initialize() {
    logger_->info("LinuxBluetooth initialized.");
    return true;
}

bool LinuxBluetooth::start() {
    stop_threads_ = false;
    scan_thread_ = std::thread(&LinuxBluetooth::scan_thread_func, this);
    accept_thread_ = std::thread(&LinuxBluetooth::accept_thread_func, this);
    logger_->info("Bluetooth scanning and acceptance threads started.");
    return true;
}

void LinuxBluetooth::stop() {
    stop_threads_ = true;
    logger_->info("Stopping Bluetooth threads...");
    if (scan_thread_.joinable()) {
        scan_thread_.join();
    }
    if (accept_thread_.joinable()) {
        accept_thread_.join();
    }
    std::lock_guard<std::mutex> lock(sockets_mutex_);
    for (auto const& [key, val] : connected_sockets_) {
        close(val);
        logger_->info("Closed socket for peer: {}", key);
    }
    connected_sockets_.clear();
    logger_->info("Bluetooth threads stopped and sockets closed.");
}

bool LinuxBluetooth::sendPacket(const BitchatPacket& packet) {
    PacketSerializer serializer;
    std::vector<uint8_t> data = serializer.serializePacket(packet);
    std::lock_guard<std::mutex> lock(sockets_mutex_);
    if (connected_sockets_.empty()) {
        logger_->warn("No connected peers to send packet to.");
        return false;
    }
    for (auto const& [key, val] : connected_sockets_) {
        if (write(val, data.data(), data.size()) < 0) {
            logger_->error("Failed to write to socket for peer {}: {}", key, strerror(errno));
            return false;
        }
        logger_->debug("Sent packet to peer: {}", key);
    }
    return true;
}

bool LinuxBluetooth::sendPacketToPeer(const BitchatPacket& packet, const std::string& peerId) {
    PacketSerializer serializer;
    std::vector<uint8_t> data = serializer.serializePacket(packet);
    std::lock_guard<std::mutex> lock(sockets_mutex_);
    auto it = connected_sockets_.find(peerId);
    if (it != connected_sockets_.end()) {
        if (write(it->second, data.data(), data.size()) < 0) {
            logger_->error("Failed to write to socket for peer {}: {}", peerId, strerror(errno));
            return false;
        }
        logger_->debug("Sent packet to specific peer: {}", peerId);
        return true;
    }
    logger_->warn("Peer {} not found in connected sockets.", peerId);
    return false;
}

bool LinuxBluetooth::isReady() const {
    return dev_id_ >= 0 && hci_socket_ >= 0;
}

std::string LinuxBluetooth::getLocalPeerId() const {
    return local_peer_id_;
}

void LinuxBluetooth::setPeerDisconnectedCallback(PeerDisconnectedCallback callback) {
    peer_disconnected_callback_ = callback;
}

void LinuxBluetooth::setPacketReceivedCallback(PacketReceivedCallback callback) {
    packet_received_callback_ = callback;
}

size_t LinuxBluetooth::getConnectedPeersCount() const {
    std::lock_guard<std::mutex> lock(sockets_mutex_);
    return connected_sockets_.size();
}

void LinuxBluetooth::scan_thread_func() {
    inquiry_info* ii = new inquiry_info[255];
    int max_rsp = 255;
    int num_rsp{};
    int flags = IREQ_CACHE_FLUSH;
    char addr[19] = { 0 };

    logger_->info("Bluetooth scan thread started.");

    while (!stop_threads_) {
        num_rsp = hci_inquiry(dev_id_, 8, max_rsp, nullptr, &ii, flags);
        if (num_rsp < 0) {
            logger_->error("hci_inquiry failed: {}", strerror(errno));
            break;
        }

        for (int i = 0; i < num_rsp; i++) {
            ba2str(&(ii[i].bdaddr), addr);
            std::string device_id = addr;

            {
                std::lock_guard<std::mutex> lock(sockets_mutex_);
                if (connected_sockets_.find(device_id) != connected_sockets_.end()) {
                    logger_->debug("Device {} already connected, skipping.", device_id);
                    continue;
                }
            }

            struct sockaddr_rc sock_addr;
            memset(&sock_addr, 0, sizeof(sock_addr));
            int s = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
            if (s < 0) {
                logger_->error("Failed to create RFCOMM socket: {}", strerror(errno));
                continue;
            }
            sock_addr.rc_family = AF_BLUETOOTH;
            sock_addr.rc_channel = (uint8_t) 1;
            str2ba(addr, &sock_addr.rc_bdaddr);

            if (connect(s, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) == 0) {
                std::lock_guard<std::mutex> lock(sockets_mutex_);
                connected_sockets_[device_id] = s;
                logger_->info("Connected to device: {}", device_id);
                std::thread(&LinuxBluetooth::reader_thread_func, this, device_id, s).detach();
            } else {
                logger_->warn("Failed to connect to device {}: {}", device_id, strerror(errno));
                close(s);
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(10)); // Scan every 10 seconds
    }
    logger_->info("Bluetooth scan thread stopped.");
    delete[] ii;
}

void LinuxBluetooth::accept_thread_func() {
    struct sockaddr_rc loc_addr, rem_addr;
    memset(&loc_addr, 0, sizeof(loc_addr));
    memset(&rem_addr, 0, sizeof(rem_addr));
    char buf[256] = { 0 };
    int client;
    socklen_t opt = sizeof(rem_addr);

    rfcomm_socket_ = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
    if (rfcomm_socket_ < 0) {
        logger_->error("Failed to create RFCOMM socket for accepting connections: {}", strerror(errno));
        return;
    }

    loc_addr.rc_family = AF_BLUETOOTH;
    bdaddr_t any_bdaddr = {0}; // Initialize to all zeros
    bacpy(&loc_addr.rc_bdaddr, &any_bdaddr);
    loc_addr.rc_channel = (uint8_t) 1;
    if (bind(rfcomm_socket_, (struct sockaddr *)&loc_addr, sizeof(loc_addr)) < 0) {
        logger_->error("Failed to bind RFCOMM socket: {}", strerror(errno));
        close(rfcomm_socket_);
        rfcomm_socket_ = -1;
        return;
    }
    listen(rfcomm_socket_, 1);
    logger_->info("Listening for incoming Bluetooth connections on channel 1.");

    while (!stop_threads_) {
        client = accept(rfcomm_socket_, (struct sockaddr *)&rem_addr, &opt);
        if (client < 0) {
            if (errno == EINTR) { // Interrupted system call, e.g., by signal
                continue;
            }
            logger_->error("Failed to accept connection: {}", strerror(errno));
            continue;
        }

        ba2str(&rem_addr.rc_bdaddr, buf);
        std::string device_id = buf;

        std::lock_guard<std::mutex> lock(sockets_mutex_);
        connected_sockets_[device_id] = client;
        logger_->info("Accepted connection from device: {}", device_id);
        std::thread(&LinuxBluetooth::reader_thread_func, this, device_id, client).detach();
    }
    logger_->info("Bluetooth accept thread stopped.");
}

void LinuxBluetooth::reader_thread_func(const std::string& device_id, int socket) {
    char buf[4096];
    ssize_t bytes_read;

    logger_->info("Reader thread started for device: {}", device_id);

    while ((bytes_read = read(socket, buf, sizeof(buf))) > 0) {
        if (packet_received_callback_) {
            std::vector<uint8_t> data(buf, buf + bytes_read);
            PacketSerializer serializer;
            BitchatPacket packet = serializer.deserializePacket(data);
            packet_received_callback_(packet);
            logger_->debug("Received packet from device: {}", device_id);
        }
    }

    if (bytes_read == 0) {
        logger_->info("Device {} disconnected gracefully.", device_id);
    } else if (bytes_read < 0) {
        logger_->error("Error reading from device {}: {}", device_id, strerror(errno));
    }

    if (peer_disconnected_callback_) {
        peer_disconnected_callback_(device_id);
        logger_->info("Peer disconnected callback invoked for device: {}", device_id);
    }

    std::lock_guard<std::mutex> lock(sockets_mutex_);
    connected_sockets_.erase(device_id);
    close(socket);
    logger_->info("Reader thread for device {} finished. Socket closed and removed from map.", device_id);
}

std::unique_ptr<BluetoothInterface> createLinuxBluetoothBridge() {
    return std::make_unique<LinuxBluetooth>();
}

} // namespace bitchat