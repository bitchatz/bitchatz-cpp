#include "bitchat/runners/bluetooth_announce_runner.h"
#include "bitchat/core/bitchat_data.h"
#include "bitchat/helpers/datetime_helper.h"
#include "bitchat/helpers/string_helper.h"
#include "bitchat/protocol/packet_serializer.h"
#include <chrono>
#include <spdlog/spdlog.h>

namespace bitchat
{

BluetoothAnnounceRunner::BluetoothAnnounceRunner()
    : shouldExit(false)
    , running(false)
{
}

BluetoothAnnounceRunner::~BluetoothAnnounceRunner()
{
    stop();
}

void BluetoothAnnounceRunner::setBluetoothInterface(std::shared_ptr<BluetoothInterface> bluetooth)
{
    bluetoothInterface = bluetooth;
}

bool BluetoothAnnounceRunner::start()
{
    if (!bluetoothInterface)
    {
        spdlog::error("BluetoothAnnounceRunner: Cannot start without Bluetooth interface");
        return false;
    }

    if (running.load())
    {
        spdlog::warn("BluetoothAnnounceRunner: Already running");
        return true;
    }

    shouldExit = false;
    running = true;

    // Start background thread
    runnerThread = std::thread(&BluetoothAnnounceRunner::runnerLoop, this);

    spdlog::info("BluetoothAnnounceRunner started");

    return true;
}

void BluetoothAnnounceRunner::stop()
{
    shouldExit = true;
    running = false;

    if (runnerThread.joinable())
    {
        runnerThread.join();
    }

    spdlog::info("BluetoothAnnounceRunner stopped");
}

bool BluetoothAnnounceRunner::isRunning() const
{
    return running.load();
}

void BluetoothAnnounceRunner::runnerLoop()
{
    spdlog::info("BluetoothAnnounceRunner: Runner loop started");
    PacketSerializer serializer;

    while (!shouldExit)
    {
        try
        {
            // Get data from BitchatData
            std::string nickname = BitchatData::shared()->getNickname();
            std::string localPeerID = BitchatData::shared()->getPeerID();

            // Create announce packet with nickname
            std::vector<uint8_t> payload = serializer.makeAnnouncePayload(nickname);

            BitchatPacket announcePacket(PKT_TYPE_ANNOUNCE, payload);

            // Convert hex string to bytes correctly
            std::vector<uint8_t> senderID;

            for (size_t i = 0; i < localPeerID.length(); i += 2)
            {
                std::string byteString = localPeerID.substr(i, 2);
                uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
                senderID.push_back(byte);
            }

            announcePacket.setSenderID(senderID);
            announcePacket.setTimestamp(DateTimeHelper::getCurrentTimestamp());

            // Send announce packet
            if (bluetoothInterface && bluetoothInterface->isReady())
            {
                bluetoothInterface->sendPacket(announcePacket);
            }

            // Sleep for announce interval
            std::this_thread::sleep_for(std::chrono::seconds(ANNOUNCE_INTERVAL));
        }
        catch (const std::exception &e)
        {
            spdlog::error("Error in announce loop: {}", e.what());
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

} // namespace bitchat
