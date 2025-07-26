#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "bitchat/core/bitchat_manager.h"
#include "bitchat/runners/bluetooth_announce_runner.h"
#include "bitchat/runners/cleanup_runner.h"
#include "bitchat/services/crypto_service.h"
#include "bitchat/services/message_service.h"
#include "bitchat/services/network_service.h"
#include "bitchat/services/noise_service.h"
#include "bitchat/ui/dummy_ui.h"
#include "mock/bluetooth_announce_runner_mock.h"
#include "mock/bluetooth_interface_mock.h"
#include "mock/cleanup_runner_mock.h"

using namespace bitchat;
using namespace ::testing;

TEST(BitchatManagerTest, Initialize)
{
    // Set up expectations
    auto bluetoothNetwork = std::make_shared<MockBluetoothNetwork>();
    EXPECT_CALL(*bluetoothNetwork, setPacketReceivedCallback(::NotNull())).Times(1);
    EXPECT_CALL(*bluetoothNetwork, setPeerConnectedCallback(::NotNull())).Times(1);
    EXPECT_CALL(*bluetoothNetwork, setPeerDisconnectedCallback(::NotNull())).Times(1);
    EXPECT_CALL(*bluetoothNetwork, initialize()).WillOnce(::testing::Return(true));
    EXPECT_CALL(*bluetoothNetwork, start()).WillOnce(::testing::Return(true));
    EXPECT_CALL(*bluetoothNetwork, sendPacket).WillOnce(::testing::Return(true));

    // Create services
    auto networkService = std::make_shared<NetworkService>();
    auto messageService = std::make_shared<MessageService>();
    auto cryptoService = std::make_shared<CryptoService>();
    auto noiseService = std::make_shared<NoiseService>();
    auto announceRunner = std::make_shared<MockBluetoothAnnounceRunner>();
    auto cleanupRunner = std::make_shared<MockCleanupRunner>();

    // Create UI
    auto dummyUserInterface = std::make_shared<bitchat::DummyUserInterface>();

    // Test the manager
    auto manager = std::make_shared<BitchatManager>();
    ASSERT_TRUE(manager->initialize(dummyUserInterface, bluetoothNetwork, networkService, messageService, cryptoService, noiseService, announceRunner, cleanupRunner));
    ASSERT_TRUE(manager->start());
    manager->stop();
}
