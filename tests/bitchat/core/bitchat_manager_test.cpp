#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "bitchat/core/bitchat_manager.h"
#include "bitchat/runners/bluetooth_announce_runner.h"
#include "bitchat/runners/cleanup_runner.h"
#include "bitchat/services/crypto_service.h"
#include "bitchat/services/message_service.h"
#include "bitchat/services/network_service.h"
#include "bitchat/services/noise_service.h"
#include "fixtures/fixture_bitchat_manager.h"

using namespace bitchat;
using namespace ::testing;

TEST_F(BitchatManagerFixture, Initialize)
{
    // Create a mock instance
    auto mockInterface = std::make_shared<bitchat::testing::MockBluetoothInterface>();
    bitchat::setMockBluetoothInterface(mockInterface);

    // Set up expectations
    EXPECT_CALL(*mockInterface, setPacketReceivedCallback(::NotNull())).Times(1);
    EXPECT_CALL(*mockInterface, setPeerConnectedCallback(::NotNull())).Times(1);
    EXPECT_CALL(*mockInterface, setPeerDisconnectedCallback(::NotNull())).Times(1);
    EXPECT_CALL(*mockInterface, initialize()).WillOnce(::testing::Return(true));
    EXPECT_CALL(*mockInterface, start()).WillOnce(::testing::Return(true));

    // Create services
    auto networkService = std::make_shared<NetworkService>();
    auto messageService = std::make_shared<MessageService>();
    auto cryptoService = std::make_shared<CryptoService>();
    auto noiseService = std::make_shared<NoiseService>();
    auto announceRunner = std::make_shared<BluetoothAnnounceRunner>();
    auto cleanupRunner = std::make_shared<CleanupRunner>();

    // Test the manager
    BitchatManager manager;
    EXPECT_TRUE(manager.initialize(networkService, messageService, cryptoService, noiseService, announceRunner, cleanupRunner));
    EXPECT_TRUE(manager.start());
}
