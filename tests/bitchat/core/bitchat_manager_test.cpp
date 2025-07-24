#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "bitchat/core/bitchat_manager.h"
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
    EXPECT_CALL(*mockInterface, setLocalPeerID(::_)).Times(1);
    EXPECT_CALL(*mockInterface, initialize()).WillOnce(::testing::Return(true));
    EXPECT_CALL(*mockInterface, start()).WillOnce(::testing::Return(true));

    // Test the manager
    BitchatManager manager;
    EXPECT_TRUE(manager.initialize());
    EXPECT_TRUE(manager.start());
}
