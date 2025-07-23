#include <gtest/gtest.h>

#include "mock/mock_bluetooth.h"

class BitchatManagerFixture : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Clear any previous mock
        bitchat::clearMockBluetoothInterface();
    }

    void TearDown() override
    {
        // Always clean up after each test
        bitchat::clearMockBluetoothInterface();
    }
};
