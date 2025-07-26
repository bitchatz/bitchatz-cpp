#pragma once

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>

#include "bitchat/runners/bluetooth_announce_runner.h"

namespace bitchat
{

// Forward declarations
class IBluetoothNetwork;

// MockBluetoothAnnounceRunner: Mock for BluetoothAnnounceRunner with all methods mocked
class MockBluetoothAnnounceRunner : public BluetoothAnnounceRunner
{
public:
    MOCK_METHOD(void, setBluetoothNetworkInterface, (std::shared_ptr<IBluetoothNetwork> bluetoothNetwork), (override));
    MOCK_METHOD(bool, start, (), (override));
    MOCK_METHOD(void, stop, (), (override));
    MOCK_METHOD(bool, isRunning, (), (const, override));
};

} // namespace bitchat
