#pragma once

#include "bitchat/platform/bluetooth_factory.h"
#include "bitchat/platform/bluetooth_interface.h"
#include "mock/mock_bluetooth_interface.h"
#include <memory>

namespace bitchat
{

// Global mock instance for testing
std::shared_ptr<bitchat::testing::MockBluetoothInterface> mockBluetoothInterface = nullptr;

// Helper functions to set and clear the mock instance
void setMockBluetoothInterface(std::shared_ptr<bitchat::testing::MockBluetoothInterface> mock)
{
    mockBluetoothInterface = mock;
}

void clearMockBluetoothInterface()
{
    mockBluetoothInterface.reset();
}

// Factory function that creates the appropriate Bluetooth interface for the current platform
// Each platform implements this function to return their specific implementation
std::shared_ptr<BluetoothInterface> createBluetoothInterface()
{
    return mockBluetoothInterface;
}

} // namespace bitchat
