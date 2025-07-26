#pragma once

#include "bitchat/platform/bluetooth_interface.h"
#include <memory>

namespace bitchat
{

// Factory function that creates the appropriate Bluetooth interface for the current platform
// Each platform implements this function to return their specific implementation
std::shared_ptr<IBluetoothNetwork> createBluetoothNetworkInterface();

} // namespace bitchat
