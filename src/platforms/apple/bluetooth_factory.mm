#include "bitchat/platform/bluetooth_interface.h"
#include "platforms/apple/bluetooth_bridge.h"
#include <memory>

namespace bitchat
{

/**
 * @brief Factory function to create a Bluetooth interface instance
 *
 * This function is called by the BluetoothFactory to create a platform-specific
 * Bluetooth implementation. It returns a unique_ptr to ensure proper memory management.
 *
 * @return Unique pointer to the Bluetooth interface implementation
 */
std::unique_ptr<BluetoothInterface> createBluetoothInterface()
{
    return std::make_unique<AppleBluetoothBridge>();
}

} // namespace bitchat
