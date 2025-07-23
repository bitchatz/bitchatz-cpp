#include "bitchat/platform/bluetooth_interface.h"
#include "platforms/apple/bluetooth_bridge.h"
#include <memory>

namespace bitchat
{

/**
 * @brief Factory function to create a Bluetooth interface instance
 *
 * This function is called by the BluetoothFactory to create a platform-specific
 * Bluetooth implementation. It returns a shared_ptr to ensure proper memory management.
 *
 * @return Shared pointer to the Bluetooth interface implementation
 */
std::shared_ptr<BluetoothInterface> createBluetoothInterface()
{
    return std::make_shared<AppleBluetoothBridge>();
}

} // namespace bitchat
