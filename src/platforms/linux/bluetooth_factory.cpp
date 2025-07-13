#include "bitchat/platform/bluetooth_factory.h"
#include "platforms/linux/bluetooth.h"
#include <memory>

namespace bitchat
{

std::unique_ptr<BluetoothInterface> createBluetoothInterface()
{
    return std::make_unique<LinuxBluetooth>();
}

} // namespace bitchat
