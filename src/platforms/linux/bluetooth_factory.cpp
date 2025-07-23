#include "bitchat/platform/bluetooth_factory.h"
#include "platforms/linux/bluetooth.h"
#include <memory>

namespace bitchat
{

std::shared_ptr<BluetoothInterface> createBluetoothInterface()
{
    return std::make_shared<LinuxBluetooth>();
}

} // namespace bitchat
