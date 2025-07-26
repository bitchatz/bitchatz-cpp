#include "bitchat/platform/bluetooth_factory.h"
#include "platforms/linux/bluetooth.h"
#include <memory>

namespace bitchat
{

std::shared_ptr<IBluetoothNetwork> createBluetoothNetworkInterface()
{
    return std::make_shared<LinuxBluetoothNetwork>();
}

} // namespace bitchat
