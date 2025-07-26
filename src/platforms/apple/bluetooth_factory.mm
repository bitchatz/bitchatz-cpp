#include "bitchat/platform/bluetooth_factory.h"
#include "platforms/apple/bluetooth_bridge.h"
#include <memory>

namespace bitchat
{

std::shared_ptr<IBluetoothNetwork> createBluetoothNetworkInterface()
{
    return std::make_shared<AppleBluetoothNetworkBridge>();
}

} // namespace bitchat
