#pragma once

#include "bitchat/platform/bluetooth_interface.h"
#include <memory>

namespace bitchat {
    std::unique_ptr<BluetoothInterface> createAppleBluetoothBridge();
}