#pragma once

#include <string>

namespace bitchat
{

namespace constants
{

// Service and Characteristic UUIDs for Bitchat BLE Protocol
const std::string BLE_SERVICE_UUID = "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C";
const std::string BLE_CHARACTERISTIC_UUID = "A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D";

// BLE Configuration Constants
const double BLE_SCAN_INTERVAL_SECONDS = 0.1;
const double BLE_CONNECTION_TIMEOUT_SECONDS = 10.0;

// Packet validation constants
const size_t BLE_MIN_PACKET_SIZE_BYTES = 21;
const size_t BLE_MAX_PACKET_SIZE_BYTES = 512;

// Peer ID generation constants (8 bytes = 16 hex characters)
const size_t BLE_PEER_ID_LENGTH_CHARS = 16;

// BLE Service Properties
const uint32_t BLE_CHARACTERISTIC_PROPERTIES =
    0x02 | // Read
    0x08 | // Write
    0x04 | // Write Without Response
    0x10;  // Notify

// BLE Service Permissions
const uint32_t BLE_CHARACTERISTIC_PERMISSIONS =
    0x01 | // Readable
    0x02;  // Writeable

} // namespace constants

} // namespace bitchat
