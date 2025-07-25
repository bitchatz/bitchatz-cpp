#pragma once

#include <chrono>
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

// Packet Validation Constants
const size_t BLE_MIN_PACKET_SIZE_BYTES = 21;
const size_t BLE_MAX_PACKET_SIZE_BYTES = 512;

// Peer ID Generation Constants (8 bytes = 16 hex characters)
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

// Data Management Constants
const size_t MAX_HISTORY_SIZE = 1000;
const size_t MAX_PROCESSED_MESSAGES = 1000;
const int PEER_TIMEOUT_SECONDS = 180;

// Noise Protocol Constants
const size_t NOISE_MAX_MESSAGE_SIZE = 65535;
const size_t NOISE_MAX_HANDSHAKE_MESSAGE_SIZE = 2048;
const std::chrono::hours NOISE_SESSION_TIMEOUT{24};
const uint64_t NOISE_MAX_MESSAGES_PER_SESSION = 1'000'000'000;
const std::chrono::seconds NOISE_HANDSHAKE_TIMEOUT{60};
const size_t NOISE_MAX_SESSIONS_PER_PEER = 3;
const size_t NOISE_MAX_HANDSHAKES_PER_MINUTE = 10;
const size_t NOISE_MAX_MESSAGES_PER_SECOND = 100;
const size_t NOISE_MAX_GLOBAL_HANDSHAKES_PER_MINUTE = 30;
const size_t NOISE_MAX_GLOBAL_MESSAGES_PER_SECOND = 500;

} // namespace constants

} // namespace bitchat
