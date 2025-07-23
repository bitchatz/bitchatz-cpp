#pragma once

#include <cstdint>
#include <string>

namespace bitchat
{

// Helper class for date/time-related helper functions
class DateTimeHelper
{
public:
    static uint64_t getCurrentTimestamp();
    static std::string formatTimestamp(uint64_t timestamp);

private:
    DateTimeHelper() = delete;
};

} // namespace bitchat
