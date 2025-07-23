#include "bitchat/helpers/datetime_helper.h"
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace bitchat
{

uint64_t DateTimeHelper::getCurrentTimestamp()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string DateTimeHelper::formatTimestamp(uint64_t timestamp)
{
    time_t time = timestamp / 1000;
    char timebuf[20];
    std::tm *tinfo = std::localtime(&time);
    std::strftime(timebuf, sizeof(timebuf), "%H:%M:%S", tinfo);
    return std::string(timebuf);
}

} // namespace bitchat
