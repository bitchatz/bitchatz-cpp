#pragma once

#include <memory>
#include <spdlog/fmt/fmt.h>
#include <spdlog/spdlog.h>

namespace bitchat
{

class ChatHelper
{
public:
    static void initialize();
    static void shutdown();

    template <typename... Args>
    static void show(const std::string &format, Args &&...args)
    {
        if (!initialized)
        {
            initialize();
        }
        chatLogger->info(fmt::format(fmt::runtime(format), std::forward<Args>(args)...));
    }

    template <typename... Args>
    static void info(const std::string &format, Args &&...args)
    {
        if (!initialized)
        {
            initialize();
        }
        chatLogger->info(fmt::format(fmt::runtime(format), std::forward<Args>(args)...));
    }

    template <typename... Args>
    static void warn(const std::string &format, Args &&...args)
    {
        if (!initialized)
        {
            initialize();
        }
        chatLogger->warn(fmt::format(fmt::runtime(format), std::forward<Args>(args)...));
    }

    template <typename... Args>
    static void error(const std::string &format, Args &&...args)
    {
        if (!initialized)
        {
            initialize();
        }
        chatLogger->error(fmt::format(fmt::runtime(format), std::forward<Args>(args)...));
    }

    template <typename... Args>
    static void success(const std::string &format, Args &&...args)
    {
        if (!initialized)
        {
            initialize();
        }
        chatLogger->info(fmt::format(fmt::runtime(format), std::forward<Args>(args)...));
    }

    static std::string getChatPrefix();

private:
    static std::shared_ptr<spdlog::logger> chatLogger;
    static bool initialized;
};

} // namespace bitchat
