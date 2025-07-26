#pragma once

#include "bitchat/core/bitchat_manager.h"
#include <memory>
#include <spdlog/fmt/fmt.h>

namespace bitchat
{

class UserInterfaceHelper
{
public:
    template <typename... Args>
    static void showChatMessage(const std::string &format, Args &&...args)
    {
        auto manager = BitchatManager::shared();
        if (manager && manager->getUserInterface())
        {
            std::string message = fmt::format(fmt::runtime(format), std::forward<Args>(args)...);
            manager->getUserInterface()->showChatMessage(message);
        }
    }

    template <typename... Args>
    static void showChatMessageInfo(const std::string &format, Args &&...args)
    {
        auto manager = BitchatManager::shared();
        if (manager && manager->getUserInterface())
        {
            std::string message = fmt::format(fmt::runtime(format), std::forward<Args>(args)...);
            manager->getUserInterface()->showChatMessageInfo(message);
        }
    }

    template <typename... Args>
    static void showChatMessageWarn(const std::string &format, Args &&...args)
    {
        auto manager = BitchatManager::shared();
        if (manager && manager->getUserInterface())
        {
            std::string message = fmt::format(fmt::runtime(format), std::forward<Args>(args)...);
            manager->getUserInterface()->showChatMessageWarn(message);
        }
    }

    template <typename... Args>
    static void showChatMessageError(const std::string &format, Args &&...args)
    {
        auto manager = BitchatManager::shared();
        if (manager && manager->getUserInterface())
        {
            std::string message = fmt::format(fmt::runtime(format), std::forward<Args>(args)...);
            manager->getUserInterface()->showChatMessageError(message);
        }
    }

    template <typename... Args>
    static void showChatMessageSuccess(const std::string &format, Args &&...args)
    {
        auto manager = BitchatManager::shared();
        if (manager && manager->getUserInterface())
        {
            std::string message = fmt::format(fmt::runtime(format), std::forward<Args>(args)...);
            manager->getUserInterface()->showChatMessageSuccess(message);
        }
    }
};

} // namespace bitchat
