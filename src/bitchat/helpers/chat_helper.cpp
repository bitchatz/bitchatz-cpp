#include "bitchat/helpers/chat_helper.h"
#include <spdlog/sinks/stdout_color_sinks.h>

namespace bitchat
{

std::shared_ptr<spdlog::logger> ChatHelper::chatLogger;
bool ChatHelper::initialized = false;

void ChatHelper::initialize()
{
    if (initialized)
    {
        return;
    }

    // Create a colored console sink for chat messages
    auto consoleSink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();

    // No prefix, just the message
    consoleSink->set_pattern("%v");

    // Create the chat logger
    chatLogger = std::make_shared<spdlog::logger>("chat", consoleSink);
    chatLogger->set_level(spdlog::level::info);

    initialized = true;
}

void ChatHelper::shutdown()
{
    if (initialized)
    {
        // Log the disconnection
        chatLogger->info("Shutdown.");

        // Force flush all pending log messages
        chatLogger->flush();

        // Reset the logger
        chatLogger.reset();
        initialized = false;
    }
}

} // namespace bitchat
