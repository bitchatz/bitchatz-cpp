#pragma once

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>

#include "bitchat/runners/cleanup_runner.h"

namespace bitchat
{

// Forward declarations
class NetworkService;

// MockCleanupRunner: Mock for CleanupRunner with all methods mocked
class MockCleanupRunner : public CleanupRunner
{
public:
    MOCK_METHOD(bool, initialize, (std::shared_ptr<NetworkService> networkService), (override));
    MOCK_METHOD(bool, start, (), (override));
    MOCK_METHOD(void, stop, (), (override));
    MOCK_METHOD(bool, isRunning, (), (const, override));

protected:
    MOCK_METHOD(void, runnerLoop, (), (override));
};

} // namespace bitchat
