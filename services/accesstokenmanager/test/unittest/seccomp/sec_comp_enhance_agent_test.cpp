/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "access_token_error.h"
#include "sec_comp_enhance_agent_test.h"

#include <atomic>
#include <climits>
#include <cstdint>
#include <cstring>
#include <functional>
#include <thread>

#include "securec.h"

using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr uint64_t CONCURRENT_TEST_START_EPOCH = 2;
constexpr uint64_t CONCURRENT_TEST_END_EPOCH = 100;

SecCompEnhanceKey CreateEnhanceKey(uint64_t epoch, uint32_t size, uint8_t value)
{
    SecCompEnhanceKey enhanceKey;
    enhanceKey.epoch = epoch;
    enhanceKey.key.size = size;
    if (size <= MAX_HMAC_SIZE) {
        (void)memset_s(enhanceKey.key.data, MAX_HMAC_SIZE, value, size);
    }
    return enhanceKey;
}

void WriteEnhanceKeys(SecCompEnhanceAgent& agent, std::atomic<bool>& writerDone, std::atomic<bool>& valid)
{
    for (uint64_t epoch = CONCURRENT_TEST_START_EPOCH; epoch <= CONCURRENT_TEST_END_EPOCH; ++epoch) {
        if (agent.StoreSecCompEnhanceKey(
            CreateEnhanceKey(epoch, MAX_HMAC_SIZE, static_cast<uint8_t>(epoch))) != RET_SUCCESS) {
            valid = false;
            break;
        }
    }
    writerDone = true;
}

void ReadEnhanceKeys(SecCompEnhanceAgent& agent, const std::atomic<bool>& writerDone, std::atomic<bool>& valid)
{
    while (!writerDone.load()) {
        SecCompEnhanceKey result;
        if (agent.GetSecCompEnhanceKey(result) != RET_SUCCESS) {
            valid = false;
            break;
        }
        for (uint32_t index = 1; index < result.key.size; ++index) {
            if (result.key.data[index] != result.key.data[0]) {
                valid = false;
                return;
            }
        }
    }
}
}

void SecCompEnhanceAgentTest::SetUpTestCase()
{
}

void SecCompEnhanceAgentTest::TearDownTestCase()
{
}

void SecCompEnhanceAgentTest::SetUp()
{
    auto& agent = SecCompEnhanceAgent::GetInstance();
    std::lock_guard<std::mutex> lock(agent.secCompEnhanceKeyMutex_);
    (void)memset_s(agent.secCompEnhanceKey_.key.data, MAX_HMAC_SIZE, 0, MAX_HMAC_SIZE);
    agent.secCompEnhanceKey_.key.size = 0;
    agent.secCompEnhanceKey_.epoch = 0;
    agent.hasSecCompEnhanceKey_ = false;
}

void SecCompEnhanceAgentTest::TearDown()
{
}

/**
 * @tc.name: ProcessFromForegroundList001
 * @tc.desc: Monitor foreground list for process after process state changed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SecCompEnhanceAgentTest, ProcessFromForegroundList001, TestSize.Level1)
{
    SecCompEnhanceData data;
    data.callback = nullptr;
    data.challenge = 0;
    data.seqNum = 0;

    SecCompEnhanceData data1;

    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        SecCompEnhanceAgent::GetInstance().GetSecCompEnhance(getpid(), data1));

    EXPECT_EQ(RET_SUCCESS, SecCompEnhanceAgent::GetInstance().RegisterSecCompEnhance(data));
    EXPECT_EQ(RET_SUCCESS, SecCompEnhanceAgent::GetInstance().GetSecCompEnhance(getpid(), data1));
    EXPECT_EQ(1, data1.count);

    SecCompEnhanceAgent::GetInstance().RemoveSecCompEnhance(data1.pid, data1.token);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        SecCompEnhanceAgent::GetInstance().GetSecCompEnhance(getpid(), data1));
}

/**
 * @tc.name: ProcessFromForegroundList002
 * @tc.desc: Monitor foreground list for process after process state changed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SecCompEnhanceAgentTest, ProcessFromForegroundList002, TestSize.Level1)
{
    SecCompEnhanceData data;
    data.callback = nullptr;
    data.challenge = 1;
    data.sessionId = 10;
    data.seqNum = 0;

    EXPECT_EQ(RET_SUCCESS, SecCompEnhanceAgent::GetInstance().RegisterSecCompEnhance(data));

    SecCompEnhanceData data1;
    EXPECT_EQ(RET_SUCCESS, SecCompEnhanceAgent::GetInstance().GetSecCompEnhance(getpid(), data1));
    EXPECT_EQ(1, data1.count);

    data.challenge = 2;
    data.sessionId = 20;
    data.seqNum = 3;
    if (memset_s(data.key, AES_KEY_STORAGE_LEN, 0x5A, AES_KEY_STORAGE_LEN) != EOK) {
        FAIL();
    }
    EXPECT_EQ(RET_SUCCESS, SecCompEnhanceAgent::GetInstance().RegisterSecCompEnhance(data));
    EXPECT_EQ(RET_SUCCESS, SecCompEnhanceAgent::GetInstance().GetSecCompEnhance(getpid(), data1));
    EXPECT_EQ(2, data1.count);
    EXPECT_EQ(2u, data1.challenge);
    EXPECT_EQ(20u, data1.sessionId);
    EXPECT_EQ(3u, data1.seqNum);
    EXPECT_EQ(0, memcmp(data.key, data1.key, AES_KEY_STORAGE_LEN));

    SecCompEnhanceAgent::GetInstance().RemoveSecCompEnhance(data1.pid, data1.token);
    EXPECT_EQ(RET_SUCCESS, SecCompEnhanceAgent::GetInstance().GetSecCompEnhance(getpid(), data1));
    EXPECT_EQ(1, data1.count);
    EXPECT_EQ(2u, data1.challenge);
    EXPECT_EQ(20u, data1.sessionId);
    EXPECT_EQ(3u, data1.seqNum);

    SecCompEnhanceAgent::GetInstance().RemoveSecCompEnhance(data1.pid, data1.token);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        SecCompEnhanceAgent::GetInstance().GetSecCompEnhance(getpid(), data1));
}

/**
 * @tc.name: SecCompEnhanceKey001
 * @tc.desc: Store and repeatedly get a stable enhance key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SecCompEnhanceAgentTest, SecCompEnhanceKey001, TestSize.Level1)
{
    auto& agent = SecCompEnhanceAgent::GetInstance();
    SecCompEnhanceKey result;
    EXPECT_EQ(AccessTokenError::ERR_RESOURCE_IS_NOT_READY, agent.GetSecCompEnhanceKey(result));

    SecCompEnhanceKey enhanceKey = CreateEnhanceKey(1, 32, 0x5A);
    EXPECT_EQ(RET_SUCCESS, agent.StoreSecCompEnhanceKey(enhanceKey));
    EXPECT_EQ(RET_SUCCESS, agent.GetSecCompEnhanceKey(result));
    EXPECT_EQ(enhanceKey.epoch, result.epoch);
    EXPECT_EQ(enhanceKey.key.size, result.key.size);
    EXPECT_EQ(0, memcmp(enhanceKey.key.data, result.key.data, result.key.size));

    SecCompEnhanceKey secondResult;
    EXPECT_EQ(RET_SUCCESS, agent.GetSecCompEnhanceKey(secondResult));
    EXPECT_EQ(0, memcmp(result.key.data, secondResult.key.data, result.key.size));
}

/**
 * @tc.name: SecCompEnhanceKey002
 * @tc.desc: Validate enhance key size and epoch update rules
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SecCompEnhanceAgentTest, SecCompEnhanceKey002, TestSize.Level1)
{
    auto& agent = SecCompEnhanceAgent::GetInstance();
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, agent.StoreSecCompEnhanceKey(CreateEnhanceKey(1, 0, 0)));
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        agent.StoreSecCompEnhanceKey(CreateEnhanceKey(1, MAX_HMAC_SIZE + 1, 0)));

    SecCompEnhanceKey first = CreateEnhanceKey(10, MAX_HMAC_SIZE, 0x11);
    EXPECT_EQ(RET_SUCCESS, agent.StoreSecCompEnhanceKey(first));
    EXPECT_EQ(RET_SUCCESS, agent.StoreSecCompEnhanceKey(first));
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        agent.StoreSecCompEnhanceKey(CreateEnhanceKey(9, MAX_HMAC_SIZE, 0x22)));
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        agent.StoreSecCompEnhanceKey(CreateEnhanceKey(10, MAX_HMAC_SIZE, 0x22)));
    SecCompEnhanceKey result;
    EXPECT_EQ(RET_SUCCESS, agent.GetSecCompEnhanceKey(result));
    EXPECT_EQ(first.epoch, result.epoch);
    EXPECT_EQ(0, memcmp(first.key.data, result.key.data, result.key.size));

    SecCompEnhanceKey latest = CreateEnhanceKey(UINT64_MAX, MAX_HMAC_SIZE, 0x33);
    EXPECT_EQ(RET_SUCCESS, agent.StoreSecCompEnhanceKey(latest));
    EXPECT_EQ(RET_SUCCESS, agent.GetSecCompEnhanceKey(result));
    EXPECT_EQ(UINT64_MAX, result.epoch);
    EXPECT_EQ(0, memcmp(latest.key.data, result.key.data, result.key.size));
}

/**
 * @tc.name: SecCompEnhanceKey003
 * @tc.desc: Application and AppMgr cleanup do not remove the stable enhance key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SecCompEnhanceAgentTest, SecCompEnhanceKey003, TestSize.Level1)
{
    auto& agent = SecCompEnhanceAgent::GetInstance();
    SecCompEnhanceKey enhanceKey = CreateEnhanceKey(1, 16, 0x44);
    ASSERT_EQ(RET_SUCCESS, agent.StoreSecCompEnhanceKey(enhanceKey));

    SecCompUsageObserver observer;
    ProcessData processData;
    processData.pid = -1;
    processData.accessTokenId = 0;
    observer.OnProcessDied(processData);
    SecCompEnhanceKey result;
    EXPECT_EQ(RET_SUCCESS, agent.GetSecCompEnhanceKey(result));
    EXPECT_EQ(enhanceKey.epoch, result.epoch);
    EXPECT_EQ(0, memcmp(enhanceKey.key.data, result.key.data, result.key.size));

    agent.OnAppMgrRemoteDiedHandle();
    result = {};
    EXPECT_EQ(RET_SUCCESS, agent.GetSecCompEnhanceKey(result));
    EXPECT_EQ(enhanceKey.epoch, result.epoch);
    EXPECT_EQ(0, memcmp(enhanceKey.key.data, result.key.data, result.key.size));
}

/**
 * @tc.name: SecCompEnhanceKey004
 * @tc.desc: Concurrent Store and Get do not expose a partial enhance key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SecCompEnhanceAgentTest, SecCompEnhanceKey004, TestSize.Level1)
{
    auto& agent = SecCompEnhanceAgent::GetInstance();
    ASSERT_EQ(RET_SUCCESS, agent.StoreSecCompEnhanceKey(CreateEnhanceKey(1, MAX_HMAC_SIZE, 1)));

    std::atomic<bool> writerDone = false;
    std::atomic<bool> valid = true;
    std::thread writer(WriteEnhanceKeys, std::ref(agent), std::ref(writerDone), std::ref(valid));
    std::thread reader(ReadEnhanceKeys, std::ref(agent), std::cref(writerDone), std::ref(valid));
    writer.join();
    reader.join();
    EXPECT_TRUE(valid.load());
}

/**
 * @tc.name: SecCompEnhanceKey005
 * @tc.desc: GetSecCompEnhanceKey rejects a corrupted stored enhance key size.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SecCompEnhanceAgentTest, SecCompEnhanceKey005, TestSize.Level1)
{
    auto& agent = SecCompEnhanceAgent::GetInstance();
    {
        std::lock_guard<std::mutex> lock(agent.secCompEnhanceKeyMutex_);
        agent.secCompEnhanceKey_ = CreateEnhanceKey(1, MAX_HMAC_SIZE + 1, 0x55);
        agent.hasSecCompEnhanceKey_ = true;
    }

    SecCompEnhanceKey result = CreateEnhanceKey(2, 1, 0x66);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, agent.GetSecCompEnhanceKey(result));
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
