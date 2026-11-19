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

#include <gtest/gtest.h>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
#include "access_token_error.h"
#include "want.h"
#define private public
#include "napi_request_permission.h"
#undef private
#include "../../src/napi_request_permission.cpp"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr int32_t TEST_INSTANCE_ID = 424242;
constexpr int32_t TEST_INSTANCE_ID_SECOND = 424243;
constexpr int32_t TEST_INSTANCE_ID_THIRD = 424244;
constexpr int32_t TEST_INSTANCE_ID_FOURTH = 424245;
constexpr uint32_t TEST_INVALID_WINDOW_ID = 99999999;

void ClearInstanceMap()
{
    std::lock_guard<std::mutex> lock(RequestAsyncInstanceControl::instanceIdMutex_);
    RequestAsyncInstanceControl::instanceIdMap_.clear();
}
} // namespace

class NapiRequestExtensionTest : public testing::Test {
public:
    void SetUp() override
    {
        ClearInstanceMap();
    }

    void TearDown() override
    {
        ClearInstanceMap();
    }
};

/**
 * @tc.name: AddCallbackByInstanceIdUiCreateFailTest001
 * @tc.desc: marker is released when UI extension creation fails at the window check.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiRequestExtensionTest, AddCallbackByInstanceIdUiCreateFailTest001, TestSize.Level4)
{
    auto asyncContext = std::make_shared<RequestAsyncContext>(nullptr);
    asyncContext->instanceId = TEST_INSTANCE_ID;
    asyncContext->windowId = TEST_INVALID_WINDOW_ID;
    asyncContext->isWithWindowId = true;
    asyncContext->uiExtensionFlag = true;
    asyncContext->needDynamicRequest = true;

    RequestAsyncInstanceControl::AddCallbackByInstanceId(asyncContext);

    EXPECT_FALSE(asyncContext->needDynamicRequest);
    EXPECT_TRUE(asyncContext->uiExtensionFlag);
    std::lock_guard<std::mutex> lock(RequestAsyncInstanceControl::instanceIdMutex_);
    EXPECT_EQ(RequestAsyncInstanceControl::instanceIdMap_.end(),
        RequestAsyncInstanceControl::instanceIdMap_.find(TEST_INSTANCE_ID));
}

/**
 * @tc.name: AddCallbackByInstanceIdServiceCreateFailTest001
 * @tc.desc: marker is released when service extension creation fails at the window check.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiRequestExtensionTest, AddCallbackByInstanceIdServiceCreateFailTest001, TestSize.Level4)
{
    auto asyncContext = std::make_shared<RequestAsyncContext>(nullptr);
    asyncContext->instanceId = TEST_INSTANCE_ID_SECOND;
    asyncContext->windowId = TEST_INVALID_WINDOW_ID;
    asyncContext->isWithWindowId = true;
    asyncContext->uiExtensionFlag = false;
    asyncContext->needDynamicRequest = true;

    RequestAsyncInstanceControl::AddCallbackByInstanceId(asyncContext);

    EXPECT_FALSE(asyncContext->needDynamicRequest);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, asyncContext->result.errorCode);
    std::lock_guard<std::mutex> lock(RequestAsyncInstanceControl::instanceIdMutex_);
    EXPECT_EQ(RequestAsyncInstanceControl::instanceIdMap_.end(),
        RequestAsyncInstanceControl::instanceIdMap_.find(TEST_INSTANCE_ID_SECOND));
}

/**
 * @tc.name: OnReleaseSkippedAfterOnResultTest001
 * @tc.desc: OnRelease is skipped after OnResult has been called.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiRequestExtensionTest, OnReleaseSkippedAfterOnResultTest001, TestSize.Level4)
{
    auto asyncContext = std::make_shared<RequestAsyncContext>(nullptr);
    asyncContext->instanceId = TEST_INSTANCE_ID_THIRD;
    asyncContext->windowId = TEST_INVALID_WINDOW_ID;
    asyncContext->isWithWindowId = true;

    UIExtensionCallback callback(asyncContext);
    AAFwk::Want result;
    callback.OnResult(0, result);
    EXPECT_TRUE(callback.isOnResult_.load());
    EXPECT_TRUE(asyncContext->releaseFlag);

    callback.OnRelease(0);
    EXPECT_TRUE(callback.isOnResult_.load());
    std::lock_guard<std::mutex> lock(RequestAsyncInstanceControl::instanceIdMutex_);
    EXPECT_EQ(RequestAsyncInstanceControl::instanceIdMap_.end(),
        RequestAsyncInstanceControl::instanceIdMap_.find(TEST_INSTANCE_ID_THIRD));
}

/**
 * @tc.name: ExecCallbackDispatchWaitingQueueTest001
 * @tc.desc: the queued waiting context is dispatched for another creation attempt
 *           after the first creation fails and releases the instance marker.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiRequestExtensionTest, ExecCallbackDispatchWaitingQueueTest001, TestSize.Level4)
{
    auto waitingContext = std::make_shared<RequestAsyncContext>(nullptr);
    waitingContext->instanceId = TEST_INSTANCE_ID_FOURTH;
    waitingContext->windowId = TEST_INVALID_WINDOW_ID;
    waitingContext->isWithWindowId = true;
    waitingContext->uiExtensionFlag = true;
    waitingContext->permissionList = { "ohos.permission.CAMERA" };
    waitingContext->needDynamicRequest = true;

    {
        std::lock_guard<std::mutex> lock(RequestAsyncInstanceControl::instanceIdMutex_);
        RequestAsyncInstanceControl::instanceIdMap_[TEST_INSTANCE_ID_FOURTH] = { waitingContext };
    }

    RequestAsyncInstanceControl::ExecCallback(TEST_INSTANCE_ID_FOURTH);

    EXPECT_FALSE(waitingContext->needDynamicRequest);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, waitingContext->result.errorCode);
    std::lock_guard<std::mutex> lock(RequestAsyncInstanceControl::instanceIdMutex_);
    EXPECT_EQ(RequestAsyncInstanceControl::instanceIdMap_.end(),
        RequestAsyncInstanceControl::instanceIdMap_.find(TEST_INSTANCE_ID_FOURTH));
}

/**
 * @tc.name: ExecCallbackDispatchWaitingQueueTest002
 * @tc.desc: the remaining queued contexts are dispatched after the popped context creation fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiRequestExtensionTest, ExecCallbackDispatchWaitingQueueTest002, TestSize.Level4)
{
    auto firstContext = std::make_shared<RequestAsyncContext>(nullptr);
    firstContext->instanceId = TEST_INSTANCE_ID_FOURTH;
    firstContext->windowId = TEST_INVALID_WINDOW_ID;
    firstContext->isWithWindowId = true;
    firstContext->uiExtensionFlag = true;
    firstContext->permissionList = { "ohos.permission.CAMERA" };
    firstContext->needDynamicRequest = true;

    auto secondContext = std::make_shared<RequestAsyncContext>(nullptr);
    secondContext->instanceId = TEST_INSTANCE_ID_FOURTH;
    secondContext->windowId = TEST_INVALID_WINDOW_ID;
    secondContext->isWithWindowId = true;
    secondContext->uiExtensionFlag = true;
    secondContext->permissionList = { "ohos.permission.CAMERA" };
    secondContext->needDynamicRequest = true;

    {
        std::lock_guard<std::mutex> lock(RequestAsyncInstanceControl::instanceIdMutex_);
        RequestAsyncInstanceControl::instanceIdMap_[TEST_INSTANCE_ID_FOURTH] = { firstContext, secondContext };
    }

    RequestAsyncInstanceControl::ExecCallback(TEST_INSTANCE_ID_FOURTH);

    EXPECT_FALSE(firstContext->needDynamicRequest);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, firstContext->result.errorCode);
    EXPECT_FALSE(secondContext->needDynamicRequest);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, secondContext->result.errorCode);
    std::lock_guard<std::mutex> lock(RequestAsyncInstanceControl::instanceIdMutex_);
    EXPECT_EQ(RequestAsyncInstanceControl::instanceIdMap_.end(),
        RequestAsyncInstanceControl::instanceIdMap_.find(TEST_INSTANCE_ID_FOURTH));
}

/**
 * @tc.name: UpdateGrantPermissionResultOnlyTest001
 * @tc.desc: UpdateGrantPermissionResultOnly validates size consistency and maps grant results.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapiRequestExtensionTest, UpdateGrantPermissionResultOnlyTest001, TestSize.Level4)
{
    auto asyncContext = std::make_shared<RequestAsyncContext>(nullptr);
    asyncContext->permissionsState = { PASS_OPER, DYNAMIC_OPER };
    asyncContext->result.errorCode = RET_SUCCESS;

    std::vector<std::string> permissions = { "perm1", "perm2" };
    std::vector<int> grantResults = { 5 };
    std::vector<int> newGrantResults;
    UpdateGrantPermissionResultOnly(permissions, grantResults, asyncContext, newGrantResults);
    EXPECT_TRUE(newGrantResults.empty());

    grantResults = { 5, 6 };
    UpdateGrantPermissionResultOnly(permissions, grantResults, asyncContext, newGrantResults);
    EXPECT_EQ(2U, newGrantResults.size());
    EXPECT_EQ(PASS_OPER, newGrantResults[0]);
    EXPECT_EQ(6, newGrantResults[1]);

    asyncContext->result.errorCode = RET_FAILED;
    newGrantResults.clear();
    UpdateGrantPermissionResultOnly(permissions, grantResults, asyncContext, newGrantResults);
    EXPECT_EQ(2U, newGrantResults.size());
    EXPECT_EQ(INVALID_OPER, newGrantResults[1]);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
