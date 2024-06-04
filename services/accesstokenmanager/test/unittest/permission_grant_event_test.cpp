/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "permission_grant_event_test.h"

#define private public
#include "permission_grant_event.h"
#undef private

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "PermissionGrantEventTest"};
}

void PermissionGrantEventTest::SetUpTestCase()
{}

void PermissionGrantEventTest::TearDownTestCase()
{
    sleep(3); // delay 3 minutes
}

void PermissionGrantEventTest::SetUp()
{}

void PermissionGrantEventTest::TearDown()
{}

/**
 * @tc.name: NotifyPermGrantStoreResult001
 * @tc.desc: test notify permssion grant event success
 * @tc.type: FUNC
 * @tc.require:issueI5OOPG
 */
HWTEST_F(PermissionGrantEventTest, NotifyPermGrantStoreResult001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "NotifyPermGrantStoreResult001!");
    AccessTokenID tokenID = 0x100000;
    std::string permissionName = "testpremission";
    uint64_t time;

    PermissionGrantEvent eventHandler;
    eventHandler.AddEvent(tokenID, permissionName, time);

    // larger than grant timestamp
    eventHandler.NotifyPermGrantStoreResult(true, time + 1);

    ASSERT_EQ(eventHandler.permGrantEventList_.size(), static_cast<uint32_t>(0));
}

/**
 * @tc.name: NotifyPermGrantStoreResult002
 * @tc.desc: test notify permssion grant event failed
 * @tc.type: FUNC
 * @tc.require:issueI5OOPG
 */
HWTEST_F(PermissionGrantEventTest, NotifyPermGrantStoreResult002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "NotifyPermGrantStoreResult002!");
    AccessTokenID tokenID = 0x100000;
    std::string permissionName = "testpremission";
    uint64_t time;

    PermissionGrantEvent eventHandler;
    eventHandler.AddEvent(tokenID, permissionName, time);

    // larger than grant timestamp
    eventHandler.NotifyPermGrantStoreResult(false, time + 1);

    ASSERT_EQ(eventHandler.permGrantEventList_.size(), static_cast<uint32_t>(0));
}

/**
 * @tc.name: NotifyPermGrantStoreResult003
 * @tc.desc: test notify permssion grant event success, but timestamp is less than add timestamp
 * @tc.type: FUNC
 * @tc.require:issueI5OOPG
 */
HWTEST_F(PermissionGrantEventTest, NotifyPermGrantStoreResult003, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "NotifyPermGrantStoreResult003!");
    AccessTokenID tokenID = 0x100000;
    std::string permissionName = "testpremission";
    uint64_t time;

    PermissionGrantEvent eventHandler;
    eventHandler.AddEvent(tokenID, permissionName, time);

    // less than grant timestamp
    eventHandler.NotifyPermGrantStoreResult(true, time - 1);

    ASSERT_EQ(eventHandler.permGrantEventList_.size(), static_cast<uint32_t>(1));
}
