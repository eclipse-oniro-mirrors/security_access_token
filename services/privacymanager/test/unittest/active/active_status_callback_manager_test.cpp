/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
#define private public
#include "active_status_callback_manager.h"
#undef private
#include "perm_active_status_change_callback_stub.h"
#include "privacy_error.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static bool g_isAddSucc = true;
}

class ActiveStatusCallbackManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ActiveStatusCallbackManagerTest::SetUpTestCase()
{
}

void ActiveStatusCallbackManagerTest::TearDownTestCase()
{
}

void ActiveStatusCallbackManagerTest::SetUp()
{
}

void ActiveStatusCallbackManagerTest::TearDown()
{
}

class PermActiveStatusChangeCallbackTest : public PermActiveStatusChangeCallbackStub {
public:
    PermActiveStatusChangeCallbackTest() = default;
    virtual ~PermActiveStatusChangeCallbackTest() = default;

    void ActiveStatusChangeCallback(ActiveChangeResponse& result) override;
    bool AddDeathRecipient(const sptr<IRemoteObject::DeathRecipient>& deathRecipient) override;
    bool IsProxyObject() const override
    {
        return true;
    };
};

void PermActiveStatusChangeCallbackTest::ActiveStatusChangeCallback(ActiveChangeResponse& result)
{
}

bool PermActiveStatusChangeCallbackTest::AddDeathRecipient(const sptr<IRemoteObject::DeathRecipient>& deathRecipient)
{
    return g_isAddSucc == true ? true : false;
}

class PermActiveStatusChangeCallbackTest1 : public PermActiveStatusChangeCallbackStub {
public:
    PermActiveStatusChangeCallbackTest1() = default;
    virtual ~PermActiveStatusChangeCallbackTest1() = default;

    void ActiveStatusChangeCallback(ActiveChangeResponse& result) override;
};

void PermActiveStatusChangeCallbackTest1::ActiveStatusChangeCallback(ActiveChangeResponse& result)
{
}

/*
 * @tc.name: AddCallback001
 * @tc.desc: AddCallback mock function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ActiveStatusCallbackManagerTest, AddCallback001, TestSize.Level0)
{
    // backup
    bool temp = g_isAddSucc;
    std::vector<CallbackData> callbackDataList = ActiveStatusCallbackManager::GetInstance().callbackDataList_;
    ActiveStatusCallbackManager::GetInstance().callbackDataList_.clear();

    sptr<IRemoteObject> callback;
    std::vector<std::string> permList;
    permList.emplace_back("ohos.permission.CAMERA");

    int32_t ret = ActiveStatusCallbackManager::GetInstance().AddCallback(GetSelfTokenID(), permList, callback);
    EXPECT_EQ(ret, ERR_PARAM_INVALID);

    wptr<IRemoteObject> remote = new (std::nothrow) PermActiveStatusChangeCallbackTest();
    callback = remote.promote();
    ret = ActiveStatusCallbackManager::GetInstance().AddCallback(GetSelfTokenID(), permList, callback);
    EXPECT_EQ(ret, RET_SUCCESS);

    g_isAddSucc = false;
    ret = ActiveStatusCallbackManager::GetInstance().AddCallback(GetSelfTokenID(), permList, callback);
    EXPECT_EQ(ret, ERR_ADD_DEATH_RECIPIENT_FAILED);

    // recovery
    g_isAddSucc = temp;
    ActiveStatusCallbackManager::GetInstance().callbackDataList_ = callbackDataList;
}

/*
 * @tc.name: AddCallback002
 * @tc.desc: AddCallback function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ActiveStatusCallbackManagerTest, AddCallback002, TestSize.Level0)
{
    // backup
    std::vector<CallbackData> callbackDataList = ActiveStatusCallbackManager::GetInstance().callbackDataList_;
    ActiveStatusCallbackManager::GetInstance().callbackDataList_.clear();

    sptr<IRemoteObject> callback;
    std::vector<std::string> permList;
    permList.emplace_back("ohos.permission.CAMERA");

    wptr<IRemoteObject> remote = new (std::nothrow) PermActiveStatusChangeCallbackTest1();
    callback = remote.promote();
    int32_t ret = ActiveStatusCallbackManager::GetInstance().AddCallback(GetSelfTokenID(), permList, callback);
    EXPECT_EQ(ret, RET_SUCCESS);

    // recovery
    ActiveStatusCallbackManager::GetInstance().callbackDataList_ = callbackDataList;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
