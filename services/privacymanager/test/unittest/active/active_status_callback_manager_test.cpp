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

class PermActiveStatusCountCallbackTest : public PermActiveStatusChangeCallbackStub {
public:
    PermActiveStatusCountCallbackTest() = default;
    virtual ~PermActiveStatusCountCallbackTest() = default;

    void ActiveStatusChangeCallback(ActiveChangeResponse& result) override
    {
        ++count_;
        type_ = result.type;
    }

    int32_t count_ = 0;
    ActiveChangeType type_ = PERM_INACTIVE;
};

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

    int32_t ret = ActiveStatusCallbackManager::GetInstance().AddCallback(
        GetSelfTokenID(), permList, callback, static_cast<int32_t>(CallbackRegisterType::TOKEN_ONLY));
    EXPECT_EQ(ret, ERR_PARAM_INVALID);

    wptr<IRemoteObject> remote = new (std::nothrow) PermActiveStatusChangeCallbackTest();
    callback = remote.promote();
    ret = ActiveStatusCallbackManager::GetInstance().AddCallback(
        GetSelfTokenID(), permList, callback, static_cast<int32_t>(CallbackRegisterType::TOKEN_ONLY));
    EXPECT_EQ(ret, RET_SUCCESS);

    g_isAddSucc = false;
    ret = ActiveStatusCallbackManager::GetInstance().AddCallback(
        GetSelfTokenID(), permList, callback, static_cast<int32_t>(CallbackRegisterType::TOKEN_ONLY));
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
    int32_t ret = ActiveStatusCallbackManager::GetInstance().AddCallback(
        GetSelfTokenID(), permList, callback, static_cast<int32_t>(CallbackRegisterType::TOKEN_ONLY));
    EXPECT_EQ(ret, RET_SUCCESS);

    // recovery
    ActiveStatusCallbackManager::GetInstance().callbackDataList_ = callbackDataList;
}

/*
 * @tc.name: AddCallback003
 * @tc.desc: AddCallback stores ALL register type correctly.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ActiveStatusCallbackManagerTest, AddCallback003, TestSize.Level0)
{
    std::vector<CallbackData> callbackDataList = ActiveStatusCallbackManager::GetInstance().callbackDataList_;
    ActiveStatusCallbackManager::GetInstance().callbackDataList_.clear();

    sptr<IRemoteObject> callback;
    std::vector<std::string> permList;
    permList.emplace_back("ohos.permission.CAMERA");

    wptr<IRemoteObject> remote = new (std::nothrow) PermActiveStatusChangeCallbackTest1();
    callback = remote.promote();
    int32_t ret = ActiveStatusCallbackManager::GetInstance().AddCallback(
        GetSelfTokenID(), permList, callback, static_cast<int32_t>(CallbackRegisterType::ALL));
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(1, ActiveStatusCallbackManager::GetInstance().callbackDataList_.size());
    EXPECT_EQ(static_cast<int32_t>(CallbackRegisterType::ALL),
        ActiveStatusCallbackManager::GetInstance().callbackDataList_[0].registerType_);

    ActiveStatusCallbackManager::GetInstance().callbackDataList_ = callbackDataList;
}

/*
 * @tc.name: ActiveStatusChangeByRegisterType001
 * @tc.desc: Verify TOKEN_ONLY only receives token events and ALL receives supported source events.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ActiveStatusCallbackManagerTest, ActiveStatusChangeByRegisterType001, TestSize.Level0)
{
    std::vector<CallbackData> callbackDataList = ActiveStatusCallbackManager::GetInstance().callbackDataList_;
    ActiveStatusCallbackManager::GetInstance().callbackDataList_.clear();

    std::vector<std::string> permList = {"ohos.permission.CAMERA"};
    sptr<PermActiveStatusCountCallbackTest> tokenCallback = new (std::nothrow) PermActiveStatusCountCallbackTest();
    sptr<PermActiveStatusCountCallbackTest> allCallback = new (std::nothrow) PermActiveStatusCountCallbackTest();
    ASSERT_NE(nullptr, tokenCallback);
    ASSERT_NE(nullptr, allCallback);

    auto& manager = ActiveStatusCallbackManager::GetInstance();
    ASSERT_EQ(RET_SUCCESS, manager.AddCallback(
        GetSelfTokenID(), permList, tokenCallback->AsObject(),
        static_cast<int32_t>(CallbackRegisterType::TOKEN_ONLY)));
    ASSERT_EQ(RET_SUCCESS, manager.AddCallback(
        GetSelfTokenID(), permList, allCallback->AsObject(),
        static_cast<int32_t>(CallbackRegisterType::ALL)));

    ActiveChangeResponse info;
    info.permissionName = "ohos.permission.CAMERA";
    info.type = PERM_ACTIVE_IN_FOREGROUND;

    manager.ActiveStatusChange(info, CallbackRegisterType::TOKEN_ONLY);
    EXPECT_EQ(1, tokenCallback->count_);
    EXPECT_EQ(1, allCallback->count_);

#ifdef PRIVACY_BUNDLE_START_STOP_ENABLE
    // Bundle-level active status changes are dispatched with the ALL source type.
    manager.ActiveStatusChange(info, CallbackRegisterType::ALL);
    EXPECT_EQ(1, tokenCallback->count_);
    EXPECT_EQ(2, allCallback->count_);
#endif

    ActiveStatusCallbackManager::GetInstance().callbackDataList_ = callbackDataList;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
