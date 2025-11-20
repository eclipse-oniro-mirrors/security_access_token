/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "permission_deny_test.h"
#include "accesstoken_kit.h"
#include "on_permission_used_record_callback_stub.h"
#include "privacy_kit.h"
#include "privacy_error.h"
#include "privacy_test_common.h"
#include "token_setproc.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static uint32_t g_selfTokenId = 0;
static uint64_t g_FullTokenId = 0;
static uint32_t g_testTokenId = 0;
static HapPolicyParams g_PolicyPrams = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
};

static HapInfoParams g_InfoParms = {
    .userID = 1,
    .bundleName = "ohos.privacy_test.bundle",
    .instIndex = 0,
    .appIDDesc = "privacy_test.bundle",
    .isSystemApp = true
};
}
using namespace testing::ext;

void PermDenyTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    PrivacyTestCommon::SetTestEvironment(g_selfTokenId);
}

void PermDenyTest::TearDownTestCase()
{
    PrivacyTestCommon::ResetTestEvironment();
}

void PermDenyTest::SetUp()
{
    AccessTokenIDEx tokenIDEx = PrivacyTestCommon::AllocTestHapToken(g_InfoParms, g_PolicyPrams);

    g_FullTokenId = tokenIDEx.tokenIDEx;
    g_testTokenId = tokenIDEx.tokenIdExStruct.tokenID;
    EXPECT_EQ(0, SetSelfTokenID(g_FullTokenId));
}

void PermDenyTest::TearDown()
{
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    PrivacyTestCommon::DeleteTestHapToken(g_testTokenId);
    {
        std::vector<std::string> reqPerm;
        reqPerm.emplace_back("ohos.permission.PERMISSION_USED_STATS");
        MockHapToken mock("PermDenyTest", reqPerm, true);
        PrivacyKit::RemovePermissionUsedRecords(g_testTokenId);
    }
}

/**
 * @tc.name: AddPermissionUsedRecord001
 * @tc.desc: Test AddPermissionUsedRecord with no permssion.
 * @tc.type: FUNC
 * @tc.require: issueI5SRUO
 */
HWTEST_F(PermDenyTest, AddPermissionUsedRecord001, TestSize.Level0)
{
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED,
        PrivacyKit::AddPermissionUsedRecord(g_testTokenId, "ohos.permission.CAMERA", 1, 0));
}

/**
 * @tc.name: RemovePermissionUsedRecords001
 * @tc.desc: Test RemovePermissionUsedRecords with no permssion.
 * @tc.type: FUNC
 * @tc.require: issueI5SRUO
 */
HWTEST_F(PermDenyTest, RemovePermissionUsedRecords001, TestSize.Level0)
{
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED, PrivacyKit::RemovePermissionUsedRecords(g_testTokenId));
}

class CbPermDenyTest : public StateCustomizedCbk {
public:
    CbPermDenyTest()
    {}

    ~CbPermDenyTest()
    {}

    virtual void StateChangeNotify(AccessTokenID tokenId, bool isShow)
    {}
};

/**
* @tc.name: StarAndStoptUsingPermission001
* @tc.desc: Test StartUsingPermission/StopUsingPermission with no permssion.
* @tc.type: FUNC
* @tc.require: issueI5SRUO
*/
HWTEST_F(PermDenyTest, StarAndStoptUsingPermission001, TestSize.Level0)
{
    auto callbackPtr = std::make_shared<CbPermDenyTest>();
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED,
        PrivacyKit::StartUsingPermission(g_testTokenId, "ohos.permission.CAMERA", callbackPtr));
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED,
        PrivacyKit::StartUsingPermission(g_testTokenId, "ohos.permission.CAMERA"));
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED,
        PrivacyKit::StopUsingPermission(g_testTokenId, "ohos.permission.CAMERA"));
}

class TestCallBack : public OnPermissionUsedRecordCallbackStub {
public:
    TestCallBack() = default;
    virtual ~TestCallBack() = default;

    void OnQueried(ErrCode code, PermissionUsedResult& result)
    {
        GTEST_LOG_(INFO) << "TestCallBack, code :" << code << ", bundleSize :" << result.bundleRecords.size();
    }
};

/**
 * @tc.name: GetPermissionUsedRecords001
 * @tc.desc: Test GetPermissionUsedRecords with no permssion.
 * @tc.type: FUNC
 * @tc.require: issueI5SRUO
 */
HWTEST_F(PermDenyTest, GetPermissionUsedRecords001, TestSize.Level0)
{
    PermissionUsedRequest request;
    request.tokenId = g_testTokenId;
    PermissionUsedResult result;
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED, PrivacyKit::GetPermissionUsedRecords(request, result));

    OHOS::sptr<TestCallBack> callback(new (std::nothrow) TestCallBack());
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED, PrivacyKit::GetPermissionUsedRecords(request, callback));
}

class CbCustomizeTest : public PermActiveStatusCustomizedCbk {
public:
    explicit CbCustomizeTest(const std::vector<std::string> &permList)
        : PermActiveStatusCustomizedCbk(permList)
    {
        GTEST_LOG_(INFO) << "CbCustomizeTest2 create";
    }

    ~CbCustomizeTest() {}

    virtual void ActiveStatusChangeCallback(ActiveChangeResponse& result)
    {
        GTEST_LOG_(INFO) << "tokenid: " << result.tokenID <<
            ", permissionName: " << result.permissionName <<
            ", deviceId " << result.deviceId << ", type " << result.type;
    }
};

/**
* @tc.name: RegisterAndUnregister001
* @tc.desc: Test RegisterPermActiveStatusCallback/UnRegisterPermActiveStatusCallback with no permssion.
* @tc.type: FUNC
* @tc.require: issueI5SRUO
*/
HWTEST_F(PermDenyTest, RegisterAndUnregister001, TestSize.Level0)
{
    std::vector<std::string> permList = {"ohos.permission.CAMERA"};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(permList);

    // register success with no permission
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr));

    // register success with permission
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    ASSERT_EQ(NO_ERROR, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr));

    // unregister fail with no permission
    EXPECT_EQ(0, SetSelfTokenID(g_FullTokenId));
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr));

    // unregister success with permission
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    ASSERT_EQ(NO_ERROR, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr));
}

/**
* @tc.name: IsAllowedUsingPermission001
* @tc.desc: Test IsAllowedUsingPermission with no permssion.
* @tc.type: FUNC
* @tc.require: issueI5SRUO
*/
HWTEST_F(PermDenyTest, IsAllowedUsingPermission001, TestSize.Level0)
{
    ASSERT_EQ(false, PrivacyKit::IsAllowedUsingPermission(123, "ohos.permission.CAMERA")); // 123: tokenId
}

/**
* @tc.name: SetPermissionUsedRecordToggleStatus001
* @tc.desc: Test SetPermissionUsedRecordToggleStatus with no permssion.
* @tc.type: FUNC
* @tc.require: issueI5SRUO
*/
HWTEST_F(PermDenyTest, SetPermissionUsedRecordToggleStatus001, TestSize.Level0)
{
    int32_t userId = 100; // 100: userId
    bool status = false;
    uint32_t selfUid = getuid();
    setuid(123); // 123: uid
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED,
        PrivacyKit::SetPermissionUsedRecordToggleStatus(userId, true));
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED,
        PrivacyKit::GetPermissionUsedRecordToggleStatus(100, status)); // 100: userId
    ASSERT_FALSE(status);
    setuid(selfUid);
}

/**
* @tc.name: SetMutePolicy001
* @tc.desc: Test SetMutePolicy with no permssion.
* @tc.type: FUNC
* @tc.require: issueI5SRUO
*/
HWTEST_F(PermDenyTest, SetMutePolicy001, TestSize.Level0)
{
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_DENIED,
        PrivacyKit::SetMutePolicy(PolicyType::EDM, CallerType::MICROPHONE, true, 123)); // 123: tokenId
}

/**
* @tc.name: SetHapWithFGReminder001
* @tc.desc: Test SetHapWithFGReminder with no permssion.
* @tc.type: FUNC
* @tc.require: issueI5SRUO
*/
HWTEST_F(PermDenyTest, SetHapWithFGReminder001, TestSize.Level0)
{
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED, PrivacyKit::SetHapWithFGReminder(123, true)); // 123: tokenId
}

/**
* @tc.name: GetPermissionUsedTypeInfos001
* @tc.desc: Test GetPermissionUsedTypeInfos with no permssion.
* @tc.type: FUNC
* @tc.require: issueI5SRUO
*/
HWTEST_F(PermDenyTest, GetPermissionUsedTypeInfos001, TestSize.Level0)
{
    std::vector<PermissionUsedTypeInfo> results;
    AccessTokenID tokenId = 0xff;
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_DENIED,
        PrivacyKit::GetPermissionUsedTypeInfos(tokenId, "ohos.permission.CAMERA", results));
}

/**
* @tc.name: SetDisablePolicy001
* @tc.desc: Test SetDisablePolicy with no permssion.
* @tc.type: FUNC
* @tc.require: issueI5SRUO
*/
HWTEST_F(PermDenyTest, SetDisablePolicy001, TestSize.Level0)
{
    std::string permissionName = "ohos.permission.CAMERA";
    bool isDisable = false;
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_DENIED, PrivacyKit::SetDisablePolicy(permissionName, true));
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_DENIED, PrivacyKit::GetDisablePolicy(permissionName, isDisable));
    EXPECT_FALSE(isDisable);
}

class DisablePolicyChangeCallbackForDenyTest : public DisablePolicyChangeCallback {
public:
    explicit DisablePolicyChangeCallbackForDenyTest(const std::vector<std::string> &permList)
        : DisablePolicyChangeCallback(permList) {}

    ~DisablePolicyChangeCallbackForDenyTest() {}

    virtual void PermDisablePolicyCallback(const PermDisablePolicyInfo& info)
    {
    }
};

/**
* @tc.name: RegisterPermDisablePolicyCallback001
* @tc.desc: Test RegisterPermDisablePolicyCallback with no permssion.
* @tc.type: FUNC
* @tc.require: issueI5SRUO
*/
HWTEST_F(PermDenyTest, RegisterPermDisablePolicyCallback001, TestSize.Level0)
{
    std::vector<std::string> permList = {"ohos.permission.CAMERA"};
    auto callbackPtr = std::make_shared<DisablePolicyChangeCallbackForDenyTest>(permList);

    // register success with no permission
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED, PrivacyKit::RegisterPermDisablePolicyCallback(callbackPtr));

    // register success with permission
    {
        MockNativeToken mock("camera_service");
        EXPECT_EQ(NO_ERROR, PrivacyKit::RegisterPermDisablePolicyCallback(callbackPtr));
    }

    // unregister fail with no permission
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_DENIED, PrivacyKit::UnRegisterPermDisablePolicyCallback(callbackPtr));

    // unregister success with permission
    {
        MockNativeToken mock("camera_service");
        EXPECT_EQ(NO_ERROR, PrivacyKit::UnRegisterPermDisablePolicyCallback(callbackPtr));
    }
}

/**
* @tc.name: GetCurrUsingPermInfo001
* @tc.desc: Test GetCurrUsingPermInfo with no permission.
* @tc.type: FUNC
* @tc.require: issue2901
*/
HWTEST_F(PermDenyTest, GetCurrUsingPermInfo001, TestSize.Level0)
{
    std::vector<CurrUsingPermInfo> results;
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_DENIED, PrivacyKit::GetCurrUsingPermInfo(results));
}

/**
* @tc.name: GetCurrUsingPermInfo002
* @tc.desc: Test GetCurrUsingPermInfo with no permission.
* @tc.type: FUNC
* @tc.require: issue2901
*/
HWTEST_F(PermDenyTest, GetCurrUsingPermInfo002, TestSize.Level0)
{
    std::vector<CurrUsingPermInfo> results;
    MockNativeToken mock("token_sync_service");
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_DENIED, PrivacyKit::GetCurrUsingPermInfo(results));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

