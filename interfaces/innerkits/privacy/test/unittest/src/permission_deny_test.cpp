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

#include "permission_deny_test.h"
#include "accesstoken_kit.h"
#include "on_permission_used_record_callback_stub.h"
#include "privacy_kit.h"
#include "privacy_error.h"
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
}

void PermDenyTest::TearDownTestCase()
{
}

void PermDenyTest::SetUp()
{
    AccessTokenIDEx tokenIDEx = AccessTokenKit::AllocHapToken(g_InfoParms, g_PolicyPrams);

    g_FullTokenId = tokenIDEx.tokenIDEx;
    g_testTokenId = tokenIDEx.tokenIdExStruct.tokenID;
    EXPECT_EQ(0, SetSelfTokenID(g_FullTokenId));
}

void PermDenyTest::TearDown()
{
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    AccessTokenKit::DeleteToken(g_testTokenId);
    PrivacyKit::RemovePermissionUsedRecords(g_testTokenId, "");
}

/**
 * @tc.name: AddPermissionUsedRecord001
 * @tc.desc: Test AddPermissionUsedRecord with no permssion.
 * @tc.type: FUNC
 * @tc.require: issueI5SRUO
 */
HWTEST_F(PermDenyTest, AddPermissionUsedRecord001, TestSize.Level1)
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
HWTEST_F(PermDenyTest, RemovePermissionUsedRecords001, TestSize.Level1)
{
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED, PrivacyKit::RemovePermissionUsedRecords(g_testTokenId, ""));
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
HWTEST_F(PermDenyTest, StarAndStoptUsingPermission001, TestSize.Level1)
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
HWTEST_F(PermDenyTest, GetPermissionUsedRecords001, TestSize.Level1)
{
    PermissionUsedRequest request;
    request.tokenId = g_testTokenId;
    PermissionUsedResult result;
    ASSERT_EQ(PrivacyError::ERR_PERMISSION_DENIED, PrivacyKit::GetPermissionUsedRecords(request, result));

    OHOS::sptr<TestCallBack> callback(new TestCallBack());
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
HWTEST_F(PermDenyTest, RegisterAndUnregister001, TestSize.Level1)
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
HWTEST_F(PermDenyTest, IsAllowedUsingPermission001, TestSize.Level1)
{
    ASSERT_EQ(false, PrivacyKit::IsAllowedUsingPermission(123, "ohos.permission.CAMERA"));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

