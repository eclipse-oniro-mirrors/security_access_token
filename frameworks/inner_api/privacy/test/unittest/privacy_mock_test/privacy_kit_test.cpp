/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "privacy_kit_test.h"
#include <thread>

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "on_permission_used_record_callback_stub.h"
#include "parameter.h"
#include "privacy_error.h"
#include "privacy_kit.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Security {
namespace AccessToken {

void PrivacyKitTest::SetUpTestCase()
{
}

void PrivacyKitTest::TearDownTestCase()
{
}

void PrivacyKitTest::SetUp()
{
}

void PrivacyKitTest::TearDown()
{
}

/**
 * @tc.name: AddPermissionUsedRecord001
 * @tc.desc: AddPermissionUsedRecord with proxy is null.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX3 issueI5RWX8
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord001, TestSize.Level1)
{
    AccessTokenID tokenId = 0xff;
    std::string permissionName = "ohos.permission.CAMERA";
    int32_t successCount = 1;
    int32_t failCount = 0;
    int32_t ret = PrivacyKit::AddPermissionUsedRecord(tokenId, permissionName, successCount, failCount);
    ASSERT_EQ(PrivacyError::ERR_SERVICE_ABNORMAL, ret);
}

/**
 * @tc.name: StartUsingPermission001
 * @tc.desc: StartUsingPermission proxy is null.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX3 issueI5RWX8
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission001, TestSize.Level1)
{
    AccessTokenID tokenId = 0xff;
    std::string permissionName = "ohos.permission.CAMERA";
    int32_t ret = PrivacyKit::StartUsingPermission(tokenId, permissionName);
    ASSERT_EQ(PrivacyError::ERR_SERVICE_ABNORMAL, ret);
}

class CbCustomizeTest4 : public StateCustomizedCbk {
public:
    CbCustomizeTest4()
    {}

    ~CbCustomizeTest4()
    {}

    virtual void StateChangeNotify(AccessTokenID tokenId, bool isShow)
    {}
};

/**
 * @tc.name: StartUsingPermission002
 * @tc.desc: Verify the StartUsingPermission abnormal branch return nullptr proxy.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX5 issueI5RWX3 issueI5RWXA
 */
HWTEST_F(PrivacyKitTest, StartUsingPermission002, TestSize.Level1)
{
    auto callbackPtr = std::make_shared<CbCustomizeTest4>();
    AccessTokenID g_TokenId_A = 0xff;
    std::string permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(PrivacyError::ERR_SERVICE_ABNORMAL,
        PrivacyKit::StartUsingPermission(g_TokenId_A, permissionName, callbackPtr));
}

/**
 * @tc.name: StopUsingPermission001
 * @tc.desc: StopUsingPermission proxy is null.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX3 issueI5RWX8
 */
HWTEST_F(PrivacyKitTest, StopUsingPermission001, TestSize.Level1)
{
    AccessTokenID tokenId = 0xff;
    std::string permissionName = "ohos.permission.CAMERA";
    int32_t ret = PrivacyKit::StopUsingPermission(tokenId, permissionName);
    ASSERT_EQ(PrivacyError::ERR_SERVICE_ABNORMAL, ret);
}

/**
 * @tc.name: RemovePermissionUsedRecords001
 * @tc.desc: RemovePermissionUsedRecords proxy is null.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX3 issueI5RWX8
 */
HWTEST_F(PrivacyKitTest, RemovePermissionUsedRecords001, TestSize.Level1)
{
    AccessTokenID tokenId = 0xff;
    std::string device = "device";
    int32_t ret = PrivacyKit::RemovePermissionUsedRecords(tokenId, device);
    ASSERT_EQ(PrivacyError::ERR_SERVICE_ABNORMAL, ret);
}

/**
 * @tc.name: GetPermissionUsedRecords001
 * @tc.desc: GetPermissionUsedRecords proxy is null.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX3 issueI5RWX8
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecords001, TestSize.Level1)
{
    PermissionUsedRequest request;
    PermissionUsedResult result;
    int32_t ret = PrivacyKit::GetPermissionUsedRecords(request, result);
    ASSERT_EQ(PrivacyError::ERR_SERVICE_ABNORMAL, ret);
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
 * @tc.name: GetPermissionUsedRecordsAsync001
 * @tc.desc: GetPermissionUsedRecords proxy is null.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX3 issueI5RWX8
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecordsAsync001, TestSize.Level1)
{
    PermissionUsedRequest request;
    OHOS::sptr<TestCallBack> callback(new TestCallBack());
    int32_t ret = PrivacyKit::GetPermissionUsedRecords(request, callback);
    ASSERT_EQ(PrivacyError::ERR_SERVICE_ABNORMAL, ret);
}

class PermActiveStatusCallbackTest : public PermActiveStatusCustomizedCbk {
public:
    explicit PermActiveStatusCallbackTest(const std::vector<std::string> &permList)
        : PermActiveStatusCustomizedCbk(permList)
    {
        GTEST_LOG_(INFO) << "PermActiveStatusCallbackTest create";
    }

    ~PermActiveStatusCallbackTest()
    {}

    virtual void ActiveStatusChangeCallback(ActiveChangeResponse& result)
    {
    }
};

/**
 * @tc.name: RegisterPermActiveStatusCallback001
 * @tc.desc: RegisterPermActiveStatusCallback proxy is null.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX3 issueI5RWX8
 */
HWTEST_F(PrivacyKitTest, RegisterPermActiveStatusCallback001, TestSize.Level1)
{
    std::vector<std::string> permList = {"ohos.permission.CAMERA"};
    auto callbackPtr = std::make_shared<PermActiveStatusCallbackTest>(permList);
    int32_t ret = PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr);
    ASSERT_EQ(PrivacyError::ERR_SERVICE_ABNORMAL, ret);

    ret = PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr);
    ASSERT_EQ(PrivacyError::ERR_SERVICE_ABNORMAL, ret);
}

/**
 * @tc.name: IsAllowedUsingPermissionTest001
 * @tc.desc: Verify the IsAllowedUsingPermission abnormal branch return nullptr proxy.
 * @tc.type: FUNC
 * @tc.require: issueI5RWX3 issueI5RWX8
 */
HWTEST_F(PrivacyKitTest, IsAllowedUsingPermissionTest001, TestSize.Level1)
{
    AccessTokenID tokenId = 0xff;
    std::string permissionName = "ohos.permission.CAMERA";
    bool ret = PrivacyKit::IsAllowedUsingPermission(tokenId, permissionName);
    ASSERT_EQ(false, ret);
}


} // namespace AccessToken
} // namespace Security
} // namespace OHOS
