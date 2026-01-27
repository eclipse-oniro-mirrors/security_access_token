/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <string>

#include <gtest/gtest.h>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "constant.h"
#include "permission_record.h"
#include "permission_used_type_info.h"
#include "permission_used_request.h"
#include "permission_used_result.h"
#define private public
#include "permission_record_manager.h"
#include "privacy_manager_service.h"
#undef private
#include "privacy_error.h"
#include "privacy_field_const.h"
#include "privacy_kit.h"
#include "privacy_test_common.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t PID = -1;
static constexpr int32_t CALLER_PID = 11;
static constexpr int32_t NATIVE_TOKEN_WITH_PERM = 672000001;
static constexpr int32_t NATIVE_TOKEN_WITHOUT_PERM = 671999999;
static AccessTokenID g_selfTokenId = 0;
static AccessTokenID g_shellToken = 0;
static MockNativeToken* g_mock = nullptr;
static const char* INVALID_PERMISSION_NAME = "ohos.permission.ACTIVITY_MOTION";
constexpr const char* CAMERA_PERMISSION_NAME = "ohos.permission.CAMERA";
constexpr const char* MICROPHONE_PERMISSION_NAME = "ohos.permission.MICROPHONE";
}
class PermissionRecordManagerMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void PermissionRecordManagerMockTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    PrivacyTestCommon::SetTestEvironment(g_selfTokenId);
    g_mock = new (std::nothrow) MockNativeToken("privacy_service");

    PermissionRecordManager::GetInstance().Init();

    g_shellToken = PrivacyTestCommon::GetNativeTokenIdFromProcess("hdcd");
}

void PermissionRecordManagerMockTest::TearDownTestCase()
{
    PrivacyTestCommon::ResetTestEvironment();
    if (g_mock != nullptr) {
        delete g_mock;
        g_mock = nullptr;
    }
}

void PermissionRecordManagerMockTest::SetUp()
{
    PermissionRecordManager::GetInstance().Init();
    PermissionRecordManager::GetInstance().Register();
}

void PermissionRecordManagerMockTest::TearDown()
{
}

static PermissionUsedTypeInfo MakeInfo(AccessTokenID tokenId, int32_t pid, const std::string& permission,
    PermissionUsedType type = PermissionUsedType::NORMAL_TYPE)
{
    PermissionUsedTypeInfo info = {
        .tokenId = tokenId,
        .pid = pid,
        .permissionName = permission,
        .type = type
    };
    return info;
}

/*
 * @tc.name: AddPermissionUsedRecordMockTest001
 * @tc.desc: PermissionRecordManager::AddPermissionUsedRecord function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerMockTest, AddPermissionUsedRecordMockTest001, TestSize.Level0)
{
    AddPermParamInfo info;
    info.tokenId = NATIVE_TOKEN_WITH_PERM;
    info.permissionName = INVALID_PERMISSION_NAME;
    info.successCount = 1;
    info.failCount = 0;
    info.type = NORMAL_TYPE;

    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().AddPermissionUsedRecord(info));

    info.permissionName = MICROPHONE_PERMISSION_NAME;
    EXPECT_EQ(Constant::SUCCESS, PermissionRecordManager::GetInstance().AddPermissionUsedRecord(info));

    PermissionUsedRequest request;
    request.tokenId = NATIVE_TOKEN_WITH_PERM;
    PermissionUsedResult result;
    
    EXPECT_EQ(Constant::SUCCESS, PermissionRecordManager::GetInstance().GetPermissionUsedRecords(request, result));

    EXPECT_EQ(result.bundleRecords.size(), 0);

    info.tokenId = NATIVE_TOKEN_WITHOUT_PERM;
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().AddPermissionUsedRecord(info));

    info.permissionName = CAMERA_PERMISSION_NAME;
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().AddPermissionUsedRecord(info));

    info.tokenId = NATIVE_TOKEN_WITH_PERM;
    EXPECT_EQ(Constant::SUCCESS, PermissionRecordManager::GetInstance().AddPermissionUsedRecord(info));

    request.tokenId = NATIVE_TOKEN_WITH_PERM;
    EXPECT_EQ(Constant::SUCCESS, PermissionRecordManager::GetInstance().GetPermissionUsedRecords(request, result));

    EXPECT_EQ(result.bundleRecords.size(), 0);

    info.tokenId = g_shellToken;
    EXPECT_EQ(PrivacyError::ERR_TOKENID_NOT_EXIST,
        PermissionRecordManager::GetInstance().AddPermissionUsedRecord(info));
}

/*
 * @tc.name: StartUsingPermissionMockTest001
 * @tc.desc: StartUsingPermission function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerMockTest, StartUsingPermissionMockTest001, TestSize.Level0)
{
    std::string permissionName = INVALID_PERMISSION_NAME;
    AccessTokenID tokenId = NATIVE_TOKEN_WITH_PERM;

    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, PID, permissionName), CALLER_PID));

    permissionName = MICROPHONE_PERMISSION_NAME;
    EXPECT_EQ(Constant::SUCCESS, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, PID, permissionName), CALLER_PID));

    tokenId = NATIVE_TOKEN_WITHOUT_PERM;
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, PID, permissionName), CALLER_PID));

    permissionName = CAMERA_PERMISSION_NAME;
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, PID, permissionName), CALLER_PID));

    tokenId = NATIVE_TOKEN_WITH_PERM;
    EXPECT_EQ(Constant::SUCCESS, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, PID, permissionName), CALLER_PID));

    tokenId = g_shellToken;
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, PID, permissionName), CALLER_PID));
}

/*
 * @tc.name: StartUsingPermissionMockTest002
 * @tc.desc: StartUsingPermission function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerMockTest, StartUsingPermissionMockTest002, TestSize.Level0)
{
    std::string permissionName = INVALID_PERMISSION_NAME;
    AccessTokenID tokenId = NATIVE_TOKEN_WITH_PERM;

    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, PID, permissionName), nullptr, CALLER_PID));

    permissionName = MICROPHONE_PERMISSION_NAME;
    EXPECT_EQ(Constant::SUCCESS, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, PID, permissionName), nullptr, CALLER_PID));

    tokenId = NATIVE_TOKEN_WITHOUT_PERM;
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, PID, permissionName), nullptr, CALLER_PID));

    permissionName = CAMERA_PERMISSION_NAME;
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, PID, permissionName), nullptr, CALLER_PID));

    tokenId = NATIVE_TOKEN_WITH_PERM;
    EXPECT_EQ(Constant::SUCCESS, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, PID, permissionName), nullptr, CALLER_PID));

    tokenId = g_shellToken;
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().StartUsingPermission(
        MakeInfo(tokenId, PID, permissionName), nullptr, CALLER_PID));
}

/*
 * @tc.name: StopUsingPermissionMockTest001
 * @tc.desc: PermissionRecordManager::StopUsingPermission function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerMockTest, StopUsingPermissionMockTest001, TestSize.Level0)
{
    std::string permissionName = INVALID_PERMISSION_NAME;
    AccessTokenID tokenId = NATIVE_TOKEN_WITH_PERM;

    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().StopUsingPermission(
        tokenId, PID, permissionName, CALLER_PID));

    permissionName = MICROPHONE_PERMISSION_NAME;
    EXPECT_EQ(Constant::SUCCESS, PermissionRecordManager::GetInstance().StopUsingPermission(
        tokenId, PID, permissionName, CALLER_PID));

    tokenId = NATIVE_TOKEN_WITHOUT_PERM;
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().StopUsingPermission(
        tokenId, PID, permissionName, CALLER_PID));

    permissionName = CAMERA_PERMISSION_NAME;
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().StopUsingPermission(
        tokenId, PID, permissionName, CALLER_PID));

    tokenId = NATIVE_TOKEN_WITH_PERM;
    EXPECT_EQ(Constant::SUCCESS, PermissionRecordManager::GetInstance().StopUsingPermission(
        tokenId, PID, permissionName, CALLER_PID));

    tokenId = g_shellToken;
    EXPECT_EQ(PrivacyError::ERR_PARAM_INVALID, PermissionRecordManager::GetInstance().StopUsingPermission(
        tokenId, PID, permissionName, CALLER_PID));
}

/*
 * @tc.name: IsAllowedUsingPermissionMockTest001
 * @tc.desc: PermissionRecordManager::StopUsingPermission function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerMockTest, IsAllowedUsingPermissionMockTest001, TestSize.Level0)
{
    std::string permissionName = INVALID_PERMISSION_NAME;
    AccessTokenID tokenId = NATIVE_TOKEN_WITH_PERM;

    EXPECT_EQ(false, PermissionRecordManager::GetInstance().IsAllowedUsingPermission(tokenId, permissionName, PID));

    permissionName = MICROPHONE_PERMISSION_NAME;
    EXPECT_EQ(true, PermissionRecordManager::GetInstance().IsAllowedUsingPermission(tokenId, permissionName, PID));

    tokenId = NATIVE_TOKEN_WITHOUT_PERM;
    EXPECT_EQ(false, PermissionRecordManager::GetInstance().IsAllowedUsingPermission(tokenId, permissionName, PID));

    permissionName = CAMERA_PERMISSION_NAME;
    EXPECT_EQ(false, PermissionRecordManager::GetInstance().IsAllowedUsingPermission(tokenId, permissionName, PID));

    tokenId = NATIVE_TOKEN_WITH_PERM;
    EXPECT_EQ(true, PermissionRecordManager::GetInstance().IsAllowedUsingPermission(tokenId, permissionName, PID));

    tokenId = g_shellToken;
    EXPECT_EQ(false, PermissionRecordManager::GetInstance().IsAllowedUsingPermission(tokenId, permissionName, PID));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS