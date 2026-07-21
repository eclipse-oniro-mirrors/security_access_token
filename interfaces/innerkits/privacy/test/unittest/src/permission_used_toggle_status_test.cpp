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

#include "privacy_kit_test.h"

#include "privacy_error.h"
#include "privacy_kit.h"
#include "privacy_test_common.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t INVALID_USER_ID = -1;
static constexpr int32_t USER_ID_2 = 2;
static constexpr uid_t ROOT_UID = 0;
static constexpr uid_t USER_2_UID = 400000;
static constexpr int32_t RET_NO_ERROR = 0;
static AccessTokenID g_toggleSelfTokenId = INVALID_TOKENID;

class PermissionUsedToggleStatusTest : public PrivacyKitTest {
public:
    static void SetUpTestCase()
    {
        g_toggleSelfTokenId = GetSelfTokenID();
        PrivacyTestCommon::SetTestEvironment(g_toggleSelfTokenId);
    }

    static void TearDownTestCase()
    {
        PrivacyTestCommon::ResetTestEvironment();
        g_toggleSelfTokenId = INVALID_TOKENID;
    }

    void SetUp() override
    {
        ASSERT_NE(INVALID_TOKENID, g_toggleSelfTokenId);
    }
};

class PermissionUsedRecordGuard final {
public:
    explicit PermissionUsedRecordGuard(AccessTokenID tokenId) : tokenId_(tokenId) {}
    ~PermissionUsedRecordGuard()
    {
        (void)PrivacyKit::RemovePermissionUsedRecords(tokenId_);
    }

private:
    AccessTokenID tokenId_;
};

class PermissionUsedRecordToggleStatusGuard final {
public:
    explicit PermissionUsedRecordToggleStatusGuard(int32_t userId) : userId_(userId)
    {
        int32_t ret = PrivacyKit::GetPermissionUsedRecordToggleStatus(userId_, originalStatus_);
        hasOriginalStatus_ = (ret == RET_SUCCESS);
    }

    ~PermissionUsedRecordToggleStatusGuard()
    {
        if (hasOriginalStatus_) {
            (void)PrivacyKit::SetPermissionUsedRecordToggleStatus(userId_, originalStatus_);
        }
    }

private:
    int32_t userId_;
    bool originalStatus_ = true;
    bool hasOriginalStatus_ = false;
};
}

/**
 * @tc.name: SetPermissionUsedRecordToggleStatus001
 * @tc.desc: SetPermissionUsedRecordToggleStatus and GetPermissionUsedRecordToggleStatus with invalid userID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionUsedToggleStatusTest, SetPermissionUsedRecordToggleStatus001, TestSize.Level0)
{
    bool status = true;
    int32_t resSet = PrivacyKit::SetPermissionUsedRecordToggleStatus(INVALID_USER_ID, status);
    int32_t resGet = PrivacyKit::GetPermissionUsedRecordToggleStatus(INVALID_USER_ID, status);
    EXPECT_EQ(resSet, PrivacyError::ERR_PARAM_INVALID);
    EXPECT_EQ(resGet, PrivacyError::ERR_PARAM_INVALID);
}

/**
 * @tc.name: SetPermissionUsedRecordToggleStatus002
 * @tc.desc: SetPermissionUsedRecordToggleStatus with true status and false status.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionUsedToggleStatusTest, SetPermissionUsedRecordToggleStatus002, TestSize.Level0)
{
    const std::string testBundleName = "SetPermissionUsedRecordToggleStatus002";
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.ERR_PERMISSION_DENIED");
    reqPerm.emplace_back("ohos.permission.PERMISSION_USED_STATS");
    reqPerm.emplace_back("ohos.permission.PERMISSION_RECORD_TOGGLE");
    MockHapToken mock(testBundleName, reqPerm, true, USER_ID_2);
    uid_t originalUid = getuid();
    (void)setuid(ROOT_UID);

    int32_t permRecordSize = 0;
    bool status = true;
    AccessTokenID tokenId = static_cast<AccessTokenID>(GetSelfTokenID());
    ASSERT_NE(INVALID_TOKENID, tokenId);
    PermissionUsedRecordGuard recordGuard(tokenId);
    PermissionUsedRecordToggleStatusGuard toggleGuard(USER_ID_2);

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::SetPermissionUsedRecordToggleStatus(USER_ID_2, true));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::GetPermissionUsedRecordToggleStatus(USER_ID_2, status));
    EXPECT_TRUE(status);

    AddPermParamInfo info;
    info.tokenId = tokenId;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 1;
    info.failCount = 0;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    permRecordSize++;

    info.permissionName = "ohos.permission.WRITE_CONTACTS";
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    permRecordSize++;

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(tokenId, testBundleName, permissionList, request);

    request.flag = FLAG_PERMISSION_USAGE_DETAIL;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    EXPECT_EQ(1, static_cast<int32_t>(result.bundleRecords.size()));
    EXPECT_EQ(permRecordSize, static_cast<int32_t>(result.bundleRecords[0].permissionRecords.size()));

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::SetPermissionUsedRecordToggleStatus(USER_ID_2, false));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    EXPECT_EQ(0, static_cast<int32_t>(result.bundleRecords.size()));

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    info.permissionName = "ohos.permission.READ_CONTACTS";
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    EXPECT_EQ(0, static_cast<int32_t>(result.bundleRecords.size()));

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::SetPermissionUsedRecordToggleStatus(USER_ID_2, true));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::RemovePermissionUsedRecords(info.tokenId));
    (void)setuid(originalUid);
}

/**
 * @tc.name: SetPermissionUsedRecordToggleStatus003
 * @tc.desc: SetPermissionUsedRecordToggleStatus with false status and true status.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionUsedToggleStatusTest, SetPermissionUsedRecordToggleStatus003, TestSize.Level0)
{
    const std::string testBundleName = "SetPermissionUsedRecordToggleStatus003";
    MockHapToken mock(testBundleName,
        {"ohos.permission.PERMISSION_USED_STATS", "ohos.permission.PERMISSION_RECORD_TOGGLE"}, true, USER_ID_2);
    uid_t originalUid = getuid();
    (void)setuid(USER_2_UID);

    int32_t permRecordSize = 0;
    bool status = true;
    AccessTokenID tokenId = static_cast<AccessTokenID>(GetSelfTokenID());
    ASSERT_NE(INVALID_TOKENID, tokenId);
    PermissionUsedRecordGuard recordGuard(tokenId);
    PermissionUsedRecordToggleStatusGuard toggleGuard(USER_ID_2);

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::SetPermissionUsedRecordToggleStatus(USER_ID_2, false));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecordToggleStatus(USER_ID_2, status));
    EXPECT_FALSE(status);

    AddPermParamInfo info;
    info.tokenId = tokenId;
    info.permissionName = "ohos.permission.READ_CONTACTS";
    info.successCount = 1;
    info.failCount = 0;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    info.permissionName = "ohos.permission.WRITE_CONTACTS";
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));

    PermissionUsedRequest request;
    PermissionUsedResult result;
    std::vector<std::string> permissionList;
    BuildQueryRequest(tokenId, testBundleName, permissionList, request);
    request.flag = FLAG_PERMISSION_USAGE_DETAIL;

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    EXPECT_TRUE(result.bundleRecords.empty());

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::SetPermissionUsedRecordToggleStatus(USER_ID_2, true));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecordToggleStatus(USER_ID_2, status));
    EXPECT_TRUE(status);

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    permRecordSize++;

    info.permissionName = "ohos.permission.READ_CONTACTS";
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(info));
    permRecordSize++;

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
    EXPECT_EQ(1, static_cast<int32_t>(result.bundleRecords.size()));
    EXPECT_EQ(permRecordSize, static_cast<int32_t>(result.bundleRecords[0].permissionRecords.size()));

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::RemovePermissionUsedRecords(info.tokenId));
    (void)setuid(originalUid);
}

#ifdef ACCESS_TOKEN_SUPPORT_SUBPROFILE
static constexpr int32_t LEGACY_SUBPROFILE_ID = -1;
static constexpr int32_t INVALID_NEGATIVE_SUBPROFILE_ID = -2;
static constexpr int32_t SUBPROFILE_ID_TEN = 10;
static constexpr int32_t SUBPROFILE_ID_ELEVEN = 11;

/**
 * @tc.name: SetPermissionUsedRecordToggleStatusWithSubProfileIdConflict001
 * @tc.desc: Verify legacy privacy toggle record blocks subProfile write and subProfile query inherits legacy value.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionUsedToggleStatusTest, SetPermissionUsedRecordToggleStatusWithSubProfileIdConflict001,
    TestSize.Level0)
{
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.ERR_PERMISSION_DENIED");
    reqPerm.emplace_back("ohos.permission.PERMISSION_USED_STATS");
    reqPerm.emplace_back("ohos.permission.PERMISSION_RECORD_TOGGLE");
    MockHapToken mock("SetPermissionUsedRecordToggleStatusWithSubProfileIdConflict001", reqPerm, true);

    bool status = true;
    PermissionUsedRecordToggleStatusGuard toggleGuard(USER_ID_2);

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::SetPermissionUsedRecordToggleStatus(USER_ID_2, false, LEGACY_SUBPROFILE_ID));
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_USED_RECORD_STORAGE_MODE_CONFLICT,
        PrivacyKit::SetPermissionUsedRecordToggleStatus(USER_ID_2, true, SUBPROFILE_ID_TEN));
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_USED_RECORD_STORAGE_MODE_CONFLICT,
        PrivacyKit::SetPermissionUsedRecordToggleStatus(USER_ID_2, false, SUBPROFILE_ID_TEN));

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecordToggleStatus(USER_ID_2, status, SUBPROFILE_ID_TEN));
    EXPECT_FALSE(status);
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::SetPermissionUsedRecordToggleStatus(USER_ID_2, true, LEGACY_SUBPROFILE_ID));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::SetPermissionUsedRecordToggleStatus(USER_ID_2, false, SUBPROFILE_ID_TEN));
}

/**
 * @tc.name: SetPermissionUsedRecordToggleStatusWithSubProfileIdConflict002
 * @tc.desc: Verify subProfile privacy toggle record blocks legacy write in kit layer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionUsedToggleStatusTest, SetPermissionUsedRecordToggleStatusWithSubProfileIdConflict002,
    TestSize.Level0)
{
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.ERR_PERMISSION_DENIED");
    reqPerm.emplace_back("ohos.permission.PERMISSION_USED_STATS");
    reqPerm.emplace_back("ohos.permission.PERMISSION_RECORD_TOGGLE");
    MockHapToken mock("SetPermissionUsedRecordToggleStatusWithSubProfileIdConflict002", reqPerm, true);
    PermissionUsedRecordToggleStatusGuard toggleGuard(USER_ID_2);

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::SetPermissionUsedRecordToggleStatus(
        USER_ID_2, false, SUBPROFILE_ID_ELEVEN));
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_USED_RECORD_STORAGE_MODE_CONFLICT,
        PrivacyKit::SetPermissionUsedRecordToggleStatus(USER_ID_2, true, LEGACY_SUBPROFILE_ID));
    EXPECT_EQ(PrivacyError::ERR_PERMISSION_USED_RECORD_STORAGE_MODE_CONFLICT,
        PrivacyKit::SetPermissionUsedRecordToggleStatus(USER_ID_2, false, LEGACY_SUBPROFILE_ID));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::SetPermissionUsedRecordToggleStatus(USER_ID_2, true, SUBPROFILE_ID_ELEVEN));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::SetPermissionUsedRecordToggleStatus(USER_ID_2, false, LEGACY_SUBPROFILE_ID));
}

/**
 * @tc.name: SetPermissionUsedRecordToggleStatusWithSubProfileIdIsolation001
 * @tc.desc: Verify one subProfile privacy toggle status does not affect another subProfile.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionUsedToggleStatusTest, SetPermissionUsedRecordToggleStatusWithSubProfileIdIsolation001,
    TestSize.Level0)
{
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.ERR_PERMISSION_DENIED");
    reqPerm.emplace_back("ohos.permission.PERMISSION_USED_STATS");
    reqPerm.emplace_back("ohos.permission.PERMISSION_RECORD_TOGGLE");
    MockHapToken mock("SetPermissionUsedRecordToggleStatusWithSubProfileIdIsolation001", reqPerm, true);
    PermissionUsedRecordToggleStatusGuard toggleGuard(USER_ID_2);

    bool status = false;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::SetPermissionUsedRecordToggleStatus(
        USER_ID_2, false, SUBPROFILE_ID_TEN));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecordToggleStatus(
        USER_ID_2, status, SUBPROFILE_ID_TEN));
    EXPECT_FALSE(status);

    status = false;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecordToggleStatus(
        USER_ID_2, status, SUBPROFILE_ID_ELEVEN));
    EXPECT_TRUE(status);

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::SetPermissionUsedRecordToggleStatus(
        USER_ID_2, false, SUBPROFILE_ID_ELEVEN));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::SetPermissionUsedRecordToggleStatus(
        USER_ID_2, true, SUBPROFILE_ID_TEN));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecordToggleStatus(
        USER_ID_2, status, SUBPROFILE_ID_TEN));
    EXPECT_TRUE(status);
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecordToggleStatus(
        USER_ID_2, status, SUBPROFILE_ID_ELEVEN));
    EXPECT_FALSE(status);
}

/**
 * @tc.name: SetPermissionUsedRecordToggleStatusWithNegativeSubProfileId001
 * @tc.desc: Verify negative subProfileId keeps legacy toggle path in privacy kit layer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionUsedToggleStatusTest, SetPermissionUsedRecordToggleStatusWithNegativeSubProfileId001,
    TestSize.Level0)
{
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.ERR_PERMISSION_DENIED");
    reqPerm.emplace_back("ohos.permission.PERMISSION_USED_STATS");
    reqPerm.emplace_back("ohos.permission.PERMISSION_RECORD_TOGGLE");
    MockHapToken mock("SetPermissionUsedRecordToggleStatusWithNegativeSubProfileId001", reqPerm, true);

    bool status = false;
    PermissionUsedRecordToggleStatusGuard toggleGuard(USER_ID_2);

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::SetPermissionUsedRecordToggleStatus(USER_ID_2, false, LEGACY_SUBPROFILE_ID));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecordToggleStatus(USER_ID_2, status));
    EXPECT_FALSE(status);

    status = true;
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecordToggleStatus(
        USER_ID_2, status, INVALID_NEGATIVE_SUBPROFILE_ID));
    EXPECT_FALSE(status);

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::SetPermissionUsedRecordToggleStatus(USER_ID_2, true, LEGACY_SUBPROFILE_ID));
}
#else
static constexpr int32_t UNSUPPORTED_SUBPROFILE_ID = 10;

/**
 * @tc.name: SetPermissionUsedRecordToggleStatusWithoutSubProfileFeature001
 * @tc.desc: Verify subProfileId parameter keeps legacy record toggle path when subProfile feature is not supported.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionUsedToggleStatusTest, SetPermissionUsedRecordToggleStatusWithoutSubProfileFeature001,
    TestSize.Level0)
{
    MockHapToken mock("SetPermissionUsedRecordToggleStatusWithoutSubProfileFeature001",
        {"ohos.permission.PERMISSION_USED_STATS", "ohos.permission.PERMISSION_RECORD_TOGGLE"}, true);
    uid_t originalUid = getuid();
    (void)setuid(ROOT_UID);

    bool status = true;
    PermissionUsedRecordToggleStatusGuard toggleGuard(USER_ID_2);

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::SetPermissionUsedRecordToggleStatus(
        USER_ID_2, false, UNSUPPORTED_SUBPROFILE_ID));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecordToggleStatus(USER_ID_2, status));
    EXPECT_FALSE(status);

    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::SetPermissionUsedRecordToggleStatus(USER_ID_2, true));
    EXPECT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecordToggleStatus(
        USER_ID_2, status, UNSUPPORTED_SUBPROFILE_ID));
    EXPECT_TRUE(status);
    (void)setuid(originalUid);
}
#endif

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
