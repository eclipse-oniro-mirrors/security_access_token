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

#include "access_token.h"
#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "accesstoken_info_utils.h"
#ifdef ACCESS_TOKEN_SUPPORT_SUBPROFILE
#include "account_error_no.h"
#include "os_account_manager_lite.h"
#endif
#include "ipc_skeleton.h"
#include "token_field_const.h"
#include "permission_request_toggle_manager.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t BASE_USER_RANGE = 200000;
static constexpr int32_t INVALID_USER_ID = -1;
static constexpr int32_t TEST_USER_ID = 123;
static constexpr int32_t LEGACY_SUBPROFILE_ID = -1;
static constexpr uint32_t INVALID_TOGGLE_STATUS = static_cast<uint32_t>(-2);
const std::string APP_TRACKING_CONSENT_PERMISSION = "ohos.permission.APP_TRACKING_CONSENT";
#ifdef ACCESS_TOKEN_SUPPORT_SUBPROFILE
static constexpr int32_t INVALID_NEGATIVE_SUBPROFILE_ID = -2;
static constexpr int32_t SUBPROFILE_ID_TEN = 10;
static constexpr int32_t SUBPROFILE_ID_ELEVEN = 11;
static constexpr int32_t SUBPROFILE_ID_TWELVE = 12;
static constexpr int32_t SUBPROFILE_ID_THIRTEEN = 13;
static constexpr int32_t SUBPROFILE_TEST_USER_ID_321 = 321;
static constexpr int32_t SUBPROFILE_TEST_USER_ID_324 = 324;
static constexpr int32_t ACCOUNT_OWNER_USER_ID = 0;
#endif

void DeletePermissionRequestToggleStatusRecords(int32_t userID, const std::string& permissionName)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_USER_ID, userID);
    condition.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);

    std::vector<DelInfo> delInfoVec;
    AccessTokenInfoUtils::GenerateDelInfoToVec(
        AtmDataType::ACCESSTOKEN_PERMISSION_REQUEST_TOGGLE_STATUS, condition, delInfoVec);
    (void)AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, {});
}

class PermissionRequestToggleStatusGuard final {
public:
    PermissionRequestToggleStatusGuard(int32_t userID, const std::string& permissionName)
        : userID_(userID), permissionName_(permissionName)
    {
        (void)PermissionRequestToggleManager::GetInstance().FindPermRequestToggleStatusRecordsFromDb(
            userID_, permissionName_, LEGACY_SUBPROFILE_ID, originalRecords_);
        DeletePermissionRequestToggleStatusRecords(userID_, permissionName_);
    }

    ~PermissionRequestToggleStatusGuard()
    {
        std::vector<AddInfo> addInfoVec;
        if (!originalRecords_.empty()) {
            AccessTokenInfoUtils::GenerateAddInfoToVec(
                AtmDataType::ACCESSTOKEN_PERMISSION_REQUEST_TOGGLE_STATUS, originalRecords_, addInfoVec);
        }

        GenericValues condition;
        condition.Put(TokenFiledConst::FIELD_USER_ID, userID_);
        condition.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName_);
        std::vector<DelInfo> delInfoVec;
        AccessTokenInfoUtils::GenerateDelInfoToVec(
            AtmDataType::ACCESSTOKEN_PERMISSION_REQUEST_TOGGLE_STATUS, condition, delInfoVec);
        (void)AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
    }

private:
    int32_t userID_;
    std::string permissionName_;
    std::vector<GenericValues> originalRecords_;
};

void VerifyRequestToggleStatusRecord(int32_t userID, const std::string& permissionName, int32_t subProfileId,
    uint32_t expectedStatus)
{
    std::vector<GenericValues> records;
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().FindPermRequestToggleStatusRecordsFromDb(
        userID, permissionName, subProfileId, records));
    ASSERT_EQ(1, static_cast<int32_t>(records.size()));
    EXPECT_EQ(subProfileId, records[0].GetInt(TokenFiledConst::FIELD_SUB_PROFILE_ID));
    EXPECT_EQ(expectedStatus, static_cast<uint32_t>(records[0].GetInt(TokenFiledConst::FIELD_REQUEST_TOGGLE_STATUS)));
}

void VerifyRequestToggleStatusRecordNotExist(int32_t userID, const std::string& permissionName, int32_t subProfileId)
{
    std::vector<GenericValues> records;
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().FindPermRequestToggleStatusRecordsFromDb(
        userID, permissionName, subProfileId, records));
    EXPECT_TRUE(records.empty());
}

}

class PermissionRequestToggleManagerTest : public testing::Test {};

/**
 * @tc.name: SetPermissionRequestToggleStatus001
 * @tc.desc: Verify that invalid request toggle parameters are rejected.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRequestToggleManagerTest, SetPermissionRequestToggleStatus001, TestSize.Level0)
{
    int32_t userID = INVALID_USER_ID;
    uint32_t status = PermissionRequestToggleStatus::CLOSED;
    std::string permissionName = "ohos.permission.CAMERA";

    ASSERT_EQ(ERR_PARAM_INVALID, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, status, userID, LEGACY_SUBPROFILE_ID));

    userID = TEST_USER_ID;
    ASSERT_EQ(ERR_PARAM_INVALID, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        "", status, userID, LEGACY_SUBPROFILE_ID));

    permissionName = "ohos.permission.invalid";
    ASSERT_EQ(ERR_PERMISSION_NOT_EXIST, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, status, userID, LEGACY_SUBPROFILE_ID));

    permissionName = "ohos.permission.USE_BLUETOOTH";
    ASSERT_EQ(ERR_PARAM_INVALID, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, status, userID, LEGACY_SUBPROFILE_ID));

    status = INVALID_TOGGLE_STATUS;
    permissionName = "ohos.permission.CAMERA";
    ASSERT_EQ(ERR_PARAM_INVALID, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, status, userID, LEGACY_SUBPROFILE_ID));
}

/**
 * @tc.name: SetPermissionRequestToggleStatus002
 * @tc.desc: Verify that legacy request toggle status can be updated.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRequestToggleManagerTest, SetPermissionRequestToggleStatus002, TestSize.Level0)
{
    int32_t userID = TEST_USER_ID;
    uint32_t status = PermissionRequestToggleStatus::CLOSED;
    std::string permissionName = "ohos.permission.CAMERA";
    PermissionRequestToggleStatusGuard guard(userID, permissionName);

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, status, userID, LEGACY_SUBPROFILE_ID));

    status = PermissionRequestToggleStatus::OPEN;
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, status, userID, LEGACY_SUBPROFILE_ID));
}

/**
 * @tc.name: SetPermissionRequestToggleStatus003
 * @tc.desc: Verify that user ID zero resolves to the calling user's request toggle status.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRequestToggleManagerTest, SetPermissionRequestToggleStatus003, TestSize.Level0)
{
    const int32_t resolvedUser = IPCSkeleton::GetCallingUid() / BASE_USER_RANGE;
    uint32_t status = PermissionRequestToggleStatus::CLOSED;
    std::string permissionName = "ohos.permission.CAMERA";
    uint32_t getStatus = PermissionRequestToggleStatus::OPEN;
    PermissionRequestToggleStatusGuard guard(resolvedUser, permissionName);

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, status, 0, LEGACY_SUBPROFILE_ID));
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        permissionName, getStatus, resolvedUser, LEGACY_SUBPROFILE_ID));
    ASSERT_EQ(status, getStatus);

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, PermissionRequestToggleStatus::OPEN, resolvedUser, LEGACY_SUBPROFILE_ID));
}

/**
 * @tc.name: GetPermissionRequestToggleStatus001
 * @tc.desc: Verify that invalid request toggle query parameters are rejected.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRequestToggleManagerTest, GetPermissionRequestToggleStatus001, TestSize.Level0)
{
    int32_t userID = INVALID_USER_ID;
    uint32_t status;
    std::string permissionName = "ohos.permission.CAMERA";

    ASSERT_EQ(ERR_PARAM_INVALID, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        permissionName, status, userID, LEGACY_SUBPROFILE_ID));

    userID = TEST_USER_ID;
    ASSERT_EQ(ERR_PARAM_INVALID, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        "", status, userID, LEGACY_SUBPROFILE_ID));

    permissionName = "ohos.permission.invalid";
    ASSERT_EQ(ERR_PERMISSION_NOT_EXIST, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        permissionName, status, userID, LEGACY_SUBPROFILE_ID));

    permissionName = "ohos.permission.USE_BLUETOOTH";
    ASSERT_EQ(ERR_PARAM_INVALID, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        permissionName, status, userID, LEGACY_SUBPROFILE_ID));
}

/**
 * @tc.name: GetPermissionRequestToggleStatus002
 * @tc.desc: Verify that legacy request toggle status is stored and queried correctly.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRequestToggleManagerTest, GetPermissionRequestToggleStatus002, TestSize.Level0)
{
    int32_t userID = TEST_USER_ID;
    const std::string permissionName = "ohos.permission.CAMERA";
    uint32_t setStatusClose = PermissionRequestToggleStatus::CLOSED;
    uint32_t setStatusOpen = PermissionRequestToggleStatus::OPEN;
    uint32_t getStatus;
    PermissionRequestToggleStatusGuard guard(userID, permissionName);

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        permissionName, getStatus, userID, LEGACY_SUBPROFILE_ID));
    ASSERT_EQ(setStatusOpen, getStatus);

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, setStatusClose, userID, LEGACY_SUBPROFILE_ID));
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        permissionName, getStatus, userID, LEGACY_SUBPROFILE_ID));
    ASSERT_EQ(setStatusClose, getStatus);

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, setStatusOpen, userID, LEGACY_SUBPROFILE_ID));
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        permissionName, getStatus, userID, LEGACY_SUBPROFILE_ID));
    ASSERT_EQ(setStatusOpen, getStatus);
}

/**
 * @tc.name: GetPermissionRequestToggleStatus003
 * @tc.desc: Verify that APP_TRACKING_CONSENT uses the closed default toggle status.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRequestToggleManagerTest, GetPermissionRequestToggleStatus003, TestSize.Level0)
{
    uint32_t status = PermissionRequestToggleStatus::OPEN;
    PermissionRequestToggleStatusGuard guard(TEST_USER_ID, APP_TRACKING_CONSENT_PERMISSION);
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        APP_TRACKING_CONSENT_PERMISSION, status, TEST_USER_ID, LEGACY_SUBPROFILE_ID));
    ASSERT_EQ(PermissionRequestToggleStatus::CLOSED, status);
}

/**
 * @tc.name: GetPermissionRequestToggleStatus005
 * @tc.desc: Verify APP_TRACKING_CONSENT query result and database record for both toggle statuses.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRequestToggleManagerTest, GetPermissionRequestToggleStatus005, TestSize.Level0)
{
    uint32_t status = PermissionRequestToggleStatus::OPEN;
    PermissionRequestToggleStatusGuard guard(TEST_USER_ID, APP_TRACKING_CONSENT_PERMISSION);

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        APP_TRACKING_CONSENT_PERMISSION, status, TEST_USER_ID, LEGACY_SUBPROFILE_ID));
    EXPECT_EQ(PermissionRequestToggleStatus::CLOSED, status);
    VerifyRequestToggleStatusRecordNotExist(TEST_USER_ID, APP_TRACKING_CONSENT_PERMISSION, LEGACY_SUBPROFILE_ID);

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        APP_TRACKING_CONSENT_PERMISSION, PermissionRequestToggleStatus::OPEN, TEST_USER_ID, LEGACY_SUBPROFILE_ID));
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        APP_TRACKING_CONSENT_PERMISSION, status, TEST_USER_ID, LEGACY_SUBPROFILE_ID));
    EXPECT_EQ(PermissionRequestToggleStatus::OPEN, status);
    VerifyRequestToggleStatusRecord(
        TEST_USER_ID, APP_TRACKING_CONSENT_PERMISSION, LEGACY_SUBPROFILE_ID, PermissionRequestToggleStatus::OPEN);

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        APP_TRACKING_CONSENT_PERMISSION, PermissionRequestToggleStatus::CLOSED, TEST_USER_ID, LEGACY_SUBPROFILE_ID));
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        APP_TRACKING_CONSENT_PERMISSION, status, TEST_USER_ID, LEGACY_SUBPROFILE_ID));
    EXPECT_EQ(PermissionRequestToggleStatus::CLOSED, status);
    VerifyRequestToggleStatusRecordNotExist(TEST_USER_ID, APP_TRACKING_CONSENT_PERMISSION, LEGACY_SUBPROFILE_ID);
}

/**
 * @tc.name: GetPermissionRequestToggleStatus004
 * @tc.desc: Verify that the account owner request toggle status can be updated and restored.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRequestToggleManagerTest, GetPermissionRequestToggleStatus004, TestSize.Level0)
{
    std::string permissionName = "ohos.permission.CAMERA";
    uint32_t oriStatus = PermissionRequestToggleStatus::OPEN;
    uint32_t status = PermissionRequestToggleStatus::OPEN;
    PermissionRequestToggleStatusGuard guard(0, permissionName);

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        permissionName, oriStatus, 0, LEGACY_SUBPROFILE_ID));

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, PermissionRequestToggleStatus::CLOSED, 0, LEGACY_SUBPROFILE_ID));
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        permissionName, status, 0, LEGACY_SUBPROFILE_ID));
    ASSERT_EQ(PermissionRequestToggleStatus::CLOSED, status);

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, oriStatus, 0, LEGACY_SUBPROFILE_ID));
}

#ifdef ACCESS_TOKEN_SUPPORT_SUBPROFILE
/**
 * @tc.name: SetPermissionRequestToggleStatusWithSubProfileId001
 * @tc.desc: Verify that legacy record blocks subProfile write until legacy mode is cleared.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRequestToggleManagerTest, SetPermissionRequestToggleStatusWithSubProfileId001, TestSize.Level0)
{
    const int32_t userID = ACCOUNT_OWNER_USER_ID;
    const std::string permissionName = "ohos.permission.CAMERA";
    PermissionRequestToggleStatusGuard guard(userID, permissionName);

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, PermissionRequestToggleStatus::CLOSED, userID, LEGACY_SUBPROFILE_ID));
    ASSERT_EQ(ERR_PERMISSION_REQUEST_TOGGLE_STORAGE_MODE_CONFLICT,
        PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
            permissionName, PermissionRequestToggleStatus::OPEN, userID, SUBPROFILE_ID_TEN));
    ASSERT_EQ(ERR_PERMISSION_REQUEST_TOGGLE_STORAGE_MODE_CONFLICT,
        PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
            permissionName, PermissionRequestToggleStatus::CLOSED, userID, SUBPROFILE_ID_TEN));

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, PermissionRequestToggleStatus::OPEN, userID, LEGACY_SUBPROFILE_ID));
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, PermissionRequestToggleStatus::CLOSED, userID, SUBPROFILE_ID_TEN));
}

/**
 * @tc.name: SetPermissionRequestToggleStatusWithSubProfileId002
 * @tc.desc: Verify that subProfile record blocks legacy write until subProfile mode is cleared.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRequestToggleManagerTest, SetPermissionRequestToggleStatusWithSubProfileId002, TestSize.Level0)
{
    const int32_t userID = ACCOUNT_OWNER_USER_ID;
    const std::string permissionName = "ohos.permission.CAMERA";
    PermissionRequestToggleStatusGuard guard(userID, permissionName);

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, PermissionRequestToggleStatus::CLOSED, userID, SUBPROFILE_ID_ELEVEN));
    ASSERT_EQ(ERR_PERMISSION_REQUEST_TOGGLE_STORAGE_MODE_CONFLICT,
        PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
            permissionName, PermissionRequestToggleStatus::OPEN, userID, LEGACY_SUBPROFILE_ID));
    ASSERT_EQ(ERR_PERMISSION_REQUEST_TOGGLE_STORAGE_MODE_CONFLICT,
        PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
            permissionName, PermissionRequestToggleStatus::CLOSED, userID, LEGACY_SUBPROFILE_ID));

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, PermissionRequestToggleStatus::OPEN, userID, SUBPROFILE_ID_ELEVEN));
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, PermissionRequestToggleStatus::CLOSED, userID, LEGACY_SUBPROFILE_ID));
}

/**
 * @tc.name: GetPermissionRequestToggleStatusWithSubProfileId001
 * @tc.desc: Verify that subProfile query inherits legacy value when subProfile record does not exist.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRequestToggleManagerTest, GetPermissionRequestToggleStatusWithSubProfileId001, TestSize.Level0)
{
    const int32_t userID = ACCOUNT_OWNER_USER_ID;
    const std::string permissionName = "ohos.permission.CAMERA";
    uint32_t status = PermissionRequestToggleStatus::OPEN;
    PermissionRequestToggleStatusGuard guard(userID, permissionName);

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, PermissionRequestToggleStatus::CLOSED, userID, LEGACY_SUBPROFILE_ID));
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        permissionName, status, userID, SUBPROFILE_ID_TWELVE));
    ASSERT_EQ(PermissionRequestToggleStatus::CLOSED, status);
}

/**
 * @tc.name: GetPermissionRequestToggleStatusWithSubProfileId002
 * @tc.desc: Verify that negative subProfile query returns stored status when records already exist.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRequestToggleManagerTest, GetPermissionRequestToggleStatusWithSubProfileId002, TestSize.Level0)
{
    const int32_t userID = SUBPROFILE_TEST_USER_ID_324;
    const std::string permissionName = "ohos.permission.CAMERA";
    uint32_t status = PermissionRequestToggleStatus::OPEN;
    PermissionRequestToggleStatusGuard guard(userID, permissionName);

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, PermissionRequestToggleStatus::CLOSED, userID, LEGACY_SUBPROFILE_ID));
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        permissionName, status, userID, INVALID_NEGATIVE_SUBPROFILE_ID));
    ASSERT_EQ(PermissionRequestToggleStatus::CLOSED, status);
}

/**
 * @tc.name: GetPermissionRequestToggleStatusWithSubProfileId003
 * @tc.desc: Verify that legacy query returns conflict when only subProfile records exist.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRequestToggleManagerTest, GetPermissionRequestToggleStatusWithSubProfileId003, TestSize.Level0)
{
    const int32_t userID = ACCOUNT_OWNER_USER_ID;
    const std::string permissionName = "ohos.permission.CAMERA";
    uint32_t status = PermissionRequestToggleStatus::OPEN;
    PermissionRequestToggleStatusGuard guard(userID, permissionName);

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, PermissionRequestToggleStatus::CLOSED, userID, SUBPROFILE_ID_THIRTEEN));
    ASSERT_EQ(ERR_PERMISSION_REQUEST_TOGGLE_LEGACY_QUERY_CONFLICT,
        PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
            permissionName, status, userID, LEGACY_SUBPROFILE_ID));
}

/**
 * @tc.name: SetPermissionRequestToggleStatusWithSubProfileId003
 * @tc.desc: Verify request toggle is isolated by userId, subProfileId and permissionName.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRequestToggleManagerTest, SetPermissionRequestToggleStatusWithSubProfileId003, TestSize.Level0)
{
    const std::string permissionName = "ohos.permission.CAMERA";
    PermissionRequestToggleStatusGuard guard(ACCOUNT_OWNER_USER_ID, permissionName);

    uint32_t status = PermissionRequestToggleStatus::OPEN;
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, PermissionRequestToggleStatus::CLOSED, ACCOUNT_OWNER_USER_ID, SUBPROFILE_ID_TEN));
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        permissionName, status, ACCOUNT_OWNER_USER_ID, SUBPROFILE_ID_TEN));
    EXPECT_EQ(PermissionRequestToggleStatus::CLOSED, status);

    status = PermissionRequestToggleStatus::CLOSED;
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        permissionName, status, ACCOUNT_OWNER_USER_ID, SUBPROFILE_ID_ELEVEN));
    EXPECT_EQ(PermissionRequestToggleStatus::OPEN, status);

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, PermissionRequestToggleStatus::CLOSED, ACCOUNT_OWNER_USER_ID, SUBPROFILE_ID_ELEVEN));
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, PermissionRequestToggleStatus::OPEN, ACCOUNT_OWNER_USER_ID, SUBPROFILE_ID_TEN));

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        permissionName, status, ACCOUNT_OWNER_USER_ID, SUBPROFILE_ID_TEN));
    EXPECT_EQ(PermissionRequestToggleStatus::OPEN, status);
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        permissionName, status, ACCOUNT_OWNER_USER_ID, SUBPROFILE_ID_ELEVEN));
    EXPECT_EQ(PermissionRequestToggleStatus::CLOSED, status);
}

/**
 * @tc.name: SetPermissionRequestToggleStatusWithSubProfileId004
 * @tc.desc: Verify subProfile record can be created after legacy record is reset to default.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRequestToggleManagerTest, SetPermissionRequestToggleStatusWithSubProfileId004, TestSize.Level0)
{
    const std::string permissionName = "ohos.permission.CAMERA";
    PermissionRequestToggleStatusGuard guard(ACCOUNT_OWNER_USER_ID, permissionName);

    uint32_t status = PermissionRequestToggleStatus::OPEN;
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, PermissionRequestToggleStatus::CLOSED, ACCOUNT_OWNER_USER_ID, LEGACY_SUBPROFILE_ID));
    EXPECT_EQ(ERR_PERMISSION_REQUEST_TOGGLE_STORAGE_MODE_CONFLICT,
        PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
            permissionName, PermissionRequestToggleStatus::OPEN, ACCOUNT_OWNER_USER_ID, SUBPROFILE_ID_TEN));

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        permissionName, status, ACCOUNT_OWNER_USER_ID, SUBPROFILE_ID_TEN));
    EXPECT_EQ(PermissionRequestToggleStatus::CLOSED, status);

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, PermissionRequestToggleStatus::OPEN, ACCOUNT_OWNER_USER_ID, LEGACY_SUBPROFILE_ID));

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        permissionName, PermissionRequestToggleStatus::CLOSED, ACCOUNT_OWNER_USER_ID, SUBPROFILE_ID_TEN));
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        permissionName, status, ACCOUNT_OWNER_USER_ID, SUBPROFILE_ID_TEN));
    EXPECT_EQ(PermissionRequestToggleStatus::CLOSED, status);
}

/**
 * @tc.name: SetPermissionRequestToggleStatusWithSubProfileId005
 * @tc.desc: Verify subProfileId outside current user returns subProfile not exist.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRequestToggleManagerTest, SetPermissionRequestToggleStatusWithSubProfileId005, TestSize.Level0)
{
    const int32_t userID = SUBPROFILE_TEST_USER_ID_321;
    const std::string permissionName = "ohos.permission.CAMERA";
    uint32_t status = PermissionRequestToggleStatus::OPEN;
    PermissionRequestToggleStatusGuard guard(userID, permissionName);

    SetMockOsAccountLocalIdForSubProfile(SUBPROFILE_TEST_USER_ID_324, ERR_OK);
    EXPECT_EQ(ERR_PERMISSION_REQUEST_TOGGLE_SUBPROFILE_NOT_EXIST,
        PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
            permissionName, PermissionRequestToggleStatus::OPEN, userID, SUBPROFILE_ID_TEN));
    EXPECT_EQ(ERR_PERMISSION_REQUEST_TOGGLE_SUBPROFILE_NOT_EXIST,
        PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
            permissionName, status, userID, SUBPROFILE_ID_TEN));
    ResetMockOsAccountManagerLite();
}

/**
 * @tc.name: SetPermissionRequestToggleStatusWithSubProfileId006
 * @tc.desc: Verify account errors are mapped correctly for subProfile toggle APIs.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRequestToggleManagerTest, SetPermissionRequestToggleStatusWithSubProfileId006, TestSize.Level0)
{
    const int32_t userID = SUBPROFILE_TEST_USER_ID_321;
    const std::string permissionName = "ohos.permission.CAMERA";
    uint32_t status = PermissionRequestToggleStatus::OPEN;
    PermissionRequestToggleStatusGuard guard(userID, permissionName);

    SetMockOsAccountLocalIdForSubProfile(userID, ERR_INVALID_VALUE);
    EXPECT_EQ(ERR_SERVICE_ABNORMAL,
        PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
            permissionName, PermissionRequestToggleStatus::OPEN, userID, SUBPROFILE_ID_TEN));
    EXPECT_EQ(ERR_SERVICE_ABNORMAL,
        PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
            permissionName, status, userID, SUBPROFILE_ID_TEN));

    SetMockOsAccountLocalIdForSubProfile(userID, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
    EXPECT_EQ(ERR_PERMISSION_REQUEST_TOGGLE_SUBPROFILE_NOT_EXIST,
        PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
            permissionName, PermissionRequestToggleStatus::OPEN, userID, SUBPROFILE_ID_TEN));
    EXPECT_EQ(ERR_PERMISSION_REQUEST_TOGGLE_SUBPROFILE_NOT_EXIST,
        PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
            permissionName, status, userID, SUBPROFILE_ID_TEN));
    ResetMockOsAccountManagerLite();
}

/**
 * @tc.name: SetPermissionRequestToggleStatusWithSubProfileId007
 * @tc.desc: Verify account query success with matched local user keeps subProfile toggle path available.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRequestToggleManagerTest, SetPermissionRequestToggleStatusWithSubProfileId007, TestSize.Level0)
{
    const int32_t userID = ACCOUNT_OWNER_USER_ID;
    const std::string permissionName = "ohos.permission.CAMERA";
    uint32_t status = PermissionRequestToggleStatus::OPEN;
    PermissionRequestToggleStatusGuard guard(userID, permissionName);

    SetMockOsAccountLocalIdForSubProfile(userID, ERR_OK);
    EXPECT_EQ(RET_SUCCESS,
        PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
            permissionName, PermissionRequestToggleStatus::OPEN, userID, SUBPROFILE_ID_TEN));
    EXPECT_EQ(RET_SUCCESS,
        PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
            permissionName, status, userID, SUBPROFILE_ID_TEN));
    EXPECT_EQ(PermissionRequestToggleStatus::OPEN, status);
    ResetMockOsAccountManagerLite();
}

/**
 * @tc.name: SetPermissionRequestToggleStatusWithSubProfileId008
 * @tc.desc: Verify APP_TRACKING_CONSENT mode conflicts preserve query and database status.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRequestToggleManagerTest, SetPermissionRequestToggleStatusWithSubProfileId008, TestSize.Level0)
{
    const int32_t userID = ACCOUNT_OWNER_USER_ID;
    uint32_t status = PermissionRequestToggleStatus::CLOSED;
    PermissionRequestToggleStatusGuard guard(userID, APP_TRACKING_CONSENT_PERMISSION);

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        APP_TRACKING_CONSENT_PERMISSION, PermissionRequestToggleStatus::OPEN, userID, LEGACY_SUBPROFILE_ID));
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        APP_TRACKING_CONSENT_PERMISSION, status, userID, LEGACY_SUBPROFILE_ID));
    EXPECT_EQ(PermissionRequestToggleStatus::OPEN, status);
    VerifyRequestToggleStatusRecord(
        userID, APP_TRACKING_CONSENT_PERMISSION, LEGACY_SUBPROFILE_ID, PermissionRequestToggleStatus::OPEN);

    EXPECT_EQ(ERR_PERMISSION_REQUEST_TOGGLE_STORAGE_MODE_CONFLICT,
        PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
            APP_TRACKING_CONSENT_PERMISSION, PermissionRequestToggleStatus::CLOSED, userID, SUBPROFILE_ID_TEN));
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        APP_TRACKING_CONSENT_PERMISSION, status, userID, LEGACY_SUBPROFILE_ID));
    EXPECT_EQ(PermissionRequestToggleStatus::OPEN, status);
    VerifyRequestToggleStatusRecord(
        userID, APP_TRACKING_CONSENT_PERMISSION, LEGACY_SUBPROFILE_ID, PermissionRequestToggleStatus::OPEN);

    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        APP_TRACKING_CONSENT_PERMISSION, PermissionRequestToggleStatus::CLOSED, userID, LEGACY_SUBPROFILE_ID));
    VerifyRequestToggleStatusRecordNotExist(userID, APP_TRACKING_CONSENT_PERMISSION, LEGACY_SUBPROFILE_ID);
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
        APP_TRACKING_CONSENT_PERMISSION, PermissionRequestToggleStatus::OPEN, userID, SUBPROFILE_ID_TEN));
    ASSERT_EQ(RET_SUCCESS, PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(
        APP_TRACKING_CONSENT_PERMISSION, status, userID, SUBPROFILE_ID_TEN));
    EXPECT_EQ(PermissionRequestToggleStatus::OPEN, status);
    VerifyRequestToggleStatusRecord(
        userID, APP_TRACKING_CONSENT_PERMISSION, SUBPROFILE_ID_TEN, PermissionRequestToggleStatus::OPEN);

    EXPECT_EQ(ERR_PERMISSION_REQUEST_TOGGLE_STORAGE_MODE_CONFLICT,
        PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(
            APP_TRACKING_CONSENT_PERMISSION, PermissionRequestToggleStatus::CLOSED, userID, LEGACY_SUBPROFILE_ID));
    VerifyRequestToggleStatusRecord(
        userID, APP_TRACKING_CONSENT_PERMISSION, SUBPROFILE_ID_TEN, PermissionRequestToggleStatus::OPEN);
}
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
